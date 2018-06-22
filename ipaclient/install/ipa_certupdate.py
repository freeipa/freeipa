# Authors: Jan Cholasta <jcholast@redhat.com>
#
# Copyright (C) 2014  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import absolute_import

import logging
import os
import tempfile
import shutil

# pylint: disable=import-error
from six.moves.urllib.parse import urlsplit
# pylint: enable=import-error

from ipalib.install import certmonger, certstore, sysrestore
from ipalib.install.kinit import kinit_keytab
from ipapython import admintool, certdb, ipaldap, ipautil
from ipaplatform import services
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks
from ipalib import api, errors, x509
from ipalib.constants import IPA_CA_NICKNAME, RENEWAL_CA_NAME
from ipalib.util import check_client_configuration

logger = logging.getLogger(__name__)


class CertUpdate(admintool.AdminTool):
    command_name = 'ipa-certupdate'

    usage = "%prog [options]"

    description = ("Update local IPA certificate databases with certificates "
                   "from the server.")

    def validate_options(self):
        super(CertUpdate, self).validate_options(needs_root=True)

    def run(self):
        check_client_configuration()

        api.bootstrap(context='cli_installer', confdir=paths.ETC_IPA)
        api.finalize()

        api.Backend.rpcclient.connect()
        run_with_args(api)
        api.Backend.rpcclient.disconnect()


def run_with_args(api):
    """
    Run the certupdate procedure with the given API object.

    :param api: API object with ldap2/rpcclient backend connected
                (such that Commands can be invoked)

    """
    server = urlsplit(api.env.jsonrpc_uri).hostname
    ldap_uri = ipaldap.get_ldap_uri(server)
    ldap = ipaldap.LDAPClient(ldap_uri)

    tmpdir = tempfile.mkdtemp(prefix="tmp-")
    ccache_name = os.path.join(tmpdir, 'ccache')
    old_krb5ccname = os.environ.get('KRB5CCNAME')
    try:
        principal = str('host/%s@%s' % (api.env.host, api.env.realm))
        kinit_keytab(principal, paths.KRB5_KEYTAB, ccache_name)
        os.environ['KRB5CCNAME'] = ccache_name

        try:
            result = api.Command.ca_is_enabled(version=u'2.107')
            ca_enabled = result['result']
        except (errors.CommandError, errors.NetworkError):
            result = api.Command.env(server=True, version=u'2.0')
            ca_enabled = result['result']['enable_ra']

        ldap.gssapi_bind()

        certs = certstore.get_ca_certs(
            ldap, api.env.basedn, api.env.realm, ca_enabled)

        if ca_enabled:
            lwcas = api.Command.ca_find()['result']
        else:
            lwcas = []

    finally:
        if old_krb5ccname is None:
            del os.environ['KRB5CCNAME']
        else:
            os.environ['KRB5CCNAME'] = old_krb5ccname
        shutil.rmtree(tmpdir)

    server_fstore = sysrestore.FileStore(paths.SYSRESTORE)
    if server_fstore.has_files():
        update_server(certs)
        try:
            # pylint: disable=import-error,ipa-forbidden-import
            from ipaserver.install import cainstance
            # pylint: enable=import-error,ipa-forbidden-import
            cainstance.add_lightweight_ca_tracking_requests(lwcas)
        except Exception:
            logger.exception(
                "Failed to add lightweight CA tracking requests")

    update_client(certs)


def update_client(certs):
    update_file(paths.IPA_CA_CRT, certs)
    update_file(paths.KDC_CA_BUNDLE_PEM, certs)
    update_file(paths.CA_BUNDLE_PEM, certs)

    ipa_db = certdb.NSSDatabase(api.env.nss_dir)

    # Remove old IPA certs from /etc/ipa/nssdb
    for nickname in ('IPA CA', 'External CA cert'):
        while ipa_db.has_nickname(nickname):
            try:
                ipa_db.delete_cert(nickname)
            except ipautil.CalledProcessError as e:
                logger.error(
                    "Failed to remove %s from %s: %s",
                    nickname, ipa_db.secdir, e)
                break

    update_db(ipa_db.secdir, certs)

    tasks.remove_ca_certs_from_systemwide_ca_store()
    tasks.insert_ca_certs_into_systemwide_ca_store(certs)


def update_server(certs):
    instance = '-'.join(api.env.realm.split('.'))
    update_db(paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance, certs)
    if services.knownservices.dirsrv.is_running():
        services.knownservices.dirsrv.restart(instance)

    if services.knownservices.httpd.is_running():
        services.knownservices.httpd.restart()

    criteria = {
        'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
        'cert-nickname': IPA_CA_NICKNAME,
        'ca-name': RENEWAL_CA_NAME,
    }
    request_id = certmonger.get_request_id(criteria)
    if request_id is not None:
        timeout = api.env.startup_timeout + 60

        logger.debug("resubmitting certmonger request '%s'", request_id)
        certmonger.resubmit_request(
            request_id, ca='dogtag-ipa-ca-renew-agent-reuse', profile='')
        try:
            state = certmonger.wait_for_request(request_id, timeout)
        except RuntimeError:
            raise admintool.ScriptError(
                "Resubmitting certmonger request '%s' timed out, "
                "please check the request manually" % request_id)
        ca_error = certmonger.get_request_value(request_id, 'ca-error')
        if state != 'MONITORING' or ca_error:
            raise admintool.ScriptError(
                "Error resubmitting certmonger request '%s', "
                "please check the request manually" % request_id)

        logger.debug("modifying certmonger request '%s'", request_id)
        certmonger.modify(request_id, ca='dogtag-ipa-ca-renew-agent')

    update_file(paths.CA_CRT, certs)
    update_file(paths.CACERT_PEM, certs)


def update_file(filename, certs, mode=0o644):
    certs = (c[0] for c in certs if c[2] is not False)
    try:
        x509.write_certificate_list(certs, filename, mode=mode)
    except Exception as e:
        logger.error("failed to update %s: %s", filename, e)


def update_db(path, certs):
    db = certdb.NSSDatabase(path)
    for cert, nickname, trusted, eku in certs:
        trust_flags = certstore.key_policy_to_trust_flags(trusted, True, eku)
        try:
            db.add_cert(cert, nickname, trust_flags)
        except ipautil.CalledProcessError as e:
            logger.error("failed to update %s in %s: %s", nickname, path, e)
