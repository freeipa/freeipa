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

import os
import tempfile
import shutil

from ipapython import (admintool, ipautil, ipaldap, sysrestore, dogtag,
                       certmonger, certdb)
from ipaplatform import services
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks
from ipalib import api, x509, certstore


class CertUpdate(admintool.AdminTool):
    command_name = 'ipa-certupdate'

    usage = "%prog [options]"

    description = ("Update local IPA certificate databases with certificates "
                   "from the server.")

    def validate_options(self):
        super(CertUpdate, self).validate_options(needs_root=True)

    def run(self):
        api.bootstrap(context='cli_installer')
        api.finalize()

        try:
            server = api.env.server
        except AttributeError:
            server = api.env.host
        ldap = ipaldap.IPAdmin(server)

        tmpdir = tempfile.mkdtemp(prefix="tmp-")
        try:
            principal = str('host/%s@%s' % (api.env.host, api.env.realm))
            ipautil.kinit_hostprincipal(paths.KRB5_KEYTAB, tmpdir, principal)

            ldap.do_sasl_gssapi_bind()

            certs = certstore.get_ca_certs(ldap, api.env.basedn,
                                           api.env.realm, api.env.enable_ra)
        finally:
            shutil.rmtree(tmpdir)

        server_fstore = sysrestore.FileStore(paths.SYSRESTORE)
        if server_fstore.has_files():
            self.update_server(certs)

        self.update_client(certs)

    def update_client(self, certs):
        self.update_file(paths.IPA_CA_CRT, certs)
        self.update_db(paths.IPA_NSSDB_DIR, certs)

        sys_db = certdb.NSSDatabase(paths.NSS_DB_DIR)
        for nickname in ('IPA CA', 'External CA cert'):
            try:
                sys_db.delete_cert(nickname)
            except ipautil.CalledProcessError, e:
                pass

        self.update_db(paths.NSS_DB_DIR, certs)

        new_nicknames = set(c[1] for c in certs)
        old_nicknames = set()
        if ipautil.file_exists(paths.NSSDB_IPA_TXT):
            try:
                list_file = open(paths.NSSDB_IPA_TXT, 'r')
            except IOError, e:
                self.log.error("failed to open %s: %s", paths.NSSDB_IPA_TXT, e)
            else:
                try:
                    lines = list_file.readlines()
                except IOError, e:
                    self.log.error(
                        "failed to read %s: %s", paths.NSSDB_IPA_TXT, e)
                else:
                    for line in lines:
                        nickname = line.strip()
                        if nickname:
                            old_nicknames.add(nickname)
                list_file.close()
        if new_nicknames != old_nicknames:
            try:
                list_file = open(paths.NSSDB_IPA_TXT, 'w')
            except IOError, e:
                self.log.error("failed to open %s: %s", paths.NSSDB_IPA_TXT, e)
            else:
                try:
                    for nickname in new_nicknames:
                        list_file.write(nickname + '\n')
                except IOError, e:
                    self.log.error(
                        "failed to write %s: %s", paths.NSSDB_IPA_TXT, e)
                list_file.close()

        tasks.remove_ca_certs_from_systemwide_ca_store()
        tasks.insert_ca_certs_into_systemwide_ca_store(certs)

    def update_server(self, certs):
        instance = '-'.join(api.env.realm.split('.'))
        self.update_db(
            paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance, certs)
        if services.knownservices.dirsrv.is_running():
            services.knownservices.dirsrv.restart(instance)

        self.update_db(paths.HTTPD_ALIAS_DIR, certs)
        if services.knownservices.httpd.is_running():
            services.knownservices.httpd.restart()

        dogtag_constants = dogtag.configured_constants()
        nickname = 'caSigningCert cert-pki-ca'
        criteria = {
            'cert-database': dogtag_constants.ALIAS_DIR,
            'cert-nickname': nickname,
        }
        request_id = certmonger.get_request_id(criteria)
        if request_id is not None:
            timeout = api.env.startup_timeout + 60

            self.log.debug("resubmitting certmonger request '%s'", request_id)
            certmonger.resubmit_request(request_id, profile='ipaRetrieval')
            try:
                state = certmonger.wait_for_request(request_id, timeout)
            except RuntimeError:
                raise admintool.ScriptError(
                    "Resubmitting certmonger request '%s' timed out, "
                    "please check the request manually" % request_id)
            if state != 'MONITORING':
                raise admintool.ScriptError(
                    "Error resubmitting certmonger request '%s', "
                    "please check the request manually" % request_id)

            self.log.debug("modifying certmonger request '%s'", request_id)
            certmonger.modify(request_id, profile='ipaCACertRenewal')

        self.update_file(paths.CA_CRT, certs)

    def update_file(self, filename, certs, mode=0444):
        certs = (c[0] for c in certs if c[2] is not False)
        try:
            x509.write_certificate_list(certs, filename)
        except Exception, e:
            self.log.error("failed to update %s: %s", filename, e)

    def update_db(self, path, certs):
        db = certdb.NSSDatabase(path)
        for cert, nickname, trusted, eku in certs:
            trust_flags = certstore.key_policy_to_trust_flags(
                trusted, True, eku)
            try:
                db.add_cert(cert, nickname, trust_flags)
            except ipautil.CalledProcessError, e:
                self.log.error(
                    "failed to update %s in %s: %s", nickname, path, e)
