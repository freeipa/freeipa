# Authors: Ade Lee <alee@redhat.com>
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

import base64
import logging
import time
import typing

import ldap
import os
import shutil
import traceback
import dbus
import re
import lxml.etree

from configparser import DEFAULTSECT, ConfigParser, RawConfigParser

import six

import pki
from pki.client import PKIConnection
import pki.system
import pki.util

from ipalib import api, errors, x509
from ipalib.install import certmonger
from ipalib.constants import CA_DBUS_TIMEOUT, IPA_CA_RECORD, RENEWAL_CA_NAME
from ipaplatform import services
from ipaplatform.constants import constants
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks
from ipapython import directivesetter
from ipapython import ipaldap
from ipapython import ipautil
from ipapython.dn import DN
from ipaserver.install import service
from ipaserver.install import sysupgrade
from ipaserver.install import replication
from ipaserver.install.installutils import stopped_service


logger = logging.getLogger(__name__)


INTERNAL_TOKEN = "internal"

OU_GROUPS_DN = DN(('ou', 'groups'), ('o', 'ipaca'))


def _person_dn(uid):
    return DN(('uid', uid), ('ou', 'people'), ('o', 'ipaca'))


def _group_dn(group):
    return DN(('cn', group), OU_GROUPS_DN)


def get_security_domain():
    """
    Get the security domain from the REST interface on the local Dogtag CA
    This function will succeed if the local dogtag CA is up.
    """
    connection = PKIConnection(
        protocol='https',
        hostname=api.env.ca_host,
        port='8443',
        cert_paths=paths.IPA_CA_CRT
    )
    domain_client = pki.system.SecurityDomainClient(connection)
    info = domain_client.get_domain_info()
    return info


def is_installing_replica(sys_type):
    """
    We expect only one of each type of Dogtag subsystem in an IPA deployment.
    That means that if a subsystem of the specified type has already been
    deployed - and therefore appears in the security domain - then we must be
    installing a replica.
    """
    info = get_security_domain()
    try:
        sys_list = info.subsystems[sys_type]
        return len(sys_list.hosts) > 0
    except KeyError:
        return False


class DogtagInstance(service.Service):
    """
    This is the base class for a Dogtag 10+ instance, which uses a
    shared tomcat instance and DS to host the relevant subsystems.

    It contains functions that will be common to installations of the
    CA, KRA, and eventually TKS and TPS.
    """

    # Mapping of nicknames for tracking requests, and the profile to
    # use for that certificate.  'configure_renewal()' reads this
    # dict.  The profile MUST be specified.
    tracking_reqs = dict()

    # HSM state is shared between CA and KRA
    hsm_sstore = 'pki_hsm'

    # override token for specific nicknames
    token_names = dict()

    def get_token_name(self, nickname):
        """Look up token name for nickname."""
        return self.token_names.get(nickname, self.token_name)

    groups_aci = (
        b'(targetfilter="(objectClass=groupOfUniqueNames)")'
        b'(targetattr="cn || description || objectclass || uniquemember")'
        b'(version 3.0; acl "Allow users from o=ipaca to read groups"; '
        b'allow (read, search, compare) '
        b'userdn="ldap:///uid=*,ou=people,o=ipaca";)'
    )

    def __init__(self, realm, subsystem, service_desc, host_name=None,
                 nss_db=paths.PKI_TOMCAT_ALIAS_DIR, service_prefix=None,
                 config=None):
        """Initializer"""

        super(DogtagInstance, self).__init__(
            'pki-tomcatd',
            service_desc=service_desc,
            realm_name=realm,
            service_user=constants.PKI_USER,
            service_prefix=service_prefix
        )

        self.admin_password = None
        self.fqdn = host_name
        self.pkcs12_info = None
        self.clone = False

        self.basedn = None
        self.admin_user = "admin"
        self.admin_dn = _person_dn(self.admin_user)
        self.admin_groups = None
        self.tmp_agent_db = None
        self.subsystem = subsystem
        # replication parameters
        self.master_host = None
        self.master_replication_port = 389
        self.nss_db = nss_db
        self.config = config  # Path to CS.cfg

        # filled out by configure_instance
        self.pki_config_override = None
        self.ca_subject = None
        self.subject_base = None
        self.ajp_secret = None

    def is_installed(self):
        """
        Determine if subsystem instance has been installed.

        Returns True/False
        """
        try:
            result = ipautil.run(
                ['pki-server', 'subsystem-show', self.subsystem.lower()],
                capture_output=True)
            # parse the command output
            return 'Enabled: ' in result.output
        except ipautil.CalledProcessError:
            return False

    def spawn_instance(self, cfg_file, nolog_list=()):
        """
        Create and configure a new Dogtag instance using pkispawn.
        Passes in a configuration file with IPA-specific
        parameters.
        """
        subsystem = self.subsystem
        spawn_env = os.environ.copy()
        timeout = str(api.env.startup_timeout)
        spawn_env["PKISPAWN_STARTUP_TIMEOUT_SECONDS"] = timeout

        args = [paths.PKISPAWN,
                "-s", subsystem,
                "-f", cfg_file,
                "--debug"]

        # specify --log-file <path> on PKI 11.0.0 or later

        pki_version = pki.util.Version(pki.specification_version())
        if pki_version >= pki.util.Version("11.0.0"):
            timestamp = time.strftime(
                "%Y%m%d%H%M%S",
                time.localtime(time.time()))
            log_file = os.path.join(
                paths.VAR_LOG_PKI_DIR,
                "pki-%s-spawn.%s.log" % (self.subsystem.lower(), timestamp))
            args.extend(["--log-file", log_file])

        with open(cfg_file) as f:
            logger.debug(
                'Contents of pkispawn configuration file (%s):\n%s',
                cfg_file, ipautil.nolog_replace(f.read(), nolog_list))

        try:
            ipautil.run(args, nolog=nolog_list, env=spawn_env)
        except ipautil.CalledProcessError as e:
            self.handle_setup_error(e)

    def clean_pkispawn_files(self):
        if self.tmp_agent_db is not None:
            logger.debug("Removing %s", self.tmp_agent_db)
            shutil.rmtree(self.tmp_agent_db, ignore_errors=True)

        client_dir = os.path.join(
            '/root/.dogtag/pki-tomcat/', self.subsystem.lower())
        logger.debug("Removing %s", client_dir)
        shutil.rmtree(client_dir, ignore_errors=True)

    def restart_instance(self):
        self.restart('pki-tomcat')

    def start_instance(self):
        self.start('pki-tomcat')

    def stop_instance(self):
        try:
            self.stop('pki-tomcat')
        except Exception:
            logger.debug("%s", traceback.format_exc())
            logger.critical(
                "Failed to stop the Dogtag instance."
                "See the installation log for details.")

    def enable_client_auth_to_db(self):
        """
        Enable client auth connection to the internal db.
        """
        sub_system_nickname = "subsystemCert cert-pki-ca"
        if self.token_name != INTERNAL_TOKEN:
            # TODO: Dogtag 10.6.9 does not like "internal" prefix.
            sub_system_nickname = '{}:{}'.format(
                self.token_name, sub_system_nickname
            )

        with stopped_service('pki-tomcatd', 'pki-tomcat'):
            directivesetter.set_directive(
                self.config,
                'authz.instance.DirAclAuthz.ldap.ldapauth.authtype',
                'SslClientAuth', quotes=False, separator='=')
            directivesetter.set_directive(
                self.config,
                'authz.instance.DirAclAuthz.ldap.ldapauth.clientCertNickname',
                sub_system_nickname, quotes=False, separator='=')
            directivesetter.set_directive(
                self.config,
                'authz.instance.DirAclAuthz.ldap.ldapconn.port', '636',
                quotes=False, separator='=')
            directivesetter.set_directive(
                self.config,
                'authz.instance.DirAclAuthz.ldap.ldapconn.secureConn',
                'true', quotes=False, separator='=')

            directivesetter.set_directive(
                self.config,
                'internaldb.ldapauth.authtype',
                'SslClientAuth', quotes=False, separator='=')

            directivesetter.set_directive(
                self.config,
                'internaldb.ldapauth.clientCertNickname',
                sub_system_nickname, quotes=False, separator='=')
            directivesetter.set_directive(
                self.config,
                'internaldb.ldapconn.port', '636', quotes=False, separator='=')
            directivesetter.set_directive(
                self.config,
                'internaldb.ldapconn.secureConn', 'true', quotes=False,
                separator='=')
            # Remove internaldb password as is not needed anymore
            directivesetter.set_directive(paths.PKI_TOMCAT_PASSWORD_CONF,
                                       'internaldb', None, separator='=')

    def uninstall(self):
        if self.is_installed():
            self.print_msg("Unconfiguring %s" % self.subsystem)

        args = []
        pki_version = pki.util.Version(pki.specification_version())
        if self.subsystem == "ACME":
            if pki_version < pki.util.Version("11.0.0"):
                return
            elif (
                pki.util.Version("11.0.0") <= pki_version
                <= pki.util.Version("11.5.0")
            ):
                args = ['pki-server', 'acme-remove']
            else:
                # fall through for PKI >= 11.6.0
                pass
        if not args:
            args = [paths.PKIDESTROY,
                    "-i", "pki-tomcat", "--force",
                    "-s", self.subsystem]

            # specify --log-file <path> on PKI 11.0.0 or later

            if pki_version >= pki.util.Version("11.0.0"):
                timestamp = time.strftime(
                    "%Y%m%d%H%M%S",
                    time.localtime(time.time()))
                log_file = os.path.join(
                    paths.VAR_LOG_PKI_DIR,
                    "pki-%s-destroy.%s.log" %
                    (self.subsystem.lower(), timestamp))
                args.extend(["--log-file", log_file])
            if pki_version >= pki.util.Version("11.6.0"):
                args.extend(["--remove-conf", "--remove-logs"])

        try:
            ipautil.run(args)

        except ipautil.CalledProcessError as e:
            logger.critical("failed to uninstall %s instance %s",
                            self.subsystem, e)

    def _is_newer_tomcat_version(self, default=None):
        try:
            result = ipautil.run([paths.BIN_TOMCAT, "version"],
                                 capture_output=True)
            sn = re.search(
                r'Server number:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
                result.output)
            if sn is None:
                logger.info("tomcat version cannot be parsed, "
                            "default to pre-%s", default)
                return False
            v = tasks.parse_ipa_version(sn.group(1))
            if v >= tasks.parse_ipa_version(default):
                return True
        except ipautil.CalledProcessError as e:
            logger.info(
                "failed to discover tomcat version, "
                "default to pre-%s, error: %s",
                default, str(e))
        return False

    def secure_ajp_connector(self):
        """ Update AJP connector to use a password protection  """

        server_xml = lxml.etree.parse(paths.PKI_TOMCAT_SERVER_XML)
        doc = server_xml.getroot()

        # no AJP connector means no need to update anything
        connectors = doc.xpath('//Connector[@protocol="AJP/1.3"]')
        if len(connectors) == 0:
            return False

        # Whether or not we should rewrite the tomcat server.xml file with
        # our changes.
        rewrite = False

        # Detect tomcat version and choose the right option name
        # pre-9.0.31.0 uses 'requiredSecret'
        # 9.0.31.0 or later uses 'secret'
        secretattr = 'requiredSecret'
        oldattr = 'requiredSecret'
        if self._is_newer_tomcat_version('9.0.31.0'):
            secretattr = 'secret'

        # AJP protocol is at version 1.3. With IPv4/IPv6 split, there might
        # be multiple AJP adapters; update them all.
        #
        # First, iterate through all adapters and see if any of them have a
        # secret value set.
        for connector in connectors:
            if not self._is_newer_tomcat_version('9.0.31.0'):
                # For a time pki unconditionally added "secret" to the
                # connector. Remove it prior to probing for the current
                # secret.
                if 'secret' in connector.attrib:
                    del connector.attrib['secret']
                    rewrite = True

            if secretattr in connector.attrib or oldattr in connector.attrib:
                # secret is already in place
                #
                # Perhaps, we need to synchronize it with Apache configuration
                # or other AJP connector entries. Save it so we know we've
                # found at least one. Because in our next loop we update the
                # config value if incorrect, it is safe to overwrite
                # self.ajp_adapter -- in the worst case, we'll create an
                # entirely new value if this element happened to have an
                # empty secret value. Plus, IPA is in charge of managing the
                # value for the httpd side of the AJP connection as well
                # which needs to happen after this call.
                #
                # The first secret found wins.
                self.ajp_secret = connector.attrib.get(secretattr) or \
                    connector.attrib.get(oldattr)
                break

        # If no secret value was detected, create a single unique value.
        if not self.ajp_secret:
            # Generate password, don't use special chars to not break XML.
            self.ajp_secret = ipautil.ipa_generate_password(special=None)

        # Finally, iterate through them all again, upgrading adapter attribute
        # and setting the secret value if missing or incorrect.
        for connector in connectors:
            if oldattr != secretattr and oldattr in connector.attrib:
                # Sufficiently new Dogtag versions (10.9.0-a2) handle the
                # upgrade for us; we need only to ensure that we're not both
                # attempting to upgrade server.xml at the same time.
                # Hopefully this is guaranteed for us.
                connector.attrib[secretattr] = self.ajp_secret
                del connector.attrib[oldattr]
                rewrite = True
            if (secretattr not in connector.attrib
                    or connector.attrib[secretattr] != self.ajp_secret):
                # We hit this either when:
                #
                #   1. pkispawn was run on an older Dogtag version, or
                #   2. there were multiple AJP adapters with mismatched
                #      secrets.
                #
                # Newer Dogtag versions will generate a random password
                # during pkispawn. In the former scenario, it is always
                # safe to change the AJP secret value. In the latter
                # scenario we should always ensure the AJP connector is
                # the one we use use with httpd, as we don't officially
                # support multiple AJP adapters for non-IPA uses.
                #
                # In new Dogtag versions, Dogtag deploys separate IPv4 and
                # IPv6 localhost adapters, which we should ensure have the
                # same AJP secret for httpd's use.
                connector.attrib[secretattr] = self.ajp_secret
                rewrite = True

        if rewrite:
            with open(paths.PKI_TOMCAT_SERVER_XML, "wb") as fd:
                server_xml.write(fd, pretty_print=True, encoding="utf-8")
                os.fchmod(fd.fileno(), 0o660)
                self.service_user.chown(fd.fileno())

        return rewrite

    def http_proxy(self):
        """ Update the http proxy file  """
        template_filename = (
            os.path.join(paths.USR_SHARE_IPA_DIR,
                         "ipa-pki-proxy.conf.template"))
        sub_dict = dict(
            DOGTAG_PORT=8009,
            CLONE='' if self.clone else '#',
            FQDN=self.fqdn,
            DOGTAG_AJP_SECRET='',
        )
        if self.ajp_secret:
            sub_dict['DOGTAG_AJP_SECRET'] = "secret={}".format(self.ajp_secret)
        template = ipautil.template_file(template_filename, sub_dict)
        with open(paths.HTTPD_IPA_PKI_PROXY_CONF, "w") as fd:
            fd.write(template)
            os.fchmod(fd.fileno(), 0o640)

    @staticmethod
    def configure_certmonger_renewal_helpers():
        """
        Create a new CA type for certmonger that will retrieve updated
        certificates from the dogtag master server.
        """
        cmonger = services.knownservices.certmonger
        cmonger.enable()
        if not services.knownservices.dbus.is_running():
            # some platforms protect dbus with RefuseManualStart=True
            services.knownservices.dbus.start()
        cmonger.start()

        bus = dbus.SystemBus()
        obj = bus.get_object('org.fedorahosted.certmonger',
                             '/org/fedorahosted/certmonger')
        iface = dbus.Interface(obj, 'org.fedorahosted.certmonger')
        for suffix, args in [
            ('', ''),
            ('-reuse', ' --reuse-existing'),
            ('-selfsigned', ' --force-self-signed'),
        ]:
            name = RENEWAL_CA_NAME + suffix
            path = iface.find_ca_by_nickname(name)
            if not path:
                command = paths.DOGTAG_IPA_CA_RENEW_AGENT_SUBMIT + args
                iface.add_known_ca(
                    name,
                    command,
                    dbus.Array([], dbus.Signature('s')),
                    # Give dogtag extra time to generate cert
                    timeout=CA_DBUS_TIMEOUT)

    def __get_pin(self, token_name=INTERNAL_TOKEN):
        try:
            return certmonger.get_pin(token_name)
        except IOError as e:
            logger.debug(
                'Unable to determine PIN for the Dogtag instance: %s', e)
            raise RuntimeError(e)

    def configure_renewal(self):
        """ Configure certmonger to renew system certs """

        if self.hsm_enabled:
            nss_user = constants.PKI_USER
        else:
            nss_user = None
        for nickname, profile in self.tracking_reqs.items():
            token_name = self.get_token_name(nickname)
            pin = self.__get_pin(token_name)
            try:
                certmonger.start_tracking(
                    certpath=self.nss_db,
                    ca=RENEWAL_CA_NAME,
                    nickname=nickname,
                    token_name=token_name,
                    pin=pin,
                    pre_command='stop_pkicad',
                    post_command='renew_ca_cert "%s"' % nickname,
                    profile=profile,
                    nss_user=nss_user,
                )
            except RuntimeError as e:
                logger.error(
                    "certmonger failed to start tracking certificate: %s", e)

    def stop_tracking_certificates(self):
        """
        Stop tracking our certificates. Called on uninstall.  Also called
        during upgrade to fix discrepancies.

        """
        logger.debug(
            "Configuring certmonger to stop tracking system certificates "
            "for %s", self.subsystem)

        cmonger = services.knownservices.certmonger
        if not services.knownservices.dbus.is_running():
            # some platforms protect dbus with RefuseManualStart=True
            services.knownservices.dbus.start()
        cmonger.start()

        for nickname in self.tracking_reqs:
            try:
                certmonger.stop_tracking(
                    self.nss_db, nickname=nickname)
            except RuntimeError as e:
                logger.error(
                    "certmonger failed to stop tracking certificate: %s", e)

    def update_cert_cs_cfg(self, directive, cert):
        """
        When renewing a Dogtag subsystem certificate the configuration file
        needs to get the new certificate as well.

        ``directive`` is the directive to update in CS.cfg
        cert is IPACertificate.
        cs_cfg is the path to the CS.cfg file
        """

        with stopped_service('pki-tomcatd', 'pki-tomcat'):
            directivesetter.set_directive(
                self.config,
                directive,
                # the cert must be only the base64 string without headers
                (base64.b64encode(cert.public_bytes(x509.Encoding.DER))
                 .decode('ascii')),
                quotes=False,
                separator='=')

    def get_admin_cert(self):
        """
        Get the certificate for the admin user by checking the ldap entry
        for the user.  There should be only one certificate per user.
        """
        logger.debug('Trying to find the certificate for the admin user')
        conn = None

        try:
            conn = ipaldap.LDAPClient.from_realm(self.realm)
            conn.external_bind()

            entry_attrs = conn.get_entry(self.admin_dn, ['usercertificate'])
            admin_cert = entry_attrs.get('usercertificate')[0]

            # TODO(edewata) Add check to warn if there is more than one cert.
        finally:
            if conn is not None:
                conn.unbind()

        return admin_cert

    def handle_setup_error(self, e):
        logger.critical("Failed to configure %s instance",
                        self.subsystem)
        logger.critical("See the installation logs and the following "
                        "files/directories for more information:")
        logger.critical("  %s", paths.TOMCAT_TOPLEVEL_DIR)

        raise RuntimeError(
            "%s configuration failed." % self.subsystem
        ) from None

    def add_ipaca_aci(self):
        """Add ACI to allow ipaca users to read their own group information

        Dogtag users aren't allowed to enumerate their own groups. The
        setup_admin() method needs the permission to wait, until all group
        information has been replicated.
        """
        dn = OU_GROUPS_DN
        mod = [(ldap.MOD_ADD, 'aci', [self.groups_aci])]
        try:
            api.Backend.ldap2.modify_s(dn, mod)
        except ldap.TYPE_OR_VALUE_EXISTS:
            logger.debug("%s already has ACI to read group information", dn)
        else:
            logger.debug("Added ACI to read groups to %s", dn)

    @staticmethod
    def ensure_group(group: str, desc: str) -> None:
        """Create the group if it does not exist."""
        dn = _group_dn(group)
        entry = api.Backend.ldap2.make_entry(
            dn,
            objectclass=["top", "groupOfUniqueNames"],
            cn=[group],
            description=[desc],
        )
        try:
            api.Backend.ldap2.add_entry(entry)
        except errors.DuplicateEntry:
            pass

    @staticmethod
    def create_user(
        uid: str,
        cn: str,
        sn: str,
        user_type: str,
        groups: typing.Collection[str],
        force: bool,
    ) -> typing.Optional[str]:
        """
        Create the user entry with a random password, and add the user to
        the given groups.

        If such a user entry already exists, ``force`` determines whether the
        existing entry is replaced, or if the operation fails.

        **Does not wait for replication**.  This should be done by caller,
        if necessary.

        Return the password if entry was created, otherwise ``None``.

        """
        user_types = {'adminType', 'agentType'}
        if user_type not in user_types:
            raise ValueError(f"user_type must be in {user_types}")

        # if entry already exists, delete (force=True) or fail
        dn = _person_dn(uid)
        try:
            api.Backend.ldap2.get_entry(dn, ['uid'])
        except errors.NotFound:
            pass
        else:
            if force:
                api.Backend.ldap2.delete_entry(dn)
            else:
                return None

        # add user
        password = ipautil.ipa_generate_password()
        entry = api.Backend.ldap2.make_entry(
            dn,
            objectclass=[
                "top", "person", "organizationalPerson",
                "inetOrgPerson", "cmsuser",
            ],
            uid=[uid],
            cn=[cn],
            sn=[sn],
            usertype=[user_type],
            userPassword=[password],
            userstate=['1'],
        )
        api.Backend.ldap2.add_entry(entry)

        # add to groups
        for group in groups:
            mod = [(ldap.MOD_ADD, 'uniqueMember', [dn])]
            try:
                api.Backend.ldap2.modify_s(_group_dn(group), mod)
            except ldap.TYPE_OR_VALUE_EXISTS:
                pass  # already there, somehow

        return password

    @staticmethod
    def delete_user(uid: str) -> bool:
        """
        Delete the user, removing group memberships along the way.

        Return True if user was deleted or False if user entry
        did not exist.

        """
        dn = _person_dn(uid)

        if not api.Backend.ldap2.isconnected():
            api.Backend.ldap2.connect()

        # remove group memberships
        try:
            entries = api.Backend.ldap2.get_entries(
                OU_GROUPS_DN, filter=f'(uniqueMember={dn})')
        except errors.EmptyResult:
            entries = []
        except errors.NotFound:
            # basedn not found; Dogtag is probably not installed.
            # Let's ignore this and keep going.
            entries = []

        for entry in entries:
            # remove the uniquemember value
            entry['uniquemember'] = [
                v for v in entry['uniquemember']
                if DN(v) != dn
            ]
            api.Backend.ldap2.update_entry(entry)

        # delete user entry
        try:
            api.Backend.ldap2.delete_entry(dn)
        except errors.NotFound:
            return False
        else:
            return True

    def setup_admin(self):
        self.admin_user = "admin-%s" % self.fqdn
        self.admin_password = ipautil.ipa_generate_password()
        self.admin_dn = _person_dn(self.admin_user)

        result = self.create_user(
            uid=self.admin_user,
            cn=self.admin_user,
            sn=self.admin_user,
            user_type='adminType',
            groups=self.admin_groups,
            force=True,
        )
        if result is None:
            return None  # something went wrong
        else:
            self.admin_password = result

        # Now wait until the other server gets replicated this data
        master_conn = ipaldap.LDAPClient.from_hostname_secure(
            self.master_host
        )
        logger.debug(
            "Waiting %s seconds for %s to appear on %s",
            api.env.replication_wait_timeout, self.admin_dn, master_conn
        )
        deadline = time.time() + api.env.replication_wait_timeout
        while time.time() < deadline:
            time.sleep(1)
            try:
                master_conn.simple_bind(self.admin_dn, self.admin_password)
            except errors.ACIError:
                # user not replicated yet
                pass
            else:
                logger.debug("Successfully logged in as %s", self.admin_dn)
                break
        else:
            logger.error(
                "Unable to log in as %s on %s", self.admin_dn, master_conn
            )
            logger.info(
                "[hint] tune with replication_wait_timeout"
            )
            raise errors.NotFound(
                reason="{} did not replicate to {}".format(
                    self.admin_dn, master_conn
                )
            )

        # wait for group membership
        for group_dn in (_group_dn(group) for group in self.admin_groups):
            replication.wait_for_entry(
                master_conn,
                group_dn,
                timeout=api.env.replication_wait_timeout,
                attr='uniqueMember',
                attrvalue=self.admin_dn
            )

    def teardown_admin(self):
        self.delete_user(self.admin_user)

    def backup_config(self):
        """
        Create a backup copy of CS.cfg
        """
        config = self.config
        bak = config + '.ipabkp'
        if services.knownservices['pki_tomcatd'].is_running('pki-tomcat'):
            raise RuntimeError(
                "Dogtag must be stopped when creating backup of %s" % config)
        shutil.copy(config, bak)
        # shutil.copy() doesn't copy owner
        s = os.stat(config)
        os.chown(bak, s.st_uid, s.st_gid)

    def reindex_task(self, force=False):
        """Reindex ipaca entries

        pkispawn sometimes does not run its indextasks. This leads to slow
        unindexed filters on attributes such as description, which is used
        to log in with a certificate. Explicitly reindex attribute that
        should have been reindexed by CA's indextasks.ldif.

        See https://pagure.io/dogtagpki/issue/3083
        """
        state_name = 'reindex_task'
        if not force and sysupgrade.get_upgrade_state('dogtag', state_name):
            return

        cn = "indextask_ipaca_{}".format(int(time.time()))
        dn = DN(
            ('cn', cn), ('cn', 'index'), ('cn', 'tasks'), ('cn', 'config')
        )
        entry = api.Backend.ldap2.make_entry(
            dn,
            objectClass=['top', 'extensibleObject'],
            cn=[cn],
            nsInstance=['ipaca'],  # Dogtag PKI database
            nsIndexAttribute=[
                # from pki/base/ca/shared/conf/indextasks.ldif
                'archivedBy', 'certstatus', 'clientId', 'dataType',
                'dateOfCreate', 'description', 'duration', 'extension',
                'issuedby', 'issuername', 'metaInfo', 'notafter',
                'notbefore', 'ownername', 'publicKeyData', 'requestid',
                'requestowner', 'requestsourceid', 'requeststate',
                'requesttype', 'revInfo', 'revokedOn', 'revokedby',
                'serialno', 'status', 'subjectname',
            ],
            ttl=[10],
        )
        logger.debug('Creating ipaca reindex task %s', dn)
        api.Backend.ldap2.add_entry(entry)
        logger.debug('Waiting for task...')
        exitcode = replication.wait_for_task(api.Backend.ldap2, dn)
        logger.debug(
            'Task %s has finished with exit code %i',
            dn, exitcode
        )
        sysupgrade.set_upgrade_state('dogtag', state_name, True)

    def set_hsm_state(self, config):
        section_name = self.subsystem.upper()
        assert section_name == 'CA'
        if config.getboolean(section_name, 'pki_hsm_enable', fallback=False):
            enable = True
            token_name = config.get(section_name, 'pki_token_name')
        else:
            enable = False
            token_name = INTERNAL_TOKEN
        self.sstore.backup_state(self.hsm_sstore, "enabled", enable)
        self.sstore.backup_state(self.hsm_sstore, "token_name", token_name)

    def restore_hsm_state(self):
        return (
            self.sstore.restore_state(self.hsm_sstore, "enabled"),
            self.sstore.restore_state(self.hsm_sstore, "token_name"),
        )

    @property
    def hsm_enabled(self):
        """Is HSM support enabled?"""
        return self.sstore.get_state(self.hsm_sstore, "enabled")

    @property
    def token_name(self):
        """HSM token name"""
        return self.sstore.get_state(self.hsm_sstore, "token_name")

    def _configure_clone(self, subsystem_config, security_domain_hostname,
                         clone_pkcs12_path):
        subsystem_config.update(
            # Security domain registration
            pki_security_domain_hostname=security_domain_hostname,
            pki_security_domain_https_port=443,
            pki_security_domain_user=self.admin_user,
            pki_security_domain_password=self.admin_password,
            # Clone
            pki_clone=True,
            pki_clone_replication_security="TLS",
            pki_clone_replication_master_port=self.master_replication_port,
            pki_clone_replication_clone_port=389,
            pki_clone_replicate_schema=False,
            pki_clone_uri="https://%s" % ipautil.format_netloc(
                self.master_host, 443),
        )
        if clone_pkcs12_path:
            subsystem_config.update(
                pki_clone_pkcs12_path=clone_pkcs12_path,
                pki_clone_pkcs12_password=self.dm_password,
            )

    def _create_spawn_config(self, subsystem_config):
        loader = PKIIniLoader(
            subsystem=self.subsystem,
            fqdn=self.fqdn,
            domain=api.env.domain,
            subject_base=self.subject_base,
            ca_subject=self.ca_subject,
            admin_user=self.admin_user,
            admin_password=self.admin_password,
            dm_password=self.dm_password,
            pki_config_override=self.pki_config_override
        )
        return loader.create_spawn_config(subsystem_config)


class PKIIniLoader:
    # supported subsystems
    subsystems = ('CA', 'KRA')
    # default, hard-coded, and immutable settings
    ipaca_default = os.path.join(
        paths.USR_SHARE_IPA_DIR, 'ipaca_default.ini'
    )
    # customizable settings
    ipaca_customize = os.path.join(
        paths.USR_SHARE_IPA_DIR, 'ipaca_customize.ini'
    )
    # keys that may be stored in a HSM token
    token_stanzas = (
        'pki_audit_signing_token',
        'pki_subsystem_token',
        'pki_ca_signing_token',
        'pki_ocsp_signing_token',
        'pki_storage_token',
        'pki_transport_token',
    )
    # Set of immutable keys, initialized on demand
    _immutable_keys = None
    # Set of immutable config keys that are defined in dynamic code instead
    # of ipaca_default config file.
    _immutable_code_keys = frozenset({
        # dogtaginstance
        'pki_admin_password',
        'pki_ds_password',
        'pki_dns_domainname',
        'pki_hostname',
        'pki_subsystem',
        'pki_subsystem_type',
        # clone settings
        'pki_security_domain_hostname',
        'pki_security_domain_https_port',
        'pki_security_domain_user',
        'pki_security_domain_password',
        'pki_clone',
        'pki_clone_pkcs12_path',
        'pki_clone_pkcs12_password',
        'pki_clone_replication_security',
        'pki_clone_replication_master_port',
        'pki_clone_replication_clone_port',
        'pki_clone_replicate_schema',
        'pki_clone_uri',
        # cainstance
        'pki_ds_secure_connection',
        'pki_server_database_password',
        'pki_ds_create_new_db',
        'pki_clone_setup_replication',
        'pki_clone_reindex_data',
        'pki_external',
        'pki_ca_signing_csr_path',
        'pki_ca_signing_cert_path',
        'pki_cert_chain_path',
        'pki_external_step_two',
        # krainstance
        'pki_issuing_ca_uri',
        'pki_client_database_dir',
        'pki_client_database_password',
        'pki_client_database_purge',
        'pki_client_pkcs12_password',
        'pki_import_admin_cert',
        'pki_client_admin_cert_p12',
    })

    def __init__(self, subsystem, fqdn, domain,
                 subject_base, ca_subject, admin_user, admin_password,
                 dm_password, pki_config_override=None):
        self.pki_config_override = pki_config_override
        self.defaults = dict(
            # pretty much static
            ipa_ca_pem_file=paths.IPA_CA_CRT,
            pki_configuration_path=paths.PKI_CONFIGURATION,
            # variable
            ipa_ca_subject=ca_subject,
            ipa_subject_base=subject_base,
            ipa_fqdn=fqdn,
            ipa_ocsp_uri="http://{}.{}/ca/ocsp".format(
                IPA_CA_RECORD, ipautil.format_netloc(domain)),
            ipa_admin_cert_p12=paths.DOGTAG_ADMIN_P12,
            ipa_admin_user=admin_user,
            pki_admin_password=admin_password,
            pki_ds_password=dm_password,
            # Dogtag's pkiparser defines these config vars by default:
            pki_dns_domainname=domain,
            pki_hostname=fqdn,
            pki_subsystem=subsystem.upper(),
            pki_subsystem_type=subsystem.lower(),
            home_dir=os.path.expanduser("~"),
            # for softhsm2 testing
            softhsm2_so=paths.LIBSOFTHSM2_SO,
            # Configure a more secure AJP password by default
            ipa_ajp_secret=ipautil.ipa_generate_password(special=None),
            # in FIPS mode use RSA-OAEP wrapping padding algo as default
            fips_use_oaep_rsa_keywrap=tasks.is_fips_enabled()
        )

    @classmethod
    def get_immutable_keys(cls):
        """Get set of immutable keys

        Immutable keys are calculated from 'ipaca_default' config file
        and known keys that are defined in code.
        """
        if cls._immutable_keys is None:
            immutable = set()
            immutable.update(cls._immutable_code_keys)
            cfg = RawConfigParser()
            with open(cls.ipaca_default) as f:
                cfg.read_file(f)
            for section in cls.subsystems:
                for k, _v in cfg.items(section, raw=True):
                    if k.startswith('pki_'):
                        immutable.add(k)
            cls._immutable_keys = frozenset(immutable)
        return cls._immutable_keys

    @classmethod
    def verify_pki_config_override(cls, filename):
        """Verify pki config override file

        * filename must be an absolute path to an existing file
        * file must be a valid ini file
        * ini file must not override immutable settings

        TODO: The checker does not verify config interpolation values, yet.
        The validator does not have access to all settings.

        :param filename: path to pki.ini
        """
        if not os.path.isfile(filename):
            raise ValueError(
                "Config file '{}' does not exist.".format(filename)
            )
        if not os.path.isabs(filename):
            raise ValueError(
                "Config file '{}' is not an absolute path.".format(filename)
            )

        try:
            cfg = RawConfigParser()
            with open(filename) as f:
                cfg.read_file(f)
        except Exception as e:
            raise ValueError(
                "Invalid config '{}': {}".format(filename, e)
            )

        immutable_keys = cls.get_immutable_keys()
        invalid_keys = set()
        sections = [cfg.default_section]
        sections.extend(cls.subsystems)
        for section in sections:
            if not cfg.has_section(section):
                continue
            for k, _v in cfg.items(section, raw=True):
                if k in immutable_keys:
                    invalid_keys.add(k)

        if invalid_keys:
            raise ValueError(
                "'{}' overrides immutable options: {}".format(
                    filename, ', '.join(sorted(invalid_keys))
                )
            )

    def _mangle_values(self, dct):
        """Stringify and quote % as %% to avoid interpolation errors

        * booleans are converted to 'True', 'False'
        * DN and numbers are converted to string
        * None is turned into empty string ''
        """
        result = {}
        for k, v in dct.items():
            if isinstance(v, (DN, bool, six.integer_types)):
                v = six.text_type(v)
            elif v is None:
                v = ''
            result[k] = v.replace('%', '%%')
        return result

    def _get_default_config(self):
        """Load default config

        :return: config parser, immutable keys
        """
        defaults = self._mangle_values(self.defaults)
        # create a config template with interpolation support
        # read base config
        cfgtpl = ConfigParser(defaults=defaults)
        cfgtpl.optionxform = str
        with open(self.ipaca_default) as f:
            cfgtpl.read_file(f)

        # overwrite defaults with our defaults
        for key, value in defaults.items():
            cfgtpl.set(DEFAULTSECT, key, value)

        # all keys in default conf + known keys defined in code are
        # considered immutable.
        immutable_keys = set()
        immutable_keys.update(self._immutable_code_keys)
        for section_name in self.subsystems:
            for k, _v in cfgtpl.items(section_name, raw=True):
                immutable_keys.add(k)

        return cfgtpl, immutable_keys

    def _verify_immutable(self, config, immutable_settings, filename):
        section_name = self.defaults['pki_subsystem']
        errs = []
        for key, isvalue in immutable_settings.items():
            cfgvalue = config.get(section_name, key)
            if isvalue != cfgvalue:
                errs.append(f"{key}: '{cfgvalue}' != '{isvalue}'")
        if errs:
            raise ValueError(
                '{} overrides immutable options:\n{}'.format(
                    filename, '\n'.join(errs)
                )
            )

    def create_spawn_config(self, subsystem_config):
        """Create config instance
        """
        section_name = self.defaults['pki_subsystem']
        cfgtpl, immutable_keys = self._get_default_config()

        # overwrite CA/KRA config with subsystem settings
        subsystem_config = self._mangle_values(subsystem_config)
        for key, value in subsystem_config.items():
            cfgtpl.set(section_name, key, value)

        # get a mapping of settings that cannot be modified by users
        immutable_settings = {
            k: v for k, v in cfgtpl.items(section_name)
            if k in immutable_keys
        }

        # add ipaca_customize overlay,
        # These are settings that can be modified by a user, too. We use
        # ipaca_customize.ini to set sensible defaults.
        with open(self.ipaca_customize) as f:
            cfgtpl.read_file(f)

        # load external overlay from command line
        if self.pki_config_override is not None:
            with open(self.pki_config_override) as f:
                cfgtpl.read_file(f)

        # verify again
        self._verify_immutable(
            cfgtpl, immutable_settings, self.pki_config_override
        )

        # key backup is not compatible with HSM support
        if cfgtpl.getboolean(section_name, 'pki_hsm_enable', fallback=False):
            cfgtpl.set(section_name, 'pki_backup_keys', 'False')
            cfgtpl.set(section_name, 'pki_backup_password', '')

        pki_token_name = cfgtpl.get(section_name, 'pki_token_name')
        for stanza in self.token_stanzas:
            if cfgtpl.has_option(section_name, stanza):
                cfgtpl.set(section_name, stanza, pki_token_name)

        # Next up, get rid of interpolation variables, DEFAULT,
        # irrelevant sections and unused variables. Only the subsystem
        # section is copied into a new raw config parser. A raw config
        # parser is necessary, because ConfigParser.write() write passwords
        # with '%' in a way, that is not accepted by Dogtag.
        config = RawConfigParser()
        config.optionxform = str
        config.add_section(section_name)
        for key, value in sorted(cfgtpl.items(section=section_name)):
            if key.startswith('pki_'):
                config.set(section_name, key, value)

        return config


def test():
    import sys

    sharedir = os.path.abspath(os.path.join(
        os.path.dirname(os.path.join(__file__)),
        os.pardir,
        os.pardir,
        'install',
        'share',
    ))

    class TestPKIIniLoader(PKIIniLoader):
        ipaca_default = os.path.join(sharedir, 'ipaca_default.ini')
        ipaca_customize = os.path.join(sharedir, 'ipaca_customize.ini')

    override = os.path.join(sharedir, 'ipaca_softhsm2.ini')

    base_settings = dict(
        fqdn='replica.ipa.example',
        domain='ipa.example',
        subject_base='o=IPA,o=EXAMPLE',
        ca_subject='cn=CA,o=IPA,o=EXAMPLE',
        admin_user='admin',
        admin_password='Secret1',
        dm_password='Secret2',
        pki_config_override=override,
    )

    for subsystem in TestPKIIniLoader.subsystems:
        print('-' * 78)
        loader = TestPKIIniLoader(subsystem=subsystem, **base_settings)
        loader.verify_pki_config_override(loader.ipaca_customize)
        loader.verify_pki_config_override(override)
        config = loader.create_spawn_config({})
        config.write(sys.stdout, False)


if __name__ == '__main__':
    test()
