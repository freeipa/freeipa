# Copyright (C) 2015 FreeIPa Project Contributors, see 'COPYING' for license.

from __future__ import print_function, absolute_import

import enum
import logging

from ipalib import api
from ipaserver.secrets.kem import IPAKEMKeys, KEMLdap
from ipaserver.secrets.client import CustodiaClient
from ipaplatform.paths import paths
from ipaplatform.constants import constants
from ipaserver.install.service import SimpleServiceInstance
from ipapython import ipautil
from ipapython import ipaldap
from ipapython.certdb import NSSDatabase
from ipaserver.install import installutils
from ipaserver.install import ldapupdate
from ipaserver.install import sysupgrade
from base64 import b64decode
from jwcrypto.common import json_decode
import os
import stat
import time
import pwd

logger = logging.getLogger(__name__)


class CustodiaModes(enum.Enum):
    # peer must have a CA
    CA_PEER = 'Custodia CA peer'
    # peer must have a CA, KRA preferred
    KRA_PEER = 'Custodia KRA peer'
    # any master will do
    MASTER_PEER = 'Custodia master peer'
    # local instance (first master)
    FIRST_MASTER = 'Custodia on first master'


def get_custodia_instance(config, mode):
    """Create Custodia instance

    :param config: configuration/installer object
    :param mode: CustodiaModes member
    :return: CustodiaInstance object

    The config object must have the following attribute

    *host_name*
      FQDN of the new replica/master
    *realm_name*
      Kerberos realm
    *master_host_name* (for *CustodiaModes.MASTER_PEER*)
      hostname of a master (may not have a CA)
    *ca_host_name* (for *CustodiaModes.CA_PEER*)
      hostname of a master with CA
    *kra_host_name* (for *CustodiaModes.KRA_PEER*)
      hostname of a master with KRA or CA

    For replicas, the instance will upload new keys and retrieve secrets
    to the same host. Therefore it uses *ca_host_name* instead of
    *master_host_name* to create a replica with CA.
    """
    assert isinstance(mode, CustodiaModes)
    logger.debug(
        "Custodia client for '%r' with promotion %s.",
        mode, 'yes' if mode != CustodiaModes.FIRST_MASTER else 'no'
    )
    if mode == CustodiaModes.CA_PEER:
        # In case we install replica with CA, prefer CA host as source for
        # all Custodia secret material.
        custodia_peer = config.ca_host_name
    elif mode == CustodiaModes.KRA_PEER:
        custodia_peer = config.kra_host_name
    elif mode == CustodiaModes.MASTER_PEER:
        custodia_peer = config.master_host_name
    elif mode == CustodiaModes.FIRST_MASTER:
        custodia_peer = None
    else:
        raise RuntimeError("Unknown custodia mode %s" % mode)

    if custodia_peer is None:
        # use ldapi with local dirsrv instance
        logger.debug("Custodia uses LDAPI.")
    else:
        logger.info("Custodia uses '%s' as master peer.", custodia_peer)

    return CustodiaInstance(
        host_name=config.host_name,
        realm=config.realm_name,
        custodia_peer=custodia_peer
    )


class CustodiaInstance(SimpleServiceInstance):
    def __init__(self, host_name=None, realm=None, custodia_peer=None):
        super(CustodiaInstance, self).__init__("ipa-custodia")
        self.config_file = paths.IPA_CUSTODIA_CONF
        self.server_keys = paths.IPA_CUSTODIA_KEYS
        self.custodia_peer = custodia_peer
        self.fqdn = host_name
        self.realm = realm

    @property
    def ldap_uri(self):
        if self.custodia_peer is None:
            return ipaldap.realm_to_ldapi_uri(self.realm)
        else:
            return "ldap://{}".format(self.custodia_peer)

    def __config_file(self):
        template_file = os.path.basename(self.config_file) + '.template'
        template = os.path.join(paths.USR_SHARE_IPA_DIR, template_file)
        httpd_info = pwd.getpwnam(constants.HTTPD_USER)
        sub_dict = dict(
            IPA_CUSTODIA_CONF_DIR=paths.IPA_CUSTODIA_CONF_DIR,
            IPA_CUSTODIA_KEYS=paths.IPA_CUSTODIA_KEYS,
            IPA_CUSTODIA_SOCKET=paths.IPA_CUSTODIA_SOCKET,
            IPA_CUSTODIA_AUDIT_LOG=paths.IPA_CUSTODIA_AUDIT_LOG,
            LDAP_URI=ipaldap.realm_to_ldapi_uri(self.realm),
            UID=httpd_info.pw_uid,
            GID=httpd_info.pw_gid
        )
        conf = ipautil.template_file(template, sub_dict)
        with open(self.config_file, "w") as f:
            f.write(conf)
            ipautil.flush_sync(f)

    def create_instance(self):
        if self.ldap_uri.startswith('ldapi://'):
            # local case, ensure container exists
            self.step("Making sure custodia container exists",
                      self.__create_container)

        self.step("Generating ipa-custodia config file", self.__config_file)
        self.step("Generating ipa-custodia keys", self.__gen_keys)
        super(CustodiaInstance, self).create_instance(
            gensvc_name='KEYS',
            fqdn=self.fqdn,
            ldap_suffix=ipautil.realm_to_suffix(self.realm),
            realm=self.realm
        )
        sysupgrade.set_upgrade_state('custodia', 'installed', True)

    def uninstall(self):
        super(CustodiaInstance, self).uninstall()
        keystore = IPAKEMKeys({
            'server_keys': self.server_keys,
            'ldap_uri': self.ldap_uri
        })
        keystore.remove_server_keys_file()
        installutils.remove_file(self.config_file)
        sysupgrade.set_upgrade_state('custodia', 'installed', False)

    def __gen_keys(self):
        keystore = IPAKEMKeys({
            'server_keys': self.server_keys,
            'ldap_uri': self.ldap_uri
        })
        keystore.generate_server_keys()

    def upgrade_instance(self):
        installed = sysupgrade.get_upgrade_state("custodia", "installed")
        if installed:
            if (not os.path.isfile(self.server_keys)
                    or not os.path.isfile(self.config_file)):
                logger.warning(
                    "Custodia server keys or config are missing, forcing "
                    "reinstallation of ipa-custodia."
                )
                installed = False

        if not installed:
            logger.info("Custodia service is being configured")
            self.create_instance()
        else:
            old_config = open(self.config_file).read()
            self.__config_file()
            new_config = open(self.config_file).read()
            if new_config != old_config:
                logger.info("Restarting Custodia")
                self.restart()

        mode = os.stat(self.server_keys).st_mode
        if stat.S_IMODE(mode) != 0o600:
            logger.info("Secure server.keys mode")
            os.chmod(self.server_keys, 0o600)

    def __create_container(self):
        """
        Runs the custodia update file to ensure custodia container is present.
        """

        sub_dict = {
            'SUFFIX': self.suffix,
        }

        updater = ldapupdate.LDAPUpdate(sub_dict=sub_dict)
        updater.update([os.path.join(paths.UPDATES_DIR, '73-custodia.update')])

    def import_ra_key(self):
        cli = self._get_custodia_client()
        # please note that ipaCert part has to stay here for historical
        # reasons (old servers expect you to ask for ra/ipaCert during
        # replication as they store the RA agent cert in an NSS database
        # with this nickname)
        cli.fetch_key('ra/ipaCert')

    def import_dm_password(self):
        cli = self._get_custodia_client()
        cli.fetch_key('dm/DMHash')

    def _wait_keys(self):
        timeout = api.env.replication_wait_timeout
        deadline = int(time.time()) + timeout
        logger.debug("Waiting up to %s seconds to see our keys "
                     "appear on host %s", timeout, self.ldap_uri)

        konn = KEMLdap(self.ldap_uri)
        saved_e = None
        while True:
            try:
                return konn.check_host_keys(self.fqdn)
            except Exception as e:
                # Print message to console only once for first error.
                if saved_e is None:
                    # FIXME: Change once there's better way to show this
                    # message in installer output,
                    print(
                        "  Waiting for keys to appear on host: {}, please "
                        "wait until this has completed.".format(
                            self.ldap_uri)
                    )
                # log only once for the same error
                if not isinstance(e, type(saved_e)):
                    logger.debug(
                        "Transient error getting keys: '%s'", e)
                    saved_e = e
                if int(time.time()) > deadline:
                    raise RuntimeError("Timed out trying to obtain keys.")
                time.sleep(1)

    def _get_custodia_client(self):
        if self.custodia_peer is None:
            raise ValueError("Can't replicate secrets without Custodia peer")
        # Before we attempt to fetch keys from this host, make sure our public
        # keys have been replicated there.
        self._wait_keys()

        return CustodiaClient(
            client_service='host@{}'.format(self.fqdn),
            keyfile=self.server_keys, keytab=paths.KRB5_KEYTAB,
            server=self.custodia_peer, realm=self.realm
        )

    def _get_keys(self, cacerts_file, cacerts_pwd, data):
        # Fetch all needed certs one by one, then combine them in a single
        # PKCS12 file
        prefix = data['prefix']
        certlist = data['list']
        cli = self._get_custodia_client()

        with NSSDatabase(None) as tmpdb:
            tmpdb.create_db()
            # Cert file password
            crtpwfile = os.path.join(tmpdb.secdir, 'crtpwfile')
            with open(crtpwfile, 'w+') as f:
                f.write(cacerts_pwd)

            for nickname in certlist:
                value = cli.fetch_key(os.path.join(prefix, nickname), False)
                v = json_decode(value)
                pk12pwfile = os.path.join(tmpdb.secdir, 'pk12pwfile')
                with open(pk12pwfile, 'w+') as f:
                    f.write(v['export password'])
                pk12file = os.path.join(tmpdb.secdir, 'pk12file')
                with open(pk12file, 'wb') as f:
                    f.write(b64decode(v['pkcs12 data']))
                tmpdb.run_pk12util([
                    '-k', tmpdb.pwd_file,
                    '-n', nickname,
                    '-i', pk12file,
                    '-w', pk12pwfile
                ])

            # Add CA certificates
            self.export_ca_certs_nssdb(tmpdb, True)

            # Now that we gathered all certs, re-export
            ipautil.run([
                paths.PKCS12EXPORT,
                '-d', tmpdb.secdir,
                '-p', tmpdb.pwd_file,
                '-w', crtpwfile,
                '-o', cacerts_file
            ])

    def get_ca_keys(self, cacerts_file, cacerts_pwd):
        certlist = ['caSigningCert cert-pki-ca',
                    'ocspSigningCert cert-pki-ca',
                    'auditSigningCert cert-pki-ca',
                    'subsystemCert cert-pki-ca']
        data = {'prefix': 'ca',
                'list': certlist}
        self._get_keys(cacerts_file, cacerts_pwd, data)

    def get_kra_keys(self, cacerts_file, cacerts_pwd):
        certlist = ['auditSigningCert cert-pki-kra',
                    'storageCert cert-pki-kra',
                    'subsystemCert cert-pki-ca',
                    'transportCert cert-pki-kra']
        data = {'prefix': 'ca',
                'list': certlist}
        self._get_keys(cacerts_file, cacerts_pwd, data)

    def __start(self):
        super(CustodiaInstance, self).__start()

    def __enable(self):
        super(CustodiaInstance, self).__enable()
