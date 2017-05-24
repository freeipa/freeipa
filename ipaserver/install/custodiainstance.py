# Copyright (C) 2015 FreeIPa Project Contributors, see 'COPYING' for license.

import logging

from ipaserver.secrets.kem import IPAKEMKeys, KEMLdap
from ipaserver.secrets.client import CustodiaClient
from ipaplatform.paths import paths
from ipaplatform.constants import constants
from ipaserver.install.service import SimpleServiceInstance
from ipapython import ipautil
from ipapython.certdb import NSSDatabase
from ipaserver.install import installutils
from ipaserver.install import ldapupdate
from ipaserver.install import sysupgrade
from base64 import b64decode
from jwcrypto.common import json_decode
import shutil
import os
import stat
import tempfile
import time
import pwd

logger = logging.getLogger(__name__)


class CustodiaInstance(SimpleServiceInstance):
    def __init__(self, host_name=None, realm=None):
        super(CustodiaInstance, self).__init__("ipa-custodia")
        self.config_file = paths.IPA_CUSTODIA_CONF
        self.server_keys = os.path.join(paths.IPA_CUSTODIA_CONF_DIR,
                                        'server.keys')
        self.ldap_uri = None
        self.fqdn = host_name
        self.realm = realm

    def __config_file(self):
        template_file = os.path.basename(self.config_file) + '.template'
        template = os.path.join(paths.USR_SHARE_IPA_DIR, template_file)
        httpd_info = pwd.getpwnam(constants.HTTPD_USER)
        sub_dict = dict(IPA_CUSTODIA_CONF_DIR=paths.IPA_CUSTODIA_CONF_DIR,
                        IPA_CUSTODIA_SOCKET=paths.IPA_CUSTODIA_SOCKET,
                        IPA_CUSTODIA_AUDIT_LOG=paths.IPA_CUSTODIA_AUDIT_LOG,
                        LDAP_URI=installutils.realm_to_ldapi_uri(self.realm),
                        UID=httpd_info.pw_uid, GID=httpd_info.pw_gid)
        conf = ipautil.template_file(template, sub_dict)
        fd = open(self.config_file, "w+")
        fd.write(conf)
        fd.flush()
        fd.close()

    def create_instance(self):
        suffix = ipautil.realm_to_suffix(self.realm)
        self.step("Generating ipa-custodia config file", self.__config_file)
        self.step("Making sure custodia container exists", self.__create_container)
        self.step("Generating ipa-custodia keys", self.__gen_keys)
        super(CustodiaInstance, self).create_instance(gensvc_name='KEYS',
                                                      fqdn=self.fqdn,
                                                      ldap_suffix=suffix,
                                                      realm=self.realm)
        sysupgrade.set_upgrade_state('custodia', 'installed', True)

    def __gen_keys(self):
        KeyStore = IPAKEMKeys({'server_keys': self.server_keys,
                               'ldap_uri': self.ldap_uri})
        KeyStore.generate_server_keys()

    def upgrade_instance(self):
        if not sysupgrade.get_upgrade_state("custodia", "installed"):
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

    def create_replica(self, master_host_name):
        suffix = ipautil.realm_to_suffix(self.realm)
        self.ldap_uri = 'ldap://%s' % master_host_name
        self.master_host_name = master_host_name

        self.step("Generating ipa-custodia config file", self.__config_file)
        self.step("Generating ipa-custodia keys", self.__gen_keys)
        super(CustodiaInstance, self).create_instance(gensvc_name='KEYS',
                                                      fqdn=self.fqdn,
                                                      ldap_suffix=suffix,
                                                      realm=self.realm)

    def __create_container(self):
        """
        Runs the custodia update file to ensure custodia container is present.
        """

        sub_dict = {
            'SUFFIX': self.suffix,
        }

        updater = ldapupdate.LDAPUpdate(sub_dict=sub_dict)
        updater.update([os.path.join(paths.UPDATES_DIR, '73-custodia.update')])

    def import_ra_key(self, master_host_name):
        cli = self.__CustodiaClient(server=master_host_name)
        # please note that ipaCert part has to stay here for historical
        # reasons (old servers expect you to ask for ra/ipaCert during
        # replication as they store the RA agent cert in an NSS database
        # with this nickname)
        cli.fetch_key('ra/ipaCert')

    def import_dm_password(self, master_host_name):
        cli = self.__CustodiaClient(server=master_host_name)
        cli.fetch_key('dm/DMHash')

    def __wait_keys(self, host, timeout=300):
        ldap_uri = 'ldap://%s' % host
        deadline = int(time.time()) + timeout
        logger.info("Waiting up to %s seconds to see our keys "
                    "appear on host: %s", timeout, host)

        konn = KEMLdap(ldap_uri)
        saved_e = None
        while True:
            try:
                return konn.check_host_keys(self.fqdn)
            except Exception as e:
                # log only once for the same error
                if not isinstance(e, type(saved_e)):
                    logger.debug(
                        "Transient error getting keys: '%s'", e)
                    saved_e = e
                if int(time.time()) > deadline:
                    raise RuntimeError("Timed out trying to obtain keys.")
                time.sleep(1)

    def __CustodiaClient(self, server):
        # Before we attempt to fetch keys from this host, make sure our public
        # keys have been replicated there.
        self.__wait_keys(server)

        return CustodiaClient('host@%s' % self.fqdn, self.server_keys,
                              paths.KRB5_KEYTAB, server, realm=self.realm)

    def __get_keys(self, ca_host, cacerts_file, cacerts_pwd, data):
        # Fecth all needed certs one by one, then combine them in a single
        # p12 file

        prefix = data['prefix']
        certlist = data['list']

        cli = self.__CustodiaClient(server=ca_host)

        # Temporary nssdb
        tmpnssdir = tempfile.mkdtemp(dir=paths.TMP)
        tmpdb = NSSDatabase(tmpnssdir)
        tmpdb.create_db()
        try:
            # Cert file password
            crtpwfile = os.path.join(tmpnssdir, 'crtpwfile')
            with open(crtpwfile, 'w+') as f:
                f.write(cacerts_pwd)
                f.flush()

            for nickname in certlist:
                value = cli.fetch_key(os.path.join(prefix, nickname), False)
                v = json_decode(value)
                pk12pwfile = os.path.join(tmpnssdir, 'pk12pwfile')
                with open(pk12pwfile, 'w+') as f:
                    f.write(v['export password'])
                pk12file = os.path.join(tmpnssdir, 'pk12file')
                with open(pk12file, 'w+') as f:
                    f.write(b64decode(v['pkcs12 data']))
                ipautil.run([paths.PK12UTIL,
                             '-d', tmpdb.secdir,
                             '-k', tmpdb.pwd_file,
                             '-n', nickname,
                             '-i', pk12file,
                             '-w', pk12pwfile])

            # Add CA certificates
            self.suffix = ipautil.realm_to_suffix(self.realm)
            self.import_ca_certs(tmpdb, True)

            # Now that we gathered all certs, re-export
            ipautil.run([paths.PKCS12EXPORT,
                         '-d', tmpdb.secdir,
                         '-p', tmpdb.pwd_file,
                         '-w', crtpwfile,
                         '-o', cacerts_file])

        finally:
            shutil.rmtree(tmpnssdir)

    def get_ca_keys(self, ca_host, cacerts_file, cacerts_pwd):
        certlist = ['caSigningCert cert-pki-ca',
                    'ocspSigningCert cert-pki-ca',
                    'auditSigningCert cert-pki-ca',
                    'subsystemCert cert-pki-ca']
        data = {'prefix': 'ca',
                'list': certlist}
        self.__get_keys(ca_host, cacerts_file, cacerts_pwd, data)

    def get_kra_keys(self, ca_host, cacerts_file, cacerts_pwd):
        certlist = ['auditSigningCert cert-pki-kra',
                    'storageCert cert-pki-kra',
                    'subsystemCert cert-pki-ca',
                    'transportCert cert-pki-kra']
        data = {'prefix': 'ca',
                'list': certlist}
        self.__get_keys(ca_host, cacerts_file, cacerts_pwd, data)

    def __start(self):
        super(CustodiaInstance, self).__start()

    def __enable(self):
        super(CustodiaInstance, self).__enable()
