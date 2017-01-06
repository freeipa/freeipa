# Copyright (C) 2015 FreeIPa Project Contributors, see 'COPYING' for license.

from ipaserver.secrets.kem import IPAKEMKeys
from ipaserver.secrets.client import CustodiaClient
from ipaplatform.paths import paths
from ipaplatform.constants import constants
from ipaserver.install.service import SimpleServiceInstance
from ipapython import ipautil
from ipapython.ipa_log_manager import root_logger
from ipapython.certdb import NSSDatabase
from ipaserver.install import installutils
from ipaserver.install import ldapupdate
from ipaserver.install import sysupgrade
from base64 import b64decode
from jwcrypto.common import json_decode
import functools
import shutil
import os
import stat
import tempfile
import pwd


class CustodiaInstance(SimpleServiceInstance):
    def __init__(self, host_name=None, realm=None):
        super(CustodiaInstance, self).__init__("ipa-custodia")
        self.config_file = paths.IPA_CUSTODIA_CONF
        self.server_keys = os.path.join(paths.IPA_CUSTODIA_CONF_DIR,
                                        'server.keys')
        self.ldap_uri = None
        self.fqdn = host_name
        self.realm = realm
        self.__CustodiaClient = functools.partial(
            CustodiaClient,
            client_service='host@%s' % self.fqdn,
            keyfile=self.server_keys,
            keytab=paths.KRB5_KEYTAB,
            realm=realm,
        )

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
            root_logger.info("Custodia service is being configured")
            self.create_instance()
        else:
            old_config = open(self.config_file).read()
            self.__config_file()
            new_config = open(self.config_file).read()
            if new_config != old_config:
                root_logger.info("Restarting Custodia")
                self.restart()

        mode = os.stat(self.server_keys).st_mode
        if stat.S_IMODE(mode) != 0o600:
            root_logger.info("Secure server.keys mode")
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
        cli.fetch_key('ra/ipaCert')

    def import_dm_password(self, master_host_name):
        cli = self.__CustodiaClient(server=master_host_name)
        cli.fetch_key('dm/DMHash')

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
