# Copyright (C) 2015 FreeIPa Project Contributors, see 'COPYING' for license.

from ipapython.secrets.kem import IPAKEMKeys
from ipapython.secrets.client import CustodiaClient
from ipaplatform.paths import paths
from service import SimpleServiceInstance
from ipapython import ipautil
from ipapython.ipa_log_manager import root_logger
from ipaserver.install import installutils
from ipaserver.install import ldapupdate
from ipaserver.install import sysupgrade
from base64 import b64encode, b64decode
from jwcrypto.common import json_decode
import shutil
import os
import tempfile


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
        template = os.path.join(ipautil.SHARE_DIR, template_file)
        sub_dict = dict(IPA_CUSTODIA_CONF_DIR=paths.IPA_CUSTODIA_CONF_DIR,
                        IPA_CUSTODIA_SOCKET=paths.IPA_CUSTODIA_SOCKET,
                        IPA_CUSTODIA_AUDIT_LOG=paths.IPA_CUSTODIA_AUDIT_LOG,
                        LDAP_URI=installutils.realm_to_ldapi_uri(self.realm))
        conf = ipautil.template_file(template, sub_dict)
        fd = open(self.config_file, "w+")
        fd.write(conf)
        fd.flush()
        fd.close()

    def create_instance(self, dm_password=None):
        suffix = ipautil.realm_to_suffix(self.realm)
        self.step("Generating ipa-custodia config file", self.__config_file)
        self.step("Making sure custodia container exists", self.__create_container)
        self.step("Generating ipa-custodia keys", self.__gen_keys)
        super(CustodiaInstance, self).create_instance(gensvc_name='KEYS',
                                                      fqdn=self.fqdn,
                                                      dm_password=dm_password,
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

    def create_replica(self, master_host_name):
        suffix = ipautil.realm_to_suffix(self.realm)
        self.ldap_uri = 'ldap://%s' % master_host_name
        self.master_host_name = master_host_name

        self.step("Generating ipa-custodia config file", self.__config_file)
        self.step("Generating ipa-custodia keys", self.__gen_keys)
        self.step("Importing RA Key", self.__import_ra_key)
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

        updater = ldapupdate.LDAPUpdate(dm_password=self.dm_password,
                                        sub_dict=sub_dict)
        updater.update([os.path.join(paths.UPDATES_DIR, '73-custodia.update')])

    def __import_ra_key(self):
        cli = CustodiaClient(self.fqdn, self.master_host_name, self.realm)
        cli.fetch_key('ra/ipaCert')

    def import_dm_password(self, master_host_name):
        cli = CustodiaClient(self.fqdn, master_host_name, self.realm)
        cli.fetch_key('dm/DMHash')

    def __get_keys(self, ca_host, cacerts_file, cacerts_pwd, data):
        # Fecth all needed certs one by one, then combine them in a single
        # p12 file

        prefix = data['prefix']
        certlist = data['list']

        cli = CustodiaClient(self.fqdn, ca_host, self.realm)

        # Temporary nssdb
        tmpnssdir = tempfile.mkdtemp(dir=paths.TMP)
        try:
            # Temporary nssdb password
            nsspwfile = os.path.join(tmpnssdir, 'nsspwfile')
            with open(nsspwfile, 'w+') as f:
                f.write(b64encode(os.urandom(16)))
                f.flush()

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
                             '-d', tmpnssdir,
                             '-k', nsspwfile,
                             '-n', nickname,
                             '-i', pk12file,
                             '-w', pk12pwfile])

            # Now that we gathered all certs, re-export
            ipautil.run([paths.PKCS12EXPORT,
                         '-d', tmpnssdir,
                         '-p', nsspwfile,
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
