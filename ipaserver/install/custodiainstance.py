# Copyright (C) 2015 FreeIPa Project Contributors, see 'COPYING' for license.

from ipapython.secrets.kem import IPAKEMKeys
from ipaplatform.paths import paths
from service import SimpleServiceInstance
from ipapython import ipautil
from ipaserver.install import installutils
import os


class CustodiaInstance(SimpleServiceInstance):
    def __init__(self):
        super(CustodiaInstance, self).__init__("ipa-custodia")
        self.config_file = paths.IPA_CUSTODIA_CONF
        self.server_keys = os.path.join(paths.IPA_CUSTODIA_CONF_DIR,
                                        'server.keys')

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

    def create_instance(self, *args, **kwargs):
        self.step("Generating ipa-custodia config file", self.__config_file)
        self.step("Generating ipa-custodia keys", self.__gen_keys)
        super(CustodiaInstance, self).create_instance(*args, **kwargs)

    def __gen_keys(self):
        KeyStore = IPAKEMKeys({'server_keys': self.server_keys})
        KeyStore.generate_server_keys()

    def upgrade_instance(self, realm):
        self.realm = realm
        if not os.path.exists(self.config_file):
            self.__config_file()
        if not os.path.exists(self.server_keys):
            self.__gen_keys()

    def __start(self):
        super(CustodiaInstance, self).__start()

    def __enable(self):
        super(CustodiaInstance, self).__enable()
