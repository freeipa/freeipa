#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

"""
This module contains default Debian-specific implementations of system tasks.
"""

from __future__ import absolute_import

from ipaplatform.base.tasks import BaseTaskNamespace
from ipaplatform.redhat.tasks import RedHatTaskNamespace
from ipaplatform.paths import paths

from ipapython import directivesetter
from ipapython import ipautil

class DebianTaskNamespace(RedHatTaskNamespace):
    @staticmethod
    def restore_pre_ipa_client_configuration(fstore, statestore,
                                             was_sssd_installed,
                                             was_sssd_configured):
        try:
            ipautil.run(["pam-auth-update",
                         "--package", "--remove", "mkhomedir"])
        except ipautil.CalledProcessError:
            return False
        return True

    @staticmethod
    def set_nisdomain(nisdomain):
        # Debian doesn't use authconfig, nothing to set
        return True

    @staticmethod
    def modify_nsswitch_pam_stack(sssd, mkhomedir, statestore, sudo=True):
        if mkhomedir:
            try:
                ipautil.run(["pam-auth-update",
                             "--package", "--enable", "mkhomedir"])
            except ipautil.CalledProcessError:
                return False
            return True
        else:
            return True

    @staticmethod
    def modify_pam_to_use_krb5(statestore):
        # Debian doesn't use authconfig, this is handled by pam-auth-update
        return True

    @staticmethod
    def backup_auth_configuration(path):
        # Debian doesn't use authconfig, nothing to backup
        return True

    @staticmethod
    def restore_auth_configuration(path):
        # Debian doesn't use authconfig, nothing to restore
        return True

    def migrate_auth_configuration(self, statestore):
        # Debian doesn't have authselect
        return True

    @staticmethod
    def parse_ipa_version(version):
        return BaseTaskNamespace.parse_ipa_version(version)

    def configure_httpd_wsgi_conf(self):
        # Debian doesn't require special mod_wsgi configuration
        pass

    def configure_httpd_protocol(self):
        # TLS 1.3 is not yet supported
        directivesetter.set_directive(paths.HTTPD_SSL_CONF,
                                      'SSLProtocol',
                                      'TLSv1.2', False)

    def setup_httpd_logging(self):
        # Debian handles httpd logging differently
        pass

    def configure_pkcs11_modules(self, fstore):
        # Debian doesn't use p11-kit
        pass

    def restore_pkcs11_modules(self, fstore):
        pass

tasks = DebianTaskNamespace()
