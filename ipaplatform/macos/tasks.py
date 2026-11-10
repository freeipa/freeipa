# Copyright (C) 2026 FreeIPA Contributors see COPYING for license
"""Administration client tasks; host configuration is not implemented."""

from ipaplatform.base.tasks import BaseTaskNamespace


class MacOSTaskNamespace(BaseTaskNamespace):
    def is_nosssd_supported(self):
        return False

    def is_mkhomedir_supported(self):
        return False

    def add_user_to_group(self, user, group):
        raise NotImplementedError('Host configuration is unsupported on macOS')

    def migrate_auth_configuration(self, statestore):
        raise NotImplementedError('Host configuration is unsupported on macOS')

    def configure_httpd(self, sstore, modules, confs, sites):
        raise NotImplementedError('Host configuration is unsupported on macOS')

    def restore_httpd(self, sstore, modules, confs, sites):
        raise NotImplementedError('Host configuration is unsupported on macOS')

    def configure_dns_resolver(self, nameservers, searchdomains, *,
                               resolve1_enabled=False, fstore=None):
        raise NotImplementedError('Host configuration is unsupported on macOS')

    def unconfigure_dns_resolver(self, fstore=None):
        raise NotImplementedError('Host configuration is unsupported on macOS')

    def configure_nsswitch_database(self, fstore, database, services,
                                    preserve=True, append=True,
                                    default_value=()):
        raise NotImplementedError('Host configuration is unsupported on macOS')

    def disable_ldap_automount(self, statestore):
        raise NotImplementedError('Host configuration is unsupported on macOS')


tasks = MacOSTaskNamespace()
