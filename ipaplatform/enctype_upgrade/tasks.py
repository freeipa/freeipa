from __future__ import absolute_import

from ipaplatform.fedora.tasks import FedoraTaskNamespace

from re import compile


def add_aes_sha1(enctypes):
    return tuple({*enctypes,
                  'aes256-cts:special', 'aes128-cts:special',
                  'aes256-cts:normal', 'aes128-cts:normal'})


class EnctypeUpgradeTaskNamespace(FedoraTaskNamespace):

    def get_masterkey_entype(self):
        return 'aes256-cts'

    def get_supported_enctypes(self):
        aes_sha2_pattern = compile('^aes[0-9]+-sha2:')

        return tuple(e for e in super().get_supported_enctypes()
                     if not aes_sha2_pattern.match(e))

    def get_removed_supported_enctypes(self):
        return add_aes_sha1(super().get_removed_supported_enctypes())

    def get_removed_default_enctypes(self):
        return add_aes_sha1(super().get_removed_default_enctypes())


tasks = EnctypeUpgradeTaskNamespace()
