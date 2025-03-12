#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import re
import textwrap

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestMkeyUpgrade(IntegrationTest):

    num_replicas = 1
    topology = 'line'

    @classmethod
    def install(cls, mh):
        cls.master.put_file_contents(
            '/etc/profile.d/ipaplatform.sh',
            'export IPAPLATFORM_OVERRIDE=test_fedora_legacy')
        cls.master.run_command(['mkdir', '/etc/systemd/system/ipa.service.d'])
        cls.master.put_file_contents(
            '/etc/systemd/system/ipa.service.d/platform.conf',
            '[Service]\n'
            'Environment="IPAPLATFORM_OVERRIDE=test_fedora_legacy"')
        cls.master.run_command(['systemctl', 'daemon-reload'])
        tasks.install_master(cls.master, setup_dns=False)
        tasks.install_replica(cls.master, cls.replicas[0], setup_dns=False)

    def test_old_active_mkey(self):
        p = re.compile('^KVNO: 1, Enctype: aes256-cts-hmac-sha1-96, .+ \\*$',
                       flags=re.MULTILINE)

        result = self.master.run_command(['kdb5_util', 'list_mkeys'])
        assert p.search(result.stdout_text)
        result = self.replicas[0].run_command(['kdb5_util', 'list_mkeys'])
        assert p.search(result.stdout_text)

    def test_enable_new_entypes(self):
        base_dn = "dc=%s" % (",dc=".join(self.master.domain.name.split(".")))
        realm = self.master.domain.name.upper()

        entry_ldif = textwrap.dedent("""
            dn: cn={realm},cn=kerberos,{base_dn}
            changetype: modify
            replace: krbSupportedEncSaltTypes
            krbSupportedEncSaltTypes: aes128-sha2:normal
            krbSupportedEncSaltTypes: aes128-sha2:special
            krbSupportedEncSaltTypes: aes256-sha2:normal
            krbSupportedEncSaltTypes: aes256-sha2:special
            krbSupportedEncSaltTypes: aes256-cts:normal
            krbSupportedEncSaltTypes: aes256-cts:special
            krbSupportedEncSaltTypes: aes128-cts:normal
            krbSupportedEncSaltTypes: aes128-cts:special
            krbSupportedEncSaltTypes: camellia128-cts-cmac:normal
            krbSupportedEncSaltTypes: camellia128-cts-cmac:special
            krbSupportedEncSaltTypes: camellia256-cts-cmac:normal
            krbSupportedEncSaltTypes: camellia256-cts-cmac:special
            -
            replace: krbDefaultEncSaltTypes
            krbDefaultEncSaltTypes: aes256-sha2:special
            krbDefaultEncSaltTypes: aes128-sha2:special
            krbDefaultEncSaltTypes: aes256-cts:special
            krbDefaultEncSaltTypes: aes128-cts:special""").format(
            base_dn=base_dn, realm=realm)
        tasks.ldapmodify_dm(self.master, entry_ldif)

    def test_add_new_mkey(self):
        self.master.run_command('kdb5_util add_mkey -e aes256-sha2 -s',
                                stdin_text='Secret123\nSecret123')

    def test_new_inactive_mkey(self):
        p = re.compile('^KVNO: 2, Enctype: aes256-cts-hmac-sha384-192, ',
                       flags=re.MULTILINE)

        result = self.master.run_command(['kdb5_util', 'list_mkeys'])
        assert p.search(result.stdout_text)
        result = self.replicas[0].run_command(['kdb5_util', 'list_mkeys'])
        assert p.search(result.stdout_text)

    def test_switch_mkey(self):
        self.master.run_command(['kdb5_util', 'use_mkey', '2'])

    def test_new_active_mkey(self):
        p = re.compile('^KVNO: 2, Enctype: aes256-cts-hmac-sha384-192, .+ \\*$',
                       flags=re.MULTILINE)

        result = self.master.run_command(['kdb5_util', 'list_mkeys'])
        assert p.search(result.stdout_text)
        result = self.replicas[0].run_command(['kdb5_util', 'list_mkeys'])
        assert p.search(result.stdout_text)

    def test_used_old_mkey(self):
        p = re.compile('^MKey: vno 1$', flags=re.MULTILINE)

        result = self.master.run_command(['kadmin.local', 'getprinc',
                                          f'ldap/{self.master.hostname}'])
        assert p.search(result.stdout_text)
        result = self.replicas[0].run_command(['kadmin.local', 'getprinc',
                                               f'ldap/{self.master.hostname}'])
        assert p.search(result.stdout_text)

    def test_reencrypt_with_new_mkey(self):
        self.master.run_command(['kdb5_util', '-x', 'unlockiter',
                                 'update_princ_encryption', '-vf'])

    def test_used_new_mkey(self):
        p = re.compile('^MKey: vno 2$', flags=re.MULTILINE)

        result = self.master.run_command(['kadmin.local', 'getprinc',
                                          f'ldap/{self.master.hostname}'])
        assert p.search(result.stdout_text)
        result = self.replicas[0].run_command(['kadmin.local', 'getprinc',
                                               f'ldap/{self.master.hostname}'])
        assert p.search(result.stdout_text)

    def test_purge_old_mkey(self):
        self.master.run_command(['kdb5_util', 'purge_mkeys', '-vf'])

    def test_only_new_mkey(self):
        p = re.compile('^KVNO: 1,', flags=re.MULTILINE)

        result = self.master.run_command(['kdb5_util', 'list_mkeys'])
        assert not p.search(result.stdout_text)
        result = self.replicas[0].run_command(['kdb5_util', 'list_mkeys'])
        assert not p.search(result.stdout_text)

    @classmethod
    def uninstall(cls, mh):
        cls.master.run_command([
            'rm', '/etc/profile.d/ipaplatform.sh',
            '/etc/systemd/system/ipa.service.d/platform.conf'])
        cls.master.run_command(['rmdir', '/etc/systemd/system/ipa.service.d'])
        super().uninstall(mh)
