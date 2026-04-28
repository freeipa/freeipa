#
# Copyright (C) 2025  FreeIPA Contributors see COPYING for license
#

import re

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest

KRB5CONF_PATH = '/etc/krb5.conf.d/00-permitted-enctypes.conf'
KRB5CONF_CONTENT = ('[libdefaults]\n'
                    'permitted_enctypes = aes256-cts-hmac-sha1-96 '
                    'aes128-cts-hmac-sha1-96 camellia256-cts-cmac '
                    'camellia128-cts-cmac')

class TestMkeyUpgrade(IntegrationTest):

    num_replicas = 1
    topology = 'line'

    @classmethod
    def install(cls, mh):
        cls.master.put_file_contents(KRB5CONF_PATH, KRB5CONF_CONTENT)
        cls.replicas[0].put_file_contents(KRB5CONF_PATH, KRB5CONF_CONTENT)
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
        self.master.run_command(['rm', KRB5CONF_PATH])
        self.replicas[0].run_command(['rm', KRB5CONF_PATH])
        tasks.restart_ipa_server(self.master)
        tasks.restart_ipa_server(self.replicas[0])

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

    def test_restart_replicas(self):
        tasks.restart_ipa_server(self.master)
        tasks.restart_ipa_server(self.replicas[0])

    def test_new_service(self):
        p = re.compile('^MKey: vno 2$', flags=re.MULTILINE)
        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa', 'service-add',
                                 f'test/{self.master.hostname}'])
        self.master.run_command(['ipa-getkeytab',
                                 '-p', f'test/{self.master.hostname}',
                                 '-k', '/root/test.keytab'])
        result = self.master.run_command(['kadmin.local', 'getprinc',
                                          f'test/{self.master.hostname}'])
        assert p.search(result.stdout_text)
        tasks.kdestroy_all(self.master)
        self.master.run_command(['kinit', '-kt', '/root/test.keytab',
                                 f'test/{self.master.hostname}'])
        tasks.kdestroy_all(self.master)

    def test_new_user(self):
        p = re.compile('^MKey: vno 2$', flags=re.MULTILINE)
        tasks.kinit_admin(self.master)
        tasks.user_add(self.master, 'testuser', password='Secret123')
        result = self.master.run_command(['kadmin.local', 'getprinc',
                                          'testuser'])
        assert p.search(result.stdout_text)
        tasks.kdestroy_all(self.master)
        self.master.run_command(['kinit', 'testuser'],
                                stdin_text='Secret123\nSecret123\nSecret123')
        tasks.kdestroy_all(self.master)

    @classmethod
    def uninstall(cls, mh):
        tasks.kinit_admin(cls.master)
        tasks.user_del(cls.master, 'testuser')
        cls.master.run_command(['ipa', 'service-del',
                                f'test/{cls.master.hostname}'])
        tasks.kdestroy_all(cls.master)
        cls.master.run_command(['rm', '/root/test.keytab'])
        cls.master.run_command(['rm', '-f', KRB5CONF_PATH])
        cls.replicas[0].run_command(['rm', '-f', KRB5CONF_PATH])
        super().uninstall(mh)
