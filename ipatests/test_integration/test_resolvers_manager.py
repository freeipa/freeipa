import pytest
import re
from contextlib import contextmanager

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestResolverManager(IntegrationTest):
    topology = 'line'
    num_clients = 1
    invalid_resolver = '2.3.4.5'

    @classmethod
    def install(cls, mh):
        test_record = 'test1234'
        cls.client = cls.clients[0]
        cls.test_record = '{}.{}'.format(test_record, cls.master.domain.name)
        cls.test_record_address = '1.2.3.4'

        if cls.domain_level is not None:
            domain_level = cls.domain_level
        else:
            domain_level = cls.master.config.domain_level
        tasks.install_topo(cls.topology, cls.master, [], [], domain_level)
        tasks.kinit_admin(cls.master)
        cls.master.run_command([
            'ipa', 'dnsrecord-add', cls.master.domain.name,
            test_record,
            '--a-ip-address={}'.format(cls.test_record_address)])

    def is_resolver_operational(self):
        res = self.client.run_command(['dig', '+short', 'redhat.com'])
        return re.match(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}',
                        res.stdout_text.strip())

    def is_ipa_dns_used(self):
        res = self.client.run_command(['dig', '+short', self.test_record])
        output = res.stdout_text.strip()
        error = res.stderr_text.strip()
        if output == self.test_record_address:
            return True
        if output == '' and error == '':
            return False
        raise Exception('Unexpected result of dig command')

    def check_ipa_name_resolution_fails(self):
        res = self.client.run_command(['dig', '+short', self.test_record],
                                      ok_returncode=9)
        assert 'connection timed out' in res.stdout_text

    @contextmanager
    def start_end_checks(self):
        assert not self.client.resolver.has_backups()
        assert self.is_resolver_operational()
        assert not self.is_ipa_dns_used()
        yield
        assert self.is_resolver_operational()
        assert not self.is_ipa_dns_used()
        assert not self.client.resolver.has_backups()

    def test_ipa_dns_not_used_by_default(self):
        assert self.is_resolver_operational()
        assert not self.is_ipa_dns_used()

    def test_changing_config_without_backup_not_allowed(self):
        with pytest.raises(Exception, match='without backup'):
            self.client.resolver.setup_resolver(self.master.ip)

    def test_change_resolver(self):
        with self.start_end_checks():
            self.client.resolver.backup()
            self.client.resolver.setup_resolver(self.master.ip)
            assert self.is_resolver_operational()
            assert self.is_ipa_dns_used()
            self.client.resolver.restore()

    def test_nested_change_resolver(self):
        with self.start_end_checks():
            self.client.resolver.backup()
            self.client.resolver.setup_resolver(self.master.ip)

            assert self.is_resolver_operational()
            assert self.is_ipa_dns_used()

            self.client.resolver.backup()
            self.client.resolver.setup_resolver(self.invalid_resolver)
            self.check_ipa_name_resolution_fails()
            self.client.resolver.restore()

            assert self.is_resolver_operational()
            assert self.is_ipa_dns_used()

            self.client.resolver.restore()

    def test_nested_change_resolver_with_context(self):
        with self.start_end_checks():
            self.client.resolver.backup()
            self.client.resolver.setup_resolver(self.master.ip)
            assert self.is_resolver_operational()
            assert self.is_ipa_dns_used()

            with self.client.resolver:
                self.client.resolver.setup_resolver(self.invalid_resolver)
                self.check_ipa_name_resolution_fails()

            self.client.resolver.restore()

    def test_repeated_changing_resolver(self):
        with self.start_end_checks():
            self.client.resolver.backup()
            self.client.resolver.setup_resolver(self.master.ip)
            assert self.is_resolver_operational()
            assert self.is_ipa_dns_used()

            self.client.resolver.setup_resolver(self.invalid_resolver)
            self.check_ipa_name_resolution_fails()

            self.client.resolver.setup_resolver(self.master.ip)
            assert self.is_resolver_operational()
            assert self.is_ipa_dns_used()

            self.client.resolver.restore()

    @pytest.mark.parametrize('reverse', [True, False])
    def test_multiple_resolvers(self, reverse):
        resolvers = [self.invalid_resolver, self.master.ip]
        if reverse:
            resolvers.reverse()

        with self.start_end_checks():
            self.client.resolver.backup()
            self.client.resolver.setup_resolver(resolvers)
            assert self.is_resolver_operational()
            assert self.is_ipa_dns_used()
            self.client.resolver.restore()

    @classmethod
    def uninstall(cls, mh):
        tasks.uninstall_master(cls.master)
