# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2013  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Base class for FreeIPA integration tests"""

import nose

from ipapython.ipa_log_manager import log_mgr
from ipatests.test_integration.config import get_global_config
from ipatests.test_integration import tasks
from ipatests.pytest_plugins.ordering import ordered

log = log_mgr.get_logger(__name__)


@ordered
class IntegrationTest(object):
    num_replicas = 0
    num_clients = 0
    num_ad_domains = 0
    required_extra_roles = []
    topology = None

    @classmethod
    def setup_class(cls):

        def get_resources(resource_container, resource_str, num_needed):
            if len(resource_container) < num_needed:
                raise nose.SkipTest(
                    'Not enough %s available (have %s, need %s)' %
                    (resource_str, len(resource_container), num_needed))
            return resource_container[:num_needed]

        config = get_global_config()
        if not config.domains:
            raise nose.SkipTest('Integration testing not configured')

        cls.logs_to_collect = {}

        cls.domain = config.domains[0]

        # Check that we have enough resources available
        cls.master = cls.domain.master
        cls.replicas = get_resources(cls.domain.replicas, 'replicas',
                                     cls.num_replicas)
        cls.clients = get_resources(cls.domain.clients, 'clients',
                                    cls.num_clients)
        cls.ad_domains = get_resources(config.ad_domains, 'AD domains',
                                       cls.num_ad_domains)

        # Check that we have all required extra hosts at our disposal
        available_extra_roles = [role for domain in cls.get_domains()
                                        for role in domain.extra_roles]
        missing_extra_roles = list(set(cls.required_extra_roles) -
                                     set(available_extra_roles))

        if missing_extra_roles:
            raise nose.SkipTest("Not all required extra hosts available, "
                                "missing: %s, available: %s"
                                % (missing_extra_roles,
                                   available_extra_roles))

        for host in cls.get_all_hosts():
            host.add_log_collector(cls.collect_log)
            cls.prepare_host(host)

        try:
            cls.install()
        except:
            cls.uninstall()
            raise

    @classmethod
    def host_by_role(cls, role):
        for domain in cls.get_domains():
            try:
                return domain.host_by_role(role)
            except LookupError:
                pass
        raise LookupError(role)

    @classmethod
    def get_all_hosts(cls):
        return ([cls.master] + cls.replicas + cls.clients +
                map(cls.host_by_role, cls.required_extra_roles))

    @classmethod
    def get_domains(cls):
        return [cls.domain] + cls.ad_domains

    @classmethod
    def prepare_host(cls, host):
        cls.log.info('Preparing host %s', host.hostname)
        tasks.prepare_host(host)

    @classmethod
    def install(cls):
        if cls.topology is None:
            return
        else:
            tasks.install_topo(cls.topology,
                               cls.master, cls.replicas, cls.clients)

    @classmethod
    def teardown_class(cls):
        for host in cls.get_all_hosts():
            host.remove_log_collector(cls.collect_log)

        try:
            cls.uninstall()
        finally:
            del cls.master
            del cls.replicas
            del cls.clients
            del cls.ad_domains
            del cls.domain

    @classmethod
    def uninstall(cls):
        tasks.uninstall_master(cls.master)
        for replica in cls.replicas:
            tasks.uninstall_master(replica)
        for client in cls.clients:
            tasks.uninstall_client(client)

    @classmethod
    def collect_log(cls, host, filename):
        cls.log.info('Adding %s:%s to list of logs to collect' %
                     (host.external_hostname, filename))
        cls.logs_to_collect.setdefault(host, []).append(filename)

IntegrationTest.log = log_mgr.get_logger(IntegrationTest())
