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

import os

import nose

from ipapython.ipa_log_manager import log_mgr
from ipatests.test_integration.config import get_global_config, env_to_script
from ipatests.test_integration import tasks
from ipatests.order_plugin import ordered

log = log_mgr.get_logger(__name__)


@ordered
class IntegrationTest(object):
    num_replicas = 0
    num_clients = 0
    topology = 'none'

    @classmethod
    def setup_class(cls):
        config = get_global_config()
        if not config.domains:
            raise nose.SkipTest('Integration testing not configured')

        cls.logs_to_collect = {}

        domain = config.domains[0]
        cls.master = domain.master
        if len(domain.replicas) < cls.num_replicas:
            raise nose.SkipTest(
                'Not enough replicas available (have %s, need %s)' %
                (len(domain.replicas), cls.num_replicas))
        if len(domain.clients) < cls.num_clients:
            raise nose.SkipTest(
                'Not enough clients available (have %s, need %s)' %
                (len(domain.clients), cls.num_clients))
        cls.replicas = domain.replicas[:cls.num_replicas]
        cls.clients = domain.clients[:cls.num_clients]
        for host in cls.get_all_hosts():
            cls.prepare_host(host)

        try:
            cls.install()
            cls.kinit_all()
        except:
            cls.uninstall()
            raise

    @classmethod
    def get_all_hosts(cls):
        return [cls.master] + cls.replicas + cls.clients

    @classmethod
    def prepare_host(cls, host):
        cls.log.info('Preparing host %s', host.hostname)
        env_filename = os.path.join(host.config.test_dir, 'env.sh')
        cls.collect_log(host, env_filename)
        host.mkdir_recursive(host.config.test_dir)
        host.put_file_contents(env_filename, env_to_script(host.to_env()))

    @classmethod
    def install(cls):
        if cls.topology == 'none':
            return
        elif cls.topology == 'star':
            tasks.install_master(cls.master, collect_log=cls.collect_log)
            for replica in cls.replicas:
                tasks.install_replica(cls.master, replica,
                                      collect_log=cls.collect_log)
        else:
            raise ValueError('Unknown topology %s' % cls.topology)

    @classmethod
    def kinit_all(cls):
        for host in cls.get_all_hosts():
            host.run_command(['kinit', 'admin'],
                             stdin_text=host.config.admin_password)

    @classmethod
    def teardown_class(cls):
        try:
            cls.uninstall()
        finally:
            del cls.master
            del cls.replicas
            del cls.clients

    @classmethod
    def uninstall(cls):
        tasks.uninstall_master(cls.master, collect_log=cls.collect_log)
        for replica in cls.replicas:
            tasks.uninstall_master(replica, collect_log=cls.collect_log)
        for client in cls.clients:
            tasks.uninstall_client(client, collect_log=cls.collect_log)

    @classmethod
    def collect_log(cls, host, filename):
        cls.log.info('Adding %s:%s to list of logs to collect' %
                     (host.hostname, filename))
        cls.logs_to_collect.setdefault(host, []).append(filename)

IntegrationTest.log = log_mgr.get_logger(IntegrationTest())
