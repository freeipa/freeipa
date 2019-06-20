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

import pytest
import subprocess

from ipatests.pytest_ipa.integration import tasks
from pytest_sourceorder import ordered


@ordered
@pytest.mark.usefixtures('mh')
@pytest.mark.usefixtures('integration_logs')
class IntegrationTest:
    num_replicas = 0
    num_clients = 0
    num_ad_domains = 0
    num_ad_subdomains = 0
    num_ad_treedomains = 0
    required_extra_roles = []
    topology = None
    domain_level = None
    fips_mode = None

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
                [cls.host_by_role(r) for r in cls.required_extra_roles])

    @classmethod
    def get_domains(cls):
        return [cls.domain] + cls.ad_domains

    @classmethod
    def enable_fips_mode(cls):
        for host in cls.get_all_hosts():
            if not host.is_fips_mode:
                host.enable_userspace_fips()

    @classmethod
    def disable_fips_mode(cls):
        for host in cls.get_all_hosts():
            if host.is_userspace_fips:
                host.disable_userspace_fips()

    @classmethod
    def install(cls, mh):
        if cls.domain_level is not None:
            domain_level = cls.domain_level
        else:
            domain_level = cls.master.config.domain_level

        if cls.master.config.fips_mode:
            cls.fips_mode = True
        if cls.fips_mode:
            cls.enable_fips_mode()

        if cls.topology is None:
            return
        else:
            tasks.install_topo(cls.topology,
                               cls.master, cls.replicas,
                               cls.clients, domain_level)
    @classmethod
    def uninstall(cls, mh):
        for replica in cls.replicas:
            try:
                tasks.run_server_del(
                    cls.master, replica.hostname, force=True,
                    ignore_topology_disconnect=True, ignore_last_of_role=True)
            except subprocess.CalledProcessError:
                # If the master has already been uninstalled,
                # this call may fail
                pass
            tasks.uninstall_master(replica)
        tasks.uninstall_master(cls.master)
        for client in cls.clients:
            tasks.uninstall_client(client)
        if cls.fips_mode:
            cls.disable_fips_mode()
