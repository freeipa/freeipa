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

from __future__ import print_function

import pytest

from ipapython.dn import DN
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


def check_replication(source_host, dest_host, login):
    source_host.run_command([
        "ipa", "user-add", login,
        "--first", "test",
        "--last", "user"
    ])

    source_ldap = source_host.ldap_connect()
    tasks.wait_for_replication(source_ldap)

    ldap = dest_host.ldap_connect()
    tasks.wait_for_replication(ldap)

    # Check using LDAP
    basedn = dest_host.domain.basedn
    user_dn = DN(
        ("uid", login), ("cn", "users"),
        ("cn", "accounts"), basedn
    )
    entry = ldap.get_entry(user_dn)
    assert entry.dn == user_dn
    assert entry["uid"] == [login]

    # Check using CLI
    result = dest_host.run_command(['ipa', 'user-show', login])
    assert "User login: {}".format(login) in result.stdout_text


@pytest.mark.ds_acceptance
class TestSimpleReplication(IntegrationTest):
    """Simple replication test

    Install a server and a replica, then add an user on one host and ensure
    it is also present on the other one.
    """
    num_replicas = 1
    topology = 'star'

    def test_user_replication_to_replica(self):
        """Test user replication master -> replica"""
        check_replication(self.master, self.replicas[0], 'testuser1')

    def test_user_replication_to_master(self):
        """Test user replication replica -> master"""
        check_replication(self.replicas[0], self.master, 'testuser2')

    def test_replica_removal(self):
        """Test replica removal"""
        result = self.master.run_command(['ipa-replica-manage', 'list'])
        assert self.replicas[0].hostname in result.stdout_text
        # has to be run with --force, there is no --unattended
        self.master.run_command(['ipa-replica-manage', 'del',
                                 self.replicas[0].hostname, '--force'])
        result = self.master.run_command(['ipa-replica-manage', 'list'])
        assert self.replicas[0].hostname not in result.stdout_text
