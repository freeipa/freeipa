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

import time

from ipatests.test_integration.base import IntegrationTest


class TestSimpleReplication(IntegrationTest):
    """Simple replication test

    Install a server and a replica, then add an user on one host and ensure
    it is also present on the other one.
    """
    num_replicas = 1
    topology = 'star'

    def test_user_replication_to_replica(self):
        """Test user replication master -> replica"""
        login = 'testuser1'
        self.master.run_command(['ipa', 'user-add', login,
                                 '--first', 'test',
                                 '--last', 'user'])

        self.log.debug('Sleeping so replication has a chance to finish')
        time.sleep(5)

        result = self.replicas[0].run_command(['ipa', 'user-show', login])
        assert 'User login: %s' % login in result.stdout_text

    def test_user_replication_to_master(self):
        """Test user replication replica -> master"""
        login = 'testuser2'
        self.replicas[0].run_command(['ipa', 'user-add', login,
                                      '--first', 'test',
                                      '--last', 'user'])

        self.log.debug('Sleeping so replication has a chance to finish')
        time.sleep(5)

        result = self.master.run_command(['ipa', 'user-show', login])
        assert 'User login: %s' % login in result.stdout_text
