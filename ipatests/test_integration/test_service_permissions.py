# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2014  Red Hat
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

import os

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


class TestServicePermissions(IntegrationTest):
    topology = 'star'

    def test_service_as_user_admin(self):
        """Test that a service in User Administrator role can manage users"""

        service_name1 = 'testservice1/%s@%s' % (self.master.hostname,
                                                self.master.domain.realm)
        keytab_file1 = os.path.join(self.master.config.test_dir,
                                    'testservice_keytab1')

        # Prepare a service

        self.master.run_command(['ipa', 'service-add', service_name1])

        self.master.run_command(['ipa-getkeytab',
                                 '-p', service_name1,
                                 '-k', keytab_file1,
                                 '-s', self.master.hostname])

        # Check that the service cannot add a user

        self.master.run_command(['kdestroy'])
        self.master.run_command(['kinit', '-k', service_name1,
                                 '-t', keytab_file1])

        result = self.master.run_command(['ipa', 'role-add-member',
                                          'User Administrator',
                                          '--service', service_name1],
                                         raiseonerr=False)
        assert result.returncode > 0

        # Add service to User Administrator role

        self.master.run_command(['kdestroy'])
        tasks.kinit_admin(self.master)

        self.master.run_command(['ipa', 'role-add-member',
                                 'User Administrator',
                                 '--service', service_name1])

        # Check that the service now can add a user

        self.master.run_command(['kdestroy'])
        self.master.run_command(['kinit', '-k', service_name1,
                                 '-t', keytab_file1])

        self.master.run_command(['ipa', 'user-add', 'tuser',
                                 '--first', 'a', '--last', 'b', '--random'])

        # Clean up

        self.master.run_command(['kdestroy'])
        tasks.kinit_admin(self.master)

        self.master.run_command(['ipa', 'service-del', service_name1])
        self.master.run_command(['ipa', 'user-del', 'tuser'])

    def test_service_access(self):
        """ Test that user is granted access when authenticated using
        credentials that are sufficient for a service, and denied access
        when using insufficient credentials"""

        service_name2 = 'testservice2/%s@%s' % (self.master.hostname,
                                                self.master.domain.realm)

        keytab_file2 = os.path.join(self.master.config.test_dir,
                                    'testservice_keytab2')

        # Prepare a service without authentication indicator
        self.master.run_command(['ipa', 'service-add', service_name2])

        self.master.run_command(['ipa-getkeytab',
                                 '-p', service_name2,
                                 '-k', keytab_file2])

        # Set authentication-type for admin user
        self.master.run_command(['ipa', 'user-mod', 'admin',
                                 '--user-auth-type=password',
                                 '--user-auth-type=otp'])

        # Authenticate
        self.master.run_command(['kinit', '-k', service_name2,
                                 '-t', keytab_file2])

        # Verify access to service is granted
        result = self.master.run_command(['kvno', service_name2],
                                         raiseonerr=False)
        assert result.returncode == 0

        # Obtain admin ticket to be able to update service
        tasks.kinit_admin(self.master)

        # Modify service to have authentication indicator
        self.master.run_command(['ipa', 'service-mod', service_name2,
                                 '--auth-ind=otp'])

        self.master.run_command(['ipa-getkeytab',
                                 '-p', service_name2,
                                 '-k', keytab_file2])

        # Authenticate
        self.master.run_command(['kinit', '-k', service_name2,
                                 '-t', keytab_file2])

        # Verify access to service is rejected
        result = self.master.run_command(['kvno', service_name2],
                                         raiseonerr=False)
        assert result.returncode > 0

    def test_service_del(self):
        """ Test that host can add and remove its own services.
        Related to : https://pagure.io/freeipa/issue/7486"""

        self.master.run_command(['kinit', '-kt', '/etc/krb5.keytab'])
        # Add service
        service_name3 = "testservice3" + '/' + self.master.hostname
        self.master.run_command(['ipa', 'service-add', service_name3])
        self.master.run_command(['ipa', 'service-del', service_name3])
