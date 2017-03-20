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
from ipatests.pytest_plugins.integration import tasks


class TestServicePermissions(IntegrationTest):
    topology = 'star'

    def test_service_as_user_admin(self):
        """Test that a service in User Administrator role can manage users"""

        service_name = 'testservice/%s@%s' % (self.master.hostname,
                                              self.master.domain.realm)
        keytab_file = os.path.join(self.master.config.test_dir,
                                   'testservice_keytab')

        # Prepare a service

        self.master.run_command(['ipa', 'service-add', service_name])

        self.master.run_command(['ipa-getkeytab',
                                 '-p', service_name,
                                 '-k', keytab_file,
                                 '-s', self.master.hostname])

        # Check that the service cannot add a user

        self.master.run_command(['kdestroy'])
        self.master.run_command(['kinit', '-k', service_name,
                                 '-t', keytab_file])

        result = self.master.run_command(['ipa', 'role-add-member',
                                          'User Administrator',
                                          '--service', service_name],
                                         raiseonerr=False)
        assert result.returncode > 0

        # Add service to User Administrator role

        self.master.run_command(['kdestroy'])
        tasks.kinit_admin(self.master)

        self.master.run_command(['ipa', 'role-add-member',
                                 'User Administrator',
                                 '--service', service_name])

        # Check that the service now can add a user

        self.master.run_command(['kdestroy'])
        self.master.run_command(['kinit', '-k', service_name,
                                 '-t', keytab_file])

        self.master.run_command(['ipa', 'user-add', 'tuser',
                                 '--first', 'a', '--last', 'b', '--random'])

        # Clean up

        self.master.run_command(['kdestroy'])
        tasks.kinit_admin(self.master)

        self.master.run_command(['ipa', 'service-del', service_name])
        self.master.run_command(['ipa', 'user-del', 'tuser'])


class TestServiceAuthenticationIndicators(IntegrationTest):
    topology = 'star'

    def test_service_access(self):
        """ Test that user is granted access when authenticated using
        credentials that are sufficient for a service, and denied access
        when using insufficient credentials"""

        service_name = 'testservice/%s@%s' % (self.master.hostname,
                                              self.master.domain.realm)

        keytab_file = os.path.join(self.master.config.test_dir,
                                   'testservice_keytab')

        # Prepare a service without authentication indicator
        self.master.run_command(['ipa', 'service-add', service_name])

        self.master.run_command(['ipa-getkeytab',
                                 '-p', service_name,
                                 '-k', keytab_file])

        # Set authentication-type for admin user
        self.master.run_command(['ipa', 'user-mod', 'admin',
                                 '--user-auth-type=password',
                                 '--user-auth-type=otp'])

        # Authenticate
        self.master.run_command(['kinit', '-k', service_name,
                                 '-t', keytab_file])

        # Verify access to service is granted
        result = self.master.run_command(['kvno', service_name],
                                         raiseonerr=False)
        assert result.returncode == 0

        # Obtain admin ticket to be able to update service
        tasks.kinit_admin(self.master)

        # Modify service to have authentication indicator
        self.master.run_command(['ipa', 'service-mod', service_name,
                                 '--auth-ind=otp'])

        self.master.run_command(['ipa-getkeytab',
                                 '-p', service_name,
                                 '-k', keytab_file])

        # Authenticate
        self.master.run_command(['kinit', '-k', service_name,
                                 '-t', keytab_file])

        # Verify access to service is rejected
        result = self.master.run_command(['kvno', service_name],
                                         raiseonerr=False)
        assert result.returncode > 0
