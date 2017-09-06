#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#
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

from ipatests.pytest_plugins.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.create_external_ca import ExternalCA
from ipatests.util import collect_logs


class TestExternalCA(IntegrationTest):
    """
    Test of FreeIPA server installation with exernal CA
    """
    @collect_logs
    def test_external_ca(self):
        # Step 1 of ipa-server-install
        self.master.run_command([
            'ipa-server-install', '-U',
            '-a', self.master.config.admin_password,
            '-p', self.master.config.dirman_password,
            '--setup-dns', '--no-forwarders',
            '-n', self.master.domain.name,
            '-r', self.master.domain.realm,
            '--domain-level=%i' % self.master.config.domain_level,
            '--external-ca'
        ])

        test_dir = self.master.config.test_dir

        # Get IPA CSR as bytes
        ipa_csr = self.master.get_file_contents('/root/ipa.csr')

        external_ca = ExternalCA()
        # Create root CA
        root_ca = external_ca.create_ca()
        # Sign CSR
        ipa_ca = external_ca.sign_csr(ipa_csr)

        root_ca_fname = os.path.join(test_dir, 'root_ca.crt')
        ipa_ca_fname = os.path.join(test_dir, 'ipa_ca.crt')

        # Transport certificates (string > file) to master
        self.master.put_file_contents(root_ca_fname, root_ca)
        self.master.put_file_contents(ipa_ca_fname, ipa_ca)

        # Step 2 of ipa-server-install
        self.master.run_command([
            'ipa-server-install',
            '-a', self.master.config.admin_password,
            '-p', self.master.config.dirman_password,
            '--external-cert-file', ipa_ca_fname,
            '--external-cert-file', root_ca_fname
        ])

        # Make sure IPA server is working properly
        tasks.kinit_admin(self.master)
        result = self.master.run_command(['ipa', 'user-show', 'admin'])
        assert 'User login: admin' in result.stdout_text
