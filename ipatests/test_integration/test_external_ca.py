# Authors:
#   Ana Krivokapic <akrivoka@redhat.com>
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
import os
import base64

from ipatests.pytest_plugins.integration import tasks
from ipatests.test_integration.base import IntegrationTest


EXTERNAL_CA_KEY_ID = base64.b64encode(os.urandom(64))
IPA_CA_KEY_ID = base64.b64encode(os.urandom(64))


class TestExternalCA(IntegrationTest):
    """
    Test of FreeIPA server installation with exernal CA
    """
    @tasks.collect_logs
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

        nss_db = os.path.join(self.master.config.test_dir, 'testdb')
        external_cert_file = os.path.join(nss_db, 'ipa.crt')
        external_ca_file = os.path.join(nss_db, 'ca.crt')
        noisefile = os.path.join(self.master.config.test_dir, 'noise.txt')
        pwdfile = os.path.join(self.master.config.test_dir, 'pwdfile.txt')

        # Create noise and password files for NSS database
        self.master.run_command('date | sha256sum > %s' % noisefile)
        self.master.run_command('echo %s > %s' %
                                (self.master.config.admin_password, pwdfile))

        # Create NSS database
        self.master.run_command(['mkdir', nss_db])
        self.master.run_command([
            'certutil', '-N',
            '-d', nss_db,
            '-f', pwdfile
        ])

        # Create external CA
        self.master.run_command([
            'certutil', '-S',
            '-d', nss_db,
            '-f', pwdfile,
            '-n', 'external',
            '-s', 'CN=External CA, O=%s' % self.master.domain.name,
            '-x',
            '-t', 'CTu,CTu,CTu',
            '-g', '2048',
            '-m', '0',
            '-v', '60',
            '-z', noisefile,
            '-2', '-1', '-5', '--extSKID'
        ], stdin_text='5\n9\nn\ny\n10\ny\n{}\nn\n5\n6\n7\n9\nn\n'
                      ''.format(EXTERNAL_CA_KEY_ID))

        # Sign IPA cert request using the external CA
        self.master.run_command([
            'certutil', '-C',
            '-d', nss_db,
            '-f', pwdfile,
            '-c', 'external',
            '-m', '1',
            '-v', '60',
            '-2', '-1', '-3', '--extSKID',
            '-i', '/root/ipa.csr',
            '-o', external_cert_file,
            '-a'
        ], stdin_text='0\n1\n5\n9\ny\ny\n\ny\ny\n{}\n-1\n\nn\n{}\nn\n'
                      ''.format(EXTERNAL_CA_KEY_ID, IPA_CA_KEY_ID))

        # Export external CA file
        self.master.run_command(
            'certutil -L -d %s -n "external" -a > %s' %
            (nss_db, external_ca_file)
        )

        # Step 2 of ipa-server-install
        self.master.run_command([
            'ipa-server-install',
            '-a', self.master.config.admin_password,
            '-p', self.master.config.dirman_password,
            '--external-cert-file', external_cert_file,
            '--external-cert-file', external_ca_file
        ])

        # Make sure IPA server is working properly
        tasks.kinit_admin(self.master)
        result = self.master.run_command(['ipa', 'user-show', 'admin'])
        assert 'User login: admin' in result.stdout_text
