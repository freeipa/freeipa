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

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


class TestKerberosFlags(IntegrationTest):
    """
    Test Kerberos Flags
    http://www.freeipa.org/page/V3/Kerberos_Flags#Test_Plan
    """
    topology = 'line'
    num_clients = 1

    def test_set_flag_with_host_add(self):
        host = 'host.example.com'
        host_service = 'host/%s' % host
        host_keytab = '/tmp/host.keytab'

        for trusted in (True, False, None):
            self.add_object('host', host, trusted=trusted, force=True)
            self.check_flag_cli('host', host, trusted=trusted)
            self.rekinit()
            self.getkeytab(host_service, host_keytab)
            self.kvno(host_service)
            self.check_flag_klist(host_service, trusted=trusted)
            self.del_object('host', host)

    def test_set_and_clear_flag_with_host_mod(self):
        client_hostname = self.clients[0].hostname
        host_service = 'host/%s' % client_hostname

        self.kvno(host_service)
        self.check_flag_cli('host', client_hostname, trusted=False)
        self.check_flag_klist(host_service, trusted=False)

        for trusted in (True, False):
            self.mod_object_cli('host', client_hostname, trusted=trusted)
            self.check_flag_cli('host', client_hostname, trusted=trusted)
            self.rekinit()
            self.kvno(host_service)
            self.check_flag_klist(host_service, trusted=trusted)

        for trusted in (True, False):
            self.mod_service_kadmin_local(host_service, trusted=trusted)
            self.check_flag_cli('host', client_hostname, trusted=trusted)
            self.rekinit()
            self.kvno(host_service)
            self.check_flag_klist(host_service, trusted=trusted)

    def test_set_flag_with_service_add(self):
        ftp_service = 'ftp/%s' % self.master.hostname
        ftp_keytab = '/tmp/ftp.keytab'

        for trusted in (True, False, None):
            self.add_object('service', ftp_service, trusted=trusted)
            self.check_flag_cli('service', ftp_service, trusted=trusted)
            self.rekinit()
            self.getkeytab(ftp_service, ftp_keytab)
            self.kvno(ftp_service)
            self.check_flag_klist(ftp_service, trusted=trusted)
            self.del_object('service', ftp_service)

    def test_set_and_clear_flag_with_service_mod(self):
        http_service = 'HTTP/%s' % self.master.hostname

        self.kvno(http_service)
        self.check_flag_cli('service', http_service, trusted=False)
        self.check_flag_klist(http_service, trusted=False)

        for trusted in (True, False):
            self.mod_object_cli('service', http_service, trusted=trusted)
            self.check_flag_cli('service', http_service, trusted=trusted)
            self.rekinit()
            self.kvno(http_service)
            self.check_flag_klist(http_service, trusted=trusted)

        for trusted in (True, False):
            self.mod_service_kadmin_local(http_service, trusted=trusted)
            self.check_flag_cli('service', http_service, trusted=trusted)
            self.rekinit()
            self.kvno(http_service)
            self.check_flag_klist(http_service, trusted=trusted)

    def test_try_to_set_flag_using_unexpected_values(self):
        http_service = 'HTTP/%s' % self.master.hostname
        invalid_values = ['blah', 'yes', 'y', '2', '1.0', '$']

        for v in invalid_values:
            self.mod_object_cli('service', http_service, trusted=v,
                                expect_fail=True)

    def add_object(self, object_type, object_id, trusted=None, force=False):
        args = ['ipa', '%s-add' % object_type, object_id]

        if trusted is True:
            args.extend(['--ok-as-delegate', '1'])
        elif trusted is False:
            args.extend(['--ok-as-delegate', '0'])

        if force:
            args.append('--force')

        self.master.run_command(args)

    def del_object(self, object_type, object_id):
        self.master.run_command(['ipa', '%s-del' % object_type, object_id])

    def mod_object_cli(self, object_type, object_id, trusted,
                       expect_fail=False):
        args = ['ipa', '%s-mod' % object_type, object_id]

        if trusted is True:
            args.extend(['--ok-as-delegate', '1'])
        elif trusted is False:
            args.extend(['--ok-as-delegate', '0'])
        else:
            args.extend(['--ok-as-delegate', trusted])

        result = self.master.run_command(args, raiseonerr=not expect_fail)

        if expect_fail:
            stderr_text = "invalid 'ipakrbokasdelegate': must be True or False"
            assert result.returncode == 1
            assert stderr_text in result.stderr_text

    def mod_service_kadmin_local(self, service, trusted):
        sign = '+' if trusted else '-'
        stdin_text = '\n'.join([
            'modify_principal %sok_as_delegate %s' % (sign, service),
            'q',
            ''
        ])
        self.master.run_command('kadmin.local', stdin_text=stdin_text)

    def check_flag_cli(self, object_type, object_id, trusted):
        result = self.master.run_command(
            ['ipa', '%s-show' % object_type, object_id, '--all']
        )

        if trusted:
            assert 'Trusted for delegation: True' in result.stdout_text
        else:
            assert 'Trusted for delegation: False' in result.stdout_text

    def check_flag_klist(self, service, trusted):
        result = self.master.run_command(['klist', '-f'])
        output_lines = result.stdout_text.split('\n')
        flags = ''

        for line, next_line in zip(output_lines, output_lines[1:]):
            if service in line:
                flags = next_line.replace('Flags:', '').strip()

        if trusted:
            assert 'O' in flags
        else:
            assert 'O' not in flags

    def rekinit(self):
        self.master.run_command(['kdestroy'])
        tasks.kinit_admin(self.master)

    def getkeytab(self, service, keytab):
        result = self.master.run_command([
            'ipa-getkeytab',
            '-s', self.master.hostname,
            '-p', service,
            '-k', keytab
        ])
        assert 'Keytab successfully retrieved' in result.stderr_text

    def kvno(self, service):
        self.master.run_command(['kvno', service])
