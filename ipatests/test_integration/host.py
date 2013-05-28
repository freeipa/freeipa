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

"""Host class for integration testing"""

import os
import collections
import socket

import paramiko

from ipapython import ipautil
from ipapython.ipa_log_manager import log_mgr

RunResult = collections.namedtuple('RunResult', 'output exit_code')


class Host(object):
    """Configuration for an IPA host"""
    def __init__(self, domain, hostname, role, index):
        self.log = log_mgr.get_logger(self)
        self.domain = domain
        self.role = role
        self.index = index

        shortname, dot, ext_domain = hostname.partition('.')
        self.hostname = shortname + '.' + self.domain.name
        self.external_hostname = hostname

        if self.config.ipv6:
            # $(dig +short $M $rrtype|tail -1)
            stdout, stderr, returncode = ipautil.run(
                ['dig', '+short', self.external_hostname, 'AAAA'])
            self.ip = stdout.splitlines()[-1].strip()
        else:
            try:
                self.ip = socket.gethostbyname(self.external_hostname)
            except socket.gaierror:
                self.ip = None

        if not self.ip:
            self.ip = ''
            self.role = 'other'

        self.root_password = self.config.root_password
        self.host_key = None
        self.ssh_port = 22

        self.env_sh_path = os.path.join(domain.config.test_dir, 'env.sh')

        self.log = log_mgr.get_logger('%s.%s.%s' % (
            self.__module__, type(self).__name__, self.hostname))

    def __repr__(self):
        template = ('<{s.__module__}.{s.__class__.__name__} '
                    '{s.hostname} ({s.role})>')
        return template.format(s=self)

    @classmethod
    def from_env(cls, env, domain, hostname, role, index):
        self = cls(domain, hostname, role, index)
        return self

    @property
    def config(self):
        return self.domain.config

    def to_env(self, **kwargs):
        """Return environment variables specific to this host"""
        env = self.domain.to_env(**kwargs)

        role = self.role.upper()
        if self.role != 'master':
            role += str(self.index)

        env['MYHOSTNAME'] = self.hostname
        env['MYBEAKERHOSTNAME'] = self.external_hostname
        env['MYIP'] = self.ip

        env['MYROLE'] = '%s%s' % (role, self.domain._env)
        env['MYENV'] = str(self.domain.index)

        return env

    def run_command(self, argv, set_env=True, stdin_text=None,
                    ignore_stdout=False):
        assert argv
        self.log.info('RUN %s', argv)
        ssh = self.transport.open_channel('session')
        try:
            ssh.invoke_shell()
            ssh.set_combine_stderr(True)
            stdin = ssh.makefile('wb')
            stdout = ssh.makefile('rb')

            if set_env:
                stdin.write('. %s\n' % self.env_sh_path)
            stdin.write('set -ex\n')

            for arg in argv:
                stdin.write(ipautil.shell_quote(arg))
                stdin.write(' ')
            if stdin_text:
                stdin_filename = os.path.join(self.config.test_dir, 'stdin')
                with self.sftp.open(stdin_filename, 'w') as f:
                    f.write(stdin_text)
                stdin.write('<')
                stdin.write(stdin_filename)
            else:
                stdin.write('< /dev/null')
            if ignore_stdout:
                stdin.write('> /dev/null')
            stdin.write('\n')
            ssh.shutdown_write()
            output = []
            for line in stdout:
                output.append(line)
                self.log.info('    %s', line.strip('\n'))
            exit_status = ssh.recv_exit_status()
            self.log.info(' -> Exit code %s', exit_status)
            if exit_status:
                raise RuntimeError('Command %s exited with error code %s' % (
                    argv[0], exit_status))
            return RunResult(''.join(output), exit_status)
        finally:
            ssh.close()

    @property
    def transport(self):
        """Paramiko Transport connected to this host"""
        try:
            return self._transport
        except AttributeError:
            sock = socket.create_connection((self.hostname, self.ssh_port))
            self._transport = transport = paramiko.Transport(sock)
            transport.connect(hostkey=self.host_key, username='root',
                              password=self.root_password)
            return transport

    @property
    def sftp(self):
        """Paramiko SFTPClient connected to this host"""
        try:
            return self._sftp
        except AttributeError:
            transport = self.transport
            self._sftp = paramiko.SFTPClient.from_transport(transport)
            return self._sftp

    def mkdir_recursive(self, path):
        """`mkdir -p` on the remote host"""
        try:
            self.sftp.chdir(path)
        except IOError:
            self.mkdir_recursive(os.path.dirname(path))
            self.sftp.mkdir(path)
            self.sftp.chdir(path)

    def get_file_contents(self, filename):
        self.log.info('READ %s', filename)
        with self.sftp.open(filename) as f:
            return f.read()

    def put_file_contents(self, filename, contents):
        self.log.info('WRITE %s', filename)
        with self.sftp.open(filename, 'w') as f:
            return f.write(contents)
