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
import socket
import threading
import subprocess
import errno

import paramiko

from ipapython import ipautil
from ipapython.ipa_log_manager import log_mgr


class RemoteCommand(object):
    """A Popen-style object representing a remote command

    Unlike subprocess.Popen, this does not run the given command; instead
    it only starts a shell. The command must be written to stdin manually.

    The standard error and output are handled by this class. They're not
    available for file-like reading. They are logged by default.
    To make sure reading doesn't stall after one buffer fills up, they are read
    in parallel using threads.

    After calling wait(), stdout_text and stderr_text attributes will be
    strings containing the output, and returncode will contain the
    exit code.

    :param host: The Host on which the command is run
    :param argv: The command that will be run (for logging only)
    :param index: An identification number added to the logs
    :param log_stdout: If false, stdout will not be logged
    """
    def __init__(self, host, argv, index, log_stdout=True):
        self.returncode = None
        self.host = host
        self.argv = argv
        self._stdout_lines = []
        self._stderr_lines = []
        self.running_threads = set()

        self.logger_name = '%s.cmd%s' % (self.host.logger_name, index)
        self.log = log_mgr.get_logger(self.logger_name)

        self.log.info('RUN %s', argv)

        self._ssh = host.transport.open_channel('session')

        self._ssh.invoke_shell()
        stdin = self.stdin = self._ssh.makefile('wb')
        stdout = self._ssh.makefile('rb')
        stderr = self._ssh.makefile_stderr('rb')

        self._start_pipe_thread(self._stdout_lines, stdout, 'out', log_stdout)
        self._start_pipe_thread(self._stderr_lines, stderr, 'err', True)

        self._done = False

    def wait(self, raiseonerr=True):
        """Wait for the remote process to exit

        Raises an excption if the exit code is not 0.
        """
        if self._done:
            return self.returncode

        self._ssh.shutdown_write()
        while self.running_threads:
            self.running_threads.pop().join()

        self.stdout_text = ''.join(self._stdout_lines)
        self.stderr_text = ''.join(self._stderr_lines)
        self.returncode = self._ssh.recv_exit_status()
        self._ssh.close()

        self._done = True

        if raiseonerr and self.returncode:
            self.log.error('Exit code: %s', self.returncode)
            raise subprocess.CalledProcessError(self.returncode, self.argv)
        else:
            self.log.debug('Exit code: %s', self.returncode)
        return self.returncode

    def _start_pipe_thread(self, result_list, stream, name, do_log=True):
        log = log_mgr.get_logger('%s.%s' % (self.logger_name, name))

        def read_stream():
            for line in stream:
                if do_log:
                    log.debug(line.rstrip('\n'))
                result_list.append(line)

        thread = threading.Thread(target=read_stream)
        self.running_threads.add(thread)
        thread.start()
        return thread


class Host(object):
    """Representation of a remote IPA host"""
    def __init__(self, domain, hostname, role, index, ip=None):
        self.domain = domain
        self.role = role
        self.index = index

        shortname, dot, ext_domain = hostname.partition('.')
        self.shortname = shortname
        self.hostname = shortname + '.' + self.domain.name
        self.external_hostname = hostname

        self.logger_name = '%s.%s.%s' % (
            self.__module__, type(self).__name__, shortname)
        self.log = log_mgr.get_logger(self.logger_name)

        if ip:
            self.ip = ip
        else:
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
                raise RuntimeError('Could not determine IP address of %s' %
                                   self.external_hostname)

        self.root_password = self.config.root_password
        self.root_ssh_key_filename = self.config.root_ssh_key_filename
        self.host_key = None
        self.ssh_port = 22

        self.env_sh_path = os.path.join(domain.config.test_dir, 'env.sh')

        self._command_index = 0

        self.log_collectors = []

    def __repr__(self):
        template = ('<{s.__module__}.{s.__class__.__name__} '
                    '{s.hostname} ({s.role})>')
        return template.format(s=self)

    def add_log_collector(self, collector):
        """Register a log collector for this host"""
        self.log_collectors.append(collector)

    def remove_log_collector(self, collector):
        """Unregister a log collector"""
        self.log_collectors.remove(collector)

    @classmethod
    def from_env(cls, env, domain, hostname, role, index):
        ip = env.get('BEAKER%s%s_IP_env%s' %
                        (role.upper(), index, domain.index), None)
        self = cls(domain, hostname, role, index, ip)
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
                    log_stdout=True, raiseonerr=True,
                    cwd=None):
        """Run the given command on this host

        Returns a RemoteCommand instance. The command will have already run
        when this method returns, so its stdout_text, stderr_text, and
        returncode attributes will be available.

        :param argv: Command to run, as either a Popen-style list, or a string
                     containing a shell script
        :param set_env: If true, env.sh exporting configuration variables will
                        be sourced before running the command.
        :param stdin_text: If given, will be written to the command's stdin
        :param log_stdout: If false, standard output will not be logged
                           (but will still be available as cmd.stdout_text)
        :param raiseonerr: If true, an exception will be raised if the command
                           does not exit with return code 0
        """
        command = RemoteCommand(self, argv, index=self._command_index,
                                log_stdout=log_stdout)
        self._command_index += 1

        if cwd is None:
            cwd = self.config.test_dir
        command.stdin.write('cd %s\n' % ipautil.shell_quote(cwd))

        if set_env:
            command.stdin.write('. %s\n' %
                                ipautil.shell_quote(self.env_sh_path))
        command.stdin.write('set -e\n')

        if isinstance(argv, basestring):
            command.stdin.write('(')
            command.stdin.write(argv)
            command.stdin.write(')')
        else:
            for arg in argv:
                command.stdin.write(ipautil.shell_quote(arg))
                command.stdin.write(' ')
        command.stdin.write(';exit\n')
        if stdin_text:
            command.stdin.write(stdin_text)
        command.stdin.flush()

        command.wait(raiseonerr=raiseonerr)
        return command

    @property
    def transport(self):
        """Paramiko Transport connected to this host"""
        try:
            return self._transport
        except AttributeError:
            sock = socket.create_connection((self.external_hostname,
                                             self.ssh_port))
            self._transport = transport = paramiko.Transport(sock)
            transport.connect(hostkey=self.host_key)
            if self.root_ssh_key_filename:
                self.log.debug('Authenticating with private RSA key')
                filename = os.path.expanduser(self.root_ssh_key_filename)
                key = paramiko.RSAKey.from_private_key_file(filename)
                transport.auth_publickey(username='root', key=key)
            elif self.root_password:
                self.log.debug('Authenticating with password')
                transport.auth_password(username='root',
                                        password=self.root_password)
            else:
                self.log.critical('No SSH credentials configured')
                raise RuntimeError('No SSH credentials configured')
            # Clean up the test directory
            self.run_command(['rm', '-rvf', self.config.test_dir])
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
            self.sftp.chdir(path or '/')
        except IOError as e:
            if not path or path == '/':
                raise
            self.mkdir_recursive(os.path.dirname(path))
            self.sftp.mkdir(path)
            self.sftp.chdir(path)

    def get_file_contents(self, filename):
        """Read the named remote file and return the contents as a string"""
        self.log.debug('READ %s', filename)
        with self.sftp.open(filename) as f:
            return f.read()

    def put_file_contents(self, filename, contents):
        """Write the given string to the named remote file"""
        self.log.info('WRITE %s', filename)
        with self.sftp.open(filename, 'w') as f:
            f.write(contents)

    def file_exists(self, filename):
        """Return true if the named remote file exists"""
        self.log.debug('STAT %s', filename)
        try:
            self.sftp.stat(filename)
        except IOError, e:
            if e.errno == errno.ENOENT:
                return False
            else:
                raise
        return True

    def get_file(self, remotepath, localpath):
        self.log.debug('GET %s', remotepath)
        self.sftp.get(remotepath, localpath)

    def put_file(self, localpath, remotepath):
        self.log.info('PUT %s', remotepath)
        self.sftp.put(localpath, remotepath)

    def collect_log(self, filename):
        for collector in self.log_collectors:
            collector(self, filename)
