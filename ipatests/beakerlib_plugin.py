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

"""A Nose plugin that integrates with BeakerLib"""

import os
import sys
import subprocess
import traceback
import logging
import tempfile
import re

import nose
from nose.plugins import Plugin

from ipapython import ipautil
from ipapython.ipa_log_manager import log_mgr

LINK_RE = re.compile(r'https?://[^\s]+')


class BeakerLibLogHandler(logging.Handler):
    def __init__(self, beakerlib_command):
        super(BeakerLibLogHandler, self).__init__()
        self.beakerlib_command = beakerlib_command

    def emit(self, record):
        command = {
            'DEBUG': 'rlLogDebug',
            'INFO': 'rlLogInfo',
            'WARNING': 'rlLogWarning',
            'ERROR': 'rlLogError',
            'CRITICAL': 'rlLogFatal',
        }.get(record.levelname, 'rlLog')
        self.beakerlib_command([command, self.format(record)])


class BeakerLibProcess(object):
    def __init__(self, env=os.environ):
        self.log = log_mgr.get_logger(self)

        if 'BEAKERLIB' not in env:
            raise RuntimeError('$BEAKERLIB not set, cannot use BeakerLib')

        self.env = env
        # Set up the Bash process
        self.bash = subprocess.Popen(['bash'],
                                     stdin=subprocess.PIPE,
                                     stdout=open('/dev/null', 'w'),
                                     stderr=open('/dev/null', 'w'))
        source_path = os.path.join(self.env['BEAKERLIB'], 'beakerlib.sh')
        self.run_beakerlib_command(['.', source_path])

        # _in_class_setup is set when we are in setup_class, so logs can be
        # collected just before the first test starts
        self._in_class_setup = False

        # Redirect logging to our own handlers
        self.setup_log_handler(BeakerLibLogHandler(self.run_beakerlib_command))

    def setup_log_handler(self, handler):
        log_mgr.configure(
            {
                'default_level': 'DEBUG',
                'handlers': [{'log_handler': handler,
                              'format': '[%(name)s] %(message)s',
                              'level': 'info'}]},
            configure_state='beakerlib_plugin')

    def run_beakerlib_command(self, cmd):
        """Given a command as a Popen-style list, run it in the Bash process"""
        if not self.bash:
            return
        for word in cmd:
            self.bash.stdin.write(ipautil.shell_quote(word))
            self.bash.stdin.write(' ')
        self.bash.stdin.write('\n')
        self.bash.stdin.flush()
        assert self.bash.returncode is None, "BeakerLib Bash process exited"

    def log_links(self, docstring):
        for match in LINK_RE.finditer(docstring or ''):
            self.log.info('Link: %s', match.group())

    def end(self):
        """End the Bash process"""
        self.run_beakerlib_command(['exit'])
        bash = self.bash
        self.bash = None
        bash.communicate()

    def collect_logs(self, logs_to_collect):
        """Collect specified logs"""
        for host, logs in logs_to_collect.items():
            self.log.info('Collecting logs from: %s', host.hostname)

            # Tar up the logs on the remote server
            cmd = host.run_command(['tar', 'cJv'] + logs, log_stdout=False,
                                    raiseonerr=False)
            if cmd.returncode:
                self.run_beakerlib_command(
                    ['rlFail', 'Could not collect all requested logs'])

            # Copy and unpack on the local side
            topdirname = tempfile.mkdtemp()
            dirname = os.path.join(topdirname, host.hostname)
            os.mkdir(dirname)
            tarname = os.path.join(dirname, 'logs.tar.xz')
            with open(tarname, 'w') as f:
                f.write(cmd.stdout_text)
            ipautil.run(['tar', 'xJvf', 'logs.tar.xz'], cwd=dirname)
            os.unlink(tarname)

            # Use BeakerLib's rlFileSubmit on the indifidual files
            # The resulting submitted filename will be
            # $HOSTNAME-$FILENAME (with '/' replaced by '-')
            self.run_beakerlib_command(['pushd', topdirname])
            for dirpath, dirnames, filenames in os.walk(topdirname):
                for filename in filenames:
                    fullname = os.path.relpath(
                        os.path.join(dirpath, filename), topdirname)
                    self.log.debug('Submitting file: %s', fullname)
                    self.run_beakerlib_command(['rlFileSubmit', fullname])
            self.run_beakerlib_command(['popd'])

            # The BeakerLib process runs asynchronously, let it clean up
            # after it's done with the directory
            self.run_beakerlib_command(['rm', '-rvf', topdirname])

        logs_to_collect.clear()

    def log_exception(self, err=None):
        """Log an exception

        err is a 3-tuple as returned from sys.exc_info(); if not given,
        sys.exc_info() is used.
        """
        if err is None:
            err = sys.exc_info()
        message = ''.join(traceback.format_exception(*err)).rstrip()
        self.run_beakerlib_command(['rlLogError', message])


class BeakerLibPlugin(Plugin):
    """A Nose plugin that integrates with BeakerLib"""
    # Since BeakerLib is a Bash library, we need to run it in Bash.
    # The plugin maintains a Bash process and feeds it with commands
    # on events like test start/end, logging, etc.
    # See nose.plugins.base.IPluginInterface for Nose plugin interface docs
    name = 'beakerlib'

    def __init__(self):
        super(BeakerLibPlugin, self).__init__()
        self.log = log_mgr.get_logger(self)
        self._in_class_setup = False

    def options(self, parser, env=os.environ):
        super(BeakerLibPlugin, self).options(parser, env=env)
        self.env = env
        self.parser = parser

    def configure(self, options, conf):
        super(BeakerLibPlugin, self).configure(options, conf)
        if not self.enabled:
            return

        if 'BEAKERLIB' not in self.env:
            self.parser.error(
                '$BEAKERLIB not set, cannot use --with-beakerlib')

        self.process = BeakerLibProcess(env=self.env)

    def run_beakerlib_command(self, cmd):
        """Given a command as a Popen-style list, run it in the Bash process"""
        self.process.run_beakerlib_command(cmd)

    def report(self, stream):
        self.process.end()

    def log_exception(self, err):
        self.process.log_exception(err)

    def log_links(self, docstring):
        self.process.log_links(docstring)

    def startContext(self, context):
        """Start a test context (module, class)

        For test classes, this starts a BeakerLib phase
        """
        if not isinstance(context, type):
            return
        try:
            docstring = context.__doc__
            caption = docstring.strip().partition('\n')[0]
        except AttributeError:
            docstring = ''
            caption = 'Nose class (no docstring)'
        phase_name = "%s-%s: %s" % (context.__module__.replace('.', '-'),
                                    context.__name__, caption)
        self.run_beakerlib_command(['rlPhaseStart', 'FAIL', phase_name])
        self._in_class_setup = True
        self.log_links(docstring)

    def stopContext(self, context):
        """End a test context"""
        if not isinstance(context, type):
            return
        self.collect_logs(context)
        self.run_beakerlib_command(['rlPhaseEnd'])

    def startTest(self, test):
        """Start a test phase"""
        if self._in_class_setup:
            self.collect_logs(test.context)
        self.log.info('Running test: %s', test.id())
        caption = test.shortDescription()
        if not caption:
            caption = 'Nose method (no docstring)'
        phase_name = "%s: %s" % (test.id().replace('.', '-'), caption)
        self.run_beakerlib_command(['rlPhaseStart', 'FAIL', phase_name])

        while hasattr(test, 'test'):
            # Un-wrap Nose test cases to get at the actual test method
            test = test.test
        self.log_links(getattr(test, '__doc__', ''))

    def stopTest(self, test):
        """End a test phase"""
        self.collect_logs(test.context)
        self.run_beakerlib_command(['rlPhaseEnd'])

    def addSuccess(self, test):
        self.run_beakerlib_command(['rlPass', 'Test succeeded'])

    def addError(self, test, err):
        if issubclass(err[0], nose.SkipTest):
            # Log skipped test.
            # Unfortunately we only get to see this if the built-in skip
            # plugin is disabled (--no-skip)
            self.run_beakerlib_command(['rlPass', 'Test skipped: %s' % err[1]])
        else:
            self.log_exception(err)
            self.run_beakerlib_command(
                ['rlFail', 'Test failed: unhandled exception'])
        self.collect_logs(test.context)

    def addFailure(self, test, err):
        self.log_exception(err)
        self.run_beakerlib_command(['rlFail', 'Test failed'])

    def collect_logs(self, test):
        """Collect logs specified in test's logs_to_collect attribute
        """
        try:
            logs_to_collect = test.logs_to_collect
        except AttributeError:
            self.log.debug('No logs to collect')
        else:
            self.process.collect_logs(logs_to_collect)
