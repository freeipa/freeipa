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

import nose
from nose.plugins import Plugin

from ipapython import ipautil
from ipapython.ipa_log_manager import log_mgr


def shell_quote(string):
    """Quote a string for the shell

    Adapted from Python3's shlex.quote
    """
    return "'" + str(string).replace("'", "'\"'\"'") + "'"


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


class BeakerLibPlugin(Plugin):
    """A Nose plugin that integrates with BeakerLib"""
    # Since BeakerLib is a Bash library, we need to run it in Bash.
    # The plugin maintains a Bash process and feeds it with commands
    # on events like test start/end, logging, etc.
    # See nose.plugins.base.IPluginInterface for Nose plugin interface docs
    name = 'beakerlib'

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
                'BeakerLib not active, cannot use --with-beakerlib')

        # Set up the Bash process
        self.bash = subprocess.Popen(['bash'],
                                     stdin=subprocess.PIPE)
        source_path = os.path.join(self.env['BEAKERLIB'], 'beakerlib.sh')
        self.run_beakerlib_command(['.', source_path])

        # _in_class is set when we are in setup_class, so its rlPhaseEnd can
        # be called when the first test starts
        self._in_class = False

        # Redirect logging to our own handlers
        self.setup_log_handler(BeakerLibLogHandler(self.run_beakerlib_command))

    def setup_log_handler(self, handler):
        log_mgr.configure(
            {
                'default_level': 'DEBUG',
                'handlers': [{'log_handler': handler,
                              'format': '[%(name)s] %(message)s',
                              'level': 'debug'}]},
            configure_state='beakerlib_plugin')

    def run_beakerlib_command(self, cmd):
        """Given a command as a Popen-style list, run it in the Bash process"""
        for word in cmd:
            self.bash.stdin.write(shell_quote(word))
            self.bash.stdin.write(' ')
        self.bash.stdin.write('\n')
        self.bash.stdin.flush()
        assert self.bash.returncode is None, "BeakerLib Bash process exited"

    def report(self, stream):
        """End the Bash process"""
        self.run_beakerlib_command(['exit'])
        self.bash.communicate()

    def startContext(self, context):
        """Start a test context (module, class)

        For test classes, this starts a BeakerLib phase
        """
        if not isinstance(context, type):
            return
        message = 'Class setup: %s' % context.__name__
        self.run_beakerlib_command(['rlPhaseStart', 'FAIL', message])
        self._in_class = True

    def stopContext(self, context):
        """End a test context"""
        if self._in_class:
            self.run_beakerlib_command(['rlPhaseEnd'])

    def startTest(self, test):
        """Start a test phase"""
        if self._in_class:
            self.run_beakerlib_command(['rlPhaseEnd'])
        self.run_beakerlib_command(['rlPhaseStart', 'FAIL',
                                 'Nose test: %s' % test])

    def stopTest(self, test):
        """End a test phase"""
        self.run_beakerlib_command(['rlPhaseEnd'])

    def addSuccess(self, test):
        self.run_beakerlib_command(['rlPass', 'Test succeeded'])

    def log_exception(self, err):
        """Log an exception

        err is a 3-tuple as returned from sys.exc_info()
        """
        message = ''.join(traceback.format_exception(*err)).rstrip()
        self.run_beakerlib_command(['rlLogError', message])

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

    def addFailure(self, test, err):
        self.log_exception(err)
        self.run_beakerlib_command(['rlFail', 'Test failed'])
