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

"""Provides command-line options for very limited Nose compatibility"""

import os
import sys
import logging

from ipapython.ipa_log_manager import Formatter, convert_log_level


def pytest_addoption(parser):
    group = parser.getgroup("IPA nosetests compatibility shim")

    group.addoption('--with-xunit', action="store_const",
           dest="xmlpath", metavar="path",  default=None,
           const=os.environ.get('IPATEST_XUNIT_PATH', './nosetests.xml'),
           help="create junit-xml style report file at $IPATEST_XUNIT_PATH,"
                "or nosetests.xml by default")

    group.addoption('--logging-level', action="store",
           dest="logging_level", metavar="level", default='CRITICAL',
           help="level for logging to stderr. "
                "Bypasses pytest logging redirection."
                "May be used to show progress of long-running tests.")


def pytest_configure(config):
    if config.getoption('logging_level'):
        # Forward IPA logging to a normal Python logger. Nose's logcapture plugin
        # can't work with IPA-managed loggers
        class LogHandler(logging.Handler):
            name = 'forwarding log handler'
            logger = logging.getLogger('IPA')

            def emit(self, record):
                capture = config.pluginmanager.getplugin('capturemanager')
                orig_stdout, orig_stderr = sys.stdout, sys.stderr
                if capture:
                    # pylint: disable=no-member
                    if hasattr(capture, 'suspend_global_capture'):
                        # pytest >= 3.3
                        capture.suspend_global_capture()
                    else:
                        # legacy support for pytest <= 3.2 (Fedora 27)
                        capture._capturing.suspend_capturing()
                    # pylint: enable=no-member
                sys.stderr.write(self.format(record))
                sys.stderr.write('\n')
                if capture:
                    # pylint: disable=no-member
                    if hasattr(capture, 'resume_global_capture'):
                        capture.resume_global_capture()
                    else:
                        capture._capturing.resume_capturing()
                    # pylint: enable=no-member
                sys.stdout, sys.stderr = orig_stdout, orig_stderr

        level = convert_log_level(config.getoption('logging_level'))

        handler = LogHandler()
        handler.setFormatter(Formatter('[%(name)s] %(message)s'))
        handler.setLevel(level)
        root_logger = logging.getLogger()
        root_logger.addHandler(handler)
