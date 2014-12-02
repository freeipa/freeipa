#!/usr/bin/python2
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
#

"""Test integration with BeakerLib

IPA-specific configuration for the BeakerLib plugin (from pytest-beakerlib).
If the plugin is active, sets up IPA logging to also log to Beaker.

"""

import logging

from ipapython.ipa_log_manager import log_mgr


def pytest_configure(config):
    plugin = config.pluginmanager.getplugin('BeakerLibPlugin')
    if plugin:
        handler = BeakerLibLogHandler(plugin.run_beakerlib_command)
        log_mgr.configure(
            {
                'default_level': 'DEBUG',
                'handlers': [{'log_handler': handler,
                              'format': '[%(name)s] %(message)s',
                              'level': 'info'}]},
            configure_state='beakerlib_plugin')


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
