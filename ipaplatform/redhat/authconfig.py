# Authors: Simo Sorce <ssorce@redhat.com>
#          Alexander Bokovoy <abokovoy@redhat.com>
#          Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2007-2014  Red Hat
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

from __future__ import absolute_import

from ipaplatform.paths import paths
from ipapython import ipautil
from ipapython.admintool import ScriptError
import os

FILES_TO_NOT_BACKUP = ['passwd', 'group', 'shadow', 'gshadow']


class RedHatAuthConfig(object):
    """
    AuthConfig class implements system-independent interface to configure
    system authentication resources. In Red Hat systems this is done with
    authconfig(8) utility.

    AuthConfig class is nothing more than a tool to gather configuration
    options and execute their processing. These options then converted by
    an actual implementation to series of a system calls to appropriate
    utilities performing real configuration.

    If you need to re-use existing AuthConfig instance for multiple runs,
    make sure to call 'AuthConfig.reset()' between the runs.
    """

    def __init__(self):
        self.parameters = {}

    def enable(self, option):
        self.parameters[option] = True
        return self

    def disable(self, option):
        self.parameters[option] = False
        return self

    def add_option(self, option):
        self.parameters[option] = None
        return self

    def add_parameter(self, option, value):
        self.parameters[option] = [value]
        return self

    def reset(self):
        self.parameters = {}
        return self

    def build_args(self):
        args = []

        for (option, value) in self.parameters.items():
            if type(value) is bool:
                if value:
                    args.append("--enable%s" % (option))
                else:
                    args.append("--disable%s" % (option))
            elif type(value) in (tuple, list):
                args.append("--%s" % (option))
                args.append("%s" % (value[0]))
            elif value is None:
                args.append("--%s" % (option))
            else:
                args.append("--%s%s" % (option, value))

        return args

    def execute(self, update=True):
        if update:
            self.add_option("update")

        args = self.build_args()
        try:
            ipautil.run([paths.AUTHCONFIG] + args)
        except ipautil.CalledProcessError:
            raise ScriptError("Failed to execute authconfig command")

    def backup(self, path):
        try:
            ipautil.run([paths.AUTHCONFIG, "--savebackup", path])
        except ipautil.CalledProcessError:
            raise ScriptError("Failed to execute authconfig command")

        # do not backup these files since we don't want to mess with
        # users/groups during restore. Authconfig doesn't seem to mind about
        # having them deleted from backup dir
        files_to_remove = [os.path.join(path, f) for f in FILES_TO_NOT_BACKUP]
        for filename in files_to_remove:
            try:
                os.remove(filename)
            except OSError:
                pass

    def restore(self, path):
        try:
            ipautil.run([paths.AUTHCONFIG, "--restorebackup", path])
        except ipautil.CalledProcessError:
            raise ScriptError("Failed to execute authconfig command")
