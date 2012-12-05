# Authors: Simo Sorce <ssorce@redhat.com>
#          Alexander Bokovoy <abokovoy@redhat.com>
#
# Copyright (C) 2007-2011   Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from ipapython import ipautil
from ipapython.platform import base

class RedHatAuthConfig(base.AuthConfig):
    """
    AuthConfig class implements system-independent interface to configure
    system authentication resources. In Red Hat-produced systems this is done with
    authconfig(8) utility.
    """
    def __build_args(self):
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
                args.append("--%s%s" % (option,value))
        return args

    def execute(self):
        args = self.__build_args()
        ipautil.run(["/usr/sbin/authconfig"]+args)
