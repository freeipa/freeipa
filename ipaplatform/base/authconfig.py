# Authors:
#   Alexander Bokovoy <abokovoy@redhat.com>
#   Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2011-2014  Red Hat
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


class AuthConfig(object):
    """
    AuthConfig class implements system-independent interface to configure
    system authentication resources. In Red Hat systems this is done with
    authconfig(8) utility.

    AuthConfig class is nothing more than a tool to gather configuration
    options and execute their processing. These options then converted by
    an actual implementation to series of a system calls to appropriate
    utilities performing real configuration.

    IPA *expects* names of AuthConfig's options to follow authconfig(8)
    naming scheme!

    Actual implementation should be done in ipapython/platform/<platform>.py
    by inheriting from platform.AuthConfig and redefining build_args()
    and execute() methods.

    from ipapython.platform import platform
    class PlatformAuthConfig(platform.AuthConfig):
        def build_args():
        ...

        def execute():
        ...

    authconfig = PlatformAuthConfig
    ....

    See ipapython/platform/redhat.py for a sample implementation that uses
    authconfig(8) as its backend.

    From IPA code perspective, the authentication configuration should be
    done with use of ipapython.services.authconfig:

    from ipapython import services as ipaservices
    auth_config = ipaservices.authconfig()
    auth_config.disable("ldap")
    auth_config.disable("krb5")
    auth_config.disable("sssd")
    auth_config.disable("sssdauth")
    auth_config.disable("mkhomedir")
    auth_config.add_option("update")
    auth_config.enable("nis")
    auth_config.add_parameter("nisdomain","foobar")
    auth_config.execute()

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

    def build_args(self):
        # do nothing
        return None

    def execute(self):
        # do nothing
        return None

    def reset(self):
        self.parameters = {}
        return self
