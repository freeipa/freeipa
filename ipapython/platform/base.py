# Authors: Alexander Bokovoy <abokovoy@redhat.com>
#
# Copyright (C) 2011  Red Hat
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

from ipalib.plugable import MagicDict

# Canonical names of services as IPA wants to see them. As we need to have
# *some* naming, set them as in Red Hat distributions. Actual implementation
# should make them available through knownservices.<name> and take care of
# re-mapping internally, if needed
wellknownservices = ['certmonger', 'dirsrv', 'httpd', 'ipa', 'krb5kdc',
                     'messagebus', 'nslcd', 'nscd', 'ntpd', 'portmap',
                     'rpcbind', 'kadmin', 'sshd', 'autofs', 'rpcgssd',
                     'rpcidmapd', 'pki_tomcatd', 'pki-cad']


# The common ports for these services. This is used to wait for the
# service to become available.
wellknownports = {
    'dirsrv@PKI-IPA.service': [7389],
    'PKI-IPA': [7389],
    'dirsrv': [389], # this is only used if the incoming instance name is blank
    'pki-cad': [9180, 9443, 9444],
    'pki-tomcatd@pki-tomcat.service': [8080, 8443],
    'pki-tomcat': [8080, 8443],
    'pki-tomcatd': [8080, 8443],  # used if the incoming instance name is blank
}

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
    by inheriting from platform.AuthConfig and redefining __build_args()
    and execute() methods.

    from ipapython.platform import platform
    class PlatformAuthConfig(platform.AuthConfig):
        def __build_args():
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
    auth_config.disable("ldap").\
                disable("krb5").\
                disable("sssd").\
                disable("sssdauth").\
                disable("mkhomedir").\
                add_option("update").\
                enable("nis").\
                add_parameter("nisdomain","foobar")
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

    def __build_args(self):
        # do nothing
        return None

    def execute(self):
        # do nothing
        return None

    def reset(self):
        self.parameters = {}
        return self

class PlatformService(object):
    """
    PlatformService abstracts out external process running on the system
    which is possible to administer (start, stop, check status, etc).

    """

    def __init__(self, service_name):
        self.service_name = service_name

    def start(self, instance_name="", capture_output=True, wait=True):
        return

    def stop(self, instance_name="", capture_output=True):
        return

    def restart(self, instance_name="", capture_output=True, wait=True):
        return

    def is_running(self, instance_name=""):
        return False

    def is_installed(self):
        return False

    def is_enabled(self, instance_name=""):
        return False

    def enable(self, instance_name=""):
        return

    def disable(self, instance_name=""):
        return

    def install(self, instance_name=""):
        return

    def remove(self, instance_name=""):
        return

    def get_config_dir(self, instance_name=""):
        return

class KnownServices(MagicDict):
    """
    KnownServices is an abstract class factory that should give out instances
    of well-known platform services. Actual implementation must create these
    instances as its own attributes on first access (or instance creation)
    and cache them.
    """

