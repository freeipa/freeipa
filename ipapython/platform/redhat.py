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

import tempfile
import re
import os
import stat
import sys
from ipapython import ipautil
from ipapython.platform import base

# All what we allow exporting directly from this module
# Everything else is made available through these symbols when they directly imported into ipapython.services:
# authconfig -- class reference for platform-specific implementation of authconfig(8)
# service    -- class reference for platform-specific implementation of a PlatformService class
# knownservices -- factory instance to access named services IPA cares about, names are ipapython.services.wellknownservices
# backup_and_replace_hostname -- platform-specific way to set hostname and make it persistent over reboots
# restore_context -- platform-sepcific way to restore security context, if applicable
__all__ = ['authconfig', 'service', 'knownservices', 'backup_and_replace_hostname', 'restore_context']

class RedHatService(base.PlatformService):
    def stop(self, instance_name="", capture_output=True):
        ipautil.run(["/sbin/service", self.service_name, "stop", instance_name], capture_output=capture_output)

    def start(self, instance_name="", capture_output=True):
        ipautil.run(["/sbin/service", self.service_name, "start", instance_name], capture_output=capture_output)

    def restart(self, instance_name="", capture_output=True):
        ipautil.run(["/sbin/service", self.service_name, "restart", instance_name], capture_output=capture_output)

    def is_running(self, instance_name=""):
        ret = True
        try:
            (sout,serr,rcode) = ipautil.run(["/sbin/service", self.service_name, "status", instance_name])
            if sout.find("is stopped") >= 0:
                ret = False
        except ipautil.CalledProcessError:
                ret = False
        return ret

    def is_installed(self):
        installed = True
        try:
            ipautil.run(["/sbin/service", self.service_name, "status"])
        except ipautil.CalledProcessError, e:
            if e.returncode == 1:
                # service is not installed or there is other serious issue
                installed = False
        return installed

    def is_enabled(self):
        (stdout, stderr, returncode) = ipautil.run(["/sbin/chkconfig", self.service_name],raiseonerr=False)
        return (returncode == 0)

    def enable(self):
        ipautil.run(["/sbin/chkconfig", self.service_name, "on"])

    def disable(self):
        ipautil.run(["/sbin/chkconfig", self.service_name, "off"])

    def install(self):
        ipautil.run(["/sbin/chkconfig", "--add", self.service_name])

    def remove(self):
        ipautil.run(["/sbin/chkconfig", "--del", self.service_name])

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

class RedHatServices(base.KnownServices):
    def __init__(self):
        services = dict()
        for s in base.wellknownservices:
            services[s] = RedHatService(s)
        # Call base class constructor. This will lock services to read-only
        super(RedHatServices, self).__init__(services)

authconfig = RedHatAuthConfig
service = RedHatService
knownservices = RedHatServices()

def restore_context(filepath):
    """
    restore security context on the file path
    SE Linux equivalent is /sbin/restorecon <filepath>
    """
    ipautil.run(["/sbin/restorecon", filepath])


def backup_and_replace_hostname(fstore, statestore, hostname):
    network_filename = "/etc/sysconfig/network"
    # Backup original /etc/sysconfig/network
    fstore.backup_file(network_filename)
    hostname_pattern = re.compile('''
(^
                        \s*
        (?P<option>     [^\#;]+?)
                        (\s*=\s*)
        (?P<value>      .+?)?
                        (\s*((\#|;).*)?)?
$)''', re.VERBOSE)
    temp_filename = None
    with tempfile.NamedTemporaryFile(delete=False) as new_config:
        temp_filename = new_config.name
        with open(network_filename, 'r') as f:
            for line in f:
                new_line = line
                m = hostname_pattern.match(line)
                if m:
                    option, value = m.group('option', 'value')
                    if option is not None and option == 'HOSTNAME':
                        if value is not None and hostname != value:
                            new_line = u"HOSTNAME=%s\n" % (hostname)
                            statestore.backup_state('network', 'hostname', value)
                new_config.write(new_line)
        new_config.flush()
        # Make sure the resulting file is readable by others before installing it
        os.fchmod(new_config.fileno(), stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        os.fchown(new_config.fileno(), 0, 0)

    # At this point new_config is closed but not removed due to 'delete=False' above
    # Now, install the temporary file as configuration and ensure old version is available as .orig
    # While .orig file is not used during uninstall, it is left there for administrator.
    ipautil.install_file(temp_filename, network_filename)
    try:
        ipautil.run(['/bin/hostname', hostname])
    except ipautil.CalledProcessError, e:
        print >>sys.stderr, "Failed to set this machine hostname to %s (%s)." % (hostname, str(e))

    # For SE Linux environments it is important to reset SE labels to the expected ones
    try:
        restore_context(network_filename)
    except ipautil.CalledProcessError, e:
        print >>sys.stderr, "Failed to set permissions for %s (%s)." % (network_filename, str(e))

