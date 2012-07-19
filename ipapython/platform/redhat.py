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
import socket
import stat

from ipapython import ipautil
from ipapython.platform import base
from ipalib import api

# All what we allow exporting directly from this module
# Everything else is made available through these symbols when they are
# directly imported into ipapython.services:
#
# authconfig -- class reference for platform-specific implementation of
#               authconfig(8)
# service    -- class reference for platform-specific implementation of a
#               PlatformService class
# knownservices -- factory instance to access named services IPA cares about,
#                  names are ipapython.services.wellknownservices
# backup_and_replace_hostname -- platform-specific way to set hostname and
#                                make it persistent over reboots
# restore_context -- platform-sepcific way to restore security context, if
#                    applicable
# check_selinux_status -- platform-specific way to see if SELinux is enabled
#                         and restorecon is installed.
__all__ = ['authconfig', 'service', 'knownservices', 'backup_and_replace_hostname', 'restore_context', 'check_selinux_status']

class RedHatService(base.PlatformService):
    def __wait_for_open_ports(self, instance_name=""):
        """
        If this is a service we need to wait for do so.
        """
        ports = None
        if instance_name in base.wellknownports:
            ports = base.wellknownports[instance_name]
        else:
            if self.service_name in base.wellknownports:
                ports = base.wellknownports[self.service_name]
        if ports:
            ipautil.wait_for_open_ports('localhost', ports, api.env.startup_timeout)

    def stop(self, instance_name="", capture_output=True):
        ipautil.run(["/sbin/service", self.service_name, "stop", instance_name], capture_output=capture_output)

    def start(self, instance_name="", capture_output=True, wait=True):
        ipautil.run(["/sbin/service", self.service_name, "start", instance_name], capture_output=capture_output)
        if wait and self.is_running(instance_name):
            self.__wait_for_open_ports(instance_name)

    def restart(self, instance_name="", capture_output=True, wait=True):
        ipautil.run(["/sbin/service", self.service_name, "restart", instance_name], capture_output=capture_output)
        if wait and self.is_running(instance_name):
            self.__wait_for_open_ports(instance_name)

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

    def is_enabled(self, instance_name=""):
        (stdout, stderr, returncode) = ipautil.run(["/sbin/chkconfig", self.service_name],raiseonerr=False)
        return (returncode == 0)

    def enable(self, instance_name=""):
        ipautil.run(["/sbin/chkconfig", self.service_name, "on"])

    def disable(self, instance_name=""):
        ipautil.run(["/sbin/chkconfig", self.service_name, "off"])

    def install(self, instance_name=""):
        ipautil.run(["/sbin/chkconfig", "--add", self.service_name])

    def remove(self, instance_name=""):
        ipautil.run(["/sbin/chkconfig", "--del", self.service_name])

class RedHatSSHService(RedHatService):
    def get_config_dir(self, instance_name=""):
        return '/etc/ssh'

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

def redhat_service(name):
    if name == 'sshd':
        return RedHatSSHService(name)
    return RedHatService(name)

class RedHatServices(base.KnownServices):
    def __init__(self):
        services = dict()
        for s in base.wellknownservices:
            services[s] = redhat_service(s)
        # Call base class constructor. This will lock services to read-only
        super(RedHatServices, self).__init__(services)

authconfig = RedHatAuthConfig
service = redhat_service
knownservices = RedHatServices()

def restore_context(filepath, restorecon='/sbin/restorecon'):
    """
    restore security context on the file path
    SELinux equivalent is /path/to/restorecon <filepath>

    restorecon's return values are not reliable so we have to
    ignore them (BZ #739604).

    ipautil.run() will do the logging.
    """
    try:
        if (os.path.exists('/usr/sbin/selinuxenabled')):
            ipautil.run(["/usr/sbin/selinuxenabled"])
        else:
            # No selinuxenabled, no SELinux
            return
    except ipautil.CalledProcessError:
        # selinuxenabled returns 1 if not enabled
        return

    if (os.path.exists(restorecon)):
        ipautil.run([restorecon, filepath], raiseonerr=False)

def backup_and_replace_hostname(fstore, statestore, hostname):
    old_hostname = socket.gethostname()
    try:
        ipautil.run(['/bin/hostname', hostname])
    except ipautil.CalledProcessError, e:
        print >>sys.stderr, "Failed to set this machine hostname to %s (%s)." % (hostname, str(e))
    replacevars = {'HOSTNAME':hostname}

    filepath = '/etc/sysconfig/network'
    if not os.path.exists(filepath):
        # file doesn't exist; create it with correct ownership & mode
        open(filepath, 'a').close()
        os.chmod(filepath,
            stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        os.chown(filepath, 0, 0)
    old_values = ipautil.backup_config_and_replace_variables(
        fstore, filepath, replacevars=replacevars)
    restore_context("/etc/sysconfig/network")

    if 'HOSTNAME' in old_values:
        statestore.backup_state('network', 'hostname', old_values['HOSTNAME'])
    else:
        statestore.backup_state('network', 'hostname', old_hostname)

def check_selinux_status(restorecon='/sbin/restorecon'):
    """
    We don't have a specific package requirement for policycoreutils
    which provides restorecon. This is because we don't require
    SELinux on client installs. However if SELinux is enabled then
    this package is required.

    This function returns nothing but may raise a Runtime exception
    if SELinux is enabled but restorecon is not available.
    """
    try:
        if (os.path.exists('/usr/sbin/selinuxenabled')):
            ipautil.run(["/usr/sbin/selinuxenabled"])
        else:
            # No selinuxenabled, no SELinux
            return
    except ipautil.CalledProcessError:
        # selinuxenabled returns 1 if not enabled
        return

    if not os.path.exists(restorecon):
        raise RuntimeError('SELinux is enabled but %s does not exist.\nInstall the policycoreutils package and start the installation again.' % restorecon)
