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

import time

from ipapython import ipautil
from ipapython.ipa_log_manager import root_logger
from ipapython.platform import base
from ipalib import api

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
        super(RedHatService, self).stop(instance_name)

    def start(self, instance_name="", capture_output=True, wait=True):
        ipautil.run(["/sbin/service", self.service_name, "start", instance_name], capture_output=capture_output)
        if wait and self.is_running(instance_name):
            self.__wait_for_open_ports(instance_name)
        super(RedHatService, self).start(instance_name)

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

class RedHatHTTPDService(RedHatService):
    def restart(self, instance_name="", capture_output=True, wait=True):
        try:
            super(RedHatHTTPDService, self).restart(instance_name, capture_output, wait)
        except ipautil.CalledProcessError:
            # http may have issues with binding to ports, try to fallback
            # https://bugzilla.redhat.com/show_bug.cgi?id=845405
            root_logger.debug("%s restart failed, try to stop&start again", self.service_name)
            time.sleep(5)
            self.stop(instance_name, capture_output)
            time.sleep(5)
            self.start(instance_name, capture_output, wait)

def redhat_service(name):
    if name == 'sshd':
        return RedHatSSHService(name)
    elif name == 'httpd':
        return RedHatHTTPDService(name)
    return RedHatService(name)

class RedHatServices(base.KnownServices):
    def __init__(self):
        services = dict()
        for s in base.wellknownservices:
            services[s] = redhat_service(s)
        # Call base class constructor. This will lock services to read-only
        super(RedHatServices, self).__init__(services)
