# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#
# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 or later
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import logging, sys
import sysrestore
from ipa import ipautil


def stop(service_name):
    ipautil.run(["/sbin/service", service_name, "stop"])

def start(service_name):
    ipautil.run(["/sbin/service", service_name, "start"])

def restart(service_name):
    ipautil.run(["/sbin/service", service_name, "restart"])
    
def is_running(service_name):
    ret = True
    try:
        ipautil.run(["/sbin/service", service_name, "status"])
    except ipautil.CalledProcessError:
        ret = False
    return ret
    
def chkconfig_on(service_name):
    ipautil.run(["/sbin/chkconfig", service_name, "on"])

def chkconfig_off(service_name):
    ipautil.run(["/sbin/chkconfig", service_name, "off"])

def is_enabled(service_name):
    (stdout, stderr) = ipautil.run(["/sbin/chkconfig", "--list", service_name])

    runlevels = {}
    for runlevel in range(0, 7):
        runlevels[runlevel] = False

    for line in stdout.split("\n"):
        parts = line.split()
        if parts[0] == service_name:
            for s in parts[1:]:
                (runlevel, status) = s.split(":")[0:2]
                try:
                    runlevels[int(runlevel)] = status == "on"
                except ValueError:
                    pass
            break

    return (runlevels[3] and runlevels[4] and runlevels[5])
    
def print_msg(message, output_fd=sys.stdout):
    logging.debug(message)
    output_fd.write(message)
    output_fd.write("\n")
    

class Service:
    def __init__(self, service_name):
        self.service_name = service_name
        self.steps = []
        self.output_fd = sys.stdout

    def set_output(self, fd):
        self.output_fd = fd
        
    def stop(self):
        stop(self.service_name)

    def start(self):
        start(self.service_name)

    def restart(self):
        restart(self.service_name)

    def is_running(self):
        return is_running(self.service_name)

    def chkconfig_on(self):
        chkconfig_on(self.service_name)

    def chkconfig_off(self):
        chkconfig_off(self.service_name)

    def is_enabled(self):
        return is_enabled(self.service_name)

    def backup_state(self, key, value):
        sysrestore.backup_state(self.service_name, key, value)

    def restore_state(self, key):
        return sysrestore.restore_state(self.service_name, key)

    def print_msg(self, message):
        print_msg(message, self.output_fd)

    def step(self, message, method):
        self.steps.append((message, method))

    def start_creation(self, message):
        self.print_msg(message)

        step = 0
        for (message, method) in self.steps:
            self.print_msg("  [%d/%d]: %s" % (step+1, len(self.steps)+1, message))
            method()
            step += 1
        
        self.print_msg("done configuring %s." % self.service_name)

        self.steps = []

class SimpleServiceInstance(Service):
    def create_instance(self):
        self.step("starting %s " % self.service_name, self.__start)
        self.step("configuring %s to start on boot" % self.service_name, self.__enable)
        self.start_creation("Configuring %s" % self.service_name)

    def __start(self):
        self.backup_state("running", self.is_running())
        self.restart()

    def __enable(self):
        self.backup_state("enabled", self.is_enabled())
        self.chkconfig_on()

    def uninstall(self):
        running = self.restore_state("running")
        enabled = not self.restore_state("enabled")

        if not running is None and not running:
            self.stop()
        if not enabled is None and not enabled:
            self.chkconfig_off()
