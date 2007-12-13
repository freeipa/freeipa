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
from ipa import ipautil


def stop(service_name):
    ipautil.run(["/sbin/service", service_name, "stop"])

def start(service_name):
    ipautil.run(["/sbin/service", service_name, "start"])

def restart(service_name):
    ipautil.run(["/sbin/service", service_name, "restart"])
    
def chkconfig_on(service_name):
    ipautil.run(["/sbin/chkconfig", service_name, "on"])

def chkconfig_off(service_name):
    ipautil.run(["/sbin/chkconfig", service_name, "off"])
    
def print_msg(message, output_fd=sys.stdout):
    logging.debug(message)
    output_fd.write(message)
    output_fd.write("\n")
    

class Service:
    def __init__(self, service_name):
        self.service_name = service_name
        self.num_steps = -1
        self.current_step = -1
        self.output_fd = sys.stdout

    def set_output(self, fd):
        self.output_fd = fd
        
    def stop(self):
        stop(self.service_name)

    def start(self):
        start(self.service_name)

    def restart(self):
        restart(self.service_name)

    def chkconfig_on(self):
        chkconfig_on(self.service_name)

    def chkconfig_off(self):
        chkconfig_off(self.service_name)

    def print_msg(self, message):
        print_msg(message, self.output_fd)
        
    def start_creation(self, num_steps, message):
        self.num_steps = num_steps
        self.cur_step = 0
        self.print_msg(message)

    def step(self, message):
        self.cur_step += 1
        self.print_msg("  [%d/%d]: %s" % (self.cur_step, self.num_steps, message))

    def done_creation(self):
        self.cur_step = -1
        self.num_steps = -1
        self.print_msg("done configuring %s." % self.service_name)

