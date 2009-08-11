# Authors: Karl MacMillan <kmacmillan@redhat.com>
#
# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
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

import logging

import service
from ipapython import sysrestore
from ipapython import ipautil

class NTPInstance(service.Service):
    def __init__(self, fstore=None):
        service.Service.__init__(self, "ntpd")

        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore('/var/lib/ipa/sysrestore')

    def __write_config(self):
        # The template sets the config to point towards ntp.pool.org, but
        # they request that software not point towards the default pool.
        # We use the OS variable to point it towards either the rhel
        # or fedora pools. Other distros should be added in the future
        # or we can get our own pool.
        os = ""
        if ipautil.file_exists("/etc/fedora-release"):
            os = "fedora"
        elif ipautil.file_exists("/etc/redhat-release"):
            os = "rhel"

        sub_dict = { }
        sub_dict["SERVERA"] = "0.%s.pool.ntp.org" % os
        sub_dict["SERVERB"] = "1.%s.pool.ntp.org" % os
        sub_dict["SERVERC"] = "2.%s.pool.ntp.org" % os

        ntp_conf = ipautil.template_file(ipautil.SHARE_DIR + "ntp.conf.server.template", sub_dict)
        ntp_sysconf = ipautil.template_file(ipautil.SHARE_DIR + "ntpd.sysconfig.template", {})

        self.fstore.backup_file("/etc/ntp.conf")
        self.fstore.backup_file("/etc/sysconfig/ntpd")

        fd = open("/etc/ntp.conf", "w")
        fd.write(ntp_conf)
        fd.close()

        fd = open("/etc/sysconfig/ntpd", "w")
        fd.write(ntp_sysconf)
        fd.close()

    def __stop(self):
        self.backup_state("running", self.is_running())
        self.stop()

    def __start(self):
        self.start()

    def __enable(self):
        self.backup_state("enabled", self.is_enabled())
        self.chkconfig_on()

    def create_instance(self):

        # we might consider setting the date manually using ntpd -qg in case
        # the current time is very far off.

        self.step("stopping ntpd", self.__stop)
        self.step("writing configuration", self.__write_config)
        self.step("configuring ntpd to start on boot", self.__enable)
        self.step("starting ntpd", self.__start)

        self.start_creation("Configuring ntpd")

    def uninstall(self):
        running = self.restore_state("running")
        enabled = self.restore_state("enabled")

        if not running is None:
            self.stop()

        try:
	    self.fstore.restore_file("/etc/ntp.conf")
        except ValueError, error:
            logging.debug(error)
            pass

        if not enabled is None and not enabled:
            self.chkconfig_off()

        if not running is None and running:
            self.start()
