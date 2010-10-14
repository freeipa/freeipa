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

        self.fstore.backup_file("/etc/ntp.conf")
        self.fstore.backup_file("/etc/sysconfig/ntpd")

        # We use the OS variable to point it towards either the rhel
        # or fedora pools. Other distros should be added in the future
        # or we can get our own pool.
        os = ""
        if ipautil.file_exists("/etc/fedora-release"):
            os = "fedora"
        elif ipautil.file_exists("/etc/redhat-release"):
            os = "rhel"

        srv_vals = []
        srv_vals.append("0.%s.pool.ntp.org" % os)
        srv_vals.append("1.%s.pool.ntp.org" % os)
        srv_vals.append("2.%s.pool.ntp.org" % os)
        srv_vals.append("127.127.1.0")
        fudge = ["fudge", "127.127.1.0", "stratum", "10"]

        #read in memory, change it, then overwrite file
        file_changed = False
        fudge_present = False
        ntpconf = []
        fd = open("/etc/ntp.conf", "r")
        for line in fd:
            opt = line.split()
            if len(opt) < 1:
                ntpconf.append(line)
                continue

            if opt[0] == "server":
                match = False
                for srv in srv_vals:
                    if opt[1] == srv:
                        match = True
                        break
                if match:
                    srv_vals.remove(srv)
                else:
                    file_changed = True
                    line = ""
            elif opt[0] == "fudge":
                if opt[0:4] == fudge[0:4]:
                    fudge_present = True
                else:
                    file_changed = True
                    line = ""

            ntpconf.append(line)

        if file_changed or len(srv_vals) != 0 or not fudge_present:
            fd = open("/etc/ntp.conf", "w")
            for line in ntpconf:
                fd.write(line)
            fd.write("\n### Added by IPA Installer ###\n")
            if len(srv_vals) != 0:
                for srv in srv_vals:
                    fd.write("server "+srv+"\n")
            if not fudge_present:
                fd.write("fudge 127.127.1.0 stratum 10\n")
            fd.close()

        #read in memory, find OPTIONS, check/change it, then overwrite file
        file_changed = False
        found_options = False
        ntpdsysc = []
        fd = open("/etc/sysconfig/ntpd", "r")
        for line in fd:
            sline = line.strip()
            if sline.find("OPTIONS") == 0:
                found_options = True
                opts = sline.split("=", 1)
                if len(opts) != 2:
                    optvals=""
                else:
                    optvals = opts[1].strip(' "')
                if optvals.find("-x") == -1:
                    optvals += " -x"
                    file_changed = True
                if optvals.find("-g") == -1:
                    optvals += " -g"
                    file_changed = True
                if file_changed:
                    line = 'OPTIONS="'+optvals+'"\n'
            ntpdsysc.append(line)
        fd.close()
        if not found_options:
            ntpdsysc.insert(0, 'OPTIONS="-x -g"\n')
            file_changed = True

        if file_changed:
            fd = open("/etc/sysconfig/ntpd", "w")
            for line in ntpdsysc:
                fd.write(line)
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
        if self.is_configured():
            self.print_msg("Unconfiguring %s" % self.service_name)

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
