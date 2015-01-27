# Authors: Karl MacMillan <kmacmillan@redhat.com>
# Authors: Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2007-2010  Red Hat
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
#

import service
from ipapython import sysrestore
from ipapython import ipautil
from ipaplatform.paths import paths
from ipapython.ipa_log_manager import *

class NTPInstance(service.Service):
    def __init__(self, fstore=None):
        service.Service.__init__(self, "ntpd", service_desc="NTP daemon")

        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore(paths.SYSRESTORE)

    def __write_config(self):

        self.fstore.backup_file(paths.NTP_CONF)
        self.fstore.backup_file(paths.SYSCONFIG_NTPD)

        # We use the OS variable to point it towards either the rhel
        # or fedora pools. Other distros should be added in the future
        # or we can get our own pool.
        os = ""
        if ipautil.file_exists(paths.ETC_FEDORA_RELEASE):
            os = "fedora"
        elif ipautil.file_exists(paths.ETC_REDHAT_RELEASE):
            os = "rhel"

        srv_vals = []
        srv_vals.append("0.%s.pool.ntp.org" % os)
        srv_vals.append("1.%s.pool.ntp.org" % os)
        srv_vals.append("2.%s.pool.ntp.org" % os)
        srv_vals.append("3.%s.pool.ntp.org" % os)
        srv_vals.append("127.127.1.0")
        fudge = ["fudge", "127.127.1.0", "stratum", "10"]

        #read in memory, change it, then overwrite file
        file_changed = False
        fudge_present = False
        ntpconf = []
        fd = open(paths.NTP_CONF, "r")
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
            fd = open(paths.NTP_CONF, "w")
            for line in ntpconf:
                fd.write(line)
            fd.write("\n### Added by IPA Installer ###\n")
            if len(srv_vals) != 0:
                for srv in srv_vals:
                    fd.write("server "+srv+" iburst\n")
            if not fudge_present:
                fd.write("fudge 127.127.1.0 stratum 10\n")
            fd.close()

        #read in memory, find OPTIONS, check/change it, then overwrite file
        needopts = [ {'val':'-x', 'need':True},
                     {'val':'-g', 'need':True} ]
        fd = open(paths.SYSCONFIG_NTPD, "r")
        lines = fd.readlines()
        fd.close()
        for line in lines:
            sline = line.strip()
            if not sline.startswith('OPTIONS'):
                continue
            sline = sline.replace('"', '')
            for opt in needopts:
                if sline.find(opt['val']) != -1:
                    opt['need'] = False

        newopts = []
        for opt in needopts:
            if opt['need']:
                newopts.append(opt['val'])

        done = False
        if newopts:
            fd = open(paths.SYSCONFIG_NTPD, "w")
            for line in lines:
                if not done:
                    sline = line.strip()
                    if not sline.startswith('OPTIONS'):
                        fd.write(line)
                        continue
                    sline = sline.replace('"', '')
                    (variable, opts) = sline.split('=', 1)
                    fd.write('OPTIONS="%s %s"\n' % (opts, ' '.join(newopts)))
                    done = True
                else:
                    fd.write(line)
            fd.close()

    def __stop(self):
        self.backup_state("running", self.is_running())
        self.stop()

    def __start(self):
        self.start()

    def __enable(self):
        self.backup_state("enabled", self.is_enabled())
        self.enable()

    def create_instance(self):

        # we might consider setting the date manually using ntpd -qg in case
        # the current time is very far off.

        self.step("stopping ntpd", self.__stop)
        self.step("writing configuration", self.__write_config)
        self.step("configuring ntpd to start on boot", self.__enable)
        self.step("starting ntpd", self.__start)

        self.start_creation()

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring %s" % self.service_name)

        running = self.restore_state("running")
        enabled = self.restore_state("enabled")

        # service is not in LDAP, stop and disable service
        # before restoring configuration
        self.stop()
        self.disable()

        try:
            self.fstore.restore_file(paths.NTP_CONF)
        except ValueError, error:
            root_logger.debug(error)
            pass

        if enabled:
            self.enable()

        if running:
            self.restart()
