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

import logging

from ipaserver.install import service
from ipaserver.install import sysupgrade
from ipaplatform.constants import constants
from ipaplatform.paths import paths

logger = logging.getLogger(__name__)

NTPD_OPTS_VAR = constants.NTPD_OPTS_VAR
NTPD_OPTS_QUOTE = constants.NTPD_OPTS_QUOTE

NTP_EXPOSED_IN_LDAP = 'exposed_in_ldap'


def ntp_ldap_enable(fqdn, base_dn, realm):
    ntp = NTPInstance(realm=realm)
    is_exposed_in_ldap = sysupgrade.get_upgrade_state(
        'ntp', NTP_EXPOSED_IN_LDAP)

    was_running = ntp.is_running()

    if ntp.is_configured() and not is_exposed_in_ldap:
        ntp.ldap_enable('NTP', fqdn, None, base_dn)
        sysupgrade.set_upgrade_state('ntp', NTP_EXPOSED_IN_LDAP, True)

        if was_running:
            ntp.start()


class NTPInstance(service.Service):
    def __init__(self, realm=None, fstore=None):
        super(NTPInstance, self).__init__(
            "ntpd",
            service_desc="NTP daemon",
            realm_name=realm,
            fstore=fstore
        )

    def __write_config(self):

        self.fstore.backup_file(paths.NTP_CONF)
        self.fstore.backup_file(paths.SYSCONFIG_NTPD)

        local_srv = "127.127.1.0"
        fudge = ["fudge", "127.127.1.0", "stratum", "10"]

        #read in memory, change it, then overwrite file
        ntpconf = []
        fd = open(paths.NTP_CONF, "r")
        for line in fd:
            opt = line.split()
            if len(opt) < 2:
                ntpconf.append(line)
                continue

            if opt[0] == "server" and opt[1] == local_srv:
                line = ""
            elif opt[0] == "fudge":
                line = ""

            ntpconf.append(line)

        with open(paths.NTP_CONF, "w") as fd:
            for line in ntpconf:
                fd.write(line)
            fd.write("\n### Added by IPA Installer ###\n")
            fd.write("server {} iburst\n".format(local_srv))
            fd.write("{}\n".format(' '.join(fudge)))

        #read in memory, find OPTIONS, check/change it, then overwrite file
        needopts = [ {'val':'-x', 'need':True},
                     {'val':'-g', 'need':True} ]
        fd = open(paths.SYSCONFIG_NTPD, "r")
        lines = fd.readlines()
        fd.close()
        for line in lines:
            sline = line.strip()
            if not sline.startswith(NTPD_OPTS_VAR):
                continue
            sline = sline.replace(NTPD_OPTS_QUOTE, '')
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
                    if not sline.startswith(NTPD_OPTS_VAR):
                        fd.write(line)
                        continue
                    sline = sline.replace(NTPD_OPTS_QUOTE, '')
                    (_variable, opts) = sline.split('=', 1)
                    fd.write(NTPD_OPTS_VAR + '="%s %s"\n' % (opts, ' '.join(newopts)))
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
        except ValueError as error:
            logger.debug("%s", error)

        if enabled:
            self.enable()

        if running:
            self.restart()
