# Authors: Karl MacMillan <kmacmillan@redhat.com>
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

from ipa.ipautil import *
import shutil

import service

class NTPInstance(service.Service):
    def __init__(self):
        service.Service.__init__(self, "ntpd")
        
    def create_instance(self):
        self.start_creation(3, "Configuring ntpd")

        self.step("writing configuration")
        # The template sets the config to point towards ntp.pool.org, but
        # they request that software not point towards the default pool.
        # We use the OS variable to point it towards either the rhel
        # or fedora pools. Other distros should be added in the future
        # or we can get our own pool.
        os = ""
        if file_exists("/etc/fedora-release"):
            os = "fedora."
        elif file_exists("/etc/redhat-release"):
            os = "rhel."

        sub_dict = { }
        sub_dict["SERVERA"] = "0.%spool.ntp.org" % os
        sub_dict["SERVERB"] = "1.%spool.ntp.org" % os
        sub_dict["SERVERC"] = "2.%spool.ntp.org" % os

        ntp_conf = template_file(SHARE_DIR + "ntp.conf.server.template", sub_dict)

        shutil.copy("/etc/ntp.conf", "/etc/ntp.conf.ipasave")

        fd = open("/etc/ntp.conf", "w")
        fd.write(ntp_conf)
        fd.close()

        # we might consider setting the date manually using ntpd -qg in case
        # the current time is very far off.

        self.step("starting ntpd")
        self.start()
        
        self.step("configuring ntpd to start on boot")
        self.chkconfig_on()
