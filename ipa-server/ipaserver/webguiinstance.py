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

import service

class WebGuiInstance(service.Service):
    def __init__(self):
        service.Service.__init__(self, "ipa-webgui")

    def create_instance(self):
        self.start_creation(2, "Configuring ipa-webgui")

        self.step("starting ipa-webgui")
        service.start("ipa-webgui")

        self.step("configuring ipa-webgui to start on boot")
        service.chkconfig_on("ipa-webgui")

        self.done_creation()


