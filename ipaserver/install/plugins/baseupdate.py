# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2011  Red Hat
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

from ipalib import api
from ipalib import errors
from ipalib import Updater, Object
from ipaserver.install import service
from ipaserver.install.plugins import PRE_UPDATE, POST_UPDATE, MIDDLE

class DSRestart(service.Service):
    """
    Restart the 389-ds service.
    """
    def __init__(self):
        """
        This class is present to provide ldapupdate the means to
        restart 389-ds.
        """
        service.Service.__init__(self, "dirsrv")

    def start(self, instance_name="", capture_output=True, wait=True):
        """
        During upgrades the server is listening only on the socket so
        we don't want to wait on ports. The caller is responsible for
        waiting for the socket to be ready.
        """
        super(DSRestart, self).start(wait=False)

    def create_instance(self):
        self.step("stopping directory server", self.stop)
        self.step("starting directory server", self.start)
        self.start_creation("Restarting Directory server to apply updates")

class update(Object):
    """
    Generic object used to register all updates into a single namespace.
    """
    backend_name = 'ldap2'

api.register(update)

class PreUpdate(Updater):
    """
    Base class for updates that run prior to file processing.
    """
    updatetype = PRE_UPDATE
    order = MIDDLE

    def __init__(self):
        super(PreUpdate, self).__init__()

class PostUpdate(Updater):
    """
    Base class for updates that run after file processing.
    """
    updatetype = POST_UPDATE
    order = MIDDLE

    def __init__(self):
        super(PostUpdate, self).__init__()
