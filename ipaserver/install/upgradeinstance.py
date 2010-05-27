# Authors: Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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

import os
import sys

from ipaserver.install import installutils
from ipaserver.install import dsinstance
from ipaserver.install import ldapupdate
from ipaserver.install import service

DSBASE = '/etc/dirsrv/slapd-'
DSE = 'dse.ldif'

class IPAUpgrade(service.Service):
    """
    Update the LDAP data in an instance by turning off all network
    listeners and updating over ldapi. This way we know the server is
    quiet.
    """
    def __init__(self, realm_name, files=[], live_run=True):
        """
        realm_name: kerberos realm name, used to determine DS instance dir
        files: list of update files to process. If none use UPDATEDIR
        live_run: boolean that defines if we are in test or live mode.
        """

        service.Service.__init__(self, "dirsrv")
        serverid = dsinstance.realm_to_serverid(realm_name)
        self.filename = '%s%s/%s' % (DSBASE, serverid, DSE)
        self.live_run = live_run
        self.files = files
        self.modified = False

    def create_instance(self):
        self.step("stopping directory server", self.stop)
        self.step("saving configuration", self.__save_config)
        self.step("disabling listeners", self.__disable_listeners)
        self.step("starting directory server", self.start)
        self.step("upgrading server", self.__upgrade)
        self.step("stopping directory server", self.stop)
        self.step("restoring configuration", self.__restore_config)
        self.step("starting directory server", self.start)

        self.start_creation("Upgrading IPA:")

    def __save_config(self):
        port = installutils.get_directive(self.filename, 'nsslapd-port',
               separator=':')
        security = installutils.get_directive(self.filename, 'nsslapd-security',
                   separator=':')
        autobind = installutils.get_directive(self.filename,
                   'nsslapd-ldapiautobind', separator=':')

        self.backup_state('nsslapd-port', port)
        self.backup_state('nsslapd-security', security)
        self.backup_state('nsslapd-ldapiautobind', autobind)

    def __restore_config(self):
        port = self.restore_state('nsslapd-port')
        security = self.restore_state('nsslapd-security')
        autobind = self.restore_state('nsslapd-ldapiautobind')

        installutils.set_directive(self.filename, 'nsslapd-port',
            port, quotes=False, separator=':')
        installutils.set_directive(self.filename, 'nsslapd-security',
            security, quotes=False, separator=':')
        installutils.set_directive(self.filename, 'nsslapd-ldapiautobind',
            autobind, quotes=False, separator=':')

    def __disable_listeners(self):
        installutils.set_directive(self.filename, 'nsslapd-port',
            0, quotes=False, separator=':')
        installutils.set_directive(self.filename, 'nsslapd-security',
            'off', quotes=False, separator=':')
        installutils.set_directive(self.filename, 'nsslapd-ldapiautobind',
            'on', quotes=False, separator=':')

    def __upgrade(self):
        ld = ldapupdate.LDAPUpdate(dm_password='', ldapi=True, live_run=self.live_run)
        if len(self.files) == 0:
            self.files = ld.get_all_files(ldapupdate.UPDATES_DIR)
        self.modified = ld.update(self.files)

def main():
    if os.getegid() != 0:
        print "Must be root to set up server"
        return 1

    update = IPAUpgrade('EXAMPLE.COM')
    update.create_instance()

    return 0

try:
    if __name__ == "__main__":
        sys.exit(main())
except SystemExit, e:
    sys.exit(e)
except KeyboardInterrupt, e:
    sys.exit(1)
