# Authors: Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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

import ldif
import os
import sys
import shutil
import random
import traceback
from ipaplatform.paths import paths
from ipaplatform import services
from ipapython.ipa_log_manager import *
from ipapython import ipaldap

from ipaserver.install import installutils
from ipaserver.install import schemaupdate
from ipaserver.install import ldapupdate
from ipaserver.install import service

DSE = 'dse.ldif'


class GetEntryFromLDIF(ldif.LDIFParser):
    """
    LDIF parser.
    To get results, method parse() must be called first, then method
    get_results() which return parsed entries
    """
    def __init__(self, input_file, entries_dn=[]):
        """
        Parse LDIF file.
        :param input_file: an LDIF file to be parsed
        :param entries_dn: list of DN which will be returned. All entries are
         returned if list is empty.
        """
        ldif.LDIFParser.__init__(self, input_file)
        self.entries_dn = entries_dn
        self.results = {}

    def get_results(self):
        """
        Returns results in dictionary {DN: entry, ...}
        """
        return self.results

    def handle(self, dn, entry):
        if self.entries_dn and dn not in self.entries_dn:
            return

        self.results[dn] = entry


class ModifyLDIF(ldif.LDIFParser):
    """
    Allows to modify LDIF file.

    Remove operations are executed before add operations
    """
    def __init__(self, input_file, writer):
        """
        :param input_file: an LDIF
        :param writer: ldif.LDIFWriter instance where modified LDIF will
        be written
        """
        ldif.LDIFParser.__init__(self, input_file)
        self.writer = writer

        self.add_dict = {}
        self.remove_dict = {}

    def add_value(self, dn, attr, value):
        """
        Add value to LDIF.
        :param dn: DN of entry (must exists)
        :param attr: attribute name
        :param value: value to be added
        """
        attr = attr.lower()
        entry = self.add_dict.setdefault(dn, {})
        attribute = entry.setdefault(attr, [])
        if value not in attribute:
            attribute.append(value)

    def remove_value(self, dn, attr, value=None):
        """
        Remove value from LDIF.
        :param dn: DN of entry
        :param attr: attribute name
        :param value: value to be removed, if value is None, attribute will
        be removed
        """
        attr = attr.lower()
        entry = self.remove_dict.setdefault(dn, {})

        if entry is None:
            return
        attribute = entry.setdefault(attr, [])
        if value is None:
            # remove all values
            entry[attr] = None
            return
        elif attribute is None:
            # already marked to remove all values
            return
        if value not in attribute:
            attribute.append(value)

    def handle(self, dn, entry):
        if dn in self.remove_dict:
            for name, value in self.remove_dict[dn].iteritems():
                if value is None:
                    attribute = []
                else:
                    attribute = entry.setdefault(name, [])
                    attribute = [v for v in attribute if v not in value]
                entry[name] = attribute

                if not attribute:  # empty
                    del entry[name]

        if dn in self.add_dict:
            for name, value in self.add_dict[dn].iteritems():
                attribute = entry.setdefault(name, [])
                attribute.extend([v for v in value if v not in attribute])

        if not entry:  # empty
            return

        self.writer.unparse(dn, entry)


class IPAUpgrade(service.Service):
    """
    Update the LDAP data in an instance by turning off all network
    listeners and updating over ldapi. This way we know the server is
    quiet.
    """
    def __init__(self, realm_name, files=[], schema_files=[]):
        """
        realm_name: kerberos realm name, used to determine DS instance dir
        files: list of update files to process. If none use UPDATEDIR
        """

        ext = ''
        rand = random.Random()
        for i in range(8):
            h = "%02x" % rand.randint(0,255)
            ext += h
        service.Service.__init__(self, "dirsrv")
        serverid = installutils.realm_to_serverid(realm_name)
        self.filename = '%s/%s' % (paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % serverid, DSE)
        self.savefilename = '%s/%s.ipa.%s' % (paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % serverid, DSE, ext)
        self.files = files
        self.modified = False
        self.serverid = serverid
        self.schema_files = schema_files
        self.realm = realm_name

    def __start(self):
        services.service(self.service_name).start(self.serverid, ldapi=True)

    def __stop_instance(self):
        """Stop only the main DS instance"""
        super(IPAUpgrade, self).stop(self.serverid)

    def create_instance(self):
        ds_running = super(IPAUpgrade, self).is_running()
        if ds_running:
            self.step("stopping directory server", self.__stop_instance)
        self.step("saving configuration", self.__save_config)
        self.step("disabling listeners", self.__disable_listeners)
        self.step("enabling DS global lock", self.__enable_ds_global_write_lock)
        self.step("starting directory server", self.__start)
        if self.schema_files:
            self.step("updating schema", self.__update_schema)
        self.step("upgrading server", self.__upgrade)

        self.step("stopping directory server", self.__stop_instance,
                  run_after_failure=True)
        self.step("restoring configuration", self.__restore_config,
                  run_after_failure=True)
        if ds_running:
            self.step("starting directory server", self.start)
        self.start_creation(start_message="Upgrading IPA:",
                            show_service_name=False)

    def __save_config(self):
        shutil.copy2(self.filename, self.savefilename)
        with open(self.filename, "rb") as in_file:
            parser = GetEntryFromLDIF(in_file, entries_dn=["cn=config"])
            parser.parse()
            try:
                config_entry = parser.get_results()["cn=config"]
            except KeyError:
                raise RuntimeError("Unable to find cn=config entry in %s" %
                                   self.filename)

            try:
                port = config_entry['nsslapd-port'][0]
            except KeyError:
                pass
            else:
                self.backup_state('nsslapd-port', port)

            try:
                security = config_entry['nsslapd-security'][0]
            except KeyError:
                pass
            else:
                self.backup_state('nsslapd-security', security)

            try:
                global_lock = config_entry['nsslapd-global-backend-lock'][0]
            except KeyError:
                pass
            else:
                self.backup_state('nsslapd-global-backend-lock', global_lock)

    def __enable_ds_global_write_lock(self):
        ldif_outfile = "%s.modified.out" % self.filename
        with open(ldif_outfile, "wb") as out_file:
            ldif_writer = ldif.LDIFWriter(out_file)
            with open(self.filename, "rb") as in_file:
                parser = ModifyLDIF(in_file, ldif_writer)

                parser.remove_value("cn=config", "nsslapd-global-backend-lock")
                parser.add_value("cn=config", "nsslapd-global-backend-lock",
                                 "on")
                parser.parse()

        shutil.copy2(ldif_outfile, self.filename)

    def __restore_config(self):
        port = self.restore_state('nsslapd-port')
        security = self.restore_state('nsslapd-security')
        global_lock = self.restore_state('nsslapd-global-backend-lock')

        ldif_outfile = "%s.modified.out" % self.filename
        with open(ldif_outfile, "wb") as out_file:
            ldif_writer = ldif.LDIFWriter(out_file)
            with open(self.filename, "rb") as in_file:
                parser = ModifyLDIF(in_file, ldif_writer)

                if port is not None:
                    parser.remove_value("cn=config", "nsslapd-port")
                    parser.add_value("cn=config", "nsslapd-port", port)
                if security is not None:
                    parser.remove_value("cn=config", "nsslapd-security")
                    parser.add_value("cn=config", "nsslapd-security", security)

                # disable global lock by default
                parser.remove_value("cn=config", "nsslapd-global-backend-lock")
                if global_lock is not None:
                    parser.add_value("cn=config", "nsslapd-global-backend-lock",
                                     global_lock)

                parser.parse()

        shutil.copy2(ldif_outfile, self.filename)

    def __disable_listeners(self):
        ldif_outfile = "%s.modified.out" % self.filename
        with open(ldif_outfile, "wb") as out_file:
            ldif_writer = ldif.LDIFWriter(out_file)
            with open(self.filename, "rb") as in_file:
                parser = ModifyLDIF(in_file, ldif_writer)

                parser.remove_value("cn=config", "nsslapd-port")
                parser.add_value("cn=config", "nsslapd-port", "0")

                parser.remove_value("cn=config", "nsslapd-security")
                parser.add_value("cn=config", "nsslapd-security", "off")

                parser.remove_value("cn=config", "nsslapd-ldapientrysearchbase")

                parser.parse()

        shutil.copy2(ldif_outfile, self.filename)

    def __update_schema(self):
        self.modified = schemaupdate.update_schema(
            self.schema_files,
            dm_password='', ldapi=True) or self.modified

    def __upgrade(self):
        try:
            ld = ldapupdate.LDAPUpdate(dm_password='', ldapi=True)
            if len(self.files) == 0:
                self.files = ld.get_all_files(ldapupdate.UPDATES_DIR)
            self.modified = (ld.update(self.files) or self.modified)
        except ldapupdate.BadSyntax as e:
            root_logger.error('Bad syntax in upgrade %s', e)
            raise
        except Exception as e:
            # Bad things happened, return gracefully
            root_logger.error('Upgrade failed with %s', e)
            root_logger.debug('%s', traceback.format_exc())
            raise RuntimeError(e)
