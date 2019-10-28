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

from __future__ import absolute_import

import logging

import ldif
import shutil
import random
import traceback

from ipalib import api
from ipaplatform.paths import paths
from ipaplatform import services
from ipapython import ipaldap

from ipaserver.install import installutils
from ipaserver.install import schemaupdate
from ipaserver.install import ldapupdate
from ipaserver.install import service

logger = logging.getLogger(__name__)

DSE = 'dse.ldif'
COMPAT_DN = "cn=Schema Compatibility,cn=plugins,cn=config"


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


class IPAUpgrade(service.Service):
    """
    Update the LDAP data in an instance by turning off all network
    listeners and updating over ldapi. This way we know the server is
    quiet.
    """
    def __init__(self, realm_name, files=[], schema_files=[], updates_dir=None):
        """
        realm_name: kerberos realm name, used to determine DS instance dir
        files: list of update files to process. If none use UPDATEDIR
        """

        ext = ''
        rand = random.Random()
        for _i in range(8):
            h = "%02x" % rand.randint(0,255)
            ext += h
        super(IPAUpgrade, self).__init__("dirsrv", realm_name=realm_name)
        serverid = ipaldap.realm_to_serverid(realm_name)
        self.filename = '%s/%s' % (paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % serverid, DSE)
        self.savefilename = '%s/%s.ipa.%s' % (paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % serverid, DSE, ext)
        self.files = files
        self.modified = False
        self.serverid = serverid
        self.schema_files = schema_files
        self.updates_dir = updates_dir
        if not self.updates_dir:
            self.updates_dir = ldapupdate.UPDATES_DIR
        if api.env.realm != self.realm:
            self.realm = api.env.realm

    def __start(self):
        srv = services.service(self.service_name, api)
        srv.start(self.serverid, ldapi=True)
        api.Backend.ldap2.connect()

    def __stop_instance(self):
        """Stop only the main DS instance"""
        if api.Backend.ldap2.isconnected():
            api.Backend.ldap2.disconnect()
        super(IPAUpgrade, self).stop(self.serverid)

    def create_instance(self):
        ds_running = super(IPAUpgrade, self).is_running()
        if ds_running:
            self.step("stopping directory server", self.__stop_instance)
        self.step("saving configuration", self.__save_config)
        self.step("disabling listeners", self.__disable_listeners)
        self.step("enabling DS global lock", self.__enable_ds_global_write_lock)
        self.step("disabling Schema Compat", self.__disable_schema_compat)
        self.step("starting directory server", self.__start)
        if self.schema_files:
            self.step("updating schema", self.__update_schema)
        self.step("upgrading server", self.__upgrade)

        self.step("stopping directory server", self.__stop_instance,
                  run_after_failure=True)
        self.step("restoring configuration", self.__restore_config,
                  run_after_failure=True)
        if ds_running:
            self.step("starting directory server", self.__start)
        self.start_creation(start_message="Upgrading IPA:",
                            show_service_name=False,
                            runtime=90)

    def __save_config(self):
        shutil.copy2(self.filename, self.savefilename)
        with open(self.filename, "r") as in_file:
            parser = GetEntryFromLDIF(in_file, entries_dn=["cn=config"])
            parser.parse()
            try:
                config_entry = parser.get_results()["cn=config"]
            except KeyError:
                raise RuntimeError("Unable to find cn=config entry in %s" %
                                   self.filename)

            try:
                port = config_entry['nsslapd-port'][0].decode('utf-8')
            except KeyError:
                pass
            else:
                self.backup_state('nsslapd-port', port)

            try:
                security = config_entry['nsslapd-security'][0].decode('utf-8')
            except KeyError:
                pass
            else:
                self.backup_state('nsslapd-security', security)

            try:
                global_lock = config_entry[
                    'nsslapd-global-backend-lock'][0].decode('utf-8')
            except KeyError:
                pass
            else:
                self.backup_state('nsslapd-global-backend-lock', global_lock)

        with open(self.filename, "r") as in_file:
            parser = GetEntryFromLDIF(in_file, entries_dn=[COMPAT_DN])
            parser.parse()

        try:
            compat_entry = parser.get_results()[COMPAT_DN]
        except KeyError:
            return

        schema_compat_enabled = compat_entry.get('nsslapd-pluginEnabled')
        if schema_compat_enabled is None:
            schema_compat_enabled = compat_entry.get('nsslapd-pluginenabled')
        if schema_compat_enabled:
            self.backup_state('schema_compat_enabled',
                              schema_compat_enabled[0].decode('utf-8'))

    def __enable_ds_global_write_lock(self):
        ldif_outfile = "%s.modified.out" % self.filename
        with open(ldif_outfile, "w") as out_file:
            with open(self.filename, "r") as in_file:
                parser = installutils.ModifyLDIF(in_file, out_file)

                parser.replace_value(
                    "cn=config", "nsslapd-global-backend-lock", [b"on"])
                parser.parse()

        shutil.copy2(ldif_outfile, self.filename)

    def __restore_config(self):
        port = self.restore_state('nsslapd-port')
        security = self.restore_state('nsslapd-security')
        global_lock = self.restore_state('nsslapd-global-backend-lock')
        schema_compat_enabled = self.restore_state('schema_compat_enabled')

        ldif_outfile = "%s.modified.out" % self.filename
        with open(ldif_outfile, "w") as out_file:
            with open(self.filename, "r") as in_file:
                parser = installutils.ModifyLDIF(in_file, out_file)

                if port is not None:
                    parser.replace_value(
                        "cn=config", "nsslapd-port", [port.encode('utf-8')])
                if security is not None:
                    parser.replace_value("cn=config", "nsslapd-security",
                                         [security.encode('utf-8')])

                # disable global lock by default
                parser.remove_value("cn=config", "nsslapd-global-backend-lock")
                if global_lock is not None:
                    parser.add_value("cn=config", "nsslapd-global-backend-lock",
                                     [global_lock.encode('utf-8')])
                if schema_compat_enabled is not None:
                    parser.replace_value(
                        COMPAT_DN, "nsslapd-pluginEnabled",
                        [schema_compat_enabled.encode('utf-8')])

                parser.parse()

        shutil.copy2(ldif_outfile, self.filename)

    def __disable_listeners(self):
        ldif_outfile = "%s.modified.out" % self.filename
        with open(ldif_outfile, "w") as out_file:
            with open(self.filename, "r") as in_file:
                parser = installutils.ModifyLDIF(in_file, out_file)
                parser.replace_value("cn=config", "nsslapd-port", [b"0"])
                parser.replace_value("cn=config", "nsslapd-security", [b"off"])
                parser.remove_value("cn=config", "nsslapd-ldapientrysearchbase")
                parser.parse()

        shutil.copy2(ldif_outfile, self.filename)

    def __disable_schema_compat(self):
        ldif_outfile = "%s.modified.out" % self.filename

        with open(self.filename, "r") as in_file:
            parser = GetEntryFromLDIF(in_file, entries_dn=[COMPAT_DN])
            parser.parse()

        try:
            compat_entry = parser.get_results()[COMPAT_DN]
        except KeyError:
            return

        if not compat_entry.get('nsslapd-pluginEnabled'):
            return

        with open(ldif_outfile, "w") as out_file:
            with open(self.filename, "r") as in_file:
                parser = installutils.ModifyLDIF(in_file, out_file)
                parser.remove_value(COMPAT_DN, "nsslapd-pluginEnabled")
                parser.remove_value(COMPAT_DN, "nsslapd-pluginenabled")
                parser.add_value(COMPAT_DN, "nsslapd-pluginEnabled",
                                 [b"off"])
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
                self.files = ld.get_all_files(self.updates_dir)
            self.modified = (ld.update(self.files) or self.modified)
        except ldapupdate.BadSyntax as e:
            logger.error('Bad syntax in upgrade %s', e)
            raise
        except Exception as e:
            # Bad things happened, return gracefully
            logger.error('Upgrade failed with %s', e)
            logger.debug('%s', traceback.format_exc())
            raise RuntimeError(e)
