# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#          Jan Cholasta <jcholast@redhat.com>
#
# Copyright (C) 2007-2013  Red Hat
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

import sys
import os
import os.path
import pwd
import optparse

from ipaplatform.paths import paths
from ipapython import admintool
from ipapython.dn import DN
from ipapython.ipautil import user_input, write_tmp_file
from ipalib import api, errors
from ipalib.constants import CACERT
from ipaserver.install import certs, dsinstance, httpinstance, installutils


class ServerCertInstall(admintool.AdminTool):
    command_name = 'ipa-server-certinstall'

    usage = "%prog <-d|-w> [options] <file> ..."

    description = "Install new SSL server certificates."

    @classmethod
    def add_options(cls, parser):
        super(ServerCertInstall, cls).add_options(parser)

        parser.add_option(
            "-d", "--dirsrv",
            dest="dirsrv", action="store_true", default=False,
            help="install certificate for the directory server")
        parser.add_option(
            "-w", "--http",
            dest="http", action="store_true", default=False,
            help="install certificate for the http server")
        parser.add_option(
            "--pin",
            dest="pin", metavar="PIN", sensitive=True,
            help="The password of the PKCS#12 file")
        parser.add_option(
            "--dirsrv_pin", "--http_pin",
            dest="pin",
            help=optparse.SUPPRESS_HELP)
        parser.add_option(
            "--cert-name",
            dest="cert_name", metavar="NAME",
            help="Name of the certificate to install")
        parser.add_option(
            "-p", "--dirman-password",
            dest="dirman_password",
            help="Directory Manager password")

    def validate_options(self):
        super(ServerCertInstall, self).validate_options(needs_root=True)

        installutils.check_server_configuration()

        if not self.options.dirsrv and not self.options.http:
            self.option_parser.error("you must specify dirsrv and/or http")

        if not self.args:
            self.option_parser.error("you must provide certificate filename")

    def ask_for_options(self):
        super(ServerCertInstall, self).ask_for_options()

        if not self.options.dirman_password:
            self.options.dirman_password = installutils.read_password(
                "Directory Manager", confirm=False, validate=False, retry=False)
            if self.options.dirman_password is None:
                raise admintool.ScriptError(
                    "Directory Manager password required")

        if self.options.pin is None:
            self.options.pin = installutils.read_password(
                "Enter private key unlock", confirm=False, validate=False)
            if self.options.pin is None:
                raise admintool.ScriptError(
                    "Private key unlock password required")

    def run(self):
        api.bootstrap(in_server=True)
        api.finalize()

        conn = api.Backend.ldap2
        conn.connect(bind_dn=DN(('cn', 'directory manager')),
                     bind_pw=self.options.dirman_password)

        if self.options.dirsrv:
            self.install_dirsrv_cert()

        if self.options.http:
            self.install_http_cert()

        conn.disconnect()

    def install_dirsrv_cert(self):
        serverid = installutils.realm_to_serverid(api.env.realm)
        dirname = dsinstance.config_dirname(serverid)

        conn = api.Backend.ldap2
        entry = conn.get_entry(DN(('cn', 'RSA'), ('cn', 'encryption'),
                                  ('cn', 'config')),
                               ['nssslpersonalityssl'])
        old_cert = entry.single_value['nssslpersonalityssl']

        server_cert = self.import_cert(dirname, self.options.pin,
                                       old_cert, 'ldap/%s' % api.env.host,
                                       'restart_dirsrv %s' % serverid)

        entry['nssslpersonalityssl'] = [server_cert]
        try:
            conn.update_entry(entry)
        except errors.EmptyModlist:
            pass

    def install_http_cert(self):
        dirname = certs.NSS_DIR

        old_cert = installutils.get_directive(paths.HTTPD_NSS_CONF,
                                              'NSSNickname')

        server_cert = self.import_cert(dirname, self.options.pin,
                                       old_cert, 'HTTP/%s' % api.env.host,
                                       'restart_httpd')

        installutils.set_directive(paths.HTTPD_NSS_CONF,
                                   'NSSNickname', server_cert)

        # Fix the database permissions
        os.chmod(os.path.join(dirname, 'cert8.db'), 0640)
        os.chmod(os.path.join(dirname, 'key3.db'), 0640)
        os.chmod(os.path.join(dirname, 'secmod.db'), 0640)

        pent = pwd.getpwnam("apache")
        os.chown(os.path.join(dirname, 'cert8.db'), 0, pent.pw_gid)
        os.chown(os.path.join(dirname, 'key3.db'), 0, pent.pw_gid)
        os.chown(os.path.join(dirname, 'secmod.db'), 0, pent.pw_gid)

    def import_cert(self, dirname, pkcs12_passwd, old_cert, principal, command):
        pkcs12_file, pin, ca_cert = installutils.load_pkcs12(
            cert_files=self.args,
            key_password=pkcs12_passwd,
            key_nickname=self.options.cert_name,
            ca_cert_files=[CACERT],
            host_name=api.env.host)

        cdb = certs.CertDB(api.env.realm, nssdir=dirname)
        try:
            ca_enabled = api.Command.ca_is_enabled()['result']
            if ca_enabled:
                cdb.untrack_server_cert(old_cert)

            cdb.delete_cert(old_cert)
            cdb.import_pkcs12(pkcs12_file.name, pin)
            server_cert = cdb.find_server_certs()[0][0]

            if ca_enabled:
                cdb.track_server_cert(server_cert, principal, cdb.passwd_fname,
                                      command)
        except RuntimeError, e:
            raise admintool.ScriptError(str(e))

        return server_cert
