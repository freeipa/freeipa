# Authors: Sumit Bose <sbose@redhat.com>
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
#

import logging

import os
import errno
import ldap
import service
import tempfile
import installutils
from ipaserver import ipaldap
from ipaserver.install.dsinstance import realm_to_serverid
from ipalib import errors
from ipapython import sysrestore
from ipapython import ipautil

import random
import string
import struct

allowed_netbios_chars = string.ascii_uppercase + string.digits

def check_inst(unattended):
    for f in ['/usr/sbin/smbd', '/usr/bin/net', '/usr/bin/smbpasswd']:
        if not os.path.exists(f):
            print "%s was not found on this system" % f
            print "Please install the 'samba' packages and start the installation again"
            return False

    #TODO: Add check for needed samba4 libraries

    return True

def ipa_smb_conf_exists():
    try:
        fd = open('/etc/samba/smb.conf', 'r')
    except IOError, e:
        if e.errno == errno.ENOENT:
            return False

    lines = fd.readlines()
    fd.close()
    for line in lines:
        if line.startswith('### Added by IPA Installer ###'):
            return True
    return False


def check_netbios_name(s):
    # NetBIOS names may not be longer than 15 allowed characters
    if not s or len(s) > 15 or ''.join([c for c in s if c not in allowed_netbios_chars]):
        return False

    return True

def make_netbios_name(s):
    return ''.join([c for c in s.split('.')[0].upper() if c in allowed_netbios_chars])[:15]

class ADTRUSTInstance(service.Service):
    def __init__(self, fstore=None, dm_password=None):
        service.Service.__init__(self, "smb", dm_password=dm_password)

        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore('/var/lib/ipa/sysrestore')

    def __create_samba_user(self):
        print "The user for Samba is %s" % self.smb_dn
        try:
            self.admin_conn.getEntry(self.smb_dn, ldap.SCOPE_BASE)
            print "Samba user entry exists, resetting password"

            self.admin_conn.modify_s(self.smb_dn, [(ldap.MOD_REPLACE, "userPassword", self.smb_dn_pwd)])
            return

        except errors.NotFound:
            pass

        # The user doesn't exist, add it
        entry = ipaldap.Entry(self.smb_dn)
        entry.setValues("objectclass", ["account", "simplesecurityobject"])
        entry.setValues("uid", "samba")
        entry.setValues("userPassword", self.smb_dn_pwd)
        self.admin_conn.add_s(entry)

        # And finally grant it permission to read NT passwords, we do not want
        # to support LM passwords so there is no need to allow access to them
        mod = [(ldap.MOD_ADD, 'aci',
            str(['(targetattr = "sambaNTPassword")(version 3.0; acl "Samba user can read NT passwords"; allow (read) userdn="ldap:///%s";)' % self.smb_dn]))]
        try:
            self.admin_conn.modify_s(self.suffix, mod)
        except ldap.TYPE_OR_VALUE_EXISTS:
            logging.debug("samba user aci already exists in suffix %s on %s" % (self.suffix, self.admin_conn.host))

    def __gen_sid_string(self):
        sub_ids = struct.unpack("<LLL", os.urandom(12))
        return "S-1-5-21-%d-%d-%d" % (sub_ids[0], sub_ids[1], sub_ids[2])

    def __create_samba_domain_object(self):
        trust_dn = "cn=trusts,%s" % self.suffix
        smb_dom_dn = "cn=ad,%s" % trust_dn

        try:
            self.admin_conn.getEntry(smb_dom_dn, ldap.SCOPE_BASE)
            print "Samba domain object already exists"
            return
        except errors.NotFound:
            pass

        try:
            self.admin_conn.getEntry(trust_dn, ldap.SCOPE_BASE)
        except errors.NotFound:
            entry = ipaldap.Entry(trust_dn)
            entry.setValues("objectclass", ["nsContainer"])
            entry.setValues("cn", "trusts")
            self.admin_conn.add_s(entry)

        entry = ipaldap.Entry(smb_dom_dn)
        entry.setValues("objectclass", ["sambaDomain", "nsContainer"])
        entry.setValues("cn", "ad")
        entry.setValues("sambaDomainName", self.netbios_name)
        entry.setValues("sambaSID", self.__gen_sid_string())
        #TODO: which MAY attributes do we want to set ?
        self.admin_conn.add_s(entry)

    def __write_smb_conf(self):
        self.fstore.backup_file(self.smb_conf)

        fd = open(self.smb_conf, "w")
        fd.write('### Added by IPA Installer ###\n')
        fd.write('[global]\n')
        fd.write('config backend = registry\n')
        fd.close()

    def __write_smb_registry(self):
        template = os.path.join(ipautil.SHARE_DIR, "smb.conf.template")
        conf = ipautil.template_file(template, self.sub_dict)
        [fd, tmp_name] = tempfile.mkstemp()
        os.write(fd, conf)
        os.close(fd)

        args = ["/usr/bin/net", "conf", "import", tmp_name]

        try:
            ipautil.run(args)
        finally:
            os.remove(tmp_name)

    def __set_smb_ldap_password(self):
        args = ["/usr/bin/smbpasswd", "-c", self.smb_conf, "-s", "-W" ]

        ipautil.run(args, stdin = self.smb_dn_pwd + "\n" + self.smb_dn_pwd + "\n" )

    def __setup_principal(self):
        cifs_principal = "cifs/" + self.fqdn + "@" + self.realm_name
        installutils.kadmin_addprinc(cifs_principal)

        self.move_service(cifs_principal)

        try:
            ipautil.run(["ipa-rmkeytab", "--principal", cifs_principal,
                                         "-k", "/etc/krb5.keytab"])
        except ipautil.CalledProcessError, e:
            if e.returncode != 5:
                logging.critical("Failed to remove old key for %s" % cifs_principal)

        try:
            ipautil.run(["ipa-getkeytab", "--server", self.fqdn,
                                          "--principal", cifs_principal,
                                          "-k", "/etc/krb5.keytab"])
        except ipautil.CalledProcessError, e:
            logging.critical("Failed to add key for %s" % cifs_principal)

    def __start(self):
        try:
            self.start()
        except:
            logging.critical("smbd service failed to start")

    def __stop(self):
        self.backup_state("running", self.is_running())
        try:
            self.stop()
        except:
            pass

    def __enable(self):
        self.backup_state("enabled", self.is_enabled())
        # We do not let the system start IPA components on its own,
        # Instead we reply on the IPA init script to start only enabled
        # components as found in our LDAP configuration tree
        try:
            self.ldap_enable('ADTRUST', self.fqdn, self.dm_password, self.suffix)
        except ldap.ALREADY_EXISTS:
            logging.critical("ADTRUST Service startup entry already exists.")
            pass

    def __setup_sub_dict(self):
        self.sub_dict = dict(REALM = self.realm_name,
                             SUFFIX = self.suffix,
                             NETBIOS_NAME = self.netbios_name,
                             SMB_DN = self.smb_dn,
                             LDAPI_SOCKET = self.ldapi_socket)

    def setup(self, fqdn, ip_address, realm_name, domain_name, netbios_name,
              smbd_user="samba"):
        self.fqdn =fqdn
        self.ip_address = ip_address
        self.realm_name = realm_name
        self.domain_name = domain_name
        self.netbios_name = netbios_name
        self.smbd_user = smbd_user
        self.suffix = ipautil.realm_to_suffix(self.realm_name)
        self.ldapi_socket = "%%2fvar%%2frun%%2fslapd-%s.socket" % realm_to_serverid(self.realm_name)

        self.smb_conf = "/etc/samba/smb.conf"

        self.smb_dn = "uid=samba,cn=sysaccounts,cn=etc,%s" % self.suffix
        self.smb_dn_pwd = ipautil.ipa_generate_password()

        self.__setup_sub_dict()


    def create_instance(self):

        self.ldap_connect()

        self.step("stopping smbd", self.__stop)
        self.step("create samba user", self.__create_samba_user)
        self.step("create samba domain object", self.__create_samba_domain_object)
        self.step("create samba config registry", self.__write_smb_registry)
        self.step("writing samba config file", self.__write_smb_conf)
        self.step("setting password for the samba user", self.__set_smb_ldap_password)
        self.step("Adding cifs Kerberos principal", self.__setup_principal)
        self.step("configuring smbd to start on boot", self.__enable)
        self.step("starting smbd", self.__start)

        self.start_creation("Configuring smbd:")

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring %s" % self.service_name)

        running = self.restore_state("running")
        enabled = self.restore_state("enabled")

        try:
            self.stop()
        except:
            pass

        for f in [self.smb_conf]:
            try:
                self.fstore.restore_file(f)
            except ValueError, error:
                logging.debug(error)
                pass

        if not enabled is None and not enabled:
            self.disable()

        if not running is None and running:
            self.start()
