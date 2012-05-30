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

import os
import errno
import ldap
import tempfile
import uuid
from ipaserver import ipaldap
from ipaserver.install import installutils
from ipaserver.install import service
from ipaserver.install.dsinstance import realm_to_serverid
from ipaserver.install.bindinstance import get_rr, add_rr, del_rr, \
                                           dns_zone_exists
from ipalib import errors, api
from ipapython import sysrestore
from ipapython import ipautil
from ipapython.ipa_log_manager import *
from ipapython import services as ipaservices

import string
import struct

ALLOWED_NETBIOS_CHARS = string.ascii_uppercase + string.digits

SELINUX_WARNING = """
WARNING: could not set selinux boolean(s) %(var)s to true.  The adtrust
service may not function correctly until this boolean is successfully
change with the command:
   /usr/sbin/setsebool -P %(var)s true
Try updating the policycoreutils and selinux-policy packages.
"""

def check_inst():
    for smbfile in ['/usr/sbin/smbd', '/usr/bin/net', '/usr/bin/smbpasswd']:
        if not os.path.exists(smbfile):
            print "%s was not found on this system" % file
            print "Please install the 'samba' packages and " \
                  "start the installation again"
            return False

    #TODO: Add check for needed samba4 libraries

    return True

def ipa_smb_conf_exists():
    try:
        conf_fd = open('/etc/samba/smb.conf', 'r')
    except IOError, err:
        if err.errno == errno.ENOENT:
            return False

    lines = conf_fd.readlines()
    conf_fd.close()
    for line in lines:
        if line.startswith('### Added by IPA Installer ###'):
            return True
    return False


def check_netbios_name(s):
    # NetBIOS names may not be longer than 15 allowed characters
    if not s or len(s) > 15 or \
       ''.join([c for c in s if c not in ALLOWED_NETBIOS_CHARS]):
        return False

    return True

def make_netbios_name(s):
    return ''.join([c for c in s.split('.')[0].upper() \
                    if c in ALLOWED_NETBIOS_CHARS])[:15]

class ADTRUSTInstance(service.Service):

    ATTR_SID = "ipaNTSecurityIdentifier"
    ATTR_FLAT_NAME = "ipaNTFlatName"
    ATTR_GUID = "ipaNTDomainGUID"
    OBJC_USER = "ipaNTUserAttrs"
    OBJC_GROUP = "ipaNTGroupAttrs"
    OBJC_DOMAIN = "ipaNTDomainAttrs"

    def __init__(self, fstore=None, dm_password=None):
        self.fqdn = None
        self.ip_address = None
        self.realm_name = None
        self.domain_name = None
        self.netbios_name = None
        self.no_msdcs = None
        self.smbd_user = None
        self.suffix = None
        self.ldapi_socket = None
        self.smb_conf = None
        self.smb_dn = None
        self.smb_dn_pwd = None
        self.trust_dn = None
        self.smb_dom_dn = None
        self.sub_dict = None
        self.cifs_principal = None
        self.cifs_agent = None
        self.selinux_booleans = None

        service.Service.__init__(self, "smb", dm_password=dm_password)

        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore('/var/lib/ipa/sysrestore')

    def __gen_sid_string(self):
        sub_ids = struct.unpack("<LLL", os.urandom(12))
        return "S-1-5-21-%d-%d-%d" % (sub_ids[0], sub_ids[1], sub_ids[2])

    def __add_admin_sids(self):
        admin_dn = "uid=admin,cn=users,cn=accounts,%s" % self.suffix
        admin_group_dn = "cn=admins,cn=groups,cn=accounts,%s" % self.suffix

        try:
            dom_entry = self.admin_conn.getEntry(self.smb_dom_dn, \
                                                 ldap.SCOPE_BASE)
        except errors.NotFound:
            print "Samba domain object not found"
            return

        dom_sid = dom_entry.getValue(self.ATTR_SID)
        if not dom_sid:
            print "Samba domain object does not have a SID"
            return

        try:
            admin_entry = self.admin_conn.getEntry(admin_dn, ldap.SCOPE_BASE)
        except:
            print "IPA admin object not found"
            return

        try:
            admin_group_entry = self.admin_conn.getEntry(admin_group_dn, \
                                                         ldap.SCOPE_BASE)
        except:
            print "IPA admin group object not found"
            return

        if admin_entry.getValue(self.ATTR_SID) or \
           admin_group_entry.getValue(self.ATTR_SID):
            print "Admin SID already set, nothing to do"
            return

        try:
            self.admin_conn.modify_s(admin_dn, \
                        [(ldap.MOD_ADD, "objectclass", self.OBJC_USER), \
                         (ldap.MOD_ADD, self.ATTR_SID, dom_sid + "-500")])
        except:
            print "Failed to modify IPA admin object"

        try:
            self.admin_conn.modify_s(admin_group_dn, \
                        [(ldap.MOD_ADD, "objectclass", self.OBJC_GROUP), \
                         (ldap.MOD_ADD, self.ATTR_SID, dom_sid + "-512")])
        except:
            print "Failed to modify IPA admin group object"

    def __create_samba_domain_object(self):

        try:
            self.admin_conn.getEntry(self.smb_dom_dn, ldap.SCOPE_BASE)
            root_logger.info("Samba domain object already exists")
            return
        except errors.NotFound:
            pass

        for new_dn in (self.trust_dn, \
                       "cn=ad,"+self.trust_dn, \
                       "cn=ad,cn=etc,"+self.suffix):
            try:
                self.admin_conn.getEntry(new_dn, ldap.SCOPE_BASE)
            except errors.NotFound:
                entry = ipaldap.Entry(new_dn)
                entry.setValues("objectclass", ["nsContainer"])
                name = new_dn.split('=')[1].split(',')[0]
                if not name:
                    print "Cannot extract RDN attribute value from [%s]" % \
                          new_dn
                    return
                entry.setValues("cn", name)
                self.admin_conn.addEntry(entry)

        entry = ipaldap.Entry(self.smb_dom_dn)
        entry.setValues("objectclass", [self.OBJC_DOMAIN, "nsContainer"])
        entry.setValues("cn", self.domain_name)
        entry.setValues(self.ATTR_FLAT_NAME, self.netbios_name)
        entry.setValues(self.ATTR_SID, self.__gen_sid_string())
        entry.setValues(self.ATTR_GUID, str(uuid.uuid4()))
        #TODO: which MAY attributes do we want to set ?
        self.admin_conn.addEntry(entry)

    def __write_smb_conf(self):
        self.fstore.backup_file(self.smb_conf)

        conf_fd = open(self.smb_conf, "w")
        conf_fd.write('### Added by IPA Installer ###\n')
        conf_fd.write('[global]\n')
        conf_fd.write('config backend = registry\n')
        conf_fd.close()

    def __add_cldap_module(self):
        try:
            self._ldap_mod("ipa-cldap-conf.ldif", self.sub_dict)
        except:
            pass

    def __write_smb_registry(self):
        template = os.path.join(ipautil.SHARE_DIR, "smb.conf.template")
        conf = ipautil.template_file(template, self.sub_dict)
        [tmp_fd, tmp_name] = tempfile.mkstemp()
        os.write(tmp_fd, conf)
        os.close(tmp_fd)

        args = ["/usr/bin/net", "conf", "import", tmp_name]

        try:
            ipautil.run(args)
        finally:
            os.remove(tmp_name)

    def __setup_principal(self):
        try:
            api.Command.service_add(unicode(self.cifs_principal))
            # Add the principal to the 'adtrust agents' group
            # as 389-ds only operates with GroupOfNames, we have to use
            # the principal's proper dn as defined in self.cifs_agent
            entry = self.admin_conn.getEntry(self.smb_dn, ldap.SCOPE_BASE)
            current = ipaldap.Entry(self.smb_dn, entry.toDict())
            if not('member' in current):
                current['member'] = []
            entry.setValues("member", current['member'] + [self.cifs_agent])
            self.admin_conn.updateEntry(self.smb_dn, current, entry)
        except Exception, e:
            # CIFS principal already exists, it is not the first time adtrustinstance is managed
            # That's fine, we we'll re-extract the key again.
            pass

        samba_keytab = "/etc/samba/samba.keytab"
        if os.path.exists(samba_keytab):
            try:
                ipautil.run(["ipa-rmkeytab", "--principal", self.cifs_principal,
                                         "-k", samba_keytab])
            except ipautil.CalledProcessError, e:
                if e.returncode != 5:
                    root_logger.critical("Failed to remove old key for %s" % self.cifs_principal)

        try:
            ipautil.run(["ipa-getkeytab", "--server", self.fqdn,
                                          "--principal", self.cifs_principal,
                                          "-k", samba_keytab])
        except ipautil.CalledProcessError, e:
            root_logger.critical("Failed to add key for %s" % self.cifs_principal)

    def __add_dns_service_records(self):
        """
        Add DNS service records for Windows if DNS is enabled and the DNS zone
        is managed. If there are already service records for LDAP and Kerberos
        their values are used. Otherwise default values are used.
        """

        zone = self.domain_name
        host = self.fqdn.split(".")[0]

        ipa_srv_rec = (
            ("_ldap._tcp", ["0 100 389 %s" % host]),
            ("_kerberos._tcp", ["0 100 88 %s" % host]),
            ("_kerberos._udp", ["0 100 88 %s" % host])
        )
        win_srv_suffix = (".Default-First-Site-Name._sites.dc._msdcs",
                          ".dc._msdcs")

        err_msg = None
        ret = api.Command['dns_is_enabled']()
        if not ret['result']:
            err_msg = "DNS management was not enabled at install time."
        else:
            if not dns_zone_exists(zone):
                err_msg = "DNS zone %s cannot be managed " \
                          "as it is not defined in IPA" % zone

        if err_msg:
            print err_msg
            print "Add the following service records to your DNS server " \
                  "for DNS zone %s: " % zone
            for (srv, rdata) in ipa_srv_rec:
                for suff in win_srv_suffix:
                    print " - %s%s"  % (srv, suff)
            return

        for (srv, rdata) in ipa_srv_rec:
            ipa_rdata = get_rr(zone, srv, "SRV")
            if not ipa_rdata:
                ipa_rdata = rdata

            for suff in win_srv_suffix:
                win_srv = srv+suff
                win_rdata = get_rr(zone, win_srv, "SRV")
                if win_rdata:
                    for rec in win_rdata:
                        del_rr(zone, win_srv, "SRV", rec)
                for rec in ipa_rdata:
                    add_rr(zone, win_srv, "SRV", rec)

    def __configure_selinux_for_smbd(self):
        selinux = False
        try:
            if (os.path.exists('/usr/sbin/selinuxenabled')):
                ipautil.run(["/usr/sbin/selinuxenabled"])
                selinux = True
        except ipautil.CalledProcessError:
            # selinuxenabled returns 1 if not enabled
            pass

        if selinux:
            # Don't assume all booleans are available
            sebools = []
            for var in self.selinux_booleans:
                try:
                    (stdout, stderr, returncode) = ipautil.run(["/usr/sbin/getsebool", var])
                    if stdout and not stderr and returncode == 0:
                        self.backup_state(var, stdout.split()[2])
                        sebools.append(var)
                except:
                    pass

            if sebools:
                bools = [var + "=true" for var in sebools]
                args = ["/usr/sbin/setsebool", "-P"]
                args.extend(bools);
                try:
                    ipautil.run(args)
                except:
                    self.print_msg(SELINUX_WARNING % dict(var=','.join(sebools)))

    def __start(self):
        try:
            self.start()
        except:
            root_logger.critical("smbd service failed to start")

    def __stop(self):
        self.backup_state("running", self.is_running())
        try:
            self.stop()
        except:
            pass

    def __restart_kdc(self):
        try:
            ipaservices.knownservices.krb5kdc.restart()
        except:
            pass

    def __enable(self):
        self.backup_state("enabled", self.is_enabled())
        # We do not let the system start IPA components on its own,
        # Instead we reply on the IPA init script to start only enabled
        # components as found in our LDAP configuration tree
        try:
            self.ldap_enable('ADTRUST', self.fqdn, self.dm_password, \
                             self.suffix)
        except (ldap.ALREADY_EXISTS, errors.DuplicateEntry), e:
            root_logger.info("ADTRUST Service startup entry already exists.")
            pass

    def __setup_sub_dict(self):
        self.sub_dict = dict(REALM = self.realm_name,
                             SUFFIX = self.suffix,
                             NETBIOS_NAME = self.netbios_name,
                             SMB_DN = self.smb_dn,
                             LDAPI_SOCKET = self.ldapi_socket,
                             FQDN = self.fqdn)

    def setup(self, fqdn, ip_address, realm_name, domain_name, netbios_name,
              no_msdcs=False, smbd_user="samba"):
        self.fqdn = fqdn
        self.ip_address = ip_address
        self.realm_name = realm_name
        self.domain_name = domain_name
        self.netbios_name = netbios_name
        self.no_msdcs = no_msdcs
        self.smbd_user = smbd_user
        self.suffix = ipautil.realm_to_suffix(self.realm_name)
        self.ldapi_socket = "%%2fvar%%2frun%%2fslapd-%s.socket" % \
                            realm_to_serverid(self.realm_name)

        self.smb_conf = "/etc/samba/smb.conf"

        self.smb_dn = "cn=adtrust agents,cn=sysaccounts,cn=etc,%s" % self.suffix

        self.trust_dn = "cn=trusts,%s" % self.suffix
        self.smb_dom_dn = "cn=%s,cn=ad,cn=etc,%s" % (self.domain_name, \
                                                     self.suffix)
        self.cifs_principal = "cifs/" + self.fqdn + "@" + self.realm_name
        self.cifs_agent = "krbprincipalname=%s,cn=services,cn=accounts,%s" % \
                          (self.cifs_principal.lower(), self.suffix)
        self.selinux_booleans = ["samba_portmapper"]

        self.__setup_sub_dict()


    def create_instance(self):

        self.ldap_connect()

        self.step("stopping smbd", self.__stop)
        self.step("creating samba domain object", \
                  self.__create_samba_domain_object)
        self.step("creating samba config registry", self.__write_smb_registry)
        self.step("writing samba config file", self.__write_smb_conf)
        self.step("adding cifs Kerberos principal", self.__setup_principal)
        self.step("adding admin(group) SIDs", self.__add_admin_sids)
        self.step("activating CLDAP plugin", self.__add_cldap_module)
        self.step("configuring smbd to start on boot", self.__enable)
        if not self.no_msdcs:
            self.step("adding special DNS service records", \
                      self.__add_dns_service_records)
        self.step("restarting KDC to take MS PAC changes into account", \
                  self.__restart_kdc)
        self.step("setting SELinux booleans", \
                  self.__configure_selinux_for_smbd)
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

        for r_file in [self.smb_conf]:
            try:
                self.fstore.restore_file(r_file)
            except ValueError, error:
                root_logger.debug(error)
                pass

        for var in self.selinux_booleans:
            sebool_state = self.restore_state(var)
            if not sebool_state is None:
                try:
                    ipautil.run(["/usr/sbin/setsebool", "-P", var, sebool_state])
                except:
                    self.print_msg(SELINUX_WARNING % dict(var=var))

        if not enabled is None and not enabled:
            self.disable()

        if not running is None and running:
            self.start()
