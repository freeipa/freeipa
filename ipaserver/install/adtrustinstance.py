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
from ipapython.dn import DN
from ipapython import sysrestore
from ipapython import ipautil
from ipapython.ipa_log_manager import *
from ipapython import services as ipaservices
from ipapython.dn import DN

import ipaclient.ipachangeconf

import string
import struct
import re

ALLOWED_NETBIOS_CHARS = string.ascii_uppercase + string.digits

SELINUX_WARNING = """
WARNING: could not set selinux boolean(s) %(var)s to true.  The adtrust
service may not function correctly until this boolean is successfully
change with the command:
   /usr/sbin/setsebool -P %(var)s true
Try updating the policycoreutils and selinux-policy packages.
"""

UPGRADE_ERROR = """
Entry %(dn)s does not exist.
This means upgrade from IPA 2.x to 3.x did not went well and required S4U2Proxy
configuration was not set up properly. Please run ipa-ldap-updater manually
and re-run ipa-adtrust-instal again afterwards.
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
    ATTR_FALLBACK_GROUP = "ipaNTFallbackPrimaryGroup"
    OBJC_USER = "ipaNTUserAttrs"
    OBJC_GROUP = "ipaNTGroupAttrs"
    OBJC_DOMAIN = "ipaNTDomainAttrs"
    FALLBACK_GROUP_NAME = u'Default SMB Group'

    def __init__(self, fstore=None):
        self.fqdn = None
        self.ip_address = None
        self.realm = None
        self.domain_name = None
        self.netbios_name = None
        self.no_msdcs = None
        self.add_sids = None
        self.smbd_user = None
        self.suffix = DN()
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
        self.rid_base = None
        self.secondary_rid_base = None

        service.Service.__init__(self, "smb", dm_password=None, ldapi=True)

        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore('/var/lib/ipa/sysrestore')

    def __gen_sid_string(self):
        sub_ids = struct.unpack("<LLL", os.urandom(12))
        return "S-1-5-21-%d-%d-%d" % (sub_ids[0], sub_ids[1], sub_ids[2])

    def __add_admin_sids(self):
        """
        The IPA admin and the IPA admins group with get the well knows SIDs
        used by AD for the administrator and the administrator group.

        By default new users belong only to a user private group (UPG) and no
        other Posix group since ipausers is not a Posix group anymore. To be
        able to add a RID to the primary RID attribute in a PAC a fallback
        group is added.
        """

        admin_dn = DN(('uid', 'admin'), api.env.container_user,
                      self.suffix)
        admin_group_dn = DN(('cn', 'admins'), api.env.container_group,
                            self.suffix)
        try:
            dom_entry = self.admin_conn.getEntry(self.smb_dom_dn, \
                                                 ldap.SCOPE_BASE)
        except errors.NotFound:
            self.print_msg("Samba domain object not found")
            return

        dom_sid = dom_entry.getValue(self.ATTR_SID)
        if not dom_sid:
            self.print_msg("Samba domain object does not have a SID")
            return

        try:
            admin_entry = self.admin_conn.getEntry(admin_dn, ldap.SCOPE_BASE)
        except:
            self.print_msg("IPA admin object not found")
            return

        try:
            admin_group_entry = self.admin_conn.getEntry(admin_group_dn, \
                                                         ldap.SCOPE_BASE)
        except:
            self.print_msg("IPA admin group object not found")
            return

        if admin_entry.getValue(self.ATTR_SID):
            self.print_msg("Admin SID already set, nothing to do")
        else:
            try:
                self.admin_conn.modify_s(admin_dn, \
                            [(ldap.MOD_ADD, "objectclass", self.OBJC_USER), \
                             (ldap.MOD_ADD, self.ATTR_SID, dom_sid + "-500")])
            except:
                self.print_msg("Failed to modify IPA admin object")

        if admin_group_entry.getValue(self.ATTR_SID):
            self.print_msg("Admin group SID already set, nothing to do")
        else:
            try:
                self.admin_conn.modify_s(admin_group_dn, \
                            [(ldap.MOD_ADD, "objectclass", self.OBJC_GROUP), \
                             (ldap.MOD_ADD, self.ATTR_SID, dom_sid + "-512")])
            except:
                self.print_msg("Failed to modify IPA admin group object")


    def __add_fallback_group(self):
        """
        By default new users belong only to a user private group (UPG) and no
        other Posix group since ipausers is not a Posix group anymore. To be
        able to add a RID to the primary RID attribute in a PAC a fallback
        group is added.

        Since this method must be run after a restart of the directory server
        to enable the sidgen plugin we have to reconnect to the directory
        server.
        """

        self.ldap_connect()

        try:
            dom_entry = self.admin_conn.getEntry(self.smb_dom_dn, \
                                                 ldap.SCOPE_BASE)
        except errors.NotFound:
            self.print_msg("Samba domain object not found")
            return

        if dom_entry.getValue(self.ATTR_FALLBACK_GROUP):
            self.print_msg("Fallback group already set, nothing to do")
            return

        fb_group_dn = DN(('cn', self.FALLBACK_GROUP_NAME),
                         api.env.container_group, self.suffix)
        try:
            self.admin_conn.getEntry(fb_group_dn, ldap.SCOPE_BASE)
        except errors.NotFound:
            try:
                self._ldap_mod('default-smb-group.ldif', self.sub_dict)
            except Exception, e:
                self.print_msg("Failed to add fallback group.")
                raise e

        # _ldap_mod does not return useful error codes, so we must check again
        # if the fallback group was created properly.
        try:
            self.admin_conn.getEntry(fb_group_dn, ldap.SCOPE_BASE)
        except errors.NotFound:
            self.print_msg("Failed to add fallback group.")
            return

        try:
            mod = [(ldap.MOD_ADD, self.ATTR_FALLBACK_GROUP, fb_group_dn)]
            self.admin_conn.modify_s(self.smb_dom_dn, mod)
        except:
            self.print_msg("Failed to add fallback group to domain object")

    def __add_rid_bases(self):
        """
        Add RID bases to the range object for the local ID range.

        TODO: handle missing or multiple ranges more gracefully.
        """

        try:
            res = self.admin_conn.getList(DN(api.env.container_ranges, self.suffix),
                                          ldap.SCOPE_ONELEVEL,
                                          "(objectclass=ipaDomainIDRange)")
            if len(res) != 1:
                root_logger.critical("Found more than one ID range for the " \
                                     "local domain.")
                raise RuntimeError("Too many ID ranges\n")

            if res[0].getValue('ipaBaseRID') or \
               res[0].getValue('ipaSecondaryBaseRID'):
                self.print_msg("RID bases already set, nothing to do")
                return

            size = res[0].getValue('ipaIDRangeSize')
            if abs(self.rid_base - self.secondary_rid_base) > size:
                self.print_msg("Primary and secondary RID base are too close. " \
                      "They have to differ at least by %d." % size)
                raise RuntimeError("RID bases too close.\n")

            try:
                self.admin_conn.modify_s(res[0].dn,
                                         [(ldap.MOD_ADD, "ipaBaseRID", \
                                                 str(self.rid_base)), \
                                         (ldap.MOD_ADD, "ipaSecondaryBaseRID", \
                                                 str(self.secondary_rid_base))])
            except:
                self.print_msg("Failed to add RID bases to the local range object")

        except errors.NotFound as e:
            root_logger.critical("ID range of the local domain not found, " \
                                 "define it and run again.")
            raise e

    def __create_samba_domain_object(self):

        try:
            self.admin_conn.getEntry(self.smb_dom_dn, ldap.SCOPE_BASE)
            root_logger.info("Samba domain object already exists")
            return
        except errors.NotFound:
            pass

        for new_dn in (self.trust_dn, \
                       DN(('cn', 'ad'), self.trust_dn), \
                       DN(api.env.container_cifsdomains, self.suffix)):
            try:
                self.admin_conn.getEntry(new_dn, ldap.SCOPE_BASE)
            except errors.NotFound:
                entry = ipaldap.Entry(new_dn)
                entry.setValues("objectclass", ["nsContainer"])
                try:
                    name = new_dn[1].attr
                except Exception, e:
                    self.print_msg('Cannot extract RDN attribute value from "%s": %s' % \
                          (new_dn, e))
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

    def __add_plugin_conf(self, name, plugin_cn, ldif_file):
        """
        Add directory server plugin configuration if it not already
        exists.
        """
        try:
            plugin_dn = DN(('cn', plugin_cn), ('cn', 'plugins'),
                           ('cn', 'config'))
            self.admin_conn.getEntry(plugin_dn, ldap.SCOPE_BASE)
            self.print_msg('%s plugin already configured, nothing to do' % name)
        except errors.NotFound:
            try:
                self._ldap_mod(ldif_file, self.sub_dict)
            except Exception:
                pass

    def __add_cldap_module(self):
        """
        Add cldap directory server plugin configuration if it not already
        exists.
        """
        self.__add_plugin_conf('CLDAP', 'ipa_cldap', 'ipa-cldap-conf.ldif')

    def __add_sidgen_module(self):
        """
        Add sidgen directory server plugin configuration and the related task
        if they not already exist.
        """
        self.__add_plugin_conf('Sidgen', 'IPA SIDGEN', 'ipa-sidgen-conf.ldif')
        self.__add_plugin_conf('Sidgen task', 'ipa-sidgen-task',
                               'ipa-sidgen-task-conf.ldif')

    def __add_sids(self):
        """
        Add SIDs for existing users and groups
        """

        try:
            self._ldap_mod("ipa-sidgen-task-run.ldif", self.sub_dict)
        except:
            pass

    def __add_extdom_module(self):
        """
        Add directory server configuration for the extdom extended operation
        if it not already exists.
        """
        self.__add_plugin_conf('Extdom', 'ipa_extdom_extop',
                               'ipa-extdom-extop-conf.ldif')

    def __add_s4u2proxy_target(self):
        """
        Add CIFS principal to S4U2Proxy target
        """

        targets_dn = DN(('cn', 'ipa-cifs-delegation-targets'), ('cn', 's4u2proxy'),
                        ('cn', 'etc'), self.suffix)
        try:
            targets = self.admin_conn.getEntry(targets_dn, ldap.SCOPE_BASE)
            current = ipaldap.Entry((targets_dn, targets.toDict()))
            members = current.getValues('memberPrincipal') or []
            if not(self.cifs_principal in members):
                current.setValues("memberPrincipal", members + [self.cifs_principal])
                self.admin_conn.updateEntry(targets_dn, targets.toDict(), current.toDict())
            else:
                self.print_msg('cifs principal already targeted, nothing to do.')
        except errors.NotFound:
            self.print_msg(UPGRADE_ERROR % dict(dn=targets_dn))

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
            try:
                entry = self.admin_conn.getEntry(self.smb_dn, ldap.SCOPE_BASE)
                current = ipaldap.Entry((self.smb_dn, entry.toDict()))
                members = current.getValues('member') or []
                if not(self.cifs_agent in members):
                    current.setValues("member", members + [self.cifs_agent])
                    self.admin_conn.updateEntry(self.smb_dn, entry.toDict(), current.toDict())
            except errors.NotFound:
                entry = ipaldap.Entry(self.smb_dn)
                entry.setValues("objectclass", ["top", "GroupOfNames"])
                entry.setValues("cn", self.smb_dn['cn'])
                entry.setValues("member", [self.cifs_agent])
                self.admin_conn.addEntry(entry)
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

        if self.no_msdcs:
            err_msg = '--no-msdcs was given, special DNS service records ' \
                      'are not added to local DNS server'
        else:
            ret = api.Command['dns_is_enabled']()
            if not ret['result']:
                err_msg = "DNS management was not enabled at install time."
            else:
                if not dns_zone_exists(zone):
                    err_msg = "DNS zone %s cannot be managed " \
                              "as it is not defined in IPA" % zone

        if err_msg:
            self.print_msg(err_msg)
            self.print_msg("Add the following service records to your DNS " \
                           "server for DNS zone %s: " % zone)
            for (srv, rdata) in ipa_srv_rec:
                for suff in win_srv_suffix:
                    self.print_msg(" - %s%s"  % (srv, suff))
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

    def __mod_krb5_conf(self):
        """
        Set dns_lookup_kdc to true and master_kdc in /etc/krb5.conf
        """

        if not self.fqdn or not self.realm:
            self.print_msg("Cannot modify /etc/krb5.conf")

        krbconf = ipaclient.ipachangeconf.IPAChangeConf("IPA Installer")
        krbconf.setOptionAssignment(" = ")
        krbconf.setSectionNameDelimiters(("[", "]"))
        krbconf.setSubSectionDelimiters(("{", "}"))
        krbconf.setIndent(("", "  ", "    "))

        libopts = [{'name':'dns_lookup_kdc', 'type':'option', 'action':'set',
                    'value':'true'}]

        master_kdc = self.fqdn + ":88"
        kropts = [{'name':'master_kdc', 'type':'option', 'action':'set',
                   'value':master_kdc}]

        ropts = [{'name':self.realm, 'type':'subsection', 'action':'set',
                  'value':kropts}]

        opts = [{'name':'libdefaults', 'type':'section', 'action':'set',
                 'value':libopts},
                {'name':'realms', 'type':'section', 'action':'set',
                 'value':ropts}]

        krbconf.changeConf("/etc/krb5.conf", opts)

    def __update_krb5_conf(self):
        """
        Update /etc/krb5.conf if needed
        """

        try:
            krb5conf = open("/etc/krb5.conf", 'r')
        except IOError, e:
            self.print_msg("Cannot open /etc/krb5.conf (%s)\n" % str(e))
            return

        has_dns_lookup_kdc_true = False
        for line in krb5conf:
            if re.match("^\s*dns_lookup_kdc\s*=\s*[Tt][Rr][Uu][Ee]\s*$", line):
                has_dns_lookup_kdc_true = True
                break
        krb5conf.close()

        if not has_dns_lookup_kdc_true:
            self.__mod_krb5_conf()
        else:
            self.print_msg("'dns_lookup_kdc' already set to 'true', "
                           "nothing to do.")



    def __start(self):
        try:
            self.start()
            ipaservices.service('winbind').start()
        except:
            root_logger.critical("CIFS services failed to start")

    def __stop(self):
        self.backup_state("running", self.is_running())
        try:
            self.stop()
        except:
            pass

    def __restart_dirsrv(self):
        try:
            ipaservices.knownservices.dirsrv.restart()
        except:
            pass

    def __enable(self):
        self.backup_state("enabled", self.is_enabled())
        # We do not let the system start IPA components on its own,
        # Instead we reply on the IPA init script to start only enabled
        # components as found in our LDAP configuration tree
        # Note that self.dm_password is None for ADTrustInstance because
        # we ensure to be called as root and using ldapi to use autobind
        try:
            self.ldap_enable('ADTRUST', self.fqdn, self.dm_password, \
                             self.suffix)
        except (ldap.ALREADY_EXISTS, errors.DuplicateEntry), e:
            root_logger.info("ADTRUST Service startup entry already exists.")

        try:
            self.ldap_enable('EXTID', self.fqdn, self.dm_password, \
                             self.suffix)
        except (ldap.ALREADY_EXISTS, errors.DuplicateEntry), e:
            root_logger.info("EXTID Service startup entry already exists.")

    def __setup_sub_dict(self):
        self.sub_dict = dict(REALM = self.realm,
                             SUFFIX = self.suffix,
                             NETBIOS_NAME = self.netbios_name,
                             SMB_DN = self.smb_dn,
                             LDAPI_SOCKET = self.ldapi_socket,
                             FQDN = self.fqdn)

    def setup(self, fqdn, ip_address, realm_name, domain_name, netbios_name,
              rid_base, secondary_rid_base, no_msdcs=False, add_sids=False,
              smbd_user="samba"):
        self.fqdn = fqdn
        self.ip_address = ip_address
        self.realm = realm_name
        self.domain_name = domain_name
        self.netbios_name = netbios_name
        self.rid_base = rid_base
        self.secondary_rid_base = secondary_rid_base
        self.no_msdcs = no_msdcs
        self.add_sids = add_sids
        self.smbd_user = smbd_user
        self.suffix = ipautil.realm_to_suffix(self.realm)
        self.ldapi_socket = "%%2fvar%%2frun%%2fslapd-%s.socket" % \
                            realm_to_serverid(self.realm)

        self.smb_conf = "/etc/samba/smb.conf"

        self.smb_dn = DN(('cn', 'adtrust agents'), ('cn', 'sysaccounts'),
                         ('cn', 'etc'), self.suffix)

        self.trust_dn = DN(api.env.container_trusts, self.suffix)
        self.smb_dom_dn = DN(('cn', self.domain_name),
                             api.env.container_cifsdomains, self.suffix)
        self.cifs_principal = "cifs/" + self.fqdn + "@" + self.realm
        self.cifs_agent = DN(('krbprincipalname', self.cifs_principal.lower()),
                             api.env.container_service,
                             self.suffix)
        self.selinux_booleans = ["samba_portmapper"]

        self.__setup_sub_dict()

    def find_local_id_range(self):
        self.ldap_connect()

        if self.admin_conn.search_s(DN(api.env.container_ranges, self.suffix),
                                    ldap.SCOPE_ONELEVEL,
                                    "objectclass=ipaDomainIDRange"):
            return

        try:
            entry = self.admin_conn.getEntry(DN(('cn', 'admins'), api.env.container_group, self.suffix),
                                             ldap.SCOPE_BASE)
        except errors.NotFound:
            raise ValueError("No local ID range and no admins group found.\n" \
                             "Add local ID range manually and try again!")

        base_id = int(entry.getValue('gidNumber'))
        id_range_size = 200000

        id_filter = "(&" \
                      "(|(objectclass=posixAccount)" \
                        "(objectclass=posixGroup)" \
                        "(objectclass=ipaIDObject))" \
                      "(|(uidNumber<=%d)(uidNumber>=%d)" \
                        "(gidNumber<=%d)(gidNumner>=%d)))" % \
                     ((base_id - 1), (base_id + id_range_size),
                      (base_id - 1), (base_id + id_range_size))
        if self.admin_conn.search_s("cn=accounts," + self.suffix,
                                   ldap.SCOPE_SUBTREE, id_filter):
            raise ValueError("There are objects with IDs out of the expected" \
                             "range.\nAdd local ID range manually and try " \
                             "again!")

        entry = ipaldap.Entry(DN(('cn', ('%s_id_range' % self.realm)),
                                 api.env.container_ranges,
                                 self.suffix))
        entry.setValue('objectclass', 'ipaDomainIDRange')
        entry.setValue('cn', ('%s_id_range' % self.realm))
        entry.setValue('ipaBaseID', str(base_id))
        entry.setValue('ipaIDRangeSize', str(id_range_size))
        self.admin_conn.addEntry(entry)

    def create_instance(self):

        self.ldap_connect()

        self.step("stopping smbd", self.__stop)
        self.step("creating samba domain object", \
                  self.__create_samba_domain_object)
        self.step("creating samba config registry", self.__write_smb_registry)
        self.step("writing samba config file", self.__write_smb_conf)
        self.step("adding cifs Kerberos principal", self.__setup_principal)
        self.step("adding cifs principal to S4U2Proxy targets", self.__add_s4u2proxy_target)
        self.step("adding admin(group) SIDs", self.__add_admin_sids)
        self.step("adding RID bases", self.__add_rid_bases)
        self.step("updating Kerberos config", self.__update_krb5_conf)
        self.step("activating CLDAP plugin", self.__add_cldap_module)
        self.step("activating sidgen plugin and task", self.__add_sidgen_module)
        self.step("activating extdom plugin", self.__add_extdom_module)
        self.step("configuring smbd to start on boot", self.__enable)
        self.step("adding special DNS service records", \
                  self.__add_dns_service_records)
        self.step("restarting Directory Server to take MS PAC and LDAP plugins changes into account", \
                  self.__restart_dirsrv)
        self.step("adding fallback group", self.__add_fallback_group)
        self.step("setting SELinux booleans", \
                  self.__configure_selinux_for_smbd)
        self.step("starting CIFS services", self.__start)

        if self.add_sids:
            self.step("adding SIDs to existing users and groups",
                      self.__add_sids)

        self.start_creation("Configuring CIFS:")

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
