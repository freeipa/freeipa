# Authors: Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2007  Red Hat
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

import tempfile
import os
import pwd
import logging

import installutils
import ldap
import service
from ipaserver import ipaldap
from ipaserver.install.dsinstance import realm_to_serverid
from ipapython import sysrestore
from ipapython import ipautil

import ipalib
from ipalib import api, util, errors

def check_inst(unattended):
    has_bind = True
    # So far this file is always present in both RHEL5 and Fedora if all the necessary
    # bind packages are installed (RHEL5 requires also the pkg: caching-nameserver)
    if not os.path.exists('/etc/named.rfc1912.zones'):
        print "BIND was not found on this system"
        print "Please install the 'bind' package and start the installation again"
        has_bind = False

    # Also check for the LDAP BIND plug-in
    if not os.path.exists('/usr/lib/bind/ldap.so') and \
       not os.path.exists('/usr/lib64/bind/ldap.so'):
        print "The BIND LDAP plug-in was not found on this system"
        print "Please install the 'bind-dyndb-ldap' package and start the installation again"
        has_bind = False

    if not has_bind:
        return False

    if not unattended and os.path.exists('/etc/named.conf'):
        msg = "Existing BIND configuration detected, overwrite?"
        return ipautil.user_input(msg, False)

    return True

def create_reverse():
    return ipautil.user_input("Do you want to configure the reverse zone?", True)

def named_conf_exists():
    named_fd = open('/etc/named.conf', 'r')
    lines = named_fd.readlines()
    named_fd.close()
    for line in lines:
        if line.startswith('dynamic-db "ipa"'):
            return True
    return False

def dns_container_exists(fqdn, suffix):
    """
    Test whether the dns container exists.
    """

    def object_exists(dn):
        """
        Test whether the given object exists in LDAP.
        """
        try:
            server.search_ext_s(dn, ldap.SCOPE_BASE)
        except ldap.NO_SUCH_OBJECT:
            return False
        else:
            return True

    try:
        server = ldap.initialize("ldap://" + fqdn)
        server.simple_bind_s()
    except ldap.SERVER_DOWN:
        raise RuntimeError('LDAP server on %s is not responding. Is IPA installed?' % fqdn)

    ret = object_exists("cn=dns,%s" % suffix)
    server.unbind_s()

    return ret

def get_reverse_zone(ip_address):
    tmp = ip_address.split(".")
    tmp.reverse()
    name = tmp.pop(0)
    zone = ".".join(tmp) + ".in-addr.arpa"

    return zone, name

def dns_zone_exists(name):
    try:
        zone = api.Command.dnszone_show(unicode(name))
    except ipalib.errors.NotFound:
        return False

    if len(zone) == 0:
        return False
    else:
        return True

def add_zone(name, update_policy=None, zonemgr=None, dns_backup=None):
    if not update_policy:
        update_policy = "grant %s krb5-self * A;" % api.env.realm

    try:
        api.Command.dnszone_add(unicode(name),
                                idnssoamname=unicode(api.env.host+"."),
                                idnssoarname=unicode(zonemgr),
                                idnsallowdynupdate=True,
                                idnsupdatepolicy=unicode(update_policy))
    except (errors.DuplicateEntry, errors.EmptyModlist):
        pass

    add_rr(name, "@", "NS", api.env.host+".", dns_backup)

    return name

def add_reverze_zone(ip_address, update_policy=None, dns_backup=None):
    zone, name = get_reverse_zone(ip_address)
    if not update_policy:
        update_policy = "grant %s krb5-subdomain %s. PTR;" % (api.env.realm, zone)
    try:
        api.Command.dnszone_add(unicode(zone),
                                idnssoamname=unicode(api.env.host+"."),
                                idnsallowdynupdate=True,
                                idnsupdatepolicy=unicode(update_policy))
    except (errors.DuplicateEntry, errors.EmptyModlist):
        pass

    add_rr(zone, "@", "NS", api.env.host+".", dns_backup)

    return zone

def add_rr(zone, name, type, rdata, dns_backup=None):
    addkw = { '%srecord' % unicode(type.lower()) : unicode(rdata) }
    try:
        api.Command.dnsrecord_add(unicode(zone), unicode(name), **addkw)
    except (errors.DuplicateEntry, errors.EmptyModlist):
        pass
    if dns_backup:
        dns_backup.add(zone, type, name, rdata)

def add_ptr_rr(ip_address, fqdn, dns_backup=None):
    zone, name = get_reverse_zone(ip_address)
    add_rr(zone, name, "PTR", fqdn+".", dns_backup)


class DnsBackup(object):
    def __init__(self, service):
        self.service = service
        self.zones = {}

    def add(self, zone, record_type, host, rdata):
        """
        Backup a DNS record in the file store so it can later be removed.
        """
        if zone not in self.zones:
            zone_id = len(self.zones)
            self.zones[zone] = (zone_id, 0)
            self.service.backup_state("dns_zone_%s" % zone_id, zone)

        (zone_id, record_id) = self.zones[zone]
        self.service.backup_state("dns_record_%s_%s" % (zone_id, record_id),
                                  "%s %s %s" % (record_type, host, rdata))
        self.zones[zone] = (zone_id, record_id + 1)

    def clear_records(self, have_ldap):
        """
        Remove all records from the file store. If we are connected to
        ldap, we will also remove them there.
        """
        i = 0
        while True:
            zone = self.service.restore_state("dns_zone_%s" % i)
            if not zone:
                return

            j = 0
            while True:
                dns_record = self.service.restore_state("dns_record_%s_%s" % (i, j))
                if not dns_record:
                    break
                if have_ldap:
                    type, host, rdata = dns_record.split(" ", 2)
                    try:
                        delkw = { '%srecord' % unicode(type.lower()) : unicode(rdata) }
                        api.Command.dnsrecord_del(unicode(zone), unicode(host), **delkw)
                    except:
                        pass
                j += 1

            i += 1


class BindInstance(service.Service):
    def __init__(self, fstore=None, dm_password=None):
        service.Service.__init__(self, "named", dm_password=dm_password)
        self.dns_backup = DnsBackup(self)
        self.named_user = None
        self.domain = None
        self.host = None
        self.ip_address = None
        self.realm = None
        self.forwarders = None
        self.sub_dict = None
        self.create_reverse = True

        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore('/var/lib/ipa/sysrestore')

    def setup(self, fqdn, ip_address, realm_name, domain_name, forwarders, ntp, create_reverse, named_user="named", zonemgr=None):
        self.named_user = named_user
        self.fqdn = fqdn
        self.ip_address = ip_address
        self.realm = realm_name
        self.domain = domain_name
        self.forwarders = forwarders
        self.host = fqdn.split(".")[0]
        self.suffix = util.realm_to_suffix(self.realm)
        self.ntp = ntp
        self.create_reverse = create_reverse

        if zonemgr:
            self.zonemgr = zonemgr.replace('@','.')
        else:
            self.zonemgr = 'root.%s.%s' % (self.host, self.domain)

        tmp = ip_address.split(".")
        tmp.reverse()

        self.reverse_host = tmp.pop(0)
        self.reverse_subnet = ".".join(tmp)

        self.__setup_sub_dict()

    def create_sample_bind_zone(self):
        bind_txt = ipautil.template_file(ipautil.SHARE_DIR + "bind.zone.db.template", self.sub_dict)
        [bind_fd, bind_name] = tempfile.mkstemp(".db","sample.zone.")
        os.write(bind_fd, bind_txt)
        os.close(bind_fd)
        print "Sample zone file for bind has been created in "+bind_name

    def create_instance(self):

        try:
            self.stop()
        except:
            pass

        # get a connection to the DS
        self.ldap_connect()

        if not dns_container_exists(self.fqdn, self.suffix):
            self.step("adding DNS container", self.__setup_dns_container)
        if not dns_zone_exists(self.domain):
            self.step("setting up our zone", self.__setup_zone)
        if self.create_reverse:
            self.step("setting up reverse zone", self.__setup_reverse_zone)
        self.step("setting up our own record", self.__add_self)

        self.step("setting up kerberos principal", self.__setup_principal)
        self.step("setting up named.conf", self.__setup_named_conf)

        self.step("restarting named", self.__start)
        self.step("configuring named to start on boot", self.__enable)

        self.step("changing resolv.conf to point to ourselves", self.__setup_resolv_conf)
        self.start_creation("Configuring named:")

    def __start(self):
        try:
            self.backup_state("running", self.is_running())
            self.restart()
        except:
            print "named service failed to start"

    def __enable(self):
        self.backup_state("enabled", self.is_running())
        # We do not let the system start IPA components on its own,
        # Instead we reply on the IPA init script to start only enabled
        # components as found in our LDAP configuration tree
        self.ldap_enable('DNS', self.fqdn, self.dm_password, self.suffix)

    def __setup_sub_dict(self):
        if self.forwarders:
            fwds = "\n"
            for forwarder in self.forwarders:
                fwds += "\t\t%s;\n" % forwarder
            fwds += "\t"
        else:
            fwds = " "

        if self.ntp:
            optional_ntp =  "\n;ntp server\n"
            optional_ntp += "_ntp._udp\t\tIN SRV 0 100 123\t%s""" % self.host
        else:
            optional_ntp = ""

        self.sub_dict = dict(FQDN=self.fqdn,
                             IP=self.ip_address,
                             DOMAIN=self.domain,
                             HOST=self.host,
                             REALM=self.realm,
                             SERVER_ID=realm_to_serverid(self.realm),
                             FORWARDERS=fwds,
                             SUFFIX=self.suffix,
                             OPTIONAL_NTP=optional_ntp,
                             ZONEMGR=self.zonemgr)

    def __setup_dns_container(self):
        self._ldap_mod("dns.ldif", self.sub_dict)

    def __setup_zone(self):
        zone = add_zone(self.domain, zonemgr=self.zonemgr, dns_backup=self.dns_backup)

    def __add_self(self):
        zone = self.domain
        resource_records = (
            (self.host, "A", self.ip_address),
            ("_ldap._tcp", "SRV", "0 100 389 %s" % self.host),
            ("_kerberos", "TXT", self.realm),
            ("_kerberos._tcp", "SRV", "0 100 88 %s" % self.host),
            ("_kerberos._udp", "SRV", "0 100 88 %s" % self.host),
            ("_kerberos-master._tcp", "SRV", "0 100 88 %s" % self.host),
            ("_kerberos-master._udp", "SRV", "0 100 88 %s" % self.host),
            ("_kpasswd._tcp", "SRV", "0 100 464 %s" % self.host),
            ("_kpasswd._udp", "SRV", "0 100 464 %s" % self.host),
        )

        for (host, type, rdata) in resource_records:
            if type == "SRV":
                add_rr(zone, host, type, rdata, self.dns_backup)
            else:
                add_rr(zone, host, type, rdata)
        if self.ntp:
            add_rr(zone, "_ntp._udp", "SRV", "0 100 123 %s" % self.host)

        if dns_zone_exists(get_reverse_zone(self.ip_address)[0]):
            add_ptr_rr(self.ip_address, self.fqdn)

    def __setup_reverse_zone(self):
        add_reverze_zone(self.ip_address, dns_backup=self.dns_backup)

    def __setup_principal(self):
        dns_principal = "DNS/" + self.fqdn + "@" + self.realm
        installutils.kadmin_addprinc(dns_principal)

        # Store the keytab on disk
        self.fstore.backup_file("/etc/named.keytab")
        installutils.create_keytab("/etc/named.keytab", dns_principal)
        p = self.move_service(dns_principal)
        if p is None:
            # the service has already been moved, perhaps we're doing a DNS reinstall
            dns_principal = "krbprincipalname=%s,cn=services,cn=accounts,%s" % (dns_principal, self.suffix)
        else:
            dns_principal = p

        # Make sure access is strictly reserved to the named user
        pent = pwd.getpwnam(self.named_user)
        os.chown("/etc/named.keytab", pent.pw_uid, pent.pw_gid)
        os.chmod("/etc/named.keytab", 0400)

        # modify the principal so that it is marked as an ipa service so that
        # it can host the memberof attribute, then also add it to the
        # dnsserver role group, this way the DNS is allowed to perform
        # DNS Updates
        dns_group = "cn=dnsserver,cn=privileges,cn=pbac,%s" % self.suffix
        if isinstance(dns_principal, unicode):
            dns_principal = dns_principal.encode('utf-8')
        mod = [(ldap.MOD_ADD, 'member', dns_principal)]

        try:
            self.admin_conn.modify_s(dns_group, mod)
        except ldap.TYPE_OR_VALUE_EXISTS:
            pass
        except Exception, e:
            logging.critical("Could not modify principal's %s entry" % dns_principal)
            raise e

    def __setup_named_conf(self):
        self.fstore.backup_file('/etc/named.conf')
        named_txt = ipautil.template_file(ipautil.SHARE_DIR + "bind.named.conf.template", self.sub_dict)
        named_fd = open('/etc/named.conf', 'w')
        named_fd.seek(0)
        named_fd.truncate(0)
        named_fd.write(named_txt)
        named_fd.close()

    def __setup_resolv_conf(self):
        self.fstore.backup_file('/etc/resolv.conf')
        resolv_txt = "search "+self.domain+"\nnameserver "+self.ip_address+"\n"
        resolv_fd = open('/etc/resolv.conf', 'w')
        resolv_fd.seek(0)
        resolv_fd.truncate(0)
        resolv_fd.write(resolv_txt)
        resolv_fd.close()

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring %s" % self.service_name)

        running = self.restore_state("running")
        enabled = self.restore_state("enabled")

        self.dns_backup.clear_records(api.Backend.ldap2.isconnected())

        if not running is None:
            self.stop()

        for f in ["/etc/named.conf", "/etc/resolv.conf"]:
            try:
                self.fstore.restore_file(f)
            except ValueError, error:
                logging.debug(error)
                pass

        if not enabled is None and not enabled:
            self.chkconfig_off()

        if not running is None and running:
            self.start()
