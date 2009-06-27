# Authors: Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2007  Red Hat
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

import string
import tempfile
import shutil
import os
import pwd
import socket
import logging

import installutils
import ldap
import service
from ipaserver import ipaldap
from ipapython import sysrestore
from ipapython import ipautil
from ipalib import util

def check_inst():
    # So far this file is always present in both RHEL5 and Fedora if all the necessary
    # bind packages are installed (RHEL5 requires also the pkg: caching-nameserver)
    if not os.path.exists('/etc/named.rfc1912.zones'):
        return False

    # Also check for the LDAP BIND plug-in
    if not os.path.exists('/usr/lib/bind/ldap.so') and \
       not os.path.exists('/usr/lib64/bind/ldap.so'):
        return False

    return True

class BindInstance(service.Service):
    def __init__(self, fstore=None, dm_password=None):
        service.Service.__init__(self, "named", dm_password=dm_password)
        self.named_user = None
        self.fqdn = None
        self.domain = None
        self.host = None
        self.ip_address = None
        self.realm = None
        self.sub_dict = None

        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore('/var/lib/ipa/sysrestore')

    def setup(self, fqdn, ip_address, realm_name, domain_name, named_user="named"):
        self.named_user = named_user
        self.fqdn = fqdn
        self.ip_address = ip_address
        self.realm = realm_name
        self.domain = domain_name
        self.host = fqdn.split(".")[0]
        self.suffix = util.realm_to_suffix(self.realm)

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

        # FIXME: this need to be split off, as only the first server can do
        # this operation
        self.step("Setting up our zone", self.__setup_zone)
        self.step("setting up reverse zone", self.__setup_reverse_zone)

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
        self.chkconfig_on()

    def __setup_sub_dict(self):
        self.sub_dict = dict(FQDN=self.fqdn,
                             IP=self.ip_address,
                             DOMAIN=self.domain,
                             HOST=self.host,
                             REALM=self.realm,
                             SUFFIX=self.suffix,
                             REVERSE_HOST=self.reverse_host,
                             REVERSE_SUBNET=self.reverse_subnet)

    def __setup_zone(self):
        self.backup_state("domain", self.domain)
        self._ldap_mod("dns.ldif", self.sub_dict)

    def __setup_reverse_zone(self):
        self._ldap_mod("dns_reverse.ldif", self.sub_dict)

    def __setup_principal(self):
        dns_principal = "DNS/" + self.fqdn + "@" + self.realm
        installutils.kadmin_addprinc(dns_principal)

        # Store the keytab on disk
        self.fstore.backup_file("/etc/named.keytab")
        installutils.create_keytab("/etc/named.keytab", dns_principal)

        # Make sure access is strictly reserved to the named user
        pent = pwd.getpwnam(self.named_user)
        os.chown("/etc/named.keytab", pent.pw_uid, pent.pw_gid)
        os.chmod("/etc/named.keytab", 0400)

        # modify the principal so that it is marked as an ipa service so that
        # it can host the memberof attribute, then also add it to the
        # dnsserver role group, this way the DNS is allowed to perform
        # DNS Updates
        conn = None

        try:
            conn = ipaldap.IPAdmin("127.0.0.1")
            conn.simple_bind_s("cn=directory manager", self.dm_password)
        except Exception, e:
            logging.critical("Could not connect to the Directory Server on %s" % self.fqdn)
            raise e

        dns_princ_dn = "krbprincipalname=%s,cn=%s,cn=kerberos,%s" % (dns_principal, self.realm, self.suffix)
        mod = [(ldap.MOD_ADD, 'objectClass', 'ipaService')]

        try:
            conn.modify_s(dns_princ_dn, mod)
        except Exception, e:
            logging.critical("Could not modify principal's %s entry" % dns_principal)
            raise e

        dns_group = "cn=dnsserver,cn=rolegroups,cn=accounts,%s" % self.suffix
        mod = [(ldap.MOD_ADD, 'member', dns_princ_dn)]

        try:
            conn.modify_s(dns_group, mod)
        except Exception, e:
            logging.critical("Could not modify principal's %s entry" % dns_principal)
            raise e

        conn.unbind()

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
        running = self.restore_state("running")
        enabled = self.restore_state("enabled")
        domain = self.restore_state("domain")

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
