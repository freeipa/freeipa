# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#
# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 or later
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

import time, logging

import ipaldap, ldap, dsinstance
from ipa import ipaerror

DIRMAN_CN = "cn=directory manager"
PORT = 636
TIMEOUT = 120

class ReplicationManager:
    """Manage replicatin agreements between DS servers"""
    def __init__(self, hostname, dirman_passwd):
        self.hostname = hostname
        self.dirman_passwd = dirman_passwd
        self.conn = ipaldap.IPAdmin(hostname)
        self.conn.do_simple_bind(bindpw=dirman_passwd)

        self.repl_man_passwd = dirman_passwd

        # these are likely constant, but you could change them
        # at runtime if you really want
        self.repl_man_dn = "cn=replication manager,cn=config"
        self.repl_man_cn = "replication manager"
        self.suffix = ""

    def find_replication_dns(self, conn):
        filt = "(objectclass=nsDS5ReplicationAgreement)"
        try:
            ents = conn.search_s("cn=mapping tree,cn=config", ldap.SCOPE_SUBTREE, filt)
        except ldap.NO_SUCH_OBJECT:
            return []
        return [ent.dn for ent in ents]

    def add_replication_manager(self, conn, passwd=None):
        """
        Create a pseudo user to use for replication. If no password
        is provided the directory manager password will be used.
        """

        if passwd:
            self.repl_man_passwd = passwd

        ent = ipaldap.Entry(self.repl_man_dn)
        ent.setValues("objectclass", "top", "person")
        ent.setValues("cn", self.repl_man_cn)
        ent.setValues("userpassword", self.repl_man_passwd)
        ent.setValues("sn", "replication manager pseudo user")

        try:
            conn.add_s(ent)
        except ldap.ALREADY_EXISTS:
            # should we set the password here?
            pass

    def delete_replication_manager(self, conn, dn="cn=replication manager,cn=config"):
        try:
            conn.delete_s(dn)
        except ldap.NO_SUCH_OBJECT:
            pass

    def get_replica_type(self, master=True):
        if master:
            return "3"
        else:
            return "2"

    def replica_dn(self):
        return 'cn=replica, cn="%s", cn=mapping tree, cn=config' % self.suffix
        

    def local_replica_config(self, conn, replica_id):
        dn = self.replica_dn()

        try:
            conn.getEntry(dn, ldap.SCOPE_BASE)
            # replication is already configured
            return
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            pass

        replica_type = self.get_replica_type()

        entry = ipaldap.Entry(dn)
        entry.setValues('objectclass', "top", "nsds5replica", "extensibleobject")
        entry.setValues('cn', "replica")
        entry.setValues('nsds5replicaroot', self.suffix)
        entry.setValues('nsds5replicaid', str(replica_id))
        entry.setValues('nsds5replicatype', replica_type)
        entry.setValues('nsds5flags', "1")
        entry.setValues('nsds5replicabinddn', [self.repl_man_dn])
        entry.setValues('nsds5replicalegacyconsumer', "off")

        conn.add_s(entry)

    def setup_changelog(self, conn):
        dn = "cn=changelog5, cn=config"
        dirpath = conn.dbdir + "/cldb"
        entry = ipaldap.Entry(dn)
        entry.setValues('objectclass', "top", "extensibleobject")
        entry.setValues('cn', "changelog5")
        entry.setValues('nsslapd-changelogdir', dirpath)
        try:
            conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            return

    def setup_chaining_backend(self, conn):
        chaindn = "cn=chaining database, cn=plugins, cn=config"
        benamebase = "chaindb"
        urls = [self.to_ldap_url(conn)]
        cn = ""
        benum = 1
        done = False
        while not done:
            try:
                cn = benamebase + str(benum) # e.g. localdb1
                dn = "cn=" + cn + ", " + chaindn
                entry = ipaldap.Entry(dn)
                entry.setValues('objectclass', 'top', 'extensibleObject', 'nsBackendInstance')
                entry.setValues('cn', cn)
                entry.setValues('nsslapd-suffix', self.suffix)
                entry.setValues('nsfarmserverurl', urls)
                entry.setValues('nsmultiplexorbinddn', self.repl_man_dn)
                entry.setValues('nsmultiplexorcredentials', self.repl_man_passwd)

                self.conn.add_s(entry)
                done = True
            except ldap.ALREADY_EXISTS:
                benum += 1
            except ldap.LDAPError, e:
                print "Could not add backend entry " + dn, e
                raise

        return cn

    def to_ldap_url(self, conn):
        return "ldap://%s:%d/" % (conn.host, conn.port)

    def setup_chaining_farm(self, conn):
        try:
            conn.modify_s(self.suffix, [(ldap.MOD_ADD, 'aci',
                                    [ "(targetattr = \"*\")(version 3.0; acl \"Proxied authorization for database links\"; allow (proxy) userdn = \"ldap:///%s\";)" % self.repl_man_dn ])])
        except ldap.TYPE_OR_VALUE_EXISTS:
            logging.debug("proxy aci already exists in suffix %s on %s" % (self.suffix, conn.host))

    def get_mapping_tree_entry(self):
        try:
            entry = self.conn.getEntry("cn=mapping tree,cn=config", ldap.SCOPE_ONELEVEL,
                                       "(cn=\"%s\")" % (self.suffix))
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND), e:
            logging.debug("failed to find mappting tree entry for %s" % self.suffix)
            raise e

        return entry        


    def enable_chain_on_update(self, bename):
        mtent = self.get_mapping_tree_entry()
        dn = mtent.dn

        plgent = self.conn.getEntry("cn=Multimaster Replication Plugin,cn=plugins,cn=config",
                                    ldap.SCOPE_BASE, "(objectclass=*)", ['nsslapd-pluginPath'])
        path = plgent.getValue('nsslapd-pluginPath')

        mod = [(ldap.MOD_REPLACE, 'nsslapd-state', 'backend'),
               (ldap.MOD_ADD, 'nsslapd-backend', bename),
               (ldap.MOD_ADD, 'nsslapd-distribution-plugin', path),
               (ldap.MOD_ADD, 'nsslapd-distribution-funct', 'repl_chain_on_update')]

        try:
            self.conn.modify_s(dn, mod)
        except ldap.TYPE_OR_VALUE_EXISTS:
            logging.debug("chainOnUpdate already enabled for %s" % self.suffix)
        
    
    def setup_chain_on_update(self, other_conn):
        chainbe = self.setup_chaining_backend(other_conn)
        self.enable_chain_on_update(chainbe)
                     

    def agreement_dn(self, conn):
        cn = "meTo%s%d" % (conn.host, PORT)
        dn = "cn=%s, %s" % (cn, self.replica_dn())

        return (cn, dn)
        

    def setup_agreement(self, a, b):
        cn, dn = self.agreement_dn(b)
        try:
            a.getEntry(dn, ldap.SCOPE_BASE)
            return
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            pass

        entry = ipaldap.Entry(dn)
        entry.setValues('objectclass', "top", "nsds5replicationagreement")
        entry.setValues('cn', cn)
        entry.setValues('nsds5replicahost', b.host)
        entry.setValues('nsds5replicaport', str(PORT))
        entry.setValues('nsds5replicatimeout', str(TIMEOUT))
        entry.setValues('nsds5replicabinddn', self.repl_man_dn)
        entry.setValues('nsds5replicacredentials', self.repl_man_passwd)
        entry.setValues('nsds5replicabindmethod', 'simple')
        entry.setValues('nsds5replicaroot', self.suffix)
        entry.setValues('nsds5replicaupdateschedule', '0000-2359 0123456')
        entry.setValues('nsds5replicatransportinfo', 'SSL')
        entry.setValues('description', "me to %s%d" % (b.host, PORT))

        a.add_s(entry)

        entry = a.waitForEntry(entry)

    def delete_agreement(self, other):
        cn, dn = self.agreement_dn(other)
        return self.conn.deleteEntry(dn)

    def check_repl_init(self, conn, agmtdn):
        done = False
        hasError = 0
        attrlist = ['cn', 'nsds5BeginReplicaRefresh', 'nsds5replicaUpdateInProgress',
					'nsds5ReplicaLastInitStatus', 'nsds5ReplicaLastInitStart',
				    'nsds5ReplicaLastInitEnd']
        entry = conn.getEntry(agmtdn, ldap.SCOPE_BASE, "(objectclass=*)", attrlist)
        if not entry:
            print "Error reading status from agreement", agmtdn
            hasError = 1
        else:
            refresh = entry.nsds5BeginReplicaRefresh
            inprogress = entry.nsds5replicaUpdateInProgress
            status = entry.nsds5ReplicaLastInitStatus
            if not refresh: # done - check status
                if not status:
                    print "No status yet"
                elif status.find("replica busy") > -1:
                    print "Update failed - replica busy - status", status
                    done = True
                    hasError = 2
                elif status.find("Total update succeeded") > -1:
                    print "Update succeeded"
                    done = True
                elif inprogress.lower() == 'true':
                    print "Update in progress yet not in progress"
                else:
                    print "Update failed: status", status
                    hasError = 1
                    done = True
            else:
                print "Update in progress"

        return done, hasError


    def wait_for_repl_init(self, conn, agmtdn):
        done = False
        haserror = 0
        while not done and not haserror:
            time.sleep(1)  # give it a few seconds to get going
            done, haserror = self.check_repl_init(conn, agmtdn)
        return haserror

    def start_replication(self, other_conn):
        print "Starting replication, please wait until this has completed."
        cn, dn = self.agreement_dn(self.conn)

        mod = [(ldap.MOD_ADD, 'nsds5BeginReplicaRefresh', 'start')]
        other_conn.modify_s(dn, mod)

        return self.wait_for_repl_init(other_conn, dn)
        

    def basic_replication_setup(self, conn, replica_id):
        self.add_replication_manager(conn)
        self.local_replica_config(conn, replica_id)
        self.setup_changelog(conn)

    def setup_replication(self, other_hostname, realm_name):
        """
        NOTES:
           - the directory manager password needs to be the same on
             both directories.
        """
        other_conn = ipaldap.IPAdmin(other_hostname)
        other_conn.do_simple_bind(bindpw=self.dirman_passwd)
        self.suffix = ipaldap.IPAdmin.normalizeDN(dsinstance.realm_to_suffix(realm_name))

        self.basic_replication_setup(self.conn, 1)
        self.basic_replication_setup(other_conn, 2)

        self.setup_agreement(other_conn, self.conn)
        self.setup_agreement(self.conn, other_conn)
        
        return self.start_replication(other_conn)
        
        

