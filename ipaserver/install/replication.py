# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
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

import time, logging

import ldap
from ipaserver.install import dsinstance
from ipaserver import ipaldap
from ldap import modlist
from ipalib import util
from ipalib import errors

DIRMAN_CN = "cn=directory manager"
CACERT = "/usr/share/ipa/html/ca.crt"
# the default container used by AD for user entries
WIN_USER_CONTAINER = "cn=Users"
# the default container used by IPA for user entries
IPA_USER_CONTAINER = "cn=users,cn=accounts"
PORT = 636
TIMEOUT = 120

IPA_REPLICA = 1
WINSYNC = 2

class ReplicationManager:
    """Manage replication agreements between DS servers, and sync
    agreements with Windows servers"""
    def __init__(self, hostname, dirman_passwd):
        self.hostname = hostname
        self.dirman_passwd = dirman_passwd

        self.conn = ipaldap.IPAdmin(hostname, port=PORT, cacert=CACERT)
        self.conn.do_simple_bind(bindpw=dirman_passwd)

        self.repl_man_passwd = dirman_passwd

        # these are likely constant, but you could change them
        # at runtime if you really want
        self.repl_man_dn = "cn=replication manager,cn=config"
        self.repl_man_cn = "replication manager"
        self.suffix = ""

    def _get_replica_id(self, conn, master_conn):
        """
        Returns the replica ID which is unique for each backend.

        conn is the connection we are trying to get the replica ID for.
        master_conn is the master we are going to replicate with.
        """
        # First see if there is already one set
        dn = self.replica_dn()
        try:
            replica = conn.search_s(dn, ldap.SCOPE_BASE, "objectclass=*")[0]
            if replica.getValue('nsDS5ReplicaId'):
                return int(replica.getValue('nsDS5ReplicaId'))
        except ldap.NO_SUCH_OBJECT:
            pass

        # Ok, either the entry doesn't exist or the attribute isn't set
        # so get it from the other master
        retval = -1
        dn = "cn=replication, cn=etc, %s" % self.suffix
        try:
            replica = master_conn.search_s(dn, ldap.SCOPE_BASE, "objectclass=*")[0]
            if not replica.getValue('nsDS5ReplicaId'):
                logging.debug("Unable to retrieve nsDS5ReplicaId from remote server")
                raise RuntimeError("Unable to retrieve nsDS5ReplicaId from remote server")
        except ldap.NO_SUCH_OBJECT:
            logging.debug("Unable to retrieve nsDS5ReplicaId from remote server")
            raise

        # Now update the value on the master
        retval = int(replica.getValue('nsDS5ReplicaId'))
        mod = [(ldap.MOD_REPLACE, 'nsDS5ReplicaId', str(retval + 1))]

        try:
            master_conn.modify_s(dn, mod)
        except Exception, e:
            logging.debug("Problem updating nsDS5ReplicaID %s" % e)
            raise

        return retval

    def find_replication_dns(self, conn):
        filt = "(|(objectclass=nsDSWindowsReplicationAgreement)(objectclass=nsds5ReplicationAgreement))"
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
        except errors.NotFound:
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
        except errors.NotFound, e:
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

    def add_passsync_user(self, conn, password):
        pass_dn = "uid=passsync,cn=sysaccounts,cn=etc,%s" % self.suffix
        print "The user for the Windows PassSync service is %s" % pass_dn
        try:
            conn.getEntry(pass_dn, ldap.SCOPE_BASE)
            print "Windows PassSync entry exists, not resetting password"
            return
        except errors.NotFound:
            pass

        # The user doesn't exist, add it
        entry = ipaldap.Entry(pass_dn)
        entry.setValues("objectclass", ["account", "simplesecurityobject"])
        entry.setValues("uid", "passsync")
        entry.setValues("userPassword", password)
        conn.add_s(entry)

        # Add it to the list of users allowed to bypass password policy
        extop_dn = "cn=ipa_pwd_extop,cn=plugins,cn=config"
        entry = conn.getEntry(extop_dn, ldap.SCOPE_BASE)
        pass_mgrs = entry.getValues('passSyncManagersDNs')
        if not pass_mgrs:
            pass_mgrs = []
        if not isinstance(pass_mgrs, list):
            pass_mgrs = [pass_mgrs]
        pass_mgrs.append(pass_dn)
        mod = [(ldap.MOD_REPLACE, 'passSyncManagersDNs', pass_mgrs)]
        conn.modify_s(extop_dn, mod)

        # And finally grant it permission to write passwords
        mod = [(ldap.MOD_ADD, 'aci',
            ['(targetattr = "userPassword || krbPrincipalKey || sambaLMPassword || sambaNTPassword || passwordHistory")(version 3.0; acl "Windows PassSync service can write passwords"; allow (write) userdn="ldap:///%s";)' % pass_dn])]
        try:
            conn.modify_s(self.suffix, mod)
        except ldap.TYPE_OR_VALUE_EXISTS:
            logging.debug("passsync aci already exists in suffix %s on %s" % (self.suffix, conn.host))

    def setup_winsync_agmt(self, entry, **kargs):
        entry.setValues("objectclass", "nsDSWindowsReplicationAgreement")
        entry.setValues("nsds7WindowsReplicaSubtree",
                        kargs.get("win_subtree",
                                  WIN_USER_CONTAINER + "," + self.suffix))
        entry.setValues("nsds7DirectoryReplicaSubtree",
                        kargs.get("ds_subtree",
                                 IPA_USER_CONTAINER + "," + self.suffix))
        # for now, just sync users and ignore groups
        entry.setValues("nsds7NewWinUserSyncEnabled", kargs.get('newwinusers', 'true'))
        entry.setValues("nsds7NewWinGroupSyncEnabled", kargs.get('newwingroups', 'false'))
        windomain = ''
        if kargs.has_key('windomain'):
            windomain = kargs['windomain']
        else:
            windomain = '.'.join(ldap.explode_dn(self.suffix, 1))
        entry.setValues("nsds7WindowsDomain", windomain)

    def agreement_dn(self, hostname, port=PORT):
        cn = "meTo%s%d" % (hostname, port)
        dn = "cn=%s, %s" % (cn, self.replica_dn())

        return (cn, dn)

    def setup_agreement(self, a, b, **kargs):
        cn, dn = self.agreement_dn(b.host)
        try:
            a.getEntry(dn, ldap.SCOPE_BASE)
            return
        except errors.NotFound:
            pass

        iswinsync = kargs.get("winsync", False)
        repl_man_dn = kargs.get("binddn", self.repl_man_dn)
        repl_man_passwd = kargs.get("bindpw", self.repl_man_passwd)
        port = kargs.get("port", PORT)

        entry = ipaldap.Entry(dn)
        entry.setValues('objectclass', "nsds5replicationagreement")
        entry.setValues('cn', cn)
        entry.setValues('nsds5replicahost', b.host)
        entry.setValues('nsds5replicaport', str(port))
        entry.setValues('nsds5replicatimeout', str(TIMEOUT))
        entry.setValues('nsds5replicabinddn', repl_man_dn)
        entry.setValues('nsds5replicacredentials', repl_man_passwd)
        entry.setValues('nsds5replicabindmethod', 'simple')
        entry.setValues('nsds5replicaroot', self.suffix)
        entry.setValues('nsds5replicaupdateschedule', '0000-2359 0123456')
        entry.setValues('nsds5replicatransportinfo', 'SSL')
        entry.setValues('nsDS5ReplicatedAttributeList', '(objectclass=*) $ EXCLUDE memberOf')
        entry.setValues('description', "me to %s%d" % (b.host, port))
        if iswinsync:
            self.setup_winsync_agmt(entry, **kargs)

        a.add_s(entry)

        entry = a.waitForEntry(entry)

    def delete_agreement(self, hostname):
        cn, dn = self.agreement_dn(hostname)
        return self.conn.deleteEntry(dn)

    def check_repl_init(self, conn, agmtdn):
        done = False
        hasError = 0
        attrlist = ['cn', 'nsds5BeginReplicaRefresh',
                    'nsds5replicaUpdateInProgress',
                    'nsds5ReplicaLastInitStatus',
                    'nsds5ReplicaLastInitStart',
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
                    print "[%s] reports: Replica Busy! Status: [%s]" % (conn.host, status)
                    done = True
                    hasError = 2
                elif status.find("Total update succeeded") > -1:
                    print "Update succeeded"
                    done = True
                elif inprogress.lower() == 'true':
                    print "Update in progress yet not in progress"
                else:
                    print "[%s] reports: Update failed! Status: [%s]" % (conn.host, status)
                    hasError = 1
                    done = True
            else:
                print "Update in progress"

        return done, hasError

    def check_repl_update(self, conn, agmtdn):
        done = False
        hasError = 0
        attrlist = ['cn', 'nsds5replicaUpdateInProgress',
                    'nsds5ReplicaLastUpdateStatus', 'nsds5ReplicaLastUpdateStart',
                    'nsds5ReplicaLastUpdateEnd']
        entry = conn.getEntry(agmtdn, ldap.SCOPE_BASE, "(objectclass=*)", attrlist)
        if not entry:
            print "Error reading status from agreement", agmtdn
            hasError = 1
        else:
            inprogress = entry.nsds5replicaUpdateInProgress
            status = entry.nsds5ReplicaLastUpdateStatus
            start = entry.nsds5ReplicaLastUpdateStart
            end = entry.nsds5ReplicaLastUpdateEnd
            # incremental update is done if inprogress is false and end >= start
            done = inprogress and inprogress.lower() == 'false' and start and end and (start <= end)
            logging.info("Replication Update in progress: %s: status: %s: start: %s: end: %s" %
                         (inprogress, status, start, end))
            if not done and status: # check for errors
                # status will usually be a number followed by a string
                # number != 0 means error
                rc, msg = status.split(' ', 1)
                if rc != '0':
                    hasError = 1
                    done = True

        return done, hasError

    def wait_for_repl_init(self, conn, agmtdn):
        done = False
        haserror = 0
        while not done and not haserror:
            time.sleep(1)  # give it a few seconds to get going
            done, haserror = self.check_repl_init(conn, agmtdn)
        return haserror

    def wait_for_repl_update(self, conn, agmtdn, maxtries=600):
        done = False
        haserror = 0
        while not done and not haserror and maxtries > 0:
            time.sleep(1)  # give it a few seconds to get going
            done, haserror = self.check_repl_update(conn, agmtdn)
            maxtries -= 1
        if maxtries == 0: # too many tries
            print "Error: timeout: could not determine agreement status: please check your directory server logs for possible errors"
            haserror = 1
        return haserror

    def start_replication(self, other_conn, conn=None):
        print "Starting replication, please wait until this has completed."
        if conn == None:
            conn = self.conn
        cn, dn = self.agreement_dn(conn.host)

        mod = [(ldap.MOD_ADD, 'nsds5BeginReplicaRefresh', 'start')]
        other_conn.modify_s(dn, mod)

        return self.wait_for_repl_init(other_conn, dn)

    def basic_replication_setup(self, conn, replica_id):
        self.add_replication_manager(conn)
        self.local_replica_config(conn, replica_id)
        self.setup_changelog(conn)

    def setup_replication(self, other_hostname, realm_name, **kargs):
        """
        NOTES:
           - the directory manager password needs to be the same on
             both directories.  Or use the optional binddn and bindpw
        """
        iswinsync = kargs.get("winsync", False)
        oth_port = kargs.get("port", PORT)
        oth_cacert = kargs.get("cacert", CACERT)
        oth_binddn = kargs.get("binddn", DIRMAN_CN)
        oth_bindpw = kargs.get("bindpw", self.dirman_passwd)
        # note - there appears to be a bug in python-ldap - it does not
        # allow connections using two different CA certs
        other_conn = ipaldap.IPAdmin(other_hostname, port=oth_port, cacert=oth_cacert)
        try:
            other_conn.do_simple_bind(binddn=oth_binddn, bindpw=oth_bindpw)
        except Exception, e:
            if iswinsync:
                logging.info("Could not validate connection to remote server %s:%d - continuing" %
                             (other_hostname, oth_port))
                logging.info("The error was: %s" % e)
            else:
                raise e

        self.suffix = ipaldap.IPAdmin.normalizeDN(util.realm_to_suffix(realm_name))

        if not iswinsync:
            local_id = self._get_replica_id(self.conn, other_conn)
        else:
            # there is no other side to get a replica ID from
            local_id = self._get_replica_id(self.conn, self.conn)
        self.basic_replication_setup(self.conn, local_id)

        if not iswinsync:
            other_id = self._get_replica_id(other_conn, other_conn)
            self.basic_replication_setup(other_conn, other_id)
            self.setup_agreement(other_conn, self.conn)
            self.setup_agreement(self.conn, other_conn)
            return self.start_replication(other_conn)
        else:
            self.add_passsync_user(self.conn, kargs.get("passsync"))
            self.setup_agreement(self.conn, other_conn, **kargs)
            logging.info("Added new sync agreement, waiting for it to become ready . . .")
            cn, dn = self.agreement_dn(other_hostname)
            self.wait_for_repl_update(self.conn, dn, 30)
            logging.info("Agreement is ready, starting replication . . .")
            return self.start_replication(self.conn, other_conn)

    def initialize_replication(self, dn, conn):
        mod = [(ldap.MOD_ADD, 'nsds5BeginReplicaRefresh', 'start')]
        try:
            conn.modify_s(dn, mod)
        except ldap.ALREADY_EXISTS:
            return

    def force_synch(self, dn, schedule, conn):
        newschedule = '2358-2359 0'

        # On the remote chance of a match. We force a synch to happen right
        # now by changing the schedule to something else and quickly changing
        # it back.
        if newschedule == schedule:
            newschedule = '2358-2359 1'
        logging.info("Changing agreement %s schedule to %s to force synch" %
                     (dn, newschedule))
        mod = [(ldap.MOD_REPLACE, 'nsDS5ReplicaUpdateSchedule', [ newschedule ])]
        conn.modify_s(dn, mod)
        time.sleep(1)
        logging.info("Changing agreement %s to restore original schedule %s" %
                     (dn, schedule))
        mod = [(ldap.MOD_REPLACE, 'nsDS5ReplicaUpdateSchedule', [ schedule ])]
        conn.modify_s(dn, mod)

    def get_agreement_type(self, hostname):
        cn, dn = self.agreement_dn(hostname)

        entry = self.conn.getEntry(dn, ldap.SCOPE_BASE)

        objectclass = entry.getValues("objectclass")

        for o in objectclass:
            if o.lower() == "nsdswindowsreplicationagreement":
                return WINSYNC

        return IPA_REPLICA
