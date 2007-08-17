# Authors: Rob Crittenden <rcritten@redhat.com>
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

import sys
sys.path.append("/usr/share/ipa")

import ldap
import ipaserver.dsinstance
import ipaserver.ipaldap
import ipaserver.util
import string
from types import *
import xmlrpclib
import ipa.config
import os

# Need a global to store this between requests
_LDAPPool = None

#
# Apache runs in multi-process mode so each process will have its own
# connection. This could theoretically drive the total number of connections
# very high but since this represents just the administrative interface
# this is not anticipated.
class IPAConnPool:
    def __init__(self):
        self.numentries = 0
        self.freelist = []

    def getConn(self, host, port, bindca, bindcert, bindkey, proxydn=None):
        self.numentries = self.numentries + 1
        if len(self.freelist) > 0:
            conn = self.freelist.pop()
        else:
            conn = ipaserver.ipaldap.IPAdmin(host,port,bindca,bindcert,bindkey)
        conn.set_proxydn(proxydn)
        return conn

    def releaseConn(self, conn):
        self.freelist.append(conn)

class IPAServer:

    def __init__(self):
        global _LDAPPool
        # FIXME, this needs to be auto-discovered
        self.host = 'localhost'
        self.port = 636
        self.bindcert = "/usr/share/ipa/cert.pem"
        self.bindkey = "/usr/share/ipa/key.pem"
        self.bindca = "/usr/share/ipa/cacert.asc"
    
        if _LDAPPool is None:
            _LDAPPool = IPAConnPool()
        ipa.config.init_config()
        self.basedn = ipaserver.util.realm_to_suffix(ipa.config.config.get_realm())
        self.scope = ldap.SCOPE_SUBTREE
        self.princ = None

    def set_principal(self, princ):
        self.princ = princ
    
    def get_dn_from_principal(self, princ):
        """Given a kerberls principal get the LDAP uid"""
        global _LDAPPool

        # FIXME: should we search for this in a specific area of the tree?
        filter = "(krbPrincipalName=" + princ + ")"
        try:
            # The only anonymous search we should have
            m1 = _LDAPPool.getConn(self.host,self.port,self.bindca,self.bindcert,self.bindkey,None)
            ent = m1.getEntry(self.basedn, self.scope, filter, ['dn'])
            _LDAPPool.releaseConn(m1)
        except ldap.LDAPError, e:
            raise xmlrpclib.Fault(1, e)
        except ipaserver.ipaldap.NoSuchEntryError:
            raise xmlrpclib.Fault(2, "No such user")
    
        return "dn:" + ent.dn
    
    def convert_entry(self, ent):
    
        # Convert to LDIF
        entry = str(ent) 
    
        # Strip off any junk
        entry = entry.strip()
    
        # Don't need to identify binary fields and this breaks the parser so
        # remove double colons
        entry = entry.replace('::', ':')
        specs = [spec.split(':') for spec in entry.split('\n')]
    
        # Convert into a dict. We need to handle multi-valued attributes as well
        # so we'll convert those into lists.
        user={}
        for (k,v) in specs:
            k = k.lower()
            if user.get(k) is not None:
                if isinstance(user[k],list):
                    user[k].append(v.strip())
                else:
                    first = user[k]
                    user[k] = []
                    user[k].append(first)
                    user[k].append(v.strip())
            else:
                    user[k] = v.strip()
    
        return user
    
    def get_user (self, args, sattrs=None, opts=None):
        """Get a specific user's entry. Return as a dict of values.
           Multi-valued fields are represented as lists.
        """
        global _LDAPPool
        ent=""

        # The XML-RPC server marshals the arguments into one variable
        # while the direct caller has them separate. So do a little
        # bit of gymnastics to figure things out. There has to be a
        # better way, so FIXME
        if isinstance(args,tuple):
            opts = sattrs
            if len(args) == 2:
                username = args[0]
                sattrs = args[1]
            else:
                username = args
                sattrs = None
        else:
            username = args

        if opts:
            self.set_principal(opts['remoteuser'])
        if (isinstance(username, tuple)):
            username = username[0]
    
        try:
            dn = self.get_dn_from_principal(self.princ)
        except ldap.LDAPError, e:
            raise xmlrpclib.Fault(1, e)
        except ipaserver.ipaldap.NoSuchEntryError:
            raise xmlrpclib.Fault(2, "No such user")
    
        filter = "(uid=" + username + ")"
        try:
            m1 = _LDAPPool.getConn(self.host,self.port,self.bindca,self.bindcert,self.bindkey,dn)
            ent = m1.getEntry(self.basedn, self.scope, filter, sattrs)
            _LDAPPool.releaseConn(m1)
        except ldap.LDAPError, e:
            raise xmlrpclib.Fault(1, e)
        except ipaserver.ipaldap.NoSuchEntryError:
            raise xmlrpclib.Fault(2, "No such user")
    
        return self.convert_entry(ent)
    
    def add_user (self, args, user_container="ou=users,ou=default",opts=None):
        """Add a user in LDAP. Takes as input a dict where the key is the
           attribute name and the value is either a string or in the case
           of a multi-valued field a list of values. user_container sets
           where in the tree the user is placed."""
        global _LDAPPool

        # The XML-RPC server marshals the arguments into one variable
        # while the direct caller has them separate. So do a little
        # bit of gymnastics to figure things out. There has to be a
        # better way, so FIXME
        if isinstance(args,tuple):
            opts = user_container
            if len(args) == 2:
                user = args[0]
                user_container = args[1]
            else:
                user = args
                user_container = "ou=users,ou=default"
        else:
            user = args

        if (isinstance(user, tuple)):
            user = user[0]

        dn="uid=%s,%s,%s" % (user['uid'], user_container,self.basedn)
        entry = ipaserver.ipaldap.Entry(dn)

        # some required objectclasses
        entry.setValues('objectClass', 'top', 'posixAccount', 'shadowAccount', 'account', 'person', 'inetOrgPerson', 'organizationalPerson', 'krbPrincipalAux', 'krbTicketPolicyAux')
    
        # Fill in shadow fields
        entry.setValue('shadowMin', '0')
        entry.setValue('shadowMax', '99999')
        entry.setValue('shadowWarning', '7')
        entry.setValue('shadowExpire', '-1')
        entry.setValue('shadowInactive', '-1')
        entry.setValue('shadowFlag', '-1')
    
        # FIXME: calculate shadowLastChange
    
        # fill in our new entry with everything sent by the user
        for u in user:
            entry.setValues(u, user[u])

        if opts:
            self.set_principal(opts['remoteuser'])
    
        try:
            dn = self.get_dn_from_principal(self.princ)
        except ldap.LDAPError, e:
            raise xmlrpclib.Fault(1, e)
        except ipaserver.ipaldap.NoSuchEntryError:
            raise xmlrpclib.Fault(2, "No such user")

        try:
            m1 = _LDAPPool.getConn(self.host,self.port,self.bindca,self.bindcert,self.bindkey,dn)
            res = m1.addEntry(entry)
            _LDAPPool.releaseConn(m1)
            return res
        except ldap.ALREADY_EXISTS:
            raise xmlrpclib.Fault(3, "User already exists")
        except ldap.LDAPError, e:
            raise xmlrpclib.Fault(1, str(e))
    
    def get_add_schema (self):
        """Get the list of fields to be used when adding users in the GUI."""
    
        # FIXME: this needs to be pulled from LDAP
        fields = []
    
        field1 = {
            "name":       "uid" ,
            "label":      "Login:",
            "type":       "text",
            "validator":  "text",
            "required":   "true"
        }
        fields.append(field1)
    
        field1 = {
            "name":       "givenName" ,
            "label":      "First name:",
            "type":       "text",
            "validator":  "string",
            "required":   "true"
        }
        fields.append(field1)
    
        field1 = {
            "name":       "sn" ,
            "label":      "Last name:",
            "type":       "text",
            "validator":  "string",
            "required":   "true"
        }
        fields.append(field1)
    
        field1 = {
            "name":       "mail" ,
            "label":      "E-mail address:",
            "type":       "text",
            "validator":  "email",
            "required":   "true"
        }
        fields.append(field1)
    
        return fields
    
    def get_all_users (self, args=None, opts=None):
        """Return a list containing a User object for each
        existing user.
        """
        global _LDAPPool
    
        if opts:
            self.set_principal(opts['remoteuser'])

        try:
            dn = self.get_dn_from_principal(self.princ)
        except ldap.LDAPError, e:
            raise xmlrpclib.Fault(1, e)
        except ipaserver.ipaldap.NoSuchEntryError:
            raise xmlrpclib.Fault(2, "No such user")
    
        # FIXME: Is this the filter we want or should it be more specific?
        filter = "(objectclass=posixAccount)"
        try:
            m1 = _LDAPPool.getConn(self.host,self.port,self.bindca,self.bindcert,self.bindkey,dn)
            all_users = m1.getList(self.basedn, self.scope, filter, None)
            _LDAPPool.releaseConn(m1)
        except ldap.LDAPError, e:
            raise xmlrpclib.Fault(1, e)
        except ipaserver.ipaldap.NoSuchEntryError:
            raise xmlrpclib.Fault(2, "No such user")
    
        users = []
        for u in all_users:
            users.append(self.convert_entry(u))
    
        return users

    def find_users (self, args, sattrs=None, opts=None):
        """Return a list containing a User object for each
        existing user that matches the criteria.
        """
        global _LDAPPool

        # The XML-RPC server marshals the arguments into one variable
        # while the direct caller has them separate. So do a little
        # bit of gymnastics to figure things out. There has to be a
        # better way, so FIXME
        if isinstance(args,tuple):
            opts = sattrs
            if len(args) == 2:
                criteria = args[0]
                sattrs = args[1]
            else:
                criteria = args
                sattrs = None
        else:
            criteria = args

        if opts:
            self.set_principal(opts['remoteuser'])

        try:
            dn = self.get_dn_from_principal(self.princ)
        except ldap.LDAPError, e:
            raise xmlrpclib.Fault(1, e)
        except ipaserver.ipaldap.NoSuchEntryError:
            raise xmlrpclib.Fault(2, "No such user")
    
        # FIXME: Is this the filter we want or do we want to do searches of
        # cn as well? Or should the caller pass in the filter?
        filter = "(uid=%s)" % criteria
        try:
            m1 = _LDAPPool.getConn(self.host,self.port,self.bindca,self.bindcert,self.bindkey,dn)
            results = m1.getList(self.basedn, self.scope, filter, sattrs)
            _LDAPPool.releaseConn(m1)
        except ldap.LDAPError, e:
            raise xmlrpclib.Fault(1, e)
        except ipaserver.ipaldap.NoSuchEntryError:
            results = []
            # raise xmlrpclib.Fault(2, "No such user")
    
        users = []
        for u in results:
            users.append(self.convert_entry(u))
    
        return users

    def update_user (self, args, newuser=None, opts=None):
        """Update a user in LDAP"""
        global _LDAPPool

        # The XML-RPC server marshals the arguments into one variable
        # while the direct caller has them separate. So do a little
        # bit of gymnastics to figure things out. There has to be a
        # better way, so FIXME
        if isinstance(args,tuple):
            opts = newuser
            if len(args) == 2:
                olduser = args[0]
                newuser = args[1]
        else:
            olduser = args

        if (isinstance(olduser, tuple)):
            olduser = olduser[0]
        if (isinstance(newuser, tuple)):
            newuser = newuser[0]

        # Should be able to get this from either the old or new user
        # but just in case someone has decided to try changing it, use the
        # original
        try:
            moddn = olduser['dn']
        except KeyError, e:
            raise xmlrpclib.Fault(4, "Old user has no dn")

        if opts:
            self.set_principal(opts['remoteuser'])
    
        try:
            proxydn = self.get_dn_from_principal(self.princ)
        except ldap.LDAPError, e:
            raise xmlrpclib.Fault(1, e)
        except ipaserver.ipaldap.NoSuchEntryError:
            raise xmlrpclib.Fault(2, "No such user")

        try:
            m1 = _LDAPPool.getConn(self.host,self.port,self.bindca,self.bindcert,self.bindkey,proxydn)
            res = m1.updateEntry(moddn, olduser, newuser)
            _LDAPPool.releaseConn(m1)
            return res
        except ldap.LDAPError, e:
            raise xmlrpclib.Fault(1, str(e))

    def mark_user_deleted (self, args, opts=None):
        """Mark a user as inactive in LDAP. We aren't actually deleting
           users here, just making it so they can't log in, etc."""
        global _LDAPPool

        uid = args[0]

        if opts:
            self.set_principal(opts['remoteuser'])

        try:
            proxydn = self.get_dn_from_principal(self.princ)
        except ldap.LDAPError, e:
            raise xmlrpclib.Fault(1, e)
        except ipaserver.ipaldap.NoSuchEntryError:
            raise xmlrpclib.Fault(2, "No such user")

        try:
            user = self.get_user(uid, ['dn', 'nsAccountlock'], opts)
        except ldap.LDAPError, e:
            raise xmlrpclib.Fault(1, str(e))

        # Are we doing an add or replace operation?
        if user.has_key('nsaccountlock'):
            has_key = True
        else:
            has_key = False

        try:
            m1 = _LDAPPool.getConn(self.host,self.port,self.bindca,self.bindcert,self.bindkey,proxydn)
            res = m1.inactivateEntry(user['dn'], has_key)
            _LDAPPool.releaseConn(m1)
            return res
        except ldap.LDAPError, e:
            raise xmlrpclib.Fault(1, str(e))
