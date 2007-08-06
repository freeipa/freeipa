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

class IPAServer:

    def __init__(self):
        # FIXME, this needs to be auto-discovered
        self.host = 'localhost'
        self.port = 636
        self.bindcert = "/usr/share/ipa/cert.pem"
        self.bindkey = "/usr/share/ipa/key.pem"
        self.bindca = "/usr/share/ipa/cacert.asc"
    
        ipa.config.init_config()
        self.basedn = ipaserver.util.realm_to_suffix(ipa.config.config.get_realm())
        self.scope = ldap.SCOPE_SUBTREE
        self.princ = None

    def set_principal(self, princ):
        self.princ = princ
    
    def get_dn_from_principal(self, princ):
        """Given a kerberls principal get the LDAP uid"""
        filter = "(krbPrincipalName=" + princ + ")"
        try:
            m1 = ipaserver.ipaldap.IPAdmin(self.host,self.port,self.bindca,self.bindcert,self.bindkey)
            ent = m1.getEntry(self.basedn, self.scope, filter, None)
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
    
    def get_user (self, username, opts=None):
        """Get a specific user's entry. Return as a dict of values.
           Multi-valued fields are represented as lists.
        """
        ent=""
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
            m1 = ipaserver.ipaldap.IPAdmin(self.host,self.port,self.bindca,self.bindcert,self.bindkey,dn)
            ent = m1.getEntry(self.basedn, self.scope, filter, None)
        except ldap.LDAPError, e:
            raise xmlrpclib.Fault(1, e)
        except ipaserver.ipaldap.NoSuchEntryError:
            raise xmlrpclib.Fault(2, "No such user")
    
        return self.convert_entry(ent)
    
    def add_user (self, user, opts=None):
        """Add a user in LDAP"""
        if (isinstance(user, tuple)):
            user = user[0]
        dn="uid=%s,ou=users,ou=default,%s" % (user['uid'], self.basedn)
        entry = ipaserver.ipaldap.Entry(str(dn))

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
            entry.setValues(str(u), str(user[u]))

        if opts:
            self.set_principal(opts['remoteuser'])
    
        try:
            dn = self.get_dn_from_principal(self.princ)
        except ldap.LDAPError, e:
            raise xmlrpclib.Fault(1, e)
        except ipaserver.ipaldap.NoSuchEntryError:
            raise xmlrpclib.Fault(2, "No such user")

        try:
            m1 = ipaserver.ipaldap.IPAdmin(self.host,self.port,self.bindca,self.bindcert,self.bindkey,dn)
            res = m1.addEntry(entry)
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
    
    def get_all_users (self):
        """Return a list containing a User object for each
        existing user.
        """
    
        # FIXME: Is this the filter we want or should it be more specific?
        filter = "(objectclass=posixAccount)"
        try:
            m1 = ipaserver.ipaldap.IPAdmin(self.host,self.port,self.bindca,self.bindcert,self.bindkey)
            all_users = m1.getList(self.basedn, self.scope, filter, None)
        except ldap.LDAPError, e:
            raise xmlrpclib.Fault(1, e)
        except ipaserver.ipaldap.NoSuchEntryError:
            raise xmlrpclib.Fault(2, "No such user")
    
        users = []
        for u in all_users:
            users.append(self.convert_entry(u))
    
        return users
