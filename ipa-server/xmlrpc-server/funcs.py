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
import ipa.ipautil
import xmlrpclib
import ipa.config
import copy
from ipa import ipaerror

import string
from types import *
import os
import re

# Need a global to store this between requests
_LDAPPool = None

DefaultUserContainer = "cn=users,cn=accounts"
DefaultGroupContainer = "cn=groups,cn=accounts"

#
# Apache runs in multi-process mode so each process will have its own
# connection. This could theoretically drive the total number of connections
# very high but since this represents just the administrative interface
# this is not anticipated.
class IPAConnPool:
    def __init__(self):
        self.freelist = []

    def getConn(self, host, port, bindca, bindcert, bindkey, proxydn=None, krbccache=None):
        conn = None
        if len(self.freelist) > 0:
            for i in range(len(self.freelist)):
                c = self.freelist[i]
                if ((c.host == host) and (c.port == port)):
                    conn = self.freelist.pop(i)
                    break
        if conn is None:
            conn = ipaserver.ipaldap.IPAdmin(host,port,bindca,bindcert,bindkey)
        if proxydn is not None:
            conn.set_proxydn(proxydn)
        else:
            conn.set_krbccache(krbccache)
        return conn

    def releaseConn(self, conn):
        # We can't re-use SASL connections. If proxydn is None it means
        # we have a Kerberos credentails cache set. See ipaldap.set_krbccache
        if conn.proxydn is None:
            conn.unbind_s()
        else:
            self.freelist.append(conn)

class IPAServer:

    def __init__(self):
        global _LDAPPool
        # FIXME, this needs to be auto-discovered
        self.host = 'localhost'
        self.port = 389
        self.sslport = 636
        self.bindcert = "/usr/share/ipa/cert.pem"
        self.bindkey = "/usr/share/ipa/key.pem"
        self.bindca = "/usr/share/ipa/cacert.asc"
    
        if _LDAPPool is None:
            _LDAPPool = IPAConnPool()
        ipa.config.init_config()
        self.basedn = ipa.ipautil.realm_to_suffix(ipa.config.config.get_realm())
        self.scope = ldap.SCOPE_SUBTREE
        self.princ = None
        self.krbccache = None

    def set_principal(self, princ):
        self.princ = princ

    def set_krbccache(self, krbccache):
        self.krbccache = krbccache
    
    def get_dn_from_principal(self, princ):
        """Given a kerberos principal get the LDAP uid"""
        global _LDAPPool

        filter = "(krbPrincipalName=" + princ + ")"
        # The only anonymous search we should have
        conn = _LDAPPool.getConn(self.host,self.sslport,self.bindca,self.bindcert,self.bindkey,None,None)
        try:
            ent = conn.getEntry(self.basedn, self.scope, filter, ['dn'])
        finally:
            _LDAPPool.releaseConn(conn)
    
        return "dn:" + ent.dn

    def __setup_connection(self, opts):
        """Set up common things done in the connection.
           If there is a Kerberos credentials cache then return None as the
           proxy dn and the ccache otherwise return the proxy dn and None as
           the ccache.

           We only want one or the other used at one time and we prefer
           the Kerberos credentials cache. So if there is a ccache, return
           that and None for proxy dn to make calling getConn() easier.
        """

        if opts:
            if opts.get('krbccache'):
                self.set_krbccache(opts['krbccache'])
                self.set_principal(None)
            else:
                self.set_krbccache(None)
                self.set_principal(opts['remoteuser'])
        else:
            # The caller should have already set the principal or the
            # krbccache. If not they'll get an authentication error later.
            pass

        if self.princ is not None:
            return self.get_dn_from_principal(self.princ), None
        else:
            return None, self.krbccache

    def getConnection(self, opts):
        """Wrapper around IPAConnPool.getConn() so we don't have to pass
           around self.* every time a connection is needed.

           For SASL connections (where we have a krbccache) we can't set
           the SSL variables for certificates. It confuses the ldap
           module.
        """
        global _LDAPPool

        (proxy_dn, krbccache) = self.__setup_connection(opts)

        if krbccache is not None:
            bindca = None
            bindcert = None
            bindkey = None
            port = self.port
#        Fallback to use proxy authentication. We no longer support this method
#        else:
#            bindca = self.bindca
#            bindcert = self.bindcert 
#            bindkey = self.bindkey
#            port = self.sslport
        else:
             return None

        return _LDAPPool.getConn(self.host,port,bindca,bindcert,bindkey,proxy_dn,krbccache)

    def releaseConnection(self, conn):
        global _LDAPPool

        _LDAPPool.releaseConn(conn)

    def convert_entry(self, ent):
        entry = dict(ent.data)
        entry['dn'] = ent.dn
        # For now convert single entry lists to a string for the ui.
        # TODO: we need to deal with multi-values better
        for key,value in entry.iteritems():
            if isinstance(value,list) or isinstance(value,tuple):
                if len(value) == 0:
                    entry[key] = ''
                elif len(value) == 1:
                    entry[key] = value[0]
        return entry

    def __get_entry (self, base, filter, sattrs=None, opts=None):
        """Get a specific entry. Return as a dict of values.
           Multi-valued fields are represented as lists.
        """
        ent=""

        conn = self.getConnection(opts)
        try:
            ent = conn.getEntry(base, self.scope, filter, sattrs)
        finally:
            self.releaseConnection(conn)
    
        return self.convert_entry(ent)

    def __update_entry (self, oldentry, newentry, opts=None):
        """Update an LDAP entry

           oldentry is a dict
           newentry is a dict
        """
        oldentry = self.convert_scalar_values(oldentry)
        newentry = self.convert_scalar_values(newentry)

        # Should be able to get this from either the old or new entry
        # but just in case someone has decided to try changing it, use the
        # original
        try:
            moddn = oldentry['dn']
        except KeyError, e:
            raise ipaerror.gen_exception(ipaerror.LDAP_MISSING_DN)

        conn = self.getConnection(opts)
        try:
            res = conn.updateEntry(moddn, oldentry, newentry)
        finally:
            self.releaseConnection(conn)
        return res

    def __safe_filter(self, criteria):
        """Make sure any arguments used when creating a filter are safe."""

        # TODO: this escaper assumes the python-ldap library will error out
        #       on invalid codepoints.  we need to check malformed utf-8 input
        #       where the second byte in a multi-byte character
        #       is (illegally) ')' and make sure python-ldap
        #       bombs out.
        criteria = re.sub(r'[\(\)\\\*]', ldap_search_escape, criteria)

        return criteria

    def __generate_match_filters(self, search_fields, criteria_words):
        """Generates a search filter based on a list of words and a list
           of fields to search against.

           Returns a tuple of two filters: (exact_match, partial_match)"""

        # construct search pattern for a single word
        # (|(f1=word)(f2=word)...)
        search_pattern = "(|"
        for field in search_fields:
            search_pattern += "(" + field + "=%(match)s)"
        search_pattern += ")"
        gen_search_pattern = lambda word: search_pattern % {'match':word}

        # construct the giant match for all words
        exact_match_filter = "(&"
        partial_match_filter = "(&"
        for word in criteria_words:
            exact_match_filter += gen_search_pattern(word)
            partial_match_filter += gen_search_pattern("*%s*" % word)
        exact_match_filter += ")"
        partial_match_filter += ")"

        return (exact_match_filter, partial_match_filter)
 
# User support

    def __is_user_unique(self, uid, opts):
        """Return 1 if the uid is unique in the tree, 0 otherwise."""
        uid = self.__safe_filter(uid)
        filter = "(&(uid=%s)(objectclass=posixAccount))" % uid
 
        try:
            entry = self.__get_entry(self.basedn, filter, ['dn','uid'], opts)
            return 0
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return 1

    def get_user_by_uid (self, uid, sattrs=None, opts=None):
        """Get a specific user's entry. Return as a dict of values.
           Multi-valued fields are represented as lists.
        """

        uid = self.__safe_filter(uid)
        filter = "(uid=" + uid + ")"
        return self.__get_entry(self.basedn, filter, sattrs, opts)
    
    def get_user_by_dn (self, dn, sattrs=None, opts=None):
        """Get a specific user's entry. Return as a dict of values.
           Multi-valued fields are represented as lists.
        """

        filter = "(objectClass=*)"
        return self.__get_entry(dn, filter, sattrs, opts)
    
    def add_user (self, user, user_container=None, opts=None):
        """Add a user in LDAP. Takes as input a dict where the key is the
           attribute name and the value is either a string or in the case
           of a multi-valued field a list of values. user_container sets
           where in the tree the user is placed."""
        if user_container is None:
            user_container = DefaultUserContainer

        if self.__is_user_unique(user['uid'], opts) == 0:
            raise ipaerror.gen_exception(ipaerror.LDAP_DUPLICATE)

        dn="uid=%s,%s,%s" % (user['uid'], user_container,self.basedn)
        entry = ipaserver.ipaldap.Entry(dn)

        # FIXME: This should be dynamic and can include just about anything

        # Let us add in some missing attributes
        if user.get('homedirectory') is None:
                user['homedirectory'] = '/home/%s' % user.get('uid')
        if not user.get('gecos') is None:
                user['gecos'] = user['uid']

        # FIXME: This can be removed once the DS plugin is installed
        user['uidnumber'] = '501'

        # FIXME: What is the default group for users?
        user['gidnumber'] = '501'

        realm = ipa.config.config.get_realm()
        user['krbprincipalname'] = "%s@%s" % (user.get('uid'), realm)

        # FIXME. This is a hack so we can request separate First and Last
        # name in the GUI.
        if user.get('cn') is None:
            user['cn'] = "%s %s" % (user.get('givenname'),
                                           user.get('sn'))

        if user.get('gn'):
            del user['gn']

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

        conn = self.getConnection(opts)
        try:
            res = conn.addEntry(entry)
        finally:
            self.releaseConnection(conn)
        return res
    
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
        filter = "(objectclass=posixAccount)"

        conn = self.getConnection(opts)
        try:
            all_users = conn.getList(self.basedn, self.scope, filter, None)
        finally:
            self.releaseConnection(conn)
    
        users = []
        for u in all_users:
            users.append(self.convert_entry(u))
    
        return users

    def find_users (self, criteria, sattrs=None, searchlimit=0, opts=None):
        """Returns a list: counter followed by the results.
           If the results are truncated, counter will be set to -1."""
        # Assume the list of fields to search will come from a central
        # configuration repository.  A good format for that would be
        # a comma-separated list of fields
        search_fields_conf_str = "uid,givenName,sn,telephoneNumber,ou,carLicense,title"
        search_fields = string.split(search_fields_conf_str, ",")

        criteria = self.__safe_filter(criteria)
        criteria_words = re.split(r'\s+', criteria)
        criteria_words = filter(lambda value:value!="", criteria_words)
        if len(criteria_words) == 0:
            return [0]

        (exact_match_filter, partial_match_filter) = self.__generate_match_filters(
                search_fields, criteria_words)

        conn = self.getConnection(opts)
        try:
            try:
                exact_results = conn.getListAsync(self.basedn, self.scope,
                        exact_match_filter, sattrs, 0, None, None, -1, searchlimit)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                exact_results = [0]

            try:
                partial_results = conn.getListAsync(self.basedn, self.scope,
                        partial_match_filter, sattrs, 0, None, None, -1, searchlimit)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                partial_results = [0]
        finally:
            self.releaseConnection(conn)

        exact_counter = exact_results[0]
        partial_counter = partial_results[0]

        exact_results = exact_results[1:]
        partial_results = partial_results[1:]

        # Remove exact matches from the partial_match list
        exact_dns = set(map(lambda e: e.dn, exact_results))
        partial_results = filter(lambda e: e.dn not in exact_dns,
                                 partial_results)

        if (exact_counter == -1) or (partial_counter == -1):
            counter = -1
        else:
            counter = len(exact_results) + len(partial_results)

        users = [counter]
        for u in exact_results + partial_results:
            users.append(self.convert_entry(u))

        return users

    def convert_scalar_values(self, orig_dict):
        """LDAP update dicts expect all values to be a list (except for dn).
           This method converts single entries to a list."""
        new_dict={}
        for (k,v) in orig_dict.iteritems():
            if not isinstance(v, list) and k != 'dn':
                v = [v]
            new_dict[k] = v

        return new_dict

    def update_user (self, olduser, newuser, opts=None):
        """Update a user in LDAP"""
        return self.__update_entry(olduser, newuser, opts)

    def mark_user_deleted (self, uid, opts=None):
        """Mark a user as inactive in LDAP. We aren't actually deleting
           users here, just making it so they can't log in, etc."""
        user = self.get_user_by_uid(uid, ['dn', 'uid', 'nsAccountlock'], opts)

        # Are we doing an add or replace operation?
        if user.has_key('nsaccountlock'):
            if user['nsaccountlock'] == "true":
                return "already marked as deleted"
            has_key = True
        else:
            has_key = False

        conn = self.getConnection(opts)
        try:
            res = conn.inactivateEntry(user['dn'], has_key)
        finally:
            self.releaseConnection(conn)
        return res

    def delete_user (self, uid, opts=None):
        """Delete a user. Not to be confused with inactivate_user. This
           makes the entry go away completely.

           uid is the uid of the user to delete

           The memberOf plugin handles removing the user from any other
           groups.
        """
        user_dn = self.get_user_by_uid(uid, ['dn', 'uid', 'objectclass'], opts)
        if user_dn is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        conn = self.getConnection(opts)
        try:
            res = conn.deleteEntry(user_dn['dn'])
        finally:
            self.releaseConnection(conn)
        return res

    def modifyPassword (self, uid, oldpass, newpass, opts=None):
        """Set/Reset a user's password

           uid tells us who's password to change
           oldpass is the old password (if available)
           newpass is the new password
        """
        user_dn = self.get_user_by_uid(uid, ['dn', 'uid', 'objectclass'], opts)
        if user_dn is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        conn = self.getConnection(opts)
        try:
            res = conn.modifyPassword(user_dn['dn'], oldpass, newpass)
        finally:
            self.releaseConnection(conn)
        return res

# Group support

    def __is_group_unique(self, cn, opts):
        """Return 1 if the cn is unique in the tree, 0 otherwise."""
        cn = self.__safe_filter(cn)
        filter = "(&(cn=%s)(objectclass=posixGroup))" % cn
 
        try:
            entry = self.__get_entry(self.basedn, filter, ['dn','cn'], opts)
            return 0
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return 1

    def get_group_by_cn (self, cn, sattrs=None, opts=None):
        """Get a specific group's entry. Return as a dict of values.
           Multi-valued fields are represented as lists.
        """

        cn = self.__safe_filter(cn)
        filter = "(cn=" + cn + ")"
        return self.__get_entry(self.basedn, filter, sattrs, opts)
    
    def get_group_by_dn (self, dn, sattrs=None, opts=None):
        """Get a specific group's entry. Return as a dict of values.
           Multi-valued fields are represented as lists.
        """

        filter = "(objectClass=*)"
        return self.__get_entry(dn, filter, sattrs, opts)
    
    def add_group (self, group, group_container=None, opts=None):
        """Add a group in LDAP. Takes as input a dict where the key is the
           attribute name and the value is either a string or in the case
           of a multi-valued field a list of values. group_container sets
           where in the tree the group is placed."""
        if group_container is None:
            group_container = DefaultGroupContainer

        if self.__is_group_unique(group['cn'], opts) == 0:
            raise ipaerror.gen_exception(ipaerror.LDAP_DUPLICATE)

        dn="cn=%s,%s,%s" % (group['cn'], group_container,self.basedn)
        entry = ipaserver.ipaldap.Entry(dn)

        # some required objectclasses
        entry.setValues('objectClass', 'top', 'groupofuniquenames', 'posixGroup')

        # FIXME, need a gidNumber generator
        if group.get('gidnumber') is None:
            entry.setValues('gidNumber', '501')

        # fill in our new entry with everything sent by the user
        for g in group:
            entry.setValues(g, group[g])

        conn = self.getConnection(opts)
        try:
            res = conn.addEntry(entry)
        finally:
            self.releaseConnection(conn)

    def find_groups (self, criteria, sattrs=None, searchlimit=0, opts=None):
        """Return a list containing a User object for each
        existing group that matches the criteria.
        """
        # Assume the list of fields to search will come from a central
        # configuration repository.  A good format for that would be
        # a comma-separated list of fields
        search_fields_conf_str = "cn,description"
        search_fields = string.split(search_fields_conf_str, ",")

        criteria = self.__safe_filter(criteria)
        criteria_words = re.split(r'\s+', criteria)
        criteria_words = filter(lambda value:value!="", criteria_words)
        if len(criteria_words) == 0:
            return [0]

        (exact_match_filter, partial_match_filter) = self.__generate_match_filters(
                search_fields, criteria_words)

        #
        # further constrain search to just the objectClass
        # TODO - need to parameterize this into generate_match_filters,
        #        and work it into the field-specification search feature
        #
        exact_match_filter = "(&(objectClass=posixGroup)%s)" % exact_match_filter
        partial_match_filter = "(&(objectClass=posixGroup)%s)" % partial_match_filter

        #
        # TODO - copy/paste from find_users.  needs to be refactored
        #
        conn = self.getConnection(opts)
        try:
            try:
                exact_results = conn.getListAsync(self.basedn, self.scope,
                        exact_match_filter, sattrs, 0, None, None, -1, searchlimit)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                exact_results = [0]

            try:
                partial_results = conn.getListAsync(self.basedn, self.scope,
                        partial_match_filter, sattrs, 0, None, None, -1, searchlimit)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                partial_results = [0]
        finally:
            self.releaseConnection(conn)

        exact_counter = exact_results[0]
        partial_counter = partial_results[0]

        exact_results = exact_results[1:]
        partial_results = partial_results[1:]

        # Remove exact matches from the partial_match list
        exact_dns = set(map(lambda e: e.dn, exact_results))
        partial_results = filter(lambda e: e.dn not in exact_dns,
                                 partial_results)

        if (exact_counter == -1) or (partial_counter == -1):
            counter = -1
        else:
            counter = len(exact_results) + len(partial_results)

        groups = [counter]
        for u in exact_results + partial_results:
            groups.append(self.convert_entry(u))

        return groups

    def add_user_to_group(self, user, group, opts=None):
        """Add a user to an existing group.
           user is a uid of the user to add
           group is the cn of the group to be added to
        """

        old_group = self.get_group_by_cn(group, None, opts)
        if old_group is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)
        new_group = copy.deepcopy(old_group)

        user_dn = self.get_user_by_uid(user, ['dn', 'uid', 'objectclass'], opts)
        if user_dn is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        if new_group.get('uniquemember') is not None:
            if ((isinstance(new_group.get('uniquemember'), str)) or (isinstance(new_group.get('uniquemember'), unicode))):
                new_group['uniquemember'] = [new_group['uniquemember']]
            new_group['uniquemember'].append(user_dn['dn'])
        else:
            new_group['uniquemember'] = user_dn['dn']

        try:
            ret = self.__update_entry(old_group, new_group, opts)
        except ipaerror.exception_for(ipaerror.LDAP_EMPTY_MODLIST):
            raise
        return ret

    def add_users_to_group(self, users, group, opts=None):
        """Given a list of user uid's add them to the group cn denoted by group
           Returns a list of the users were not added to the group.
        """

        failed = []

        if (isinstance(users, str)):
            users = [users]

        for user in users:
            try:
                self.add_user_to_group(user, group, opts)
            except ipaerror.exception_for(ipaerror.LDAP_EMPTY_MODLIST):
                # User is already in the group
                failed.append(user)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                # User or the group does not exist
                failed.append(user)

        return failed

    def remove_user_from_group(self, user, group, opts=None):
        """Remove a user from an existing group.
           user is a uid of the user to remove
           group is the cn of the group to be removed from
        """

        old_group = self.get_group_by_cn(group, None, opts)
        if old_group is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)
        new_group = copy.deepcopy(old_group)

        user_dn = self.get_user_by_uid(user, ['dn', 'uid', 'objectclass'], opts)
        if user_dn is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        if new_group.get('uniquemember') is not None:
            if ((isinstance(new_group.get('uniquemember'), str)) or (isinstance(new_group.get('uniquemember'), unicode))):
                new_group['uniquemember'] = [new_group['uniquemember']]
            try:
                new_group['uniquemember'].remove(user_dn['dn'])
            except ValueError:
                # User is not in the group
                # FIXME: raise more specific error?
                raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)
        else:
            # Nothing to do if the group has no members
            # FIXME raise SOMETHING?
            return "Success"

        try:
            ret = self.__update_entry(old_group, new_group, opts)
        except ipaerror.exception_for(ipaerror.LDAP_EMPTY_MODLIST):
            raise
        return ret

    def remove_users_from_group(self, users, group, opts=None):
        """Given a list of user uid's remove them from the group cn denoted
           by group
           Returns a list of the users were not removed from the group.
        """

        failed = []

        if (isinstance(users, str)):
            users = [users]

        for user in users:
            try:
                self.remove_user_from_group(user, group, opts)
            except ipaerror.exception_for(ipaerror.LDAP_EMPTY_MODLIST):
                # User is not in the group
                failed.append(user)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                # User or the group does not exist
                failed.append(user)

        return failed

    def update_group (self, oldgroup, newgroup, opts=None):
        """Update a group in LDAP"""
        return self.__update_entry(oldgroup, newgroup, opts)

    def delete_group (self, group_cn, opts=None):
        """Delete a group
           group_cn is the cn of the group to delete

           The memberOf plugin handles removing the group from any other
           groups.
        """
        group = self.get_group_by_cn(group_cn, ['dn', 'cn'], opts)

        if len(group) != 1:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        conn = self.getConnection(opts)
        try:
            res = conn.deleteEntry(group[0]['dn'])
        finally:
            self.releaseConnection(conn)
        return res

    def add_group_to_group(self, group, tgroup, opts=None):
        """Add a user to an existing group.
           group is a cn of the group to add
           tgroup is the cn of the group to be added to
        """

        old_group = self.get_group_by_cn(tgroup, None, opts)
        if old_group is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)
        new_group = copy.deepcopy(old_group)

        group_dn = self.get_group_by_cn(group, ['dn', 'cn', 'objectclass'], opts)
        if group_dn is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        if new_group.get('uniquemember') is not None:
            if ((isinstance(new_group.get('uniquemember'), str)) or (isinstance(new_group.get('uniquemember'), unicode))):
                new_group['uniquemember'] = [new_group['uniquemember']]
            new_group['uniquemember'].append(group_dn['dn'])
        else:
            new_group['uniquemember'] = group_dn['dn']

        try:
            ret = self.__update_entry(old_group, new_group, opts)
        except ipaerror.exception_for(ipaerror.LDAP_EMPTY_MODLIST):
            raise
        return ret

def ldap_search_escape(match):
    """Escapes out nasty characters from the ldap search.
    See RFC 2254."""
    value = match.group()
    if (len(value) != 1):
        return ""

    if value == "(":
        return "\\28"
    elif value == ")":
        return "\\29"
    elif value == "\\":
        return "\\5c"
    elif value == "*":
        # drop '*' from input.  search performs its own wildcarding
        return ""
    else:
        return value
