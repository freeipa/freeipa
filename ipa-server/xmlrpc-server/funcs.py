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

import krbV
import ldap
import ldap.dn
import ipaserver.dsinstance
import ipaserver.ipaldap
import ipa.ipautil
import xmlrpclib
import copy
import attrs
from ipa import ipaerror
from urllib import quote,unquote
from ipa import radius_util

import string
from types import *
import os
import re
import logging
import subprocess

try:
    from threading import Lock
except ImportError:
    from dummy_threading import Lock

# Need a global to store this between requests
_LDAPPool = None

ACIContainer = "cn=accounts"
DefaultUserContainer = "cn=users,cn=accounts"
DefaultGroupContainer = "cn=groups,cn=accounts"
DefaultServiceContainer = "cn=services,cn=accounts"

# FIXME: need to check the ipadebug option in ipa.conf
#logging.basicConfig(level=logging.DEBUG,
#    format='%(asctime)s %(levelname)s %(message)s',
#    stream=sys.stderr)

#
# Apache runs in multi-process mode so each process will have its own
# connection. This could theoretically drive the total number of connections
# very high but since this represents just the administrative interface
# this is not anticipated.
#
# The pool consists of two things, a dictionary keyed on the principal name
# that contains the connection and a list that is used to keep track of the
# order. If the list fills up just pop the top entry off and you've got
# the least recently used.

# maxsize = 0 means no limit
class IPAConnPool:
    def __init__(self, maxsize = 0):
        self._dict = {}
        self._lru = []
        self._lock = Lock()
        self._maxsize = maxsize
        self._ctx = krbV.default_context()

    def getConn(self, host, port, krbccache=None, debug=None):
        conn = None

        ccache = krbV.CCache(name=krbccache, context=self._ctx)
        cprinc = ccache.principal()

        conn = ipaserver.ipaldap.IPAdmin(host,port,None,None,None,debug)

        # This will bind the connection
        try:
            conn.set_krbccache(krbccache, cprinc.name)
        except ldap.UNWILLING_TO_PERFORM, e:
            raise ipaerror.gen_exception(ipaerror.CONNECTION_UNWILLING)

        return conn

    def releaseConn(self, conn):
        if conn is None:
            return

        conn.unbind_s()

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
        self.krbctx = krbV.default_context()
        self.realm = self.krbctx.default_realm

        if _LDAPPool is None:
            _LDAPPool = IPAConnPool(128)
        self.basedn = ipa.ipautil.realm_to_suffix(self.realm)
        self.scope = ldap.SCOPE_SUBTREE
        self.princ = None
        self.krbccache = None

    def set_principal(self, princ):
        self.princ = princ

    def set_krbccache(self, krbccache):
        self.krbccache = krbccache
    
    def get_dn_from_principal(self, princ, debug):
        """Given a kerberos principal get the LDAP uid"""
        global _LDAPPool

        princ = self.__safe_filter(princ)
        filter = "(krbPrincipalName=" + princ + ")"
        # The only anonymous search we should have
        conn = _LDAPPool.getConn(self.host,self.sslport,self.bindca,self.bindcert,self.bindkey,None,None,debug)
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

        debug = "Off"

        if opts is not None:
            debug = opts.get('ipadebug')
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
            return self.get_dn_from_principal(self.princ, debug), None, debug
        else:
            return None, self.krbccache, debug

    def getConnection(self, opts):
        """Wrapper around IPAConnPool.getConn() so we don't have to pass
           around self.* every time a connection is needed.

           For SASL connections (where we have a krbccache) we can't set
           the SSL variables for certificates. It confuses the ldap
           module.
        """
        global _LDAPPool

        (proxy_dn, krbccache, debug) = self.__setup_connection(opts)

        if krbccache is not None:
            bindca = None
            bindcert = None
            bindkey = None
            port = self.port
        else:
            raise ipaerror.gen_exception(ipaerror.CONNECTION_NO_CCACHE)

        try:
            conn = _LDAPPool.getConn(self.host,port,krbccache,debug)
        except ldap.INVALID_CREDENTIALS, e:
            raise ipaerror.gen_exception(ipaerror.CONNECTION_GSSAPI_CREDENTIALS, nested_exception=e)

        if conn is None:
            raise ipaerror.gen_exception(ipaerror.CONNECTION_NO_CONN)

        return conn

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

    # TODO: rethink the get_entry vs get_list API calls.
    #       they currently restrict the data coming back without
    #       restricting scope.  For now adding a __get_base/sub_entry()
    #       calls, but the API isn't great.
    def __get_entry (self, base, scope, filter, sattrs=None, opts=None):
        """Get a specific entry (with a parametized scope).
           Return as a dict of values.
           Multi-valued fields are represented as lists.
        """
        ent=""

        conn = self.getConnection(opts)
        try:
            ent = conn.getEntry(base, scope, filter, sattrs)

        finally:
            self.releaseConnection(conn)

        return self.convert_entry(ent)

    def __get_base_entry (self, base, filter, sattrs=None, opts=None):
        """Get a specific entry (with a scope of BASE).
           Return as a dict of values.
           Multi-valued fields are represented as lists.
        """
        return self.__get_entry(base, ldap.SCOPE_BASE, filter, sattrs, opts)

    def __get_sub_entry (self, base, filter, sattrs=None, opts=None):
        """Get a specific entry (with a scope of SUB).
           Return as a dict of values.
           Multi-valued fields are represented as lists.
        """
        return self.__get_entry(base, ldap.SCOPE_SUBTREE, filter, sattrs, opts)

    def __get_list (self, base, filter, sattrs=None, opts=None):
        """Gets a list of entries. Each is converted to a dict of values.
           Multi-valued fields are represented as lists.
        """
        entries = []

        conn = self.getConnection(opts)
        try:
            entries = conn.getList(base, self.scope, filter, sattrs)
        finally:
            self.releaseConnection(conn)

        return map(self.convert_entry, entries)

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

    def __get_schema(self, opts=None):
        """Retrieves the current LDAP schema from the LDAP server."""

        schema_entry = self.__get_base_entry("", "objectclass=*", ['dn','subschemasubentry'], opts)
        schema_cn = schema_entry.get('subschemasubentry')
        schema = self.__get_base_entry(schema_cn, "objectclass=*", ['*'], opts)

        return schema

    def __get_objectclasses(self, opts=None):
        """Returns a list of available objectclasses that the LDAP
           server supports. This parses out the syntax, attributes, etc
           and JUST returns a lower-case list of the names."""

        schema = self.__get_schema(opts)

        objectclasses = schema.get('objectclasses')

        # Convert this list into something more readable
        result = []
        for i in range(len(objectclasses)):
            oc = objectclasses[i].lower().split(" ")
            result.append(oc[3].replace("'",""))

        return result

# Higher-level API

    def get_aci_entry(self, sattrs, opts=None):
        """Returns the entry containing access control ACIs."""

        dn="%s,%s" % (ACIContainer, self.basedn)
        return self.get_entry_by_dn(dn, sattrs, opts)

# General searches

    def get_entry_by_dn (self, dn, sattrs, opts=None):
        """Get a specific entry. Return as a dict of values.
           Multi-valued fields are represented as lists.
        """

        filter = "(objectClass=*)"
        return self.__get_base_entry(dn, filter, sattrs, opts)

    def get_entry_by_cn (self, cn, sattrs, opts=None):
        """Get a specific entry by cn. Return as a dict of values.
           Multi-valued fields are represented as lists.
        """

        cn = self.__safe_filter(cn)
        filter = "(cn=" + cn + ")"
        return self.__get_sub_entry(self.basedn, filter, sattrs, opts)

    def update_entry (self, oldentry, newentry, opts=None):
        """Update an entry in LDAP"""
        return self.__update_entry(oldentry, newentry, opts)

# User support

    def __is_user_unique(self, uid, opts):
        """Return 1 if the uid is unique in the tree, 0 otherwise."""
        uid = self.__safe_filter(uid)
        filter = "(&(uid=%s)(objectclass=posixAccount))" % uid
 
        try:
            entry = self.__get_sub_entry(self.basedn, filter, ['dn','uid'], opts)
            return 0
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return 1

    def get_user_by_uid (self, uid, sattrs, opts=None):
        """Get a specific user's entry. Return as a dict of values.
           Multi-valued fields are represented as lists.
        """

        uid = self.__safe_filter(uid)
        filter = "(uid=" + uid + ")"
        return self.__get_sub_entry(self.basedn, filter, sattrs, opts)

    def get_user_by_principal(self, principal, sattrs, opts=None):
        """Get a user entry searching by Kerberos Principal Name.
           Return as a dict of values. Multi-valued fields are
           represented as lists.
        """

        filter = "(krbPrincipalName="+self.__safe_filter(principal)+")"
        return self.__get_sub_entry(self.basedn, filter, sattrs, opts)

    def get_user_by_email (self, email, sattrs, opts=None):
        """Get a specific user's entry. Return as a dict of values.
           Multi-valued fields are represented as lists.
        """

        email = self.__safe_filter(email)
        filter = "(mail=" + email + ")"
        return self.__get_sub_entry(self.basedn, filter, sattrs, opts)

    def get_users_by_manager (self, manager_dn, sattrs, opts=None):
        """Gets the users that report to a particular manager.
        """

        manager_dn = self.__safe_filter(manager_dn)
        filter = "(&(objectClass=person)(manager=%s))" % manager_dn

        try:
            return self.__get_list(self.basedn, filter, sattrs, opts)
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return []

    def add_user (self, user, user_container, opts=None):
        """Add a user in LDAP. Takes as input a dict where the key is the
           attribute name and the value is either a string or in the case
           of a multi-valued field a list of values. user_container sets
           where in the tree the user is placed."""
        if not user_container:
            user_container = DefaultUserContainer

        if self.__is_user_unique(user['uid'], opts) == 0:
            raise ipaerror.gen_exception(ipaerror.LDAP_DUPLICATE)

        # dn is set here, not by the user
        try:
            del user['dn']
        except KeyError:
            pass

        # No need to set empty fields, and they can cause issues when they
        # get to LDAP, like:
        #     TypeError: ('expected a string in the list', None)
        for k in user.keys():
            if not user[k] or len(user[k]) == 0 or (len(user[k]) == 1 and '' in user[k]):
                del user[k]

        dn="uid=%s,%s,%s" % (ldap.dn.escape_dn_chars(user['uid']),
                             user_container,self.basedn)
        entry = ipaserver.ipaldap.Entry(dn)

        # FIXME: This should be dynamic and can include just about anything

        # Get our configuration
        config = self.get_ipa_config(opts)

        # Let us add in some missing attributes
        if user.get('homedirectory') is None:
            user['homedirectory'] = '%s/%s' % (config.get('ipahomesrootdir'), user.get('uid'))
            user['homedirectory'] = user['homedirectory'].replace('//', '/')
            user['homedirectory'] = user['homedirectory'].rstrip('/')
        if user.get('loginshell') is None:
            user['loginshell'] = config.get('ipadefaultloginshell')
        if user.get('gecos') is None:
            user['gecos'] = user['uid']

        # If uidnumber is blank the the FDS dna_plugin will automatically
        # assign the next value. So we don't have to do anything with it.

        group_dn="cn=%s,%s,%s" % (config.get('ipadefaultprimarygroup'), DefaultGroupContainer, self.basedn)
        try:
            default_group = self.get_entry_by_dn(group_dn, ['dn','gidNumber'], opts)
            if default_group:
                user['gidnumber'] = default_group.get('gidnumber')
        except ipaerror.exception_for(ipaerror.LDAP_DATABASE_ERROR):
            # Fake an LDAP error so we can return something useful to the user
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND, "No default group for new users can be found.")

        if user.get('krbprincipalname') is None:
            user['krbprincipalname'] = "%s@%s" % (user.get('uid'), self.realm)

        # FIXME. This is a hack so we can request separate First and Last
        # name in the GUI.
        if user.get('cn') is None:
            user['cn'] = "%s %s" % (user.get('givenname'),
                                           user.get('sn'))

        if user.get('gn'):
            del user['gn']

        # some required objectclasses
        entry.setValues('objectClass', (config.get('ipauserobjectclasses')))

        # fill in our new entry with everything sent by the user
        for u in user:
            entry.setValues(u, user[u])

        conn = self.getConnection(opts)
        try:
            try:
                res = conn.addEntry(entry)
            except TypeError, e:
                raise ipaerror.gen_exception(ipaerror.LDAP_DATABASE_ERROR, "There is a problem with one of the data types.")
            except Exception, e:
                raise ipaerror.gen_exception(ipaerror.LDAP_DATABASE_ERROR, e)
            try:
                self.add_user_to_group(user.get('uid'), group_dn, opts)
            except Exception, e:
                raise ipaerror.gen_exception(ipaerror.LDAP_DATABASE_ERROR, "The user was created but adding to group %s failed" % group_dn)
        finally:
            self.releaseConnection(conn)
        return res
    
    def get_custom_fields (self, opts=None):
        """Get the list of custom user fields.

           A schema is a list of dict's of the form:
               label: The label dispayed to the user
               field: the attribute name
               required: true/false

           It is displayed to the user in the order of the list.
        """

        config = self.get_ipa_config(opts)

        fields = config.get('ipacustomfields')

        if fields is None or fields == '':
            return []

        fl = fields.split('$')
        schema = []
        for x in range(len(fl)):
            vals = fl[x].split(',')
            if len(vals) != 3:
                # Raise?
                print "Invalid field, skipping"
            d = dict(label=unquote(vals[0]), field=unquote(vals[1]), required=unquote(vals[2]))
            schema.append(d)

        return schema
# radius support

    # clients
    def get_radius_client_by_ip_addr(self, ip_addr, container=None, sattrs=None, opts=None):
        filter = radius_util.radius_client_filter(ip_addr)
        basedn = radius_util.radius_clients_basedn(container, self.basedn)
        return self.__get_sub_entry(basedn, filter, sattrs, opts)

    def __radius_client_exists(self, ip_addr, container, opts):
        filter = radius_util.radius_client_filter(ip_addr)
        basedn = radius_util.radius_clients_basedn(container, self.basedn)
 
        try:
            entry = self.__get_sub_entry(basedn, filter, ['dn','uid'], opts)
            return True
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return False

    def add_radius_client (self, client, container=None, opts=None):
        if container is None:
            container = radius_util.clients_container

        ip_addr = client['radiusClientIPAddress']

        if self.__radius_client_exists(ip_addr, container, opts):
            raise ipaerror.gen_exception(ipaerror.LDAP_DUPLICATE)

        dn = radius_util.radius_client_dn(ip_addr, container, self.basedn)
        entry = ipaserver.ipaldap.Entry(dn)

        # some required objectclasses
        entry.setValues('objectClass', 'top', 'radiusClientProfile')

        # fill in our new entry with everything sent by the client
        for attr in client:
            entry.setValues(attr, client[attr])

        conn = self.getConnection(opts)
        try:
            res = conn.addEntry(entry)
        finally:
            self.releaseConnection(conn)
        return res
    
    def update_radius_client(self, oldentry, newentry, opts=None):
        return self.update_entry(oldentry, newentry, opts)

    def delete_radius_client(self, ip_addr, container=None, opts=None):
        client = self.get_radius_client_by_ip_addr(ip_addr, container, ['dn', 'cn'], opts)
        if client is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        conn = self.getConnection(opts)
        try:
            res = conn.deleteEntry(client['dn'])
        finally:
            self.releaseConnection(conn)
        return res

    def find_radius_clients(self, ip_attrs, container=None, sattrs=None, searchlimit=0, timelimit=-1, opts=None):
        def gen_filter(objectclass, attr, values):
            '''Given ('myclass', 'myattr', [v1, v2]) returns
               (&(objectclass=myclass)(|(myattr=v1)(myattr=v2)))
            '''
            # Don't use __safe_filter, prevents wildcarding
            #attrs = ''.join(['(%s=%s)' % (attr, self.__safe_filter(val)) for val in values])
            attrs = ''.join(['(%s=%s)' % (attr, val) for val in values])
            filter = "(&(objectclass=%s)(|%s))" % (objectclass, attrs)
            return filter

        basedn = radius_util.radius_clients_basedn(container, self.basedn)
        filter = gen_filter('radiusClientProfile', 'radiusClientIPAddress', ip_attrs)
        conn = self.getConnection(opts)
        try:
            try:
                results = conn.getListAsync(basedn, self.scope, filter, sattrs, 0, None, None, timelimit, searchlimit)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                results = [0]
        finally:
            self.releaseConnection(conn)

        counter = results[0]
        results = results[1:]
        radius_clients = [counter]
        for radius_client in results:
            radius_clients.append(self.convert_entry(radius_client))

        return radius_clients

    # profiles
    def get_radius_profile_by_uid(self, uid, user_profile=True, sattrs=None, opts=None):
        if user_profile:
            container = DefaultUserContainer
        else:
            container = radius_util.profiles_container

        uid = self.__safe_filter(uid)
        filter = radius_util.radius_profile_filter(uid)
        basedn = radius_util.radius_profiles_basedn(container, self.basedn)
        return self.__get_sub_entry(basedn, filter, sattrs, opts)

    def __radius_profile_exists(self, uid, user_profile, opts):
        if user_profile:
            container = DefaultUserContainer
        else:
            container = radius_util.profiles_container

        uid = self.__safe_filter(uid)
        filter = radius_util.radius_profile_filter(uid)
        basedn = radius_util.radius_profiles_basedn(container, self.basedn)
 
        try:
            entry = self.__get_sub_entry(basedn, filter, ['dn','uid'], opts)
            return True
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return False

    def add_radius_profile (self, profile, user_profile=True, opts=None):
        uid = profile['uid']

        if self.__radius_profile_exists(uid, user_profile, opts):
            raise ipaerror.gen_exception(ipaerror.LDAP_DUPLICATE)

        if user_profile:
            container = DefaultUserContainer
        else:
            container = radius_util.profiles_container

        dn = radius_util.radius_profile_dn(uid, container, self.basedn)
        entry = ipaserver.ipaldap.Entry(dn)

        # some required objectclasses
        entry.setValues('objectClass', 'top', 'radiusprofile')

        # fill in our new entry with everything sent by the profile
        for attr in profile:
            entry.setValues(attr, profile[attr])

        conn = self.getConnection(opts)
        try:
            res = conn.addEntry(entry)
        finally:
            self.releaseConnection(conn)
        return res
    
    def update_radius_profile(self, oldentry, newentry, opts=None):
        return self.update_entry(oldentry, newentry, opts)

    def delete_radius_profile(self, uid, user_profile, opts=None):
        profile = self.get_radius_profile_by_uid(uid, user_profile, ['dn', 'cn'], opts)
        if profile is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        conn = self.getConnection(opts)
        try:
            res = conn.deleteEntry(profile['dn'])
        finally:
            self.releaseConnection(conn)
        return res

    def find_radius_profiles(self, uids, user_profile=True, sattrs=None, searchlimit=0, timelimit=-1, opts=None):
        def gen_filter(objectclass, attr, values):
            '''Given ('myclass', 'myattr', [v1, v2]) returns
               (&(objectclass=myclass)(|(myattr=v1)(myattr=v2)))
            '''
            # Don't use __safe_filter, prevents wildcarding
            #attrs = ''.join(['(%s=%s)' % (attr, self.__safe_filter(val)) for val in values])
            attrs = ''.join(['(%s=%s)' % (attr, val) for val in values])
            filter = "(&(objectclass=%s)(|%s))" % (objectclass, attrs)
            return filter

        if user_profile:
            container = DefaultUserContainer
        else:
            container = radius_util.profiles_container

        filter = gen_filter('radiusprofile', 'uid', uids)
        basedn="%s,%s" % (container, self.basedn)
        conn = self.getConnection(opts)
        try:
            try:
                results = conn.getListAsync(basedn, self.scope, filter, sattrs, 0, None, None, timelimit, searchlimit)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                results = [0]
        finally:
            self.releaseConnection(conn)

        counter = results[0]
        results = results[1:]
        radius_profiles = [counter]
        for radius_profile in results:
            radius_profiles.append(self.convert_entry(radius_profile))

        return radius_profiles

    def set_custom_fields (self, schema, opts=None):
        """Set the list of custom user fields.

           A schema is a list of dict's of the form:
               label: The label dispayed to the user
               field: the attribute name
               required: true/false

           It is displayed to the user in the order of the list.
        """
        config = self.get_ipa_config(opts)

        # The schema is stored as:
        #     label,field,required$label,field,required$...
        # quote() from urilib is used to ensure that it is easy to unparse

        stored_schema = ""
        for i in range(len(schema)):
            entry = schema[i]
            entry = quote(entry.get('label')) + "," + quote(entry.get('field')) + "," + quote(entry.get('required'))

            if stored_schema != "":
                stored_schema = stored_schema + "$" + entry
            else:
                stored_schema = entry

        new_config = copy.deepcopy(config)
        new_config['ipacustomfields'] = stored_schema

        return self.update_entry(config, new_config, opts)

    def get_all_users (self, opts=None):
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

    def find_users (self, criteria, sattrs, searchlimit=-1, timelimit=-1,
            opts=None):
        """Returns a list: counter followed by the results.
           If the results are truncated, counter will be set to -1."""

        config = self.get_ipa_config(opts)
        if timelimit < 0:
            timelimit = float(config.get('ipasearchtimelimit'))
        if searchlimit < 0:
            searchlimit = float(config.get('ipasearchrecordslimit'))

        # Assume the list of fields to search will come from a central
        # configuration repository.  A good format for that would be
        # a comma-separated list of fields
        search_fields_conf_str = config.get('ipausersearchfields')
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
        exact_match_filter = "(&(objectClass=person)%s)" % exact_match_filter
        partial_match_filter = "(&(objectClass=person)%s)" % partial_match_filter

        conn = self.getConnection(opts)
        try:
            try:
                exact_results = conn.getListAsync(self.basedn, self.scope,
                        exact_match_filter, sattrs, 0, None, None, timelimit,
                        searchlimit)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                exact_results = [0]

            try:
                partial_results = conn.getListAsync(self.basedn, self.scope,
                        partial_match_filter, sattrs, 0, None, None, timelimit,
                        searchlimit)
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

    def update_user (self, oldentry, newentry, opts=None):
        """Wrapper around update_entry with user-specific handling.

           If you want to change the RDN of a user you must use
           this function. update_entry will fail.
        """

        newrdn = 0

        if oldentry.get('uid') != newentry.get('uid'):
            # RDN change
            conn = self.getConnection(opts)
            try:
                res = conn.updateRDN(oldentry.get('dn'), "uid=" + newentry.get('uid'))
                newdn = oldentry.get('dn')
                newdn = newdn.replace("uid=%s" % oldentry.get('uid'), "uid=%s" % newentry.get('uid'))

                # Now fix up the dns and uids so they aren't seen as having
                # changed.
                oldentry['dn'] = newdn
                newentry['dn'] = newdn
                oldentry['uid'] = newentry['uid']
                newrdn = 1
            finally:
                self.releaseConnection(conn)

        # Get our configuration
        config = self.get_ipa_config(opts)

        # Make sure we have the latest object classes
        newentry['objectclass'] = uniq_list(newentry.get('objectclass') + config.get('ipauserobjectclasses'))
        
        try:
           rv = self.update_entry(oldentry, newentry, opts)
           return rv
        except ipaerror.exception_for(ipaerror.LDAP_EMPTY_MODLIST):
           # This means that there was just an rdn change, nothing else.
           if newrdn == 1:
               return "Success"
           else:
               raise

    def mark_entry_active (self, dn, opts=None):
        """Mark an entry as active in LDAP."""

        # This can be tricky. The entry itself can be marked inactive
        # by being in the inactivated group. It can also be inactivated by
        # being the member of an inactive group.
        #
        # First we try to remove the entry from the inactivated group. Then
        # if it is still inactive we have to add it to the activated group
        # which will override the group membership.

        logging.debug("IPA: activating entry %s" % dn)

        res = ""
        # First, check the entry status
        entry = self.get_entry_by_dn(dn, ['dn', 'nsAccountlock'], opts)

        if entry.get('nsaccountlock', 'false') == "false":
            logging.debug("IPA: already active")
            raise ipaerror.gen_exception(ipaerror.LDAP_EMPTY_MODLIST)

        group = self.get_entry_by_cn("inactivated", None, opts)
        res = self.remove_member_from_group(entry.get('dn'), group.get('dn'), opts)

        # Now they aren't a member of inactivated directly, what is the status
        # now?
        entry = self.get_entry_by_dn(dn, ['dn', 'nsAccountlock'], opts)

        if entry.get('nsaccountlock', 'false') == "false":
            # great, we're done
            logging.debug("IPA: removing from inactivated did it.")
            return res

        # So still inactive, add them to activated
        group = self.get_entry_by_cn("activated", None, opts)
        res = self.add_member_to_group(dn, group.get('dn'), opts)
        logging.debug("IPA: added to activated.")

        return res

    def mark_entry_inactive (self, dn, opts=None):
        """Mark an entry as inactive in LDAP."""

        logging.debug("IPA: inactivating entry %s" % dn)

        entry = self.get_entry_by_dn(dn, ['dn', 'nsAccountlock', 'memberOf'], opts)

        if entry.get('nsaccountlock', 'false') == "true":
            logging.debug("IPA: already marked as inactive")
            raise ipaerror.gen_exception(ipaerror.LDAP_EMPTY_MODLIST)

        # First see if they are in the activated group as this will override
        # the our inactivation.
        group = self.get_entry_by_cn("activated", None, opts)
        self.remove_member_from_group(dn, group.get('dn'), opts)

        # Now add them to inactivated
        group = self.get_entry_by_cn("inactivated", None, opts)
        res = self.add_member_to_group(dn, group.get('dn'), opts)
            
        return res

    def mark_user_active(self, uid, opts=None):
        """Mark a user as active"""

        user = self.get_user_by_uid(uid, ['dn', 'uid'], opts)
        return self.mark_entry_active(user.get('dn'))

    def mark_user_inactive(self, uid, opts=None):
        """Mark a user as inactive"""

        user = self.get_user_by_uid(uid, ['dn', 'uid'], opts)
        return self.mark_entry_inactive(user.get('dn'))

    def delete_user (self, uid, opts=None):
        """Delete a user. Not to be confused with inactivate_user. This
           makes the entry go away completely.

           uid is the uid of the user to delete

           The memberOf plugin handles removing the user from any other
           groups.
        """
        user = self.get_user_by_uid(uid, ['dn', 'uid', 'objectclass'], opts)
        if user is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        conn = self.getConnection(opts)
        try:
            res = conn.deleteEntry(user['dn'])
        finally:
            self.releaseConnection(conn)
        return res

    def modifyPassword (self, principal, oldpass, newpass, opts=None):
        """Set/Reset a user's password

           uid tells us who's password to change
           oldpass is the old password (if available)
           newpass is the new password
        """
        user = self.get_user_by_principal(principal, ['krbprincipalname'], opts)
        if user is None or user['krbprincipalname'] != principal:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        conn = self.getConnection(opts)
        try:
            res = conn.modifyPassword(user['dn'], oldpass, newpass)
        finally:
            self.releaseConnection(conn)
        return res

# Group support

    def __is_group_unique(self, cn, opts):
        """Return 1 if the cn is unique in the tree, 0 otherwise."""
        cn = self.__safe_filter(cn)
        filter = "(&(cn=%s)(objectclass=posixGroup))" % cn
 
        try:
            entry = self.__get_sub_entry(self.basedn, filter, ['dn','cn'], opts)
            return 0
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return 1

    def get_groups_by_member (self, member_dn, sattrs, opts=None):
        """Get a specific group's entry. Return as a dict of values.
           Multi-valued fields are represented as lists.
        """

        member_dn = self.__safe_filter(member_dn)
        filter = "(&(objectClass=posixGroup)(member=%s))" % member_dn

        try:
            return self.__get_list(self.basedn, filter, sattrs, opts)
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return []

    def add_group (self, group, group_container, opts=None):
        """Add a group in LDAP. Takes as input a dict where the key is the
           attribute name and the value is either a string or in the case
           of a multi-valued field a list of values. group_container sets
           where in the tree the group is placed."""
        if not group_container:
            group_container = DefaultGroupContainer

        if self.__is_group_unique(group['cn'], opts) == 0:
            raise ipaerror.gen_exception(ipaerror.LDAP_DUPLICATE)

        # Get our configuration
        config = self.get_ipa_config(opts)

        dn="cn=%s,%s,%s" % (ldap.dn.escape_dn_chars(group['cn']),
                            group_container,self.basedn)
        entry = ipaserver.ipaldap.Entry(dn)

        # some required objectclasses
        entry.setValues('objectClass', (config.get('ipagroupobjectclasses')))

        # No need to explicitly set gidNumber. The dna_plugin will do this
        # for us if the value isn't provided by the user.

        # fill in our new entry with everything sent by the user
        for g in group:
            entry.setValues(g, group[g])

        conn = self.getConnection(opts)
        try:
            res = conn.addEntry(entry)
        finally:
            self.releaseConnection(conn)

    def find_groups (self, criteria, sattrs, searchlimit=-1, timelimit=-1,
            opts=None):
        """Return a list containing a User object for each
        existing group that matches the criteria.
        """

        config = self.get_ipa_config(opts)
        if timelimit < 0:
            timelimit = float(config.get('ipasearchtimelimit'))
        if searchlimit < 0:
            searchlimit = float(config.get('ipasearchrecordslimit'))

        # Assume the list of fields to search will come from a central
        # configuration repository.  A good format for that would be
        # a comma-separated list of fields
        search_fields_conf_str = config.get('ipagroupsearchfields')
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
                        exact_match_filter, sattrs, 0, None, None, timelimit,
                        searchlimit)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                exact_results = [0]

            try:
                partial_results = conn.getListAsync(self.basedn, self.scope,
                        partial_match_filter, sattrs, 0, None, None, timelimit,
                        searchlimit)
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

    def add_member_to_group(self, member_dn, group_dn, opts=None):
        """Add a member to an existing group.
        """

        old_group = self.get_entry_by_dn(group_dn, None, opts)
        if old_group is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)
        new_group = copy.deepcopy(old_group)

        # check to make sure member_dn exists
        member_entry = self.__get_base_entry(member_dn, "(objectClass=*)", ['dn','uid'], opts)

        if new_group.get('member') is not None:
            if ((isinstance(new_group.get('member'), str)) or (isinstance(new_group.get('member'), unicode))):
                new_group['member'] = [new_group['member']]
            new_group['member'].append(member_dn)
        else:
            new_group['member'] = member_dn

        try:
            ret = self.__update_entry(old_group, new_group, opts)
        except ipaerror.exception_for(ipaerror.LDAP_EMPTY_MODLIST):
            raise
        return ret

    def add_members_to_group(self, member_dns, group_dn, opts=None):
        """Given a list of dn's, add them to the group cn denoted by group
           Returns a list of the member_dns that were not added to the group.
        """

        failed = []

        if (isinstance(member_dns, str)):
            member_dns = [member_dns]

        for member_dn in member_dns:
            try:
                self.add_member_to_group(member_dn, group_dn, opts)
            except ipaerror.exception_for(ipaerror.LDAP_EMPTY_MODLIST):
                # User is already in the group
                failed.append(member_dn)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                # User or the group does not exist
                failed.append(member_dn)

        return failed

    def remove_member_from_group(self, member_dn, group_dn, opts=None):
        """Remove a member_dn from an existing group.
        """

        old_group = self.get_entry_by_dn(group_dn, None, opts)
        if old_group is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)
        new_group = copy.deepcopy(old_group)

        if new_group.get('member') is not None:
            if ((isinstance(new_group.get('member'), str)) or (isinstance(new_group.get('member'), unicode))):
                new_group['member'] = [new_group['member']]
            try:
                new_group['member'].remove(member_dn)
            except ValueError:
                # member is not in the group
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

    def remove_members_from_group(self, member_dns, group_dn, opts=None):
        """Given a list of member dn's remove them from the group.
           Returns a list of the members not removed from the group.
        """

        failed = []

        if (isinstance(member_dns, str)):
            member_dns = [member_dns]

        for member_dn in member_dns:
            try:
                self.remove_member_from_group(member_dn, group_dn, opts)
            except ipaerror.exception_for(ipaerror.LDAP_EMPTY_MODLIST):
                # member is not in the group
                failed.append(member_dn)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                # member_dn or the group does not exist
                failed.append(member_dn)

        return failed

    def add_user_to_group(self, user_uid, group_dn, opts=None):
        """Add a user to an existing group.
        """

        user = self.get_user_by_uid(user_uid, ['dn', 'uid', 'objectclass'], opts)
        if user is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        return self.add_member_to_group(user['dn'], group_dn, opts)

    def add_users_to_group(self, user_uids, group_dn, opts=None):
        """Given a list of user uid's add them to the group cn denoted by group
           Returns a list of the users were not added to the group.
        """

        failed = []

        if (isinstance(user_uids, str)):
            user_uids = [user_uids]

        for user_uid in user_uids:
            try:
                self.add_user_to_group(user_uid, group_dn, opts)
            except ipaerror.exception_for(ipaerror.LDAP_EMPTY_MODLIST):
                # User is already in the group
                failed.append(user_uid)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                # User or the group does not exist
                failed.append(user_uid)

        return failed

    def remove_user_from_group(self, user_uid, group_dn, opts=None):
        """Remove a user from an existing group.
        """

        user = self.get_user_by_uid(user_uid, ['dn', 'uid', 'objectclass'], opts)
        if user is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        return self.remove_member_from_group(user['dn'], group_dn, opts)

    def remove_users_from_group(self, user_uids, group_dn, opts=None):
        """Given a list of user uid's remove them from the group
           Returns a list of the user uids not removed from the group.
        """

        failed = []

        if (isinstance(user_uids, str)):
            user_uids = [user_uids]

        for user_uid in user_uids:
            try:
                self.remove_user_from_group(user_uid, group_dn, opts)
            except ipaerror.exception_for(ipaerror.LDAP_EMPTY_MODLIST):
                # User is not in the group
                failed.append(user_uid)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                # User or the group does not exist
                failed.append(user_uid)

        return failed

    def add_groups_to_user(self, group_dns, user_dn, opts=None):
        """Given a list of group dn's add them to the user.

           Returns a list of the group dns that were not added.
        """

        failed = []

        if (isinstance(group_dns, str)):
            group_dns = [group_dns]

        for group_dn in group_dns:
            try:
                self.add_member_to_group(user_dn, group_dn, opts)
            except ipaerror.exception_for(ipaerror.LDAP_EMPTY_MODLIST):
                # User is already in the group
                failed.append(group_dn)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                # User or the group does not exist
                failed.append(group_dn)

        return failed

    def remove_groups_from_user(self, group_dns, user_dn, opts=None):
        """Given a list of group dn's remove them from the user.

           Returns a list of the group dns that were not removed.
        """

        failed = []

        if (isinstance(group_dns, str)):
            group_dns = [group_dns]

        for group_dn in group_dns:
            try:
                self.remove_member_from_group(user_dn, group_dn, opts)
            except ipaerror.exception_for(ipaerror.LDAP_EMPTY_MODLIST):
                # User is not in the group
                failed.append(group_dn)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                # User or the group does not exist
                failed.append(group_dn)

        return failed

    def update_group (self, oldentry, newentry, opts=None):
        """Wrapper around update_entry with group-specific handling.

           If you want to change the RDN of a group you must use
           this function. update_entry will fail.
        """

        newrdn = 0

        oldcn=oldentry.get('cn')
        newcn=newentry.get('cn')
        if isinstance(oldcn, str):
            oldcn = [oldcn]
        if isinstance(newcn, str):
            newcn = [newcn]

        oldcn.sort()
        newcn.sort()
        if oldcn != newcn:
            # RDN change
            conn = self.getConnection(opts)
            try:
                res = conn.updateRDN(oldentry.get('dn'), "cn=" + newcn[0])
                newdn = oldentry.get('dn')
                newcn = newentry.get('cn')
                if isinstance(newcn, str):
                    newcn = [newcn]

                # Ick. Need to find the exact cn used in the old DN so we'll
                # walk the list of cns and skip the obviously bad ones:
                for c in oldentry.get('dn').split("cn="):
                    if c and c != "groups" and not c.startswith("accounts"):
                        newdn = newdn.replace("cn=%s" % c, "cn=%s," % newcn[0])
                        break

                # Now fix up the dns and cns so they aren't seen as having
                # changed.
                oldentry['dn'] = newdn
                newentry['dn'] = newdn
                oldentry['cn'] = newentry.get('cn')
                newrdn = 1
            finally:
                self.releaseConnection(conn)

        # Get our configuration
        config = self.get_ipa_config(opts)

        # Make sure we have the latest object classes
        newentry['objectclass'] = uniq_list(newentry.get('objectclass') + config.get('ipagroupobjectclasses'))

        try:
           rv = self.update_entry(oldentry, newentry, opts)
           return rv
        except ipaerror.exception_for(ipaerror.LDAP_EMPTY_MODLIST):
           if newrdn == 1:
               # This means that there was just the rdn change, no other
               # attributes
               return "Success"
           else:
               raise

    def delete_group (self, group_dn, opts=None):
        """Delete a group
           group_dn is the DN of the group to delete

           The memberOf plugin handles removing the group from any other
           groups.
        """
        group = self.get_entry_by_dn(group_dn, ['dn', 'cn'], opts)
        if group is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        # We have 2 special groups, don't allow them to be removed
        if "admins" in group.get('cn') or "editors" in group.get('cn'):
            raise ipaerror.gen_exception(ipaerror.CONFIG_REQUIRED_GROUPS)

        # Don't allow the default user group to be removed
        config=self.get_ipa_config(opts)
        default_group = self.get_entry_by_cn(config.get('ipadefaultprimarygroup'), None, opts)
        if group_dn == default_group.get('dn'):
            raise ipaerror.gen_exception(ipaerror.CONFIG_DEFAULT_GROUP)

        conn = self.getConnection(opts)
        try:
            res = conn.deleteEntry(group_dn)
        finally:
            self.releaseConnection(conn)
        return res

    def add_group_to_group(self, group, tgroup, opts=None):
        """Add a user to an existing group.
           group is a DN of the group to add
           tgroup is the DN of the target group to be added to
        """

        old_group = self.get_entry_by_dn(tgroup, None, opts)
        if old_group is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)
        new_group = copy.deepcopy(old_group)

        group_dn = self.get_entry_by_dn(group, ['dn', 'cn', 'objectclass'], opts)
        if group_dn is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        if new_group.get('member') is not None:
            if ((isinstance(new_group.get('member'), str)) or (isinstance(new_group.get('member'), unicode))):
                new_group['member'] = [new_group['member']]
            new_group['member'].append(group_dn['dn'])
        else:
            new_group['member'] = group_dn['dn']

        try:
            ret = self.__update_entry(old_group, new_group, opts)
        except ipaerror.exception_for(ipaerror.LDAP_EMPTY_MODLIST):
            raise
        return ret

    def attrs_to_labels(self, attr_list, opts=None):
        """Take a list of LDAP attributes and convert them to more friendly
           labels."""
        label_list = {}

        for a in attr_list:
            label_list[a] = attrs.attr_label_list.get(a,a)

        return label_list

    def group_members(self, groupdn, attr_list, opts=None):
        """Do a memberOf search of groupdn and return the attributes in
           attr_list (an empty list returns everything)."""

        config = self.get_ipa_config(opts)
        timelimit = float(config.get('ipasearchtimelimit'))

        searchlimit = float(config.get('ipasearchrecordslimit'))

        groupdn = self.__safe_filter(groupdn)
        filter = "(memberOf=%s)" % groupdn

        conn = self.getConnection(opts)
        try:
            try:
                results = conn.getListAsync(self.basedn, self.scope,
                    filter, attr_list, 0, None, None, timelimit,
                    searchlimit)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                results = [0]
        finally:
            self.releaseConnection(conn)

        counter = results[0]
        results = results[1:]

        entries = [counter]
        for e in results:
            entries.append(self.convert_entry(e))

        return entries

    def mark_group_active(self, cn, opts=None):
        """Mark a group as active"""

        group = self.get_entry_by_cn(cn, ['dn', 'cn'], opts)
        return self.mark_entry_active(group.get('dn'))

    def mark_group_inactive(self, cn, opts=None):
        """Mark a group as inactive"""

        group = self.get_entry_by_cn(cn, ['dn', 'uid'], opts)
        return self.mark_entry_inactive(group.get('dn'))

    def __is_service_unique(self, name, opts):
        """Return 1 if the uid is unique in the tree, 0 otherwise."""
        name = self.__safe_filter(name)
        filter = "(&(krbprincipalname=%s)(objectclass=krbPrincipal))" % name
 
        try:
            entry = self.__get_sub_entry(self.basedn, filter, ['dn','krbprincipalname'], opts)
            return 0
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return 1

    def add_service_principal(self, name, opts=None):
        service_container = DefaultServiceContainer

        princ_name = name + "@" + self.realm
        
        conn = self.getConnection(opts)
        if self.__is_service_unique(name, opts) == 0:
            raise ipaerror.gen_exception(ipaerror.LDAP_DUPLICATE)

        dn = "krbprincipalname=%s,%s,%s" % (ldap.dn.escape_dn_chars(princ_name),
                                            service_container,self.basedn)
        entry = ipaserver.ipaldap.Entry(dn)

        entry.setValues('objectclass', 'krbPrincipal', 'krbPrincipalAux', 'krbTicketPolicyAux')
        entry.setValues('krbprincipalname', princ_name)
        
        try:
            res = conn.addEntry(entry)
        finally:
            self.releaseConnection(conn)
        return res

    def find_service_principal(self, criteria, sattrs, searchlimit=-1,
            timelimit=-1, opts=None):
        """Returns a list: counter followed by the results.
           If the results are truncated, counter will be set to -1."""

        config = self.get_ipa_config(opts)
        if timelimit < 0:
            timelimit = float(config.get('ipasearchtimelimit'))
        if searchlimit < 0:
            searchlimit = float(config.get('ipasearchrecordslimit'))

        search_fields = ["krbprincipalname"]

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
        exact_match_filter = "(&(objectclass=krbPrincipalAux)(!(objectClass=person))(!(krbprincipalname=kadmin/*))%s)" % exact_match_filter
        partial_match_filter = "(&(objectclass=krbPrincipalAux)(!(objectClass=person))(!(krbprincipalname=kadmin/*))%s)" % partial_match_filter

        conn = self.getConnection(opts)
        try:
            try:
                exact_results = conn.getListAsync(self.basedn, self.scope,
                        exact_match_filter, sattrs, 0, None, None, timelimit,
                        searchlimit)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                exact_results = [0]

            try:
                partial_results = conn.getListAsync(self.basedn, self.scope,
                        partial_match_filter, sattrs, 0, None, None, timelimit,
                        searchlimit)
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

        entries = [counter]
        for e in exact_results + partial_results:
            entries.append(self.convert_entry(e))

        return entries

    def get_keytab(self, name, opts=None):
        """get a keytab"""

        princ_name = name + "@" + self.realm

        conn = self.getConnection(opts)

        if conn.principal != "admin@" + self.realm:
            raise ipaerror.gen_exception(ipaerror.CONNECTION_GSSAPI_CREDENTIALS)

        try:
            try:
                princs = conn.getList(self.basedn, self.scope, "krbprincipalname=" + princ_name, None)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                return None
        finally:
            self.releaseConnection(conn)


        # This is ugly - call out to a C wrapper around kadmin.local
        p = subprocess.Popen(["/usr/sbin/ipa-keytab-util", princ_name, self.realm],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout,stderr = p.communicate()

        if p.returncode != 0:
            return None

        return stdout
        
        

# Configuration support
    def get_ipa_config(self, opts=None):
        """Retrieve the IPA configuration"""
        try:
            config = self.get_entry_by_cn("ipaconfig", None, opts)
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            raise ipaerror.gen_exception(ipaerror.LDAP_NO_CONFIG)

        return config

    def update_ipa_config(self, oldconfig, newconfig, opts=None):
        """Update the IPA configuration"""
 
        # The LDAP routines want strings, not ints, so convert a few
        # things. Otherwise it sees a string -> int conversion as a change.
        try:
            newconfig['ipapwdexpadvnotify'] = str(newconfig.get('ipapwdexpadvnotify'))
            newconfig['ipasearchtimelimit'] = str(newconfig.get('ipasearchtimelimit'))
            newconfig['ipasearchrecordslimit'] = str(newconfig.get('ipasearchrecordslimit'))
            newconfig['ipamaxusernamelength'] = str(newconfig.get('ipamaxusernamelength'))
        except KeyError:
            # These should all be there but if not, let things proceed
            pass

        # Ensure that the default group for users exists
        try:
            group = self.get_entry_by_cn(newconfig.get('ipadefaultprimarygroup'), None, opts)
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            raise
        except:
            raise 

        # Run through the list of User and Group object classes to make
        # sure they are all valid. This doesn't handle dependencies but it
        # will at least catch typos.
        classes = self.__get_objectclasses(opts)
        oc = newconfig['ipauserobjectclasses']
        for i in range(len(oc)):
            if not oc[i].lower() in classes:
                raise ipaerror.gen_exception(ipaerror.CONFIG_INVALID_OC)
        oc = newconfig['ipagroupobjectclasses']
        for i in range(len(oc)):
            if not oc[i].lower() in classes:
                raise ipaerror.gen_exception(ipaerror.CONFIG_INVALID_OC)

        return self.update_entry(oldconfig, newconfig, opts)

    def get_password_policy(self, opts=None):
        """Retrieve the IPA password policy"""
        try:
            policy = self.get_entry_by_cn("accounts", None, opts)
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            raise ipaerror.gen_exception(ipaerror.LDAP_NO_CONFIG)

        # convert some values for display purposes
        policy['krbmaxpwdlife'] = str(int(policy.get('krbmaxpwdlife')) / 86400)
        policy['krbminpwdlife'] = str(int(policy.get('krbminpwdlife')) / 3600)

        return policy

    def update_password_policy(self, oldpolicy, newpolicy, opts=None):
        """Update the IPA configuration"""

        # The LDAP routines want strings, not ints, so convert a few
        # things. Otherwise it sees a string -> int conversion as a change.
        try:
            for k in oldpolicy.iterkeys():
                if k.startswith("krb", 0, 3):
                    oldpolicy[k] = str(oldpolicy[k])
            for k in newpolicy.iterkeys():
                if k.startswith("krb", 0, 3):
                    newpolicy[k] = str(newpolicy[k])

            # Convert hours and days to seconds       
            oldpolicy['krbmaxpwdlife'] = str(int(oldpolicy.get('krbmaxpwdlife')) * 86400)
            oldpolicy['krbminpwdlife'] = str(int(oldpolicy.get('krbminpwdlife')) * 3600)
            newpolicy['krbmaxpwdlife'] = str(int(newpolicy.get('krbmaxpwdlife')) * 86400)
            newpolicy['krbminpwdlife'] = str(int(newpolicy.get('krbminpwdlife')) * 3600)
        except KeyError:
            # These should all be there but if not, let things proceed
            pass
        except:
            # Anything else raise an error
            raise

        return self.update_entry(oldpolicy, newpolicy, opts)

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
    elif value =='\x00':
        return r'\00'
    else:
        return value

def uniq_list(x):
    """Return a unique list, preserving order and ignoring case"""
    set = {}
    return [set.setdefault(e,e) for e in x if e.lower() not in set]
