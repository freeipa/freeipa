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

import krbV
import ldap
import ldap.dn
import ipaserver.dsinstance
import ipaserver.ipaldap
import copy
from ipaserver import attrs
from ipa import version
from ipa import ipaerror
from ipa import ipautil
from urllib import quote,unquote
from ipa import radius_util
from ipa import dnsclient

import string
from types import *
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
        except ldap.UNWILLING_TO_PERFORM:
            raise ipaerror.gen_exception(ipaerror.CONNECTION_UNWILLING)
        except Exception, e:
            raise ipaerror.gen_exception(ipaerror.CONNECTION_NO_CONN, nested_exception=e)

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
        self.basedn = ipautil.realm_to_suffix(self.realm)
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
        searchfilter = "(krbPrincipalName=" + princ + ")"
        # The only anonymous search we should have
        conn = _LDAPPool.getConn(self.host,self.sslport,self.bindca,self.bindcert,self.bindkey,None,None,debug)
        try:
            ent = conn.getEntry(self.basedn, self.scope, searchfilter, ['dn'])
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
    def __get_entry (self, base, scope, searchfilter, sattrs=None, opts=None):
        """Get a specific entry (with a parametized scope).
           Return as a dict of values.
           Multi-valued fields are represented as lists.
        """
        ent=""

        conn = self.getConnection(opts)
        try:
            ent = conn.getEntry(base, scope, searchfilter, sattrs)

        finally:
            self.releaseConnection(conn)

        return self.convert_entry(ent)

    def __get_base_entry (self, base, searchfilter, sattrs=None, opts=None):
        """Get a specific entry (with a scope of BASE).
           Return as a dict of values.
           Multi-valued fields are represented as lists.
        """
        return self.__get_entry(base, ldap.SCOPE_BASE, searchfilter, sattrs, opts)

    def __get_sub_entry (self, base, searchfilter, sattrs=None, opts=None):
        """Get a specific entry (with a scope of SUB).
           Return as a dict of values.
           Multi-valued fields are represented as lists.
        """
        return self.__get_entry(base, ldap.SCOPE_SUBTREE, searchfilter, sattrs, opts)

    def __get_list (self, base, searchfilter, sattrs=None, opts=None):
        """Gets a list of entries. Each is converted to a dict of values.
           Multi-valued fields are represented as lists.
        """
        entries = []

        conn = self.getConnection(opts)
        try:
            entries = conn.getList(base, self.scope, searchfilter, sattrs)
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
        except KeyError:
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
        partial_match_filter = "(|"
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

    def __has_nsaccountlock(self, dn, opts):
        """Check to see if an entry has the nsaccountlock attribute.
           This attribute is provided by the Class of Service plugin so
           doing a search isn't enough. It is provided by the two
           entries cn=inactivated and cn=activated. So if the entry has
           the attribute and isn't in either cn=activated or cn=inactivated
           then the attribute must be in the entry itself.

           Returns True or False
        """
        # First get the entry. If it doesn't have nsaccountlock at all we
        # can exit early.
        entry = self.get_entry_by_dn(dn, ['dn', 'nsaccountlock', 'memberof'], opts)
        if not entry.get('nsaccountlock'):
            return False

        # Now look to see if they are in activated or inactivated
        # entry is a member
        memberof = entry.get('memberof')
        if isinstance(memberof, basestring):
            memberof = [memberof]
        for m in memberof:
            inactivated = m.find("cn=inactivated")
            activated = m.find("cn=activated")
            # if they are in either group that means that the nsaccountlock
            # value comes from there, otherwise it must be in this entry.
            if inactivated >= 0 or activated >= 0:
                return False
        
        return True

# Higher-level API
    def version(self, opts=None):
       """The version of IPA"""
       logging.debug("IPA: version %d" % version.NUM_VERSION)
       return version.NUM_VERSION

    def get_aci_entry(self, sattrs, opts=None):
        """Returns the entry containing access control ACIs."""
        
        if sattrs is not None and not isinstance(sattrs,list):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        logging.info("IPA: get_aci_entry")

        dn="%s,%s" % (ACIContainer, self.basedn)
        return self.get_entry_by_dn(dn, sattrs, opts)

# General searches

    def get_entry_by_dn (self, dn, sattrs, opts=None):
        """Get a specific entry. Return as a dict of values.
           Multi-valued fields are represented as lists.
        """
        if not isinstance(dn,basestring) or len(dn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if sattrs is not None and not isinstance(sattrs,list):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        searchfilter = "(objectClass=*)"
        logging.info("IPA: get_entry_by_dn '%s'" % dn)
        return self.__get_base_entry(dn, searchfilter, sattrs, opts)

    def get_entry_by_cn (self, cn, sattrs, opts=None):
        """Get a specific entry by cn. Return as a dict of values.
           Multi-valued fields are represented as lists.
        """

        if not isinstance(cn,basestring) or len(cn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if sattrs is not None and not isinstance(sattrs,list):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        logging.info("IPA: get_entry_by_cn '%s'" % cn)
        cn = self.__safe_filter(cn)
        searchfilter = "(cn=" + cn + ")"
        return self.__get_sub_entry(self.basedn, searchfilter, sattrs, opts)

    def update_entry (self, oldentry, newentry, opts=None):
        """Update an entry in LDAP

           oldentry and newentry are XML-RPC structs.

           If oldentry is not empty then it is used when determine what
           has changed.

           If oldentry is empty then the value of newentry is compared
           to the current value of oldentry.
        """
        if not newentry:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        if not oldentry:
            oldentry = self.get_entry_by_dn(newentry.get('dn'), None, opts)
            if oldentry is None:
                raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        logging.info("IPA: update_entry '%s'" % newentry.get('dn'))
        return self.__update_entry(oldentry, newentry, opts)

# User support

    def __is_user_unique(self, uid, opts):
        """Return True if the uid is unique in the tree, False otherwise."""
        uid = self.__safe_filter(uid)
        searchfilter = "(&(uid=%s)(objectclass=posixAccount))" % uid
 
        try:
            entry = self.__get_sub_entry(self.basedn, searchfilter, ['dn','uid'], opts)
            return False
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return True

    def __uid_too_long(self, uid, opts):
        """Verify that the new uid is within the limits we set. This is a
           very narrow test.

           Returns True if it is longer than allowed
                   False otherwise
        """
        if not isinstance(uid,basestring) or len(uid) == 0:
            # It is bad, but not too long
            return False
        logging.debug("IPA: __uid_too_long(%s)" % uid)
        try:
            config = self.get_ipa_config(opts)
            maxlen = int(config.get('ipamaxusernamelength', 0))
            if maxlen > 0 and len(uid) > maxlen:
                return True
        except Exception, e:
            logging.debug("There was a problem " + str(e))

        return False

    def get_user_by_uid (self, uid, sattrs, opts=None):
        """Get a specific user's entry. Return as a dict of values.
           Multi-valued fields are represented as lists.
        """

        if not isinstance(uid,basestring) or len(uid) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if sattrs is not None and not isinstance(sattrs,list):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        logging.info("IPA: get_user_by_uid '%s'" % uid)
        uid = self.__safe_filter(uid)
        searchfilter = "(uid=" + uid + ")"
        return self.__get_sub_entry(self.basedn, searchfilter, sattrs, opts)

    def get_user_by_principal(self, principal, sattrs, opts=None):
        """Get a user entry searching by Kerberos Principal Name.
           Return as a dict of values. Multi-valued fields are
           represented as lists.
        """

        if not isinstance(principal,basestring) or len(principal) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if sattrs is not None and not isinstance(sattrs,list):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        searchfilter = "(krbPrincipalName="+self.__safe_filter(principal)+")"
        logging.info("IPA: get_user_by_principal '%s'" % principal)
        return self.__get_sub_entry(self.basedn, searchfilter, sattrs, opts)

    def get_user_by_email (self, email, sattrs, opts=None):
        """Get a specific user's entry. Return as a dict of values.
           Multi-valued fields are represented as lists.
        """

        if not isinstance(email,basestring) or len(email) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if sattrs is not None and not isinstance(sattrs,list):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        logging.info("IPA: get_user_by_email '%s'" % email)
        email = self.__safe_filter(email)
        searchfilter = "(mail=" + email + ")"
        return self.__get_sub_entry(self.basedn, searchfilter, sattrs, opts)

    def get_users_by_manager (self, manager_dn, sattrs, opts=None):
        """Gets the users that report to a particular manager.
        """

        if not isinstance(manager_dn,basestring) or len(manager_dn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if sattrs is not None and not isinstance(sattrs,list):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        logging.info("IPA: get_user_by_manager '%s'" % manager_dn)
        manager_dn = self.__safe_filter(manager_dn)
        searchfilter = "(&(objectClass=person)(manager=%s))" % manager_dn

        try:
            return self.__get_list(self.basedn, searchfilter, sattrs, opts)
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return []

    def add_user (self, user, user_container, opts=None):
        """Add a user in LDAP. Takes as input a dict where the key is the
           attribute name and the value is either a string or in the case
           of a multi-valued field a list of values. user_container sets
           where in the tree the user is placed.
        """
        logging.info("IPA: add_user")
        if not user_container:
            user_container = DefaultUserContainer

        if not isinstance(user,dict):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(user_container,basestring) or len(user_container) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        if not self.__is_user_unique(user['uid'], opts):
            raise ipaerror.gen_exception(ipaerror.LDAP_DUPLICATE)
        if self.__uid_too_long(user['uid'], opts):
            raise ipaerror.gen_exception(ipaerror.INPUT_UID_TOO_LONG)

        # dn is set here, not by the user
        try:
            del user['dn']
        except KeyError:
            pass

        # No need to set empty fields, and they can cause issues when they
        # get to LDAP, like:
        #     TypeError: ('expected a string in the list', None)
        for k in user.keys():
            if not user[k] or len(user[k]) == 0 or (isinstance(user[k],list) and len(user[k]) == 1 and '' in user[k]):
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
        except ipaerror.exception_for(ipaerror.LDAP_DATABASE_ERROR), e:
            raise ipaerror.gen_exception(ipaerror.LDAP_DATABASE_ERROR, message=None, nested_exception=e.detail)
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
            except ipaerror.exception_for(ipaerror.LDAP_DATABASE_ERROR), e:
                raise ipaerror.gen_exception(ipaerror.LDAP_DATABASE_ERROR, message=None, nested_exception=e.detail)
            except Exception, e:
                raise ipaerror.gen_exception(ipaerror.LDAP_DATABASE_ERROR, nested_exception=e)
            try:
                self.add_user_to_group(user.get('uid'), group_dn, opts)
            except ipaerror.exception_for(ipaerror.LDAP_DATABASE_ERROR), e:
                raise ipaerror.gen_exception(ipaerror.LDAP_DATABASE_ERROR, message=None, nested_exception=e.detail)
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
                logging.debug("IPA: Invalid field, skipping: %s", vals)
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

    def find_radius_clients(self, ip_attrs, container=None, sattrs=None, sizelimit=-1, timelimit=-1, opts=None):
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
                results = conn.getListAsync(basedn, self.scope, filter, sattrs, 0, None, None, timelimit, sizelimit)
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

    def find_radius_profiles(self, uids, user_profile=True, sattrs=None, sizelimit=-1, timelimit=-1, opts=None):
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
                results = conn.getListAsync(basedn, self.scope, filter, sattrs, 0, None, None, timelimit, sizelimit)
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
        if not isinstance(schema,basestring) or len(schema) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

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
        logging.info("IPA: get_all_users")
        searchfilter = "(objectclass=posixAccount)"

        conn = self.getConnection(opts)
        try:
            all_users = conn.getList(self.basedn, self.scope, searchfilter, None)
        finally:
            self.releaseConnection(conn)
    
        users = []
        for u in all_users:
            users.append(self.convert_entry(u))
    
        return users

    def find_users (self, criteria, sattrs, sizelimit=-1, timelimit=-1,
            opts=None):
        """Returns a list: counter followed by the results.
           If the results are truncated, counter will be set to -1."""

        if not isinstance(criteria,basestring) or len(criteria) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if sattrs is not None and not isinstance(sattrs, list):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(sizelimit,int):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(timelimit,int):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        logging.info("IPA: find_users '%s'" % criteria)
        config = self.get_ipa_config(opts)
        if timelimit < 0:
            timelimit = float(config.get('ipasearchtimelimit'))
        if sizelimit < 0:
            sizelimit = int(config.get('ipasearchrecordslimit'))

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
                        sizelimit)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                exact_results = [0]

            try:
                partial_results = conn.getListAsync(self.basedn, self.scope,
                        partial_match_filter, sattrs, 0, None, None, timelimit,
                        sizelimit)
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
        if not orig_dict or not isinstance(orig_dict, dict):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        new_dict={}
        for (k,v) in orig_dict.iteritems():
            if not isinstance(v, list) and k != 'dn':
                v = [v]
            new_dict[k] = v

        return new_dict

    def update_user (self, oldentry, newentry, opts=None):
        """Wrapper around update_entry with user-specific handling.

           oldentry and newentry are XML-RPC structs.

           If oldentry is not empty then it is used when determine what
           has changed.

           If oldentry is empty then the value of newentry is compared
           to the current value of oldentry.

           If you want to change the RDN of a user you must use
           this function. update_entry will fail.
        """
        logging.info("IPA: update_user")
        if not isinstance(newentry,dict):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if oldentry and not isinstance(oldentry,dict):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not oldentry:
            oldentry = self.get_entry_by_dn(newentry.get('dn'), None, opts)
            if oldentry is None:
                raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        newrdn = 0

        if oldentry.get('uid') != newentry.get('uid'):
            if self.__uid_too_long(newentry.get('uid'), opts):
                raise ipaerror.gen_exception(ipaerror.INPUT_UID_TOO_LONG)
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
        # newentry['objectclass'] = uniq_list(newentry.get('objectclass') + config.get('ipauserobjectclasses'))
        
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

        if not dn:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        res = ""
        # First, check the entry status
        entry = self.get_entry_by_dn(dn, ['dn', 'nsAccountlock'], opts)

        if entry.get('nsaccountlock', 'false').lower() == "false":
            logging.debug("IPA: already active")
            raise ipaerror.gen_exception(ipaerror.STATUS_ALREADY_ACTIVE)

        if self.__has_nsaccountlock(dn, opts):
            logging.debug("IPA: appears to have the nsaccountlock attribute")
            raise ipaerror.gen_exception(ipaerror.STATUS_HAS_NSACCOUNTLOCK)

        group = self.get_entry_by_cn("inactivated", None, opts)
        try:
            self.remove_member_from_group(entry.get('dn'), group.get('dn'), opts)
        except ipaerror.exception_for(ipaerror.STATUS_NOT_GROUP_MEMBER):
            # Perhaps the user is there as a result of group membership
            pass

        # Now they aren't a member of inactivated directly, what is the status
        # now?
        entry = self.get_entry_by_dn(dn, ['dn', 'nsAccountlock'], opts)

        if entry.get('nsaccountlock', 'false').lower() == "false":
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

        if not dn:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        entry = self.get_entry_by_dn(dn, ['dn', 'nsAccountlock', 'memberOf'], opts)

        if entry.get('nsaccountlock', 'false').lower() == "true":
            logging.debug("IPA: already marked as inactive")
            raise ipaerror.gen_exception(ipaerror.STATUS_ALREADY_INACTIVE)

        if self.__has_nsaccountlock(dn, opts):
            logging.debug("IPA: appears to have the nsaccountlock attribute")
            raise ipaerror.gen_exception(ipaerror.STATUS_HAS_NSACCOUNTLOCK)

        # First see if they are in the activated group as this will override
        # the our inactivation.
        group = self.get_entry_by_cn("activated", None, opts)
        try:
            self.remove_member_from_group(dn, group.get('dn'), opts)
        except ipaerror.exception_for(ipaerror.STATUS_NOT_GROUP_MEMBER):
            # this is fine, they may not be explicitly in this group
            pass

        # Now add them to inactivated
        group = self.get_entry_by_cn("inactivated", None, opts)
        res = self.add_member_to_group(dn, group.get('dn'), opts)
            
        return res

    def mark_user_active(self, uid, opts=None):
        """Mark a user as active"""

        if not isinstance(uid,basestring) or len(uid) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        user = self.get_user_by_uid(uid, ['dn', 'uid'], opts)
        logging.info("IPA: mark_user_active '%s'" % user.get('dn'))
        return self.mark_entry_active(user.get('dn'))

    def mark_user_inactive(self, uid, opts=None):
        """Mark a user as inactive"""

        if not isinstance(uid,basestring) or len(uid) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if uid == "admin":
            raise ipaerror.gen_exception(ipaerror.INPUT_CANT_INACTIVATE)
        user = self.get_user_by_uid(uid, ['dn', 'uid'], opts)
        logging.info("IPA: mark_user_inactive '%s'" % user.get('dn'))
        return self.mark_entry_inactive(user.get('dn'))

    def delete_user (self, uid, opts=None):
        """Delete a user. Not to be confused with inactivate_user. This
           makes the entry go away completely.

           uid is the uid of the user to delete

           The memberOf plugin handles removing the user from any other
           groups.
        """
        if not isinstance(uid,basestring) or len(uid) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if uid == "admin":
            raise ipaerror.gen_exception(ipaerror.INPUT_ADMIN_REQUIRED)
        logging.info("IPA: delete_user '%s'" % uid)
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
        if not isinstance(principal,basestring) or len(principal) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if oldpass and not isinstance(oldpass,basestring):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(newpass,basestring) or len(newpass) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        logging.info("IPA: modifyPassword '%s'" % principal)

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
        """Return True if the cn is unique in the tree, False otherwise."""
        cn = self.__safe_filter(cn)
        searchfilter = "(&(cn=%s)(objectclass=posixGroup))" % cn
 
        try:
            entry = self.__get_sub_entry(self.basedn, searchfilter, ['dn','cn'], opts)
            return False
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return True

    def get_groups_by_member (self, member_dn, sattrs, opts=None):
        """Get all of the groups an object is explicitly a member of.

           This does not include groups an entry may be a member of as a
           result of recursion (being a group that is a member of another
           group). In other words, this searches on 'member' and not
           'memberof'.

           Return as a dict of values.
           Multi-valued fields are represented as lists.
        """
        if not isinstance(member_dn,basestring) or len(member_dn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if sattrs is not None and not isinstance(sattrs,list):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        logging.info("IPA: get_groups_by_member '%s'" % member_dn)

        member_dn = self.__safe_filter(member_dn)
        searchfilter = "(&(objectClass=posixGroup)(member=%s))" % member_dn

        try:
            return self.__get_list(self.basedn, searchfilter, sattrs, opts)
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return []

    def add_group (self, group, group_container, opts=None):
        """Add a group in LDAP. Takes as input a dict where the key is the
           attribute name and the value is either a string or in the case
           of a multi-valued field a list of values. group_container sets
           where in the tree the group is placed."""
        if not group_container:
            group_container = DefaultGroupContainer

        if not isinstance(group,dict):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(group_container,basestring) or len(group_container) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        if not self.__is_group_unique(group['cn'], opts):
            raise ipaerror.gen_exception(ipaerror.LDAP_DUPLICATE)

        # Get our configuration
        config = self.get_ipa_config(opts)

        dn="cn=%s,%s,%s" % (ldap.dn.escape_dn_chars(group['cn']),
                            group_container,self.basedn)
        logging.info("IPA: add_group '%s'" % dn)
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

    def find_groups (self, criteria, sattrs, sizelimit=-1, timelimit=-1,
            opts=None):
        """Return a list containing a User object for each
        existing group that matches the criteria.
        """
        if not isinstance(criteria,basestring) or len(criteria) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if sattrs is not None and not isinstance(sattrs, list):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(sizelimit,int):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(timelimit,int):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        logging.info("IPA: find groups '%s'" % criteria)

        config = self.get_ipa_config(opts)
        if timelimit < 0:
            timelimit = float(config.get('ipasearchtimelimit'))
        if sizelimit < 0:
            sizelimit = int(config.get('ipasearchrecordslimit'))

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
                        sizelimit)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                exact_results = [0]

            try:
                partial_results = conn.getListAsync(self.basedn, self.scope,
                        partial_match_filter, sattrs, 0, None, None, timelimit,
                        sizelimit)
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
        if not isinstance(member_dn,basestring) or len(member_dn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(group_dn,basestring) or len(group_dn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        logging.info("IPA: add_member_to_group '%s' to '%s'" % (member_dn, group_dn))
        if member_dn.lower() == group_dn.lower():
            raise ipaerror.gen_exception(ipaerror.INPUT_SAME_GROUP)

        old_group = self.get_entry_by_dn(group_dn, None, opts)
        if old_group is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)
        new_group = copy.deepcopy(old_group)

        # check to make sure member_dn exists
        member_entry = self.__get_base_entry(member_dn, "(objectClass=*)", ['dn','uid'], opts)
        if not member_entry:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        if new_group.get('member') is not None:
            if isinstance(new_group.get('member'),basestring):
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
        if not (isinstance(member_dns,list) or isinstance(member_dns,basestring)):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(group_dn,basestring) or len(group_dn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        if not member_dns or not group_dn:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        logging.info("IPA: add_members_to_group '%s'" % group_dn)

        failed = []

        if (isinstance(member_dns,basestring)):
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
        if not isinstance(member_dn,basestring) or len(member_dn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(group_dn,basestring) or len(group_dn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        old_group = self.get_entry_by_dn(group_dn, None, opts)
        if old_group is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)
        if old_group.get('cn') == "admins":
            member = self.get_entry_by_dn(member_dn, ['dn','uid'], opts)
            if member.get('uid') == "admin":
                raise ipaerror.gen_exception(ipaerror.INPUT_ADMIN_REQUIRED_IN_ADMINS)
        logging.info("IPA: remove_member_from_group '%s' from '%s'" % (member_dn, group_dn))
        new_group = copy.deepcopy(old_group)

        if new_group.get('member') is not None:
            if isinstance(new_group.get('member'),basestring):
                new_group['member'] = [new_group['member']]
            for i in range(len(new_group['member'])):
                new_group['member'][i] = ipaserver.ipaldap.IPAdmin.normalizeDN(new_group['member'][i])
            try:
                new_group['member'].remove(member_dn)
            except ValueError:
                # member is not in the group
                # FIXME: raise more specific error?
                raise ipaerror.gen_exception(ipaerror.STATUS_NOT_GROUP_MEMBER)
        else:
            # Nothing to do if the group has no members
            raise ipaerror.gen_exception(ipaerror.STATUS_NOT_GROUP_MEMBER)

        try:
            ret = self.__update_entry(old_group, new_group, opts)
        except ipaerror.exception_for(ipaerror.LDAP_EMPTY_MODLIST):
            raise
        return ret

    def remove_members_from_group(self, member_dns, group_dn, opts=None):
        """Given a list of member dn's remove them from the group.
           Returns a list of the members not removed from the group.
        """
        if not (isinstance(member_dns,list) or isinstance(member_dns,basestring)):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(group_dn,basestring) or len(group_dn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        logging.info("IPA: remove_members_from_group '%s'" % group_dn)
        failed = []

        if (isinstance(member_dns,basestring)):
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
            except ipaerror.exception_for(ipaerror.STATUS_NOT_GROUP_MEMBER):
                # not a member of the group
                failed.append(member_dn)
            except ipaerror.exception_for(ipaerror.INPUT_ADMIN_REQUIRED_IN_ADMINS):
                # Can't remove admin from admins group
                failed.append(member_dn)

        return failed

    def add_user_to_group(self, user_uid, group_dn, opts=None):
        """Add a user to an existing group.
        """
        if not isinstance(user_uid,basestring) or len(user_uid) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(group_dn,basestring) or len(group_dn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        logging.info("IPA: add_user_to_group '%s' to '%s'" % (user_uid, group_dn))

        user = self.get_user_by_uid(user_uid, ['dn', 'uid', 'objectclass'], opts)
        if user is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        return self.add_member_to_group(user['dn'], group_dn, opts)

    def add_users_to_group(self, user_uids, group_dn, opts=None):
        """Given a list of user uid's add them to the group cn denoted by group
           Returns a list of the users were not added to the group.
        """
        if not (isinstance(user_uids,list) or isinstance(user_uids,basestring)):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(group_dn,basestring) or len(group_dn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        logging.info("IPA: add_users_to_group '%s'" % group_dn)
        failed = []

        if (isinstance(user_uids,basestring)):
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
        if not isinstance(user_uid,basestring) or len(user_uid) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(group_dn,basestring) or len(group_dn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        logging.info("IPA: remove_user_from_group '%s' from '%s'" % (user_uid, group_dn))
        user = self.get_user_by_uid(user_uid, ['dn', 'uid', 'objectclass'], opts)
        if user is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        return self.remove_member_from_group(user['dn'], group_dn, opts)

    def remove_users_from_group(self, user_uids, group_dn, opts=None):
        """Given a list of user uid's remove them from the group
           Returns a list of the user uids not removed from the group.
        """
        if not (isinstance(user_uids,list) or isinstance(user_uids,basestring)):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(group_dn,basestring) or len(group_dn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        logging.info("IPA: remove_users_from_group '%s'" % group_dn)
        failed = []

        if (isinstance(user_uids,basestring)):
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
        if not (isinstance(group_dns,list) or isinstance(group_dns,basestring)):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(user_dn,basestring) or len(user_dn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        logging.info("IPA: add_groups_to_user '%s'" % user_dn)
        failed = []

        if (isinstance(group_dns, basestring)):
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
        if not (isinstance(group_dns,list) or isinstance(group_dns,basestring)):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(user_dn,basestring) or len(user_dn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        logging.info("IPA: remove_groups_from_user '%s'" % user_dn)
        failed = []

        if (isinstance(group_dns,basestring)):
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
            except ipaerror.exception_for(ipaerror.STATUS_NOT_GROUP_MEMBER):
                # User is not in the group
                failed.append(group_dn)
            except ipaerror.exception_for(ipaerror.INPUT_ADMIN_REQUIRED_IN_ADMINS):
                # Can't remove admin from admins group
                failed.append(member_dn)

        return failed

    def update_group (self, oldentry, newentry, opts=None):
        """Wrapper around update_entry with group-specific handling.

           oldentry and newentry are XML-RPC structs.

           If oldentry is not empty then it is used when determine what
           has changed.

           If oldentry is empty then the value of newentry is compared
           to the current value of oldentry.

           If you want to change the RDN of a group you must use
           this function. update_entry will fail.
        """
        if not isinstance(newentry,dict):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if oldentry and not isinstance(oldentry,dict):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not oldentry:
            oldentry = self.get_entry_by_dn(newentry.get('dn'), None, opts)
            if oldentry is None:
                raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        logging.info("IPA: update_group '%s'" % oldentry.get('cn'))
        newrdn = 0

        oldcn=oldentry.get('cn')
        newcn=newentry.get('cn')
        if isinstance(oldcn,basestring):
            oldcn = [oldcn]
        if isinstance(newcn,basestring):
            newcn = [newcn]

        if "admins" in oldcn:
            raise ipaerror.gen_exception(ipaerror.INPUT_ADMINS_IMMUTABLE)

        oldcn.sort()
        newcn.sort()
        if oldcn != newcn:
            # RDN change
            conn = self.getConnection(opts)
            try:
                res = conn.updateRDN(oldentry.get('dn'), "cn=" + newcn[0])
                newdn = oldentry.get('dn')
                newcn = newentry.get('cn')
                if isinstance(newcn,basestring):
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
        # newentry['objectclass'] = uniq_list(newentry.get('objectclass') + config.get('ipagroupobjectclasses'))

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
        if not isinstance(group_dn,basestring) or len(group_dn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        group = self.get_entry_by_dn(group_dn, ['dn', 'cn'], opts)
        if group is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)
        logging.info("IPA: delete_group '%s'" % group_dn)

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
        """Add a group to an existing group.
           group is a DN of the group to add
           tgroup is the DN of the target group to be added to
        """
        if not isinstance(group,basestring) or len(group) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(tgroup,basestring) or len(tgroup) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if group.lower() == tgroup.lower():
            raise ipaerror.gen_exception(ipaerror.INPUT_SAME_GROUP)
        old_group = self.get_entry_by_dn(tgroup, None, opts)
        if old_group is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)
        logging.info("IPA: add_group_to_group '%s' to '%s'" % (group, tgroup))
        new_group = copy.deepcopy(old_group)

        group_dn = self.get_entry_by_dn(group, ['dn', 'cn', 'objectclass'], opts)
        if group_dn is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

        if new_group.get('member') is not None:
            if isinstance(new_group.get('member'),basestring):
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
        if not (isinstance(attr_list,list)):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        logging.info("IPA: attrs_to_labels")

        label_list = {}

        for a in attr_list:
            label_list[a] = attrs.attr_label_list.get(a,a)

        return label_list

    def get_all_attrs(self, opts=None):
        """We have a list of hardcoded attributes -> readable labels. Return
           that complete list if someone wants it.
        """
        logging.info("IPA: get_all_attrs")

        return attrs.attr_label_list

    def group_members(self, groupdn, attr_list, membertype, opts=None):
        """Do a memberOf search of groupdn and return the attributes in
           attr_list (an empty list returns all attributes).

           membertype = 0 all members returned
           membertype = 1 only direct members are returned
           membertype = 2 only inherited members are returned

           Members may be included in a group as a result of being a member
           of a group that is a member of the group being queried.
        """

        if not isinstance(groupdn,basestring) or len(groupdn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if attr_list is not None and not isinstance(attr_list,list):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if membertype is not None and not isinstance(membertype,int):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if membertype is None:
            membertype = 0
        if membertype < 0 or membertype > 3:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        logging.info("IPA: group_members '%s' %d" % (groupdn, membertype))
        config = self.get_ipa_config(opts)
        timelimit = float(config.get('ipasearchtimelimit'))

        sizelimit = int(config.get('ipasearchrecordslimit'))

        groupdn = self.__safe_filter(groupdn)
        searchfilter = "(memberOf=%s)" % groupdn

        if attr_list is None:
            attr_list = []
        attr_list.append("member")

        conn = self.getConnection(opts)
        try:
            try:
                results = conn.getListAsync(self.basedn, self.scope,
                    searchfilter, attr_list, 0, None, None, timelimit,
                    sizelimit)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                results = [0]
        finally:
            self.releaseConnection(conn)

        counter = results[0]
        results = results[1:]

        if membertype == 0:
            entries = [counter]
            for e in results:
                entries.append(self.convert_entry(e))

            return entries

        group = self.get_entry_by_dn(groupdn, ['dn', 'member'], opts)
        real_members = group.get('member')
        if isinstance(real_members, basestring):
            real_members = [real_members]
        if real_members is None:
            real_members = []

        # Normalize all the dns
        for i in range(len(real_members)):
            real_members[i] = ipaserver.ipaldap.IPAdmin.normalizeDN(real_members[i])

        entries = [0]
        for e in results:
            if ipaserver.ipaldap.IPAdmin.normalizeDN(e.dn) not in real_members:
                if membertype == 2:
                    entries.append(self.convert_entry(e))
            else:
                if membertype == 1:
                    entries.append(self.convert_entry(e))

        if len(entries) > 1:
            entries[0] = len(entries) - 1

        return entries

    def mark_group_active(self, cn, opts=None):
        """Mark a group as active"""

        if not isinstance(cn,basestring) or len(cn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        logging.info("IPA: mark_group_active '%s'" % cn)
        group = self.get_entry_by_cn(cn, ['dn', 'cn'], opts)
        return self.mark_entry_active(group.get('dn'))

    def mark_group_inactive(self, cn, opts=None):
        """Mark a group as inactive"""

        if not isinstance(cn,basestring) or len(cn) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if cn == "admins" or cn == "editors":
            raise ipaerror.gen_exception(ipaerror.INPUT_CANT_INACTIVATE)
        logging.info("IPA: mark_group_inactive '%s'" % cn)
        group = self.get_entry_by_cn(cn, ['dn', 'uid'], opts)
        return self.mark_entry_inactive(group.get('dn'))

    def __is_service_unique(self, name, opts):
        """Return True if the uid is unique in the tree, False otherwise."""
        name = self.__safe_filter(name)
        searchfilter = "(&(krbprincipalname=%s)(objectclass=krbPrincipal))" % name
 
        try:
            entry = self.__get_sub_entry(self.basedn, searchfilter, ['dn','krbprincipalname'], opts)
            return False
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return True

    def add_service_principal(self, name, force, opts=None):
        """Given a name of the form: service/FQDN create a service
           principal for it in the default realm.

           Ensure that the principal points at a DNS A record so it will
           work with Kerberos unless force is set to 1"""
        if not name:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        try:
            f = int(force)
        except ValueError:
            f = 1
        logging.info("IPA: add_service_principal '%s' (%d)" % (name, f))

        # Break down the principal into its component parts, which may or
        # may not include the realm.
        sp = name.split('/')
        if len(sp) != 2:
            raise ipaerror.gen_exception(ipaerror.INPUT_MALFORMED_SERVICE_PRINCIPAL)
        service = sp[0]

        sr = sp[1].split('@')
        if len(sr) == 1:
            hostname = sr[0].lower()
            realm = self.realm
        elif len(sr) == 2:
            hostname = sr[0].lower()
            realm = sr[1]
        else:
            raise ipaerror.gen_exception(ipaerror.INPUT_MALFORMED_SERVICE_PRINCIPAL)

        if not f:
            fqdn = hostname + "."
            rs = dnsclient.query(fqdn, dnsclient.DNS_C_IN, dnsclient.DNS_T_A)
            if len(rs) == 0:
                logging.debug("IPA: DNS A record lookup failed for '%s'" % hostname)
                raise ipaerror.gen_exception(ipaerror.INPUT_NOT_DNS_A_RECORD)
            else:
                logging.debug("IPA: found %d records for '%s'" % (len(rs), hostname))

        service_container = DefaultServiceContainer

        # At some point we'll support multiple realms
        if (realm != self.realm):
            raise ipaerror.gen_exception(ipaerror.INPUT_REALM_MISMATCH)

        # Put the principal back together again
        princ_name = service + "/" + hostname + "@" + realm
        
        conn = self.getConnection(opts)
        if not self.__is_service_unique(princ_name, opts):
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

    def delete_service_principal (self, principal, opts=None):
        """Delete a service principal.

           principal is the full DN of the entry to delete.

           This should be called with much care.
        """
        if not isinstance(principal,basestring) or len(principal) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        entry = self.get_entry_by_dn(principal, ['dn', 'objectclass'], opts)
        if entry is None:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)
        dn_list = ldap.explode_dn(entry['dn'].lower())
        if "cn=kerberos" in dn_list:
            raise ipaerror.gen_exception(ipaerror.INPUT_SERVICE_PRINCIPAL_REQUIRED)
        logging.info("IPA: delete_service_principal '%s'" % principal)

        conn = self.getConnection(opts)
        try:
            res = conn.deleteEntry(entry['dn'])
        finally:
            self.releaseConnection(conn)
        return res

    def find_service_principal(self, criteria, sattrs, sizelimit=-1,
            timelimit=-1, opts=None):
        """Returns a list: counter followed by the results.
           If the results are truncated, counter will be set to -1."""
        if not isinstance(criteria,basestring) or len(criteria) == 0:
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if sattrs is not None and not isinstance(sattrs, list):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(sizelimit,int):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not isinstance(timelimit,int):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)

        config = self.get_ipa_config(opts)
        if timelimit < 0:
            timelimit = float(config.get('ipasearchtimelimit'))
        if sizelimit < 0:
            sizelimit = int(config.get('ipasearchrecordslimit'))

        search_fields = ["krbprincipalname"]
        logging.info("IPA: find_service_principal '%s'" % criteria)

        criteria = self.__safe_filter(criteria)
        criteria = criteria.lower()
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
        exact_match_filter = "(&(objectclass=krbPrincipalAux)(!(objectClass=person))(!(|(krbprincipalname=kadmin/*)(krbprincipalname=K/M@*)(krbprincipalname=krbtgt/*)))%s)" % exact_match_filter
        partial_match_filter = "(&(objectclass=krbPrincipalAux)(!(objectClass=person))(!(|(krbprincipalname=kadmin/*)(krbprincipalname=K/M@*)(krbprincipalname=krbtgt/*)))%s)" % partial_match_filter


        conn = self.getConnection(opts)
        try:
            try:
                exact_results = conn.getListAsync(self.basedn, self.scope,
                        exact_match_filter, sattrs, 0, None, None, timelimit,
                        sizelimit)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                exact_results = [0]

            try:
                partial_results = conn.getListAsync(self.basedn, self.scope,
                        partial_match_filter, sattrs, 0, None, None, timelimit,
                        sizelimit)
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


# Configuration support
    def get_ipa_config(self, opts=None):
        """Retrieve the IPA configuration"""
        try:
            config = self.get_entry_by_cn("ipaconfig", None, opts)
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            raise ipaerror.gen_exception(ipaerror.LDAP_NO_CONFIG)

        return config

    def update_ipa_config(self, oldconfig, newconfig, opts=None):
        """Update the IPA configuration.

           oldconfig and newconfig are XML-RPC structs.

           If oldconfig is not empty then it is used when determine what
           has changed.

           If oldconfig is empty then the value of newconfig is compared
           to the current value of oldconfig.

        """
        if not isinstance(newconfig,dict):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if oldconfig and not isinstance(oldconfig,dict):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not oldconfig:
            oldconfig = self.get_entry_by_dn(newconfig.get('dn'), None, opts)
            if oldconfig is None:
                raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)

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
        """Update the IPA configuration

           oldpolicy and newpolicy are XML-RPC structs.

           If oldpolicy is not empty then it is used when determine what
           has changed.

           If oldpolicy is empty then the value of newpolicy is compared
           to the current value of oldpolicy.

        """
        if not isinstance(newpolicy,dict):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if oldpolicy and not isinstance(oldpolicy,dict):
            raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
        if not oldpolicy:
            oldpolicy = self.get_entry_by_dn(newpolicy.get('dn'), None, opts)
            if oldpolicy is None:
                raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND)


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
    return [set.setdefault(e.lower(),e) for e in x if e.lower() not in set]
