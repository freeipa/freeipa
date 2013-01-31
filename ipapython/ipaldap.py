# Authors: Rich Megginson <richm@redhat.com>
#          Rob Crittenden <rcritten@redhat.com>
#          John Dennis <jdennis@redhat.com>
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

import string
import time
import shutil
from decimal import Decimal
from copy import deepcopy
import contextlib

import ldap
import ldap.sasl
import ldap.filter
from ldap.ldapobject import SimpleLDAPObject
import ldapurl

from ipalib import errors, _
from ipapython import ipautil
from ipapython.ipautil import (
    format_netloc, wait_for_open_socket, wait_for_open_ports, CIDict)
from ipapython.ipa_log_manager import log_mgr
from ipapython.dn import DN, RDN

# Global variable to define SASL auth
SASL_GSSAPI = ldap.sasl.sasl({}, 'GSSAPI')

DEFAULT_TIMEOUT = 10
DN_SYNTAX_OID = '1.3.6.1.4.1.1466.115.121.1.12'
_debug_log_ldap = False

# Group Member types
MEMBERS_ALL = 0
MEMBERS_DIRECT = 1
MEMBERS_INDIRECT = 2

_missing = object()


def unicode_from_utf8(val):
    '''
    val is a UTF-8 encoded string, return a unicode object.
    '''
    return val.decode('utf-8')


def value_to_utf8(val):
    '''
    Coerce the val parameter to a UTF-8 encoded string representation
    of the val.
    '''

    # If val is not a string we need to convert it to a string
    # (specifically a unicode string). Naively we might think we need to
    # call str(val) to convert to a string. This is incorrect because if
    # val is already a unicode object then str() will call
    # encode(default_encoding) returning a str object encoded with
    # default_encoding. But we don't want to apply the default_encoding!
    # Rather we want to guarantee the val object has been converted to a
    # unicode string because from a unicode string we want to explicitly
    # encode to a str using our desired encoding (utf-8 in this case).
    #
    # Note: calling unicode on a unicode object simply returns the exact
    # same object (with it's ref count incremented). This means calling
    # unicode on a unicode object is effectively a no-op, thus it's not
    # inefficient.

    return unicode(val).encode('utf-8')


class _ServerSchema(object):
    '''
    Properties of a schema retrieved from an LDAP server.
    '''

    def __init__(self, server, schema):
        self.server = server
        self.schema = schema
        self.retrieve_timestamp = time.time()


class SchemaCache(object):
    '''
    Cache the schema's from individual LDAP servers.
    '''

    def __init__(self):
        self.log = log_mgr.get_logger(self)
        self.servers = {}

    def get_schema(self, url, conn, force_update=False):
        '''
        Return schema belonging to a specific LDAP server.

        For performance reasons the schema is retrieved once and
        cached unless force_update is True. force_update flushes the
        existing schema for the server from the cache and reacquires
        it.
        '''

        if force_update:
            self.flush(url)

        server_schema = self.servers.get(url)
        if server_schema is None:
            schema = self._retrieve_schema_from_server(url, conn)
            server_schema = _ServerSchema(url, schema)
            self.servers[url] = server_schema
        return server_schema.schema

    def flush(self, url):
        self.log.debug('flushing %s from SchemaCache', url)
        try:
            del self.servers[url]
        except KeyError:
            pass

    def _retrieve_schema_from_server(self, url, conn):
        """
        Retrieve the LDAP schema from the provided url and determine if
        User-Private Groups (upg) are configured.

        Bind using kerberos credentials. If in the context of the
        in-tree "lite" server then use the current ccache. If in the context of
        Apache then create a new ccache and bind using the Apache HTTP service
        principal.

        If a connection is provided then it the credentials bound to it are
        used. The connection is not closed when the request is done.
        """
        tmpdir = None
        assert conn is not None

        self.log.debug(
            'retrieving schema for SchemaCache url=%s conn=%s', url, conn)

        try:
            try:
                schema_entry = conn.search_s('cn=schema', ldap.SCOPE_BASE,
                    attrlist=['attributetypes', 'objectclasses'])[0]
            except ldap.NO_SUCH_OBJECT:
                # try different location for schema
                # openldap has schema located in cn=subschema
                self.log.debug('cn=schema not found, fallback to cn=subschema')
                schema_entry = conn.search_s('cn=subschema', ldap.SCOPE_BASE,
                    attrlist=['attributetypes', 'objectclasses'])[0]
        except ldap.SERVER_DOWN:
            raise errors.NetworkError(uri=url,
                               error=u'LDAP Server Down, unable to retrieve LDAP schema')
        except ldap.LDAPError, e:
            desc = e.args[0]['desc'].strip()
            info = e.args[0].get('info', '').strip()
            raise errors.DatabaseError(desc = u'uri=%s' % url,
                                info = u'Unable to retrieve LDAP schema: %s: %s' % (desc, info))
        except IndexError:
            # no 'cn=schema' entry in LDAP? some servers use 'cn=subschema'
            # TODO: DS uses 'cn=schema', support for other server?
            #       raise a more appropriate exception
            raise
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir)

        return ldap.schema.SubSchema(schema_entry[1])

schema_cache = SchemaCache()


class IPASimpleLDAPObject(object):
    '''
    The purpose of this class is to provide a boundary between IPA and
    python-ldap. In IPA we use IPA defined types because they are
    richer and are designed to meet our needs. We also require that we
    consistently use those types without exception. On the other hand
    python-ldap uses different types. The goal is to be able to have
    IPA code call python-ldap methods using the types native to
    IPA. This class accomplishes that goal by exposing python-ldap
    methods which take IPA types, convert them to python-ldap types,
    call python-ldap, and then convert the results returned by
    python-ldap into IPA types.

    IPA code should never call python-ldap directly, it should only
    call python-ldap methods in this class.
    '''

    # Note: the oid for dn syntax is: 1.3.6.1.4.1.1466.115.121.1.12

    _SYNTAX_MAPPING = {
        '1.3.6.1.4.1.1466.115.121.1.1'   : str, # ACI item
        '1.3.6.1.4.1.1466.115.121.1.4'   : str, # Audio
        '1.3.6.1.4.1.1466.115.121.1.5'   : str, # Binary
        '1.3.6.1.4.1.1466.115.121.1.8'   : str, # Certificate
        '1.3.6.1.4.1.1466.115.121.1.9'   : str, # Certificate List
        '1.3.6.1.4.1.1466.115.121.1.10'  : str, # Certificate Pair
        '1.3.6.1.4.1.1466.115.121.1.23'  : str, # Fax
        '1.3.6.1.4.1.1466.115.121.1.28'  : str, # JPEG
        '1.3.6.1.4.1.1466.115.121.1.40'  : str, # OctetString (same as Binary)
        '1.3.6.1.4.1.1466.115.121.1.49'  : str, # Supported Algorithm
        '1.3.6.1.4.1.1466.115.121.1.51'  : str, # Teletext Terminal Identifier

        DN_SYNTAX_OID                    : DN,  # DN, member, memberof
        '2.16.840.1.113730.3.8.3.3'      : DN,  # enrolledBy
        '2.16.840.1.113730.3.8.3.18'     : DN,  # managedBy
        '2.16.840.1.113730.3.8.3.5'      : DN,  # memberUser
        '2.16.840.1.113730.3.8.3.7'      : DN,  # memberHost
        '2.16.840.1.113730.3.8.3.20'     : DN,  # memberService
        '2.16.840.1.113730.3.8.11.4'     : DN,  # ipaNTFallbackPrimaryGroup
        '2.16.840.1.113730.3.8.11.21'    : DN,  # ipaAllowToImpersonate
        '2.16.840.1.113730.3.8.11.22'    : DN,  # ipaAllowedTarget
        '2.16.840.1.113730.3.8.7.1'      : DN,  # memberAllowCmd
        '2.16.840.1.113730.3.8.7.2'      : DN,  # memberDenyCmd

        '2.16.840.1.113719.1.301.4.14.1' : DN,  # krbRealmReferences
        '2.16.840.1.113719.1.301.4.17.1' : DN,  # krbKdcServers
        '2.16.840.1.113719.1.301.4.18.1' : DN,  # krbPwdServers
        '2.16.840.1.113719.1.301.4.26.1' : DN,  # krbPrincipalReferences
        '2.16.840.1.113719.1.301.4.29.1' : DN,  # krbAdmServers
        '2.16.840.1.113719.1.301.4.36.1' : DN,  # krbPwdPolicyReference
        '2.16.840.1.113719.1.301.4.40.1' : DN,  # krbTicketPolicyReference
        '2.16.840.1.113719.1.301.4.41.1' : DN,  # krbSubTrees
        '2.16.840.1.113719.1.301.4.52.1' : DN,  # krbObjectReferences
        '2.16.840.1.113719.1.301.4.53.1' : DN,  # krbPrincContainerRef
    }

    # In most cases we lookup the syntax from the schema returned by
    # the server. However, sometimes attributes may not be defined in
    # the schema (e.g. extensibleObject which permits undefined
    # attributes), or the schema was incorrectly defined (i.e. giving
    # an attribute the syntax DirectoryString when in fact it's really
    # a DN). This (hopefully sparse) table allows us to trap these
    # anomalies and force them to be the syntax we know to be in use.
    #
    # FWIW, many entries under cn=config are undefined :-(

    _SCHEMA_OVERRIDE = CIDict({
        'managedtemplate': DN_SYNTAX_OID, # DN
        'managedbase':     DN_SYNTAX_OID, # DN
        'originscope':     DN_SYNTAX_OID, # DN
    })

    def __init__(self, uri, force_schema_updates, no_schema=False,
                 decode_attrs=True):
        """An internal LDAP connection object

        :param uri: The LDAP URI to connect to
        :param force_schema_updates:
            If true, this object will always request a new schema from the
            server. If false, a cached schema will be reused if it exists.

            Generally, it should be true if the API context is 'installer' or
            'updates', but it must be given explicitly since the API object
            is not always available
        :param no_schema: If true, schema is never requested from the server.
        :param decode_attrs:
            If true, attributes are decoded to Python types according to their
            syntax.
        """
        self.log = log_mgr.get_logger(self)
        self.uri = uri
        self.conn = SimpleLDAPObject(uri)
        self._no_schema = no_schema
        self._has_schema = False
        self._schema = None
        self._force_schema_updates = force_schema_updates
        self._decode_attrs = decode_attrs

    def _get_schema(self):
        if self._no_schema:
            return None
        if not self._has_schema:
            try:
                self._schema = schema_cache.get_schema(
                    self.uri, self.conn,
                    force_update=self._force_schema_updates)
            except (errors.ExecutionError, IndexError):
                pass
            self._has_schema = True
        return self._schema

    schema = property(_get_schema, None, None, 'schema associated with this LDAP server')


    def flush_cached_schema(self):
        '''
        Force this instance to forget it's cached schema and reacquire
        it from the schema cache.
        '''

        # Currently this is called during bind operations to assure
        # we're working with valid schema for a specific
        # connection. This causes self._get_schema() to query the
        # schema cache for the server's schema passing along a flag
        # indicating if we're in a context that requires freshly
        # loading the schema vs. returning the last cached version of
        # the schema. If we're in a mode that permits use of
        # previously cached schema the flush and reacquire is a very
        # low cost operation.
        #
        # The schema is reacquired whenever this object is
        # instantiated or when binding occurs. The schema is not
        # reacquired for operations during a bound connection, it is
        # presumed schema cannot change during this interval. This
        # provides for maximum efficiency in contexts which do need
        # schema refreshing by only peforming the refresh inbetween
        # logical operations that have the potential to cause a schema
        # change.

        self._has_schema = False
        self._schema = None

    def get_syntax(self, attr):
        # Is this a special case attribute?
        syntax = self._SCHEMA_OVERRIDE.get(attr)
        if syntax is not None:
            return syntax

        if self.schema is None:
            return None

        # Try to lookup the syntax in the schema returned by the server
        obj = self.schema.get_obj(ldap.schema.AttributeType, attr)
        if obj is not None:
            return obj.syntax
        else:
            return None

    def has_dn_syntax(self, attr):
        """
        Check the schema to see if the attribute uses DN syntax.

        Returns True/False
        """
        syntax = self.get_syntax(attr)
        return syntax == DN_SYNTAX_OID


    def encode(self, val):
        '''
        '''
        # Booleans are both an instance of bool and int, therefore
        # test for bool before int otherwise the int clause will be
        # entered for a boolean value instead of the boolean clause.
        if isinstance(val, bool):
            if val:
                return 'TRUE'
            else:
                return 'FALSE'
        elif isinstance(val, (unicode, float, int, long, Decimal, DN)):
            return value_to_utf8(val)
        elif isinstance(val, str):
            return val
        elif isinstance(val, list):
            return [self.encode(m) for m in val]
        elif isinstance(val, tuple):
            return tuple(self.encode(m) for m in val)
        elif isinstance(val, dict):
            dct = dict((self.encode(k), self.encode(v)) for k, v in val.iteritems())
            return dct
        elif val is None:
            return None
        else:
            raise TypeError("attempt to pass unsupported type to ldap, value=%s type=%s" %(val, type(val)))

    def convert_value_list(self, attr, target_type, values):
        '''
        '''

        if not self._decode_attrs:
            return values

        ipa_values = []

        for original_value in values:
            if isinstance(target_type, type) and isinstance(original_value, target_type):
                ipa_value = original_value
            else:
                try:
                    ipa_value = target_type(original_value)
                except Exception, e:
                    msg = 'unable to convert the attribute "%s" value "%s" to type %s' % (attr, original_value, target_type)
                    self.log.error(msg)
                    raise ValueError(msg)

            ipa_values.append(ipa_value)

        return ipa_values

    def convert_result(self, result):
        '''
        result is a python-ldap result tuple of the form (dn, attrs),
        where dn is a string containing the dn (distinguished name) of
        the entry, and attrs is a dictionary containing the attributes
        associated with the entry. The keys of attrs are strings, and
        the associated values are lists of strings.

        We convert the dn to a DN object.

        We convert every value associated with an attribute according
        to it's syntax into the desired Python type.

        returns a IPA result tuple of the same form as a python-ldap
        result tuple except everything inside of the result tuple has
        been converted to it's preferred IPA python type.
        '''

        ipa_result = []
        for dn_tuple in result:
            original_dn = dn_tuple[0]
            original_attrs = dn_tuple[1]

            ipa_entry = LDAPEntry(self, DN(original_dn))

            for attr, original_values in original_attrs.items():
                target_type = self._SYNTAX_MAPPING.get(self.get_syntax(attr), unicode_from_utf8)
                ipa_entry[attr] = self.convert_value_list(attr, target_type, original_values)

            ipa_result.append(ipa_entry)

        if _debug_log_ldap:
            self.log.debug('ldap.result: %s', ipa_result)
        return ipa_result

    #---------- python-ldap emulations ----------

    def add(self, dn, modlist):
        assert isinstance(dn, DN)
        dn = str(dn)
        modlist = self.encode(modlist)
        return self.conn.add(dn, modlist)

    def add_ext(self, dn, modlist, serverctrls=None, clientctrls=None):
        assert isinstance(dn, DN)
        dn = str(dn)
        modlist = self.encode(modlist)
        return self.conn.add_ext(dn, modlist, serverctrls, clientctrls)

    def add_ext_s(self, dn, modlist, serverctrls=None, clientctrls=None):
        assert isinstance(dn, DN)
        dn = str(dn)
        modlist = self.encode(modlist)
        return self.conn.add_ext_s(dn, modlist, serverctrls, clientctrls)

    def add_s(self, dn, modlist):
        assert isinstance(dn, DN)
        dn = str(dn)
        modlist = self.encode(modlist)
        return self.conn.add_s(dn, modlist)

    def bind(self, who, cred, method=ldap.AUTH_SIMPLE):
        self.flush_cached_schema()
        if who is None:
            who = DN()
        assert isinstance(who, DN)
        who = str(who)
        cred = self.encode(cred)
        return self.conn.bind(who, cred, method)

    def delete(self, dn):
        assert isinstance(dn, DN)
        dn = str(dn)
        return self.conn.delete(dn)

    def delete_s(self, dn):
        assert isinstance(dn, DN)
        dn = str(dn)
        return self.conn.delete_s(dn)

    def get_option(self, option):
        return self.conn.get_option(option)

    def modify_s(self, dn, modlist):
        assert isinstance(dn, DN)
        dn = str(dn)
        modlist = [(x[0], self.encode(x[1]), self.encode(x[2])) for x in modlist]
        return self.conn.modify_s(dn, modlist)

    def modrdn_s(self, dn, newrdn, delold=1):
        assert isinstance(dn, DN)
        dn = str(dn)
        assert isinstance(newrdn, (DN, RDN))
        newrdn = str(newrdn)
        return self.conn.modrdn_s(dn, newrdn, delold)

    def passwd_s(self, dn, oldpw, newpw, serverctrls=None, clientctrls=None):
        assert isinstance(dn, DN)
        dn = str(dn)
        oldpw = self.encode(oldpw)
        newpw = self.encode(newpw)
        return self.conn.passwd_s(dn, oldpw, newpw, serverctrls, clientctrls)

    def rename_s(self, dn, newrdn, newsuperior=None, delold=1):
        # NOTICE: python-ldap of version 2.3.10 and lower does not support
        # serverctrls and clientctrls for rename_s operation. Thus, these
        # options are ommited from this command until really needed
        assert isinstance(dn, DN)
        dn = str(dn)
        assert isinstance(newrdn, (DN, RDN))
        newrdn = str(newrdn)
        return self.conn.rename_s(dn, newrdn, newsuperior, delold)

    def result(self, msgid=ldap.RES_ANY, all=1, timeout=None):
        resp_type, resp_data = self.conn.result(msgid, all, timeout)
        resp_data = self.convert_result(resp_data)
        return resp_type, resp_data

    def sasl_interactive_bind_s(self, who, auth, serverctrls=None,
                                clientctrls=None, sasl_flags=ldap.SASL_QUIET):
        self.flush_cached_schema()
        if who is None:
            who = DN()
        assert isinstance(who, DN)
        who = str(who)
        return self.conn.sasl_interactive_bind_s(who, auth, serverctrls, clientctrls, sasl_flags)

    def search(self, base, scope, filterstr='(objectClass=*)', attrlist=None, attrsonly=0):
        assert isinstance(base, DN)
        base = str(base)
        filterstr = self.encode(filterstr)
        attrlist = self.encode(attrlist)
        return self.conn.search(base, scope, filterstr, attrlist, attrsonly)

    def search_ext(self, base, scope, filterstr='(objectClass=*)', attrlist=None, attrsonly=0, serverctrls=None, clientctrls=None, timeout=-1, sizelimit=0):
        assert isinstance(base, DN)
        base = str(base)
        filterstr = self.encode(filterstr)
        attrlist = self.encode(attrlist)

        if _debug_log_ldap:
            self.log.debug(
                "ldap.search_ext: dn: %s\nfilter: %s\nattrs_list: %s",
                base, filterstr, attrlist)


        return self.conn.search_ext(base, scope, filterstr, attrlist, attrsonly, serverctrls, clientctrls, timeout, sizelimit)

    def search_ext_s(self, base, scope, filterstr='(objectClass=*)', attrlist=None, attrsonly=0, serverctrls=None, clientctrls=None, timeout=-1, sizelimit=0):
        assert isinstance(base, DN)
        base = str(base)
        filterstr = self.encode(filterstr)
        attrlist = self.encode(attrlist)
        ldap_result = self.conn.search_ext_s(base, scope, filterstr, attrlist, attrsonly, serverctrls, clientctrls, timeout, sizelimit)
        ipa_result = self.convert_result(ldap_result)
        return ipa_result

    def search_s(self, base, scope, filterstr='(objectClass=*)', attrlist=None, attrsonly=0):
        assert isinstance(base, DN)
        base = str(base)
        filterstr = self.encode(filterstr)
        attrlist = self.encode(attrlist)
        ldap_result = self.conn.search_s(base, scope, filterstr, attrlist, attrsonly)
        ipa_result = self.convert_result(ldap_result)
        return ipa_result

    def search_st(self, base, scope, filterstr='(objectClass=*)', attrlist=None, attrsonly=0, timeout=-1):
        assert isinstance(base, DN)
        base = str(base)
        filterstr = self.encode(filterstr)
        attrlist = self.encode(attrlist)
        ldap_result = self.conn.search_st(base, scope, filterstr, attrlist, attrsonly, timeout)
        ipa_result = self.convert_result(ldap_result)
        return ipa_result

    def set_option(self, option, invalue):
        return self.conn.set_option(option, invalue)

    def simple_bind_s(self, who=None, cred='', serverctrls=None, clientctrls=None):
        self.flush_cached_schema()
        if who is None:
            who = DN()
        assert isinstance(who, DN)
        who = str(who)
        cred = self.encode(cred)
        return self.conn.simple_bind_s(who, cred, serverctrls, clientctrls)

    def start_tls_s(self):
        return self.conn.start_tls_s()

    def unbind_s(self):
        self.flush_cached_schema()
        return self.conn.unbind_s()


# Make python-ldap tuple style result compatible with Entry and Entity
# objects by allowing access to the dn (tuple index 0) via the 'dn'
# attribute name and the attr dict (tuple index 1) via the 'data'
# attribute name. Thus:
# r = result[0]
# r[0] == r.dn
# r[1] == r.data
class LDAPEntry(dict):
    __slots__ = ('_conn', '_dn', '_names', '_orig')

    def __init__(self, _conn, _dn=None, _obj=None, **kwargs):
        """
        LDAPEntry constructor.

        Takes 1 to 3 positional arguments and an arbitrary number of keyword
        arguments. The 3 forms of positional arguments are:

          * LDAPEntry(entry) - create a shallow copy of an existing LDAPEntry.
          * LDAPEntry(dn, entry) - create a shallow copy of an existing
            LDAPEntry with a different DN.
          * LDAPEntry(conn, dn, mapping) - create a new LDAPEntry using the
            specified IPASimpleLDAPObject and DN and optionally initialize
            attributes from the specified mapping object.

        Keyword arguments can be used to override values of specific attributes.
        """
        super(LDAPEntry, self).__init__()

        if isinstance(_conn, LDAPEntry):
            assert _dn is None
            _dn = _conn
            _conn = _conn._conn

        if isinstance(_dn, LDAPEntry):
            assert _obj is None
            _obj = _dn
            _dn = DN(_dn._dn)

        if isinstance(_obj, LDAPEntry):
            orig = _obj._orig
        else:
            if _obj is None:
                _obj = {}
            orig = self

        assert isinstance(_conn, IPASimpleLDAPObject)
        assert isinstance(_dn, DN)

        self._conn = _conn
        self._dn = _dn
        self._orig = orig
        self._names = CIDict()

        self.update(_obj, **kwargs)

    @property
    def conn(self):
        return self._conn

    # properties for Entry and Entity compatibility
    @property
    def dn(self):
        return self._dn

    @dn.setter
    def dn(self, value):
        assert isinstance(value, DN)
        self._dn = value

    @property
    def data(self):
        # FIXME: for backwards compatibility only
        return self

    @property
    def orig_data(self):
        # FIXME: for backwards compatibility only
        return self._orig

    def __repr__(self):
        return '%s(%r, %s)' % (type(self).__name__, self._dn,
            super(LDAPEntry, self).__repr__())

    def copy(self):
        return LDAPEntry(self)

    def clone(self):
        result = LDAPEntry(self._conn, self._dn)

        for name in self.iterkeys():
            super(LDAPEntry, result).__setitem__(
                name, deepcopy(super(LDAPEntry, self).__getitem__(name)))

        result._names = deepcopy(self._names)
        if self._orig is not self:
            result._orig = self._orig.clone()

        return result

    def commit(self):
        """
        Make the current state of the entry a new reference point for change
        tracking.
        """
        self._orig = self
        self._orig = self.clone()

    def _attr_name(self, name):
        if not isinstance(name, basestring):
            raise TypeError(
                "attribute name must be unicode or str, got %s object %r" % (
                    name.__class__.__name__, name))

        if isinstance(name, str):
            name = name.decode('utf-8')

        return name

    def __setitem__(self, name, value):
        name = self._attr_name(name)

        if self._names.has_key(name):
            oldname = self._names[name]

            if oldname != name:
                for (altname, keyname) in self._names.iteritems():
                    if keyname == oldname:
                        self._names[altname] = name

                super(LDAPEntry, self).__delitem__(oldname)
        else:
            self._names[name] = name

            if self._conn.schema is not None:
                attrtype = self._conn.schema.get_obj(ldap.schema.AttributeType,
                    name.encode('utf-8'))
                if attrtype is not None:
                    for altname in attrtype.names:
                        altname = altname.decode('utf-8')
                        self._names[altname] = name

        super(LDAPEntry, self).__setitem__(name, value)

    def setdefault(self, name, default):
        if name not in self:
            self[name] = default
        return self[name]

    def update(self, _obj={}, **kwargs):
        _obj = dict(_obj, **kwargs)
        for (name, value) in _obj.iteritems():
            self[name] = value

    def _get_attr_name(self, name):
        name = self._attr_name(name)
        name = self._names[name]
        return name

    def __getitem__(self, name):
        # for python-ldap tuple compatibility
        if name == 0:
            return self._dn
        elif name == 1:
            return self

        return super(LDAPEntry, self).__getitem__(self._get_attr_name(name))

    def get(self, name, default=None):
        try:
            name = self._get_attr_name(name)
        except KeyError:
            return default

        return super(LDAPEntry, self).get(name, default)

    def single_value(self, name, default=_missing):
        """Return a single attribute value

        Checks that the attribute really has one and only one value

        If the entry is missing and default is given, return the default.
        If the entry is missing and default is not given, raise KeyError.
        """
        try:
            attr_name = self._get_attr_name(name)
            values = super(LDAPEntry, self).__getitem__(attr_name)
        except KeyError:
            if default is _missing:
                raise
            return default
        if not isinstance(values, list):  # TODO: remove when we enforce lists
            return values
        if len(values) != 1:
            raise ValueError(
                '%s has %s values, one expected' % (name, len(values)))
        return values[0]

    def _del_attr_name(self, name):
        name = self._get_attr_name(name)

        for (altname, keyname) in self._names.items():
            if keyname == name:
                del self._names[altname]

        return name

    def __delitem__(self, name):
        super(LDAPEntry, self).__delitem__(self._del_attr_name(name))

    def pop(self, name, *default):
        try:
            name = self._del_attr_name(name)
        except KeyError:
            if not default:
                raise

        return super(LDAPEntry, self).pop(name, *default)

    def popitem(self):
        name, value = super(LDAPEntry, self).popitem()
        self._del_attr_name(name)
        return (name, value)

    def clear(self):
        super(LDAPEntry, self).clear()
        self._names.clear()

    def __contains__(self, name):
        return self._names.has_key(self._attr_name(name))

    def has_key(self, name):
        return name in self

    # for python-ldap tuple compatibility
    def __iter__(self):
        yield self._dn
        yield self

    def toDict(self):
        # FIXME: for backwards compatibility only
        """Convert the attrs and values to a dict. The dict is keyed on the
        attribute name.  The value is either single value or a list of values."""
        assert isinstance(self.dn, DN)
        result = ipautil.CIDict(self.data)
        for i in result.keys():
            result[i] = ipautil.utf8_encode_values(result[i])
        result['dn'] = self.dn
        return result

    def origDataDict(self):
        """Returns a dict of the original values of the user.

        Used for updates.
        """
        result = ipautil.CIDict(self.orig_data)
        result['dn'] = self.dn
        return result


class LDAPClient(object):
    """LDAP backend class

    This class abstracts a LDAP connection, providing methods that work with
    LADPEntries.

    This class is not intended to be used directly; instead, use one of its
    subclasses, IPAdmin or the ldap2 plugin.
    """

    # rules for generating filters from entries
    MATCH_ANY = '|'   # (|(filter1)(filter2))
    MATCH_ALL = '&'   # (&(filter1)(filter2))
    MATCH_NONE = '!'  # (!(filter1)(filter2))

    # search scope for find_entries()
    SCOPE_BASE = ldap.SCOPE_BASE
    SCOPE_ONELEVEL = ldap.SCOPE_ONELEVEL
    SCOPE_SUBTREE = ldap.SCOPE_SUBTREE

    def __init__(self, ldap_uri):
        self.ldap_uri = ldap_uri
        self.log = log_mgr.get_logger(self)
        self._init_connection()

    def _init_connection(self):
        self.conn = None

    def get_api(self):
        """Return the API if available, otherwise None

        May be overridden in a subclass.
        """
        return None

    @contextlib.contextmanager
    def error_handler(self, arg_desc=None):
        """Context manager that handles LDAPErrors
        """
        try:
            try:
                yield
            except ldap.TIMEOUT:
                raise errors.DatabaseTimeout()
            except ldap.LDAPError, e:
                desc = e.args[0]['desc'].strip()
                info = e.args[0].get('info', '').strip()
                if arg_desc is not None:
                    info = "%s arguments: %s" % (info, arg_desc)
                raise
        except ldap.NO_SUCH_OBJECT:
            raise errors.NotFound(reason=arg_desc or 'no such entry')
        except ldap.ALREADY_EXISTS:
            raise errors.DuplicateEntry()
        except ldap.CONSTRAINT_VIOLATION:
            # This error gets thrown by the uniqueness plugin
            _msg = 'Another entry with the same attribute value already exists'
            if info.startswith(_msg):
                raise errors.DuplicateEntry()
            else:
                raise errors.DatabaseError(desc=desc, info=info)
        except ldap.INSUFFICIENT_ACCESS:
            raise errors.ACIError(info=info)
        except ldap.INVALID_CREDENTIALS:
            raise errors.ACIError(info="%s %s" % (info, desc))
        except ldap.INAPPROPRIATE_AUTH:
            raise errors.ACIError(info="%s: %s" % (desc, info))
        except ldap.NO_SUCH_ATTRIBUTE:
            # this is raised when a 'delete' attribute isn't found.
            # it indicates the previous attribute was removed by another
            # update, making the oldentry stale.
            raise errors.MidairCollision()
        except ldap.INVALID_SYNTAX:
            raise errors.InvalidSyntax(attr=info)
        except ldap.OBJECT_CLASS_VIOLATION:
            raise errors.ObjectclassViolation(info=info)
        except ldap.ADMINLIMIT_EXCEEDED:
            raise errors.LimitsExceeded()
        except ldap.SIZELIMIT_EXCEEDED:
            raise errors.LimitsExceeded()
        except ldap.TIMELIMIT_EXCEEDED:
            raise errors.LimitsExceeded()
        except ldap.NOT_ALLOWED_ON_RDN:
            raise errors.NotAllowedOnRDN(attr=info)
        except ldap.FILTER_ERROR:
            raise errors.BadSearchFilter(info=info)
        except ldap.NOT_ALLOWED_ON_NONLEAF:
            raise errors.NotAllowedOnNonLeaf()
        except ldap.SERVER_DOWN:
            raise errors.NetworkError(uri=self.ldap_uri,
                                      error=info)
        except ldap.LOCAL_ERROR:
            raise errors.ACIError(info=info)
        except ldap.SUCCESS:
            pass
        except ldap.CONNECT_ERROR:
            raise errors.DatabaseError(desc=desc, info=info)
        except ldap.LDAPError, e:
            if 'NOT_ALLOWED_TO_DELEGATE' in info:
                raise errors.ACIError(
                    info="KDC returned NOT_ALLOWED_TO_DELEGATE")
            self.log.debug(
                'Unhandled LDAPError: %s: %s' % (type(e).__name__, str(e)))
            raise errors.DatabaseError(desc=desc, info=info)

    @property
    def schema(self):
        """schema associated with this LDAP server"""
        return self.conn.schema

    def get_syntax(self, attr, value):
        if self.schema is None:
            return None
        obj = self.schema.get_obj(ldap.schema.AttributeType, attr)
        if obj is not None:
            return obj.syntax
        else:
            return None

    def has_dn_syntax(self, attr):
        return self.conn.has_dn_syntax(attr)

    def get_allowed_attributes(self, objectclasses, raise_on_unknown=False):
        if self.schema is None:
            return None
        allowed_attributes = []
        for oc in objectclasses:
            obj = self.schema.get_obj(ldap.schema.ObjectClass, oc)
            if obj is not None:
                allowed_attributes += obj.must + obj.may
            elif raise_on_unknown:
                raise errors.NotFound(
                    reason=_('objectclass %s not found') % oc)
        return [unicode(a).lower() for a in list(set(allowed_attributes))]

    def get_single_value(self, attr):
        """
        Check the schema to see if the attribute is single-valued.

        If the attribute is in the schema then returns True/False

        If there is a problem loading the schema or the attribute is
        not in the schema return None
        """
        if self.schema is None:
            return None
        obj = self.schema.get_obj(ldap.schema.AttributeType, attr)
        return obj and obj.single_value

    def make_dn_from_attr(self, attr, value, parent_dn=None):
        """
        Make distinguished name from attribute.

        Keyword arguments:
        parent_dn -- DN of the parent entry (default '')
        """
        if parent_dn is None:
            parent_dn = DN()

        if isinstance(value, (list, tuple)):
            value = value[0]

        return DN((attr, value), parent_dn)

    def make_dn(self, entry_attrs, primary_key='cn', parent_dn=None):
        """
        Make distinguished name from entry attributes.

        Keyword arguments:
        primary_key -- attribute from which to make RDN (default 'cn')
        parent_dn -- DN of the parent entry (default '')
        """

        assert primary_key in entry_attrs
        assert isinstance(parent_dn, DN)

        return DN((primary_key, entry_attrs[primary_key]), parent_dn)

    def make_entry(self, _dn=None, _obj=None, **kwargs):
        return LDAPEntry(self.conn, _dn, _obj, **kwargs)

    # generating filters for find_entry
    # some examples:
    # f1 = ldap2.make_filter_from_attr(u'firstName', u'Pavel')
    # f2 = ldap2.make_filter_from_attr(u'lastName', u'Zuna')
    # f = ldap2.combine_filters([f1, f2], ldap2.MATCH_ALL)
    # # f should be (&(firstName=Pavel)(lastName=Zuna))
    # # it should be equivalent to:
    # entry_attrs = {u'firstName': u'Pavel', u'lastName': u'Zuna'}
    # f = ldap2.make_filter(entry_attrs, rules=ldap2.MATCH_ALL)

    def combine_filters(self, filters, rules='|'):
        """
        Combine filters into one for ldap2.find_entries.

        Keyword arguments:
        rules -- see ldap2.make_filter
        """

        assert isinstance(filters, (list, tuple))

        filters = [f for f in filters if f]
        if filters and rules == self.MATCH_NONE:  # unary operator
            return '(%s%s)' % (self.MATCH_NONE,
                               self.combine_filters(filters, self.MATCH_ANY))

        if len(filters) > 1:
            flt = '(%s' % rules
        else:
            flt = ''
        for f in filters:
            if not f.startswith('('):
                f = '(%s)' % f
            flt = '%s%s' % (flt, f)
        if len(filters) > 1:
            flt = '%s)' % flt
        return flt

    def make_filter_from_attr(
            self, attr, value, rules='|', exact=True,
            leading_wildcard=True, trailing_wildcard=True):
        """
        Make filter for ldap2.find_entries from attribute.

        Keyword arguments:
        rules -- see ldap2.make_filter
        exact -- boolean, True - make filter as (attr=value)
                          False - make filter as (attr=*value*)
        leading_wildcard -- boolean:
            True - allow heading filter wildcard when exact=False
            False - forbid heading filter wildcard when exact=False
        trailing_wildcard -- boolean:
            True - allow trailing filter wildcard when exact=False
            False - forbid trailing filter wildcard when exact=False
        """
        if isinstance(value, (list, tuple)):
            if rules == self.MATCH_NONE:
                make_filter_rules = self.MATCH_ANY
            else:
                make_filter_rules = rules
            flts = [
                self.make_filter_from_attr(
                    attr, v, exact=exact,
                    leading_wildcard=leading_wildcard,
                    trailing_wildcard=trailing_wildcard)
                for v in value
            ]
            return self.combine_filters(flts, rules)
        elif value is not None:
            value = ldap.filter.escape_filter_chars(value_to_utf8(value))
            if not exact:
                template = '%s'
                if leading_wildcard:
                    template = '*' + template
                if trailing_wildcard:
                    template = template + '*'
                value = template % value
            if rules == self.MATCH_NONE:
                return '(!(%s=%s))' % (attr, value)
            return '(%s=%s)' % (attr, value)
        return ''

    def make_filter(
            self, entry_attrs, attrs_list=None, rules='|', exact=True,
            leading_wildcard=True, trailing_wildcard=True):
        """
        Make filter for ldap2.find_entries from entry attributes.

        Keyword arguments:
        attrs_list -- list of attributes to use, all if None (default None)
        rules -- specifies how to determine a match (default ldap2.MATCH_ANY)
        exact -- boolean, True - make filter as (attr=value)
                          False - make filter as (attr=*value*)
        leading_wildcard -- boolean:
            True - allow heading filter wildcard when exact=False
            False - forbid heading filter wildcard when exact=False
        trailing_wildcard -- boolean:
            True - allow trailing filter wildcard when exact=False
            False - forbid trailing filter wildcard when exact=False

        rules can be one of the following:
        ldap2.MATCH_NONE - match entries that do not match any attribute
        ldap2.MATCH_ALL - match entries that match all attributes
        ldap2.MATCH_ANY - match entries that match any of attribute
        """
        if rules == self.MATCH_NONE:
            make_filter_rules = self.MATCH_ANY
        else:
            make_filter_rules = rules
        flts = []
        if attrs_list is None:
            for (k, v) in entry_attrs.iteritems():
                flts.append(
                    self.make_filter_from_attr(
                        k, v, make_filter_rules, exact,
                        leading_wildcard, trailing_wildcard)
                )
        else:
            for a in attrs_list:
                value = entry_attrs.get(a, None)
                if value is not None:
                    flts.append(
                        self.make_filter_from_attr(
                            a, value, make_filter_rules, exact,
                            leading_wildcard, trailing_wildcard)
                    )
        return self.combine_filters(flts, rules)

    def get_entries(self, base_dn, scope=None, filter=None, attrs_list=None):
        """Return a list of matching entries.

        Raises an error if the list is truncated by the server

        :param base_dn: dn of the entry at which to start the search
        :param scope: search scope, see LDAP docs (default ldap2.SCOPE_SUBTREE)
        :param filter: LDAP filter to apply
        :param attrs_list: ist of attributes to return, all if None (default)

        Use the find_entries method for more options.
        """
        entries, truncated = self.find_entries(
            base_dn=base_dn, scope=scope, filter=filter, attrs_list=attrs_list)
        if truncated:
            raise errors.LimitsExceeded()
        return entries

    def find_entries(self, filter=None, attrs_list=None, base_dn=None,
                     scope=ldap.SCOPE_SUBTREE, time_limit=None,
                     size_limit=None, search_refs=False):
        """
        Return a list of entries and indication of whether the results were
        truncated ([(dn, entry_attrs)], truncated) matching specified search
        parameters followed by truncated flag. If the truncated flag is True,
        search hit a server limit and its results are incomplete.

        Keyword arguments:
        attrs_list -- list of attributes to return, all if None (default None)
        base_dn -- dn of the entry at which to start the search (default '')
        scope -- search scope, see LDAP docs (default ldap2.SCOPE_SUBTREE)
        time_limit -- time limit in seconds (default use IPA config values)
        size_limit -- size (number of entries returned) limit
            (default use IPA config values)
        search_refs -- allow search references to be returned
            (default skips these entries)
        """
        if base_dn is None:
            base_dn = DN()
        assert isinstance(base_dn, DN)
        if not filter:
            filter = '(objectClass=*)'
        res = []
        truncated = False

        if time_limit is None or size_limit is None:
            config = self.get_ipa_config()
            if time_limit is None:
                time_limit = config.get('ipasearchtimelimit', [-1])[0]
            if size_limit is None:
                size_limit = config.get('ipasearchrecordslimit', [0])[0]
        if time_limit == 0:
            time_limit = -1
        if not isinstance(size_limit, int):
            size_limit = int(size_limit)
        if not isinstance(time_limit, float):
            time_limit = float(time_limit)

        if attrs_list:
            attrs_list = list(set(attrs_list))

        # pass arguments to python-ldap
        with self.error_handler():
            try:
                id = self.conn.search_ext(
                    base_dn, scope, filter, attrs_list, timeout=time_limit,
                    sizelimit=size_limit
                )
                while True:
                    (objtype, res_list) = self.conn.result(id, 0)
                    if not res_list:
                        break
                    if (objtype == ldap.RES_SEARCH_ENTRY or
                            (search_refs and
                                objtype == ldap.RES_SEARCH_REFERENCE)):
                        res.append(res_list[0])
            except (ldap.ADMINLIMIT_EXCEEDED, ldap.TIMELIMIT_EXCEEDED,
                    ldap.SIZELIMIT_EXCEEDED), e:
                truncated = True

        if not res and not truncated:
            raise errors.NotFound(reason='no such entry')

        if attrs_list and (
                'memberindirect' in attrs_list or '*' in attrs_list):
            for r in res:
                if not 'member' in r[1]:
                    continue
                else:
                    members = r[1]['member']
                    indirect = self.get_members(
                        r[0], members, membertype=MEMBERS_INDIRECT,
                        time_limit=time_limit, size_limit=size_limit)
                    if len(indirect) > 0:
                        r[1]['memberindirect'] = indirect
        if attrs_list and (
                'memberofindirect' in attrs_list or '*' in attrs_list):
            for r in res:
                if 'memberof' in r[1]:
                    memberof = r[1]['memberof']
                    del r[1]['memberof']
                elif 'memberOf' in r[1]:
                    memberof = r[1]['memberOf']
                    del r[1]['memberOf']
                else:
                    continue
                direct, indirect = self.get_memberof(
                    r[0], memberof, time_limit=time_limit,
                    size_limit=size_limit)
                if len(direct) > 0:
                    r[1]['memberof'] = direct
                if len(indirect) > 0:
                    r[1]['memberofindirect'] = indirect

        return (res, truncated)

    def find_entry_by_attr(self, attr, value, object_class, attrs_list=None,
                           base_dn=None):
        """
        Find entry (dn, entry_attrs) by attribute and object class.

        Keyword arguments:
        attrs_list - list of attributes to return, all if None (default None)
        base_dn - dn of the entry at which to start the search (default '')
        """

        if base_dn is None:
            base_dn = DN()
        assert isinstance(base_dn, DN)

        search_kw = {attr: value, 'objectClass': object_class}
        filter = self.make_filter(search_kw, rules=self.MATCH_ALL)
        (entries, truncated) = self.find_entries(filter, attrs_list, base_dn)

        if len(entries) > 1:
            raise errors.SingleMatchExpected(found=len(entries))
        else:
            if truncated:
                raise errors.LimitsExceeded()
            else:
                return entries[0]

    def get_entry(self, dn, attrs_list=None, time_limit=None,
                  size_limit=None):
        """
        Get entry (dn, entry_attrs) by dn.

        Keyword arguments:
        attrs_list - list of attributes to return, all if None (default None)
        """

        assert isinstance(dn, DN)

        (entry, truncated) = self.find_entries(
            None, attrs_list, dn, self.SCOPE_BASE, time_limit=time_limit,
            size_limit=size_limit
        )

        if truncated:
            raise errors.LimitsExceeded()
        return entry[0]

    def get_ipa_config(self, attrs_list=None):
        """Returns the IPA configuration entry.

        Overriden in the subclasses that have access to IPA configuration.
        """
        return {}

    def get_memberof(self, entry_dn, memberof, time_limit=None,
                     size_limit=None):
        """
        Examine the objects that an entry is a member of and determine if they
        are a direct or indirect member of that group.

        entry_dn: dn of the entry we want the direct/indirect members of
        memberof: the memberOf attribute for entry_dn

        Returns two memberof lists: (direct, indirect)
        """

        assert isinstance(entry_dn, DN)

        self.log.debug(
            "get_memberof: entry_dn=%s memberof=%s", entry_dn, memberof)
        if not type(memberof) in (list, tuple):
            return ([], [])
        if len(memberof) == 0:
            return ([], [])

        search_entry_dn = ldap.filter.escape_filter_chars(str(entry_dn))
        attr_list = ["memberof"]
        searchfilter = "(|(member=%s)(memberhost=%s)(memberuser=%s))" % (
            search_entry_dn, search_entry_dn, search_entry_dn)

        # Search only the groups for which the object is a member to
        # determine if it is directly or indirectly associated.

        results = []
        for group in memberof:
            assert isinstance(group, DN)
            try:
                result, truncated = self.find_entries(
                    searchfilter, attr_list,
                    group, time_limit=time_limit, size_limit=size_limit,
                    scope=ldap.SCOPE_BASE)
                results.extend(list(result))
            except errors.NotFound:
                pass

        direct = []
        # If there is an exception here, it is likely due to a failure in
        # referential integrity. All members should have corresponding
        # memberOf entries.
        indirect = list(memberof)
        for r in results:
            direct.append(r[0])
            try:
                indirect.remove(r[0])
            except ValueError, e:
                self.log.info(
                    'Failed to remove indirect entry %s from %s',
                    r[0], entry_dn)
                raise e

        self.log.debug(
            "get_memberof: result direct=%s indirect=%s", direct, indirect)
        return (direct, indirect)

    def get_members(self, group_dn, members, attr_list=[],
                    membertype=MEMBERS_ALL, time_limit=None, size_limit=None):
        """Do a memberOf search of groupdn and return the attributes in
           attr_list (an empty list returns all attributes).

           membertype = MEMBERS_ALL all members returned
           membertype = MEMBERS_DIRECT only direct members are returned
           membertype = MEMBERS_INDIRECT only inherited members are returned

           Members may be included in a group as a result of being a member
           of a group that is a member of the group being queried.

           Returns a list of DNs.
        """

        assert isinstance(group_dn, DN)

        if membertype not in [MEMBERS_ALL, MEMBERS_DIRECT, MEMBERS_INDIRECT]:
            return None

        self.log.debug(
            "get_members: group_dn=%s members=%s membertype=%s",
            group_dn, members, membertype)
        search_group_dn = ldap.filter.escape_filter_chars(str(group_dn))
        searchfilter = "(memberof=%s)" % search_group_dn

        attr_list.append("member")

        # Verify group membership

        results = []
        if membertype == MEMBERS_ALL or membertype == MEMBERS_INDIRECT:
            api = self.get_api()
            if api:
                user_container_dn = DN(api.env.container_user, api.env.basedn)
                host_container_dn = DN(api.env.container_host, api.env.basedn)
            else:
                user_container_dn = host_container_dn = None
            checkmembers = set(DN(x) for x in members)
            checked = set()
            while checkmembers:
                member_dn = checkmembers.pop()
                checked.add(member_dn)

                # No need to check entry types that are not nested for
                # additional members
                if user_container_dn and (
                        member_dn.endswith(user_container_dn) or
                        member_dn.endswith(host_container_dn)):
                    results.append([member_dn, {}])
                    continue
                try:
                    result, truncated = self.find_entries(
                        searchfilter, attr_list, member_dn,
                        time_limit=time_limit, size_limit=size_limit,
                        scope=ldap.SCOPE_BASE)
                    if truncated:
                        raise errors.LimitsExceeded()
                    results.append(list(result[0]))
                    for m in result[0][1].get('member', []):
                        # This member may contain other members, add it to our
                        # candidate list
                        if m not in checked:
                            checkmembers.add(m)
                except errors.NotFound:
                    pass

        if membertype == MEMBERS_ALL:
            entries = []
            for e in results:
                entries.append(e[0])

            return entries

        dn, group = self.get_entry(
            group_dn, ['member'],
            size_limit=size_limit, time_limit=time_limit)
        real_members = group.get('member', [])

        entries = []
        for e in results:
            if e[0] not in real_members and e[0] not in entries:
                if membertype == MEMBERS_INDIRECT:
                    entries.append(e[0])
            else:
                if membertype == MEMBERS_DIRECT:
                    entries.append(e[0])

        self.log.debug("get_members: result=%s", entries)
        return entries

    def _get_dn_and_attrs(self, entry_or_dn, entry_attrs):
        """Helper for legacy calling style for {add,update}_entry
        """
        if entry_attrs is None:
            return entry_or_dn.dn, entry_or_dn
        else:
            assert isinstance(entry_or_dn, DN)
            entry_attrs = self.make_entry(entry_or_dn, entry_attrs)
            for key, value in entry_attrs.items():
                if value is None:
                    entry_attrs[key] = []
            return entry_or_dn, entry_attrs

    def add_entry(self, entry, entry_attrs=None):
        """Create a new entry.

        This should be called as add_entry(entry).

        The legacy two-argument variant is:
            add_entry(dn, entry_attrs)
        """
        dn, attrs = self._get_dn_and_attrs(entry, entry_attrs)

        # remove all [] values (python-ldap hates 'em)
        attrs = dict((k, v) for k, v in attrs.iteritems()
            # FIXME: Once entry values are always lists, this condition can
            # be just "if v":
            if v is not None and v != [])

        with self.error_handler():
            self.conn.add_s(dn, attrs.items())

    def update_entry_rdn(self, dn, new_rdn, del_old=True):
        """
        Update entry's relative distinguished name.

        Keyword arguments:
        del_old -- delete old RDN value (default True)
        """

        assert isinstance(dn, DN)
        assert isinstance(new_rdn, RDN)

        if dn[0] == new_rdn:
            raise errors.EmptyModlist()
        with self.error_handler():
            self.conn.rename_s(dn, new_rdn, delold=int(del_old))
            time.sleep(.3)  # Give memberOf plugin a chance to work

    def _generate_modlist(self, dn, entry_attrs):
        assert isinstance(dn, DN)

        # get original entry
        dn, entry_attrs_old = self.get_entry(dn, entry_attrs.keys())

        # generate modlist
        # for multi value attributes: no MOD_REPLACE to handle simultaneous
        # updates better
        # for single value attribute: always MOD_REPLACE
        modlist = []
        for (k, v) in entry_attrs.iteritems():
            if v is None and k in entry_attrs_old:
                modlist.append((ldap.MOD_DELETE, k, None))
            else:
                if not isinstance(v, (list, tuple)):
                    v = [v]
                v = set(filter(lambda value: value is not None, v))
                old_v = set(entry_attrs_old.get(k.lower(), []))

                # FIXME: Convert all values to either unicode, DN or str
                # before detecting value changes (see IPASimpleLDAPObject for
                # supported types).
                # This conversion will set a common ground for the comparison.
                #
                # This fix can be removed when ticket 2265 is fixed and our
                # encoded entry_attrs' types will match get_entry result
                try:
                    v = set(
                        unicode_from_utf8(self.conn.encode(value))
                        if not isinstance(value, (DN, str, unicode))
                        else value for value in v)
                except Exception, e:
                    # Rather let the value slip in modlist than let ldap2 crash
                    self.log.error(
                        "Cannot convert attribute '%s' for modlist "
                        "for modlist comparison: %s", k, e)

                adds = list(v.difference(old_v))
                rems = list(old_v.difference(v))

                is_single_value = self.get_single_value(k)

                value_count = len(old_v) + len(adds) - len(rems)
                if is_single_value and value_count > 1:
                    raise errors.OnlyOneValueAllowed(attr=k)

                force_replace = False
                if len(v) > 0 and len(v.intersection(old_v)) == 0:
                    force_replace = True

                if adds:
                    if force_replace:
                        modlist.append((ldap.MOD_REPLACE, k, adds))
                    else:
                        modlist.append((ldap.MOD_ADD, k, adds))
                if rems:
                    if not force_replace:
                        modlist.append((ldap.MOD_DELETE, k, rems))

        return modlist

    def update_entry(self, entry, entry_attrs=None):
        """Update entry's attributes.

        This should be called as update_entry(entry).

        The legacy two-argument variant is:
            update_entry(dn, entry_attrs)
        """
        dn, attrs = self._get_dn_and_attrs(entry, entry_attrs)

        # generate modlist
        modlist = self._generate_modlist(dn, attrs)
        if not modlist:
            raise errors.EmptyModlist()

        # pass arguments to python-ldap
        with self.error_handler():
            self.conn.modify_s(dn, modlist)

    def delete_entry(self, entry_or_dn):
        """Delete an entry given either the DN or the entry itself"""
        if isinstance(entry_or_dn, DN):
            dn = entry_or_dn
        else:
            dn = entry_or_dn.dn

        with self.error_handler():
            self.conn.delete_s(dn)


class IPAdmin(LDAPClient):

    def __get_ldap_uri(self, protocol):
        if protocol == 'ldaps':
            return 'ldaps://%s' % format_netloc(self.host, self.port)
        elif protocol == 'ldapi':
            return 'ldapi://%%2fvar%%2frun%%2fslapd-%s.socket' % (
                "-".join(self.realm.split(".")))
        elif protocol == 'ldap':
            return 'ldap://%s' % format_netloc(self.host, self.port)
        else:
            raise ValueError('Protocol %r not supported' % protocol)


    def __guess_protocol(self):
        """Return the protocol to use based on flags passed to the constructor

        Only used when "protocol" is not specified explicitly.

        If a CA certificate is provided then it is assumed that we are
        doing SSL client authentication with proxy auth.

        If a CA certificate is not present then it is assumed that we are
        using a forwarded kerberos ticket for SASL auth. SASL provides
        its own encryption.
        """
        if self.cacert is not None:
            return 'ldaps'
        elif self.ldapi:
            return 'ldapi'
        else:
            return 'ldap'

    def __init__(self, host='', port=389, cacert=None, debug=None, ldapi=False,
                 realm=None, protocol=None, force_schema_updates=True,
                 start_tls=False, ldap_uri=None, no_schema=False,
                 decode_attrs=True, sasl_nocanon=False, demand_cert=False):
        self.conn = None
        log_mgr.get_logger(self, True)
        if debug and debug.lower() == "on":
            ldap.set_option(ldap.OPT_DEBUG_LEVEL,255)
        if cacert is not None:
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, cacert)

        self.port = port
        self.host = host
        self.cacert = cacert
        self.ldapi = ldapi
        self.realm = realm
        self.suffixes = {}

        if not ldap_uri:
            ldap_uri = self.__get_ldap_uri(protocol or self.__guess_protocol())

        LDAPClient.__init__(self, ldap_uri)

        with self.error_handler():
            self.conn = IPASimpleLDAPObject(ldap_uri,
                                            force_schema_updates=True,
                                            no_schema=no_schema,
                                            decode_attrs=decode_attrs)

            if demand_cert:
                ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, True)
                self.conn.set_option(ldap.OPT_X_TLS_DEMAND, True)

            if sasl_nocanon:
                self.conn.set_option(ldap.OPT_X_SASL_NOCANON, ldap.OPT_ON)

            if start_tls:
                self.conn.start_tls_s()

    def __str__(self):
        return self.host + ":" + str(self.port)

    def __wait_for_connection(self, timeout):
        lurl = ldapurl.LDAPUrl(self.ldap_uri)
        if lurl.urlscheme == 'ldapi':
            wait_for_open_socket(lurl.hostport, timeout)
        else:
            (host,port) = lurl.hostport.split(':')
            wait_for_open_ports(host, int(port), timeout)

    def __bind_with_wait(self, bind_func, timeout, *args, **kwargs):
        with self.error_handler():
            try:
                bind_func(*args, **kwargs)
            except (ldap.CONNECT_ERROR, ldap.SERVER_DOWN), e:
                if not timeout or 'TLS' in e.args[0].get('info', ''):
                    # No connection to continue on if we have a TLS failure
                    # https://bugzilla.redhat.com/show_bug.cgi?id=784989
                    raise
                self.__wait_for_connection(timeout)
                bind_func(*args, **kwargs)

    def do_simple_bind(self, binddn=DN(('cn', 'directory manager')), bindpw="",
                       timeout=DEFAULT_TIMEOUT):
        self.__bind_with_wait(self.conn.simple_bind_s, timeout, binddn, bindpw)

    def do_sasl_gssapi_bind(self, timeout=DEFAULT_TIMEOUT):
        self.__bind_with_wait(
            self.conn.sasl_interactive_bind_s, timeout, None, SASL_GSSAPI)

    def do_external_bind(self, user_name=None, timeout=DEFAULT_TIMEOUT):
        auth_tokens = ldap.sasl.external(user_name)
        self.__bind_with_wait(
            self.conn.sasl_interactive_bind_s, timeout, None, auth_tokens)

    def updateEntry(self,dn,oldentry,newentry):
        # FIXME: for backwards compatibility only
        """This wraps the mod function. It assumes that the entry is already
           populated with all of the desired objectclasses and attributes"""

        assert isinstance(dn, DN)

        modlist = self.generateModList(oldentry, newentry)

        if len(modlist) == 0:
            raise errors.EmptyModlist

        with self.error_handler():
            self.modify_s(dn, modlist)
        return True

    def generateModList(self, old_entry, new_entry):
        # FIXME: for backwards compatibility only
        """A mod list generator that computes more precise modification lists
           than the python-ldap version.  For single-value attributes always
           use a REPLACE operation, otherwise use ADD/DEL.
        """

        # Some attributes, like those in cn=config, need to be replaced
        # not deleted/added.
        FORCE_REPLACE_ON_UPDATE_ATTRS = ('nsslapd-ssl-check-hostname', 'nsslapd-lookthroughlimit', 'nsslapd-idlistscanlimit', 'nsslapd-anonlimitsdn', 'nsslapd-minssf-exclude-rootdse')
        modlist = []

        old_entry = ipautil.CIDict(old_entry)
        new_entry = ipautil.CIDict(new_entry)

        keys = set(map(string.lower, old_entry.keys()))
        keys.update(map(string.lower, new_entry.keys()))

        for key in keys:
            new_values = new_entry.get(key, [])
            if not(isinstance(new_values,list) or isinstance(new_values,tuple)):
                new_values = [new_values]
            new_values = filter(lambda value:value!=None, new_values)

            old_values = old_entry.get(key, [])
            if not(isinstance(old_values,list) or isinstance(old_values,tuple)):
                old_values = [old_values]
            old_values = filter(lambda value:value!=None, old_values)

            # We used to convert to sets and use difference to calculate
            # the changes but this did not preserve order which is important
            # particularly for schema
            adds = [x for x in new_values if x not in old_values]
            removes = [x for x in old_values if x not in new_values]

            if len(adds) == 0 and len(removes) == 0:
                continue

            is_single_value = self.get_single_value(key)
            force_replace = False
            if key in FORCE_REPLACE_ON_UPDATE_ATTRS or is_single_value:
                force_replace = True

            # You can't remove schema online. An add will automatically
            # replace any existing schema.
            if old_entry.get('dn', DN()) == DN(('cn', 'schema')):
                if len(adds) > 0:
                    modlist.append((ldap.MOD_ADD, key, adds))
            else:
                if adds:
                    if force_replace:
                        modlist.append((ldap.MOD_REPLACE, key, adds))
                    else:
                        modlist.append((ldap.MOD_ADD, key, adds))
                if removes:
                    if not force_replace:
                        modlist.append((ldap.MOD_DELETE, key, removes))

        return modlist

    def modify_s(self, *args, **kwargs):
        # FIXME: for backwards compatibility only
        return self.conn.modify_s(*args, **kwargs)

    def set_option(self, *args, **kwargs):
        # FIXME: for backwards compatibility only
        return self.conn.set_option(*args, **kwargs)

    def encode(self, *args, **kwargs):
        # FIXME: for backwards compatibility only
        return self.conn.encode(*args, **kwargs)

    def unbind(self, *args, **kwargs):
        return self.conn.unbind_s(*args, **kwargs)
