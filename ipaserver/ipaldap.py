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

import sys
import os
import os.path
import socket
import string
import time
import struct
import shutil
from decimal import Decimal

import ldap
import ldap as _ldap
import ldap.sasl
from ldap.controls import LDAPControl
from ldap.ldapobject import SimpleLDAPObject
import ldapurl

from ipalib import errors
from ipapython import ipautil
from ipapython.ipautil import (
    format_netloc, wait_for_open_socket, wait_for_open_ports, CIDict)
from ipapython.ipa_log_manager import log_mgr
from ipapython.dn import DN, RDN

# Global variable to define SASL auth
SASL_AUTH = ldap.sasl.sasl({}, 'GSSAPI')

DEFAULT_TIMEOUT = 10
DN_SYNTAX_OID = '1.3.6.1.4.1.1466.115.121.1.12'
_debug_log_ldap = False

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
                schema_entry = conn.search_s('cn=schema', _ldap.SCOPE_BASE,
                    attrlist=['attributetypes', 'objectclasses'])[0]
            except _ldap.NO_SUCH_OBJECT:
                # try different location for schema
                # openldap has schema located in cn=subschema
                self.log.debug('cn=schema not found, fallback to cn=subschema')
                schema_entry = conn.search_s('cn=subschema', _ldap.SCOPE_BASE,
                    attrlist=['attributetypes', 'objectclasses'])[0]
        except _ldap.SERVER_DOWN:
            raise errors.NetworkError(uri=url,
                               error=u'LDAP Server Down, unable to retrieve LDAP schema')
        except _ldap.LDAPError, e:
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

        return _ldap.schema.SubSchema(schema_entry[1])

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

    def __init__(self, uri, force_schema_updates):
        """An internal LDAP connection object

        :param uri: The LDAP URI to connect to
        :param force_schema_updates:
            If true, this object will always request a new schema from the
            server. If false, a cached schema will be reused if it exists.

            Generally, it should be true if the API context is 'installer' or
            'updates', but it must be given explicitly since the API object
            is not always available
        """
        self.log = log_mgr.get_logger(self)
        self.uri = uri
        self.conn = SimpleLDAPObject(uri)
        self._schema = None
        self._force_schema_updates = force_schema_updates

    def _get_schema(self):
        if self._schema is None:
            self._schema = schema_cache.get_schema(
                self.uri, self.conn, force_update=self._force_schema_updates)
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

        self._schema = None

    def get_syntax(self, attr):
        # Is this a special case attribute?
        syntax = self._SCHEMA_OVERRIDE.get(attr)
        if syntax is not None:
            return syntax

        # Try to lookup the syntax in the schema returned by the server
        obj = self.schema.get_obj(_ldap.schema.AttributeType, attr)
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

            ipa_entry = LDAPEntry(DN(original_dn))

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

    def bind(self, who, cred, method=_ldap.AUTH_SIMPLE):
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

    def result(self, msgid=_ldap.RES_ANY, all=1, timeout=None):
        resp_type, resp_data = self.conn.result(msgid, all, timeout)
        resp_data = self.convert_result(resp_data)
        return resp_type, resp_data

    def sasl_interactive_bind_s(self, who, auth, serverctrls=None, clientctrls=None, sasl_flags=_ldap.SASL_QUIET):
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

    def unbind(self):
        self.flush_cached_schema()
        return self.conn.unbind()

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
    __slots__ = ('_dn',)

    def __init__(self, _dn=None, _obj=None, **kwargs):
        if isinstance(_dn, LDAPEntry):
            assert _obj is None
            _obj = _dn
            self._dn = DN(_obj._dn)    #pylint: disable=E1103
        else:
            assert isinstance(_dn, DN)
            if _obj is None:
                _obj = {}
            self._dn = _dn

        super(LDAPEntry, self).__init__(self._init_iter(_obj, **kwargs))

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

    def _attr_name(self, name):
        if not isinstance(name, basestring):
            raise TypeError(
                "attribute name must be unicode or str, got %s object %r" % (
                    name.__class__.__name__, name))
        if isinstance(name, str):
            name = name.decode('ascii')
        return name.lower()

    def _init_iter(self, _obj, **kwargs):
        _obj = dict(_obj, **kwargs)
        for (k, v) in _obj.iteritems():
            yield (self._attr_name(k), v)

    def __repr__(self):
        dict_repr = super(LDAPEntry, self).__repr__()
        return '%s(%s, %s)' % (type(self).__name__, repr(self._dn), dict_repr)

    def copy(self):
        return LDAPEntry(self)

    def __setitem__(self, name, value):
        super(LDAPEntry, self).__setitem__(self._attr_name(name), value)

    def setdefault(self, name, default):
        return super(LDAPEntry, self).setdefault(self._attr_name(name), default)

    def update(self, _obj={}, **kwargs):
        super(LDAPEntry, self).update(self._init_iter(_obj, **kwargs))

    def __getitem__(self, name):
        # for python-ldap tuple compatibility
        if name == 0:
            return self._dn
        elif name == 1:
            return self

        return super(LDAPEntry, self).__getitem__(self._attr_name(name))

    def get(self, name, default=None):
        return super(LDAPEntry, self).get(self._attr_name(name), default)

    def __delitem__(self, name):
        super(LDAPEntry, self).__delitem__(self._attr_name(name))

    def pop(self, name, *default):
        return super(LDAPEntry, self).pop(self._attr_name(name), *default)

    def __contains__(self, name):
        return super(LDAPEntry, self).__contains__(self._attr_name(name))

    def has_key(self, name):
        return super(LDAPEntry, self).has_key(self._attr_name(name))

    # for python-ldap tuple compatibility
    def __iter__(self):
        yield self._dn
        yield self

    def getValues(self, name):
        # FIXME: for backwards compatibility only
        """Get the list (array) of values for the attribute named name"""
        return self.data.get(name)

    def getValue(self, name, default=None):
        # FIXME: for backwards compatibility only
        """Get the first value for the attribute named name"""
        value = self.data.get(name, default)
        if isinstance(value, (list, tuple)):
            return value[0]
        return value

    def setValue(self, name, *value):
        # FIXME: for backwards compatibility only
        """
        Set a value on this entry.

        The value passed in may be a single value, several values, or a
        single sequence.  For example:

           * ent.setValue('name', 'value')
           * ent.setValue('name', 'value1', 'value2', ..., 'valueN')
           * ent.setValue('name', ['value1', 'value2', ..., 'valueN'])
           * ent.setValue('name', ('value1', 'value2', ..., 'valueN'))

        Since value is a tuple, we may have to extract a list or tuple from
        that tuple as in the last two examples above.
        """
        if isinstance(value[0],list) or isinstance(value[0],tuple):
            self.data[name] = value[0]
        else:
            self.data[name] = value

    setValues = setValue

    def toTupleList(self):
        # FIXME: for backwards compatibility only
        """Convert the attrs and values to a list of 2-tuples.  The first element
        of the tuple is the attribute name.  The second element is either a
        single value or a list of values."""
        r = []
        for i in self.data.iteritems():
            n = ipautil.utf8_encode_values(i[1])
            r.append((i[0], n))
        return r

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


class Entry(LDAPEntry):
    """For compatibility with old code only

    This class represents an LDAP Entry object.  An LDAP entry consists of
    a DN and a list of attributes.  Each attribute consists of a name and
    a list of values.  In python-ldap, entries are returned as a list of
    2-tuples.  Instance variables:

        * dn - DN object - the DN of the entry
        * data - CIDict - case insensitive dict of the attributes and values
    """
    def __init__(self, entrydata):
        """data is the raw data returned from the python-ldap result method, which is
        a search result entry or a reference or None.
        If creating a new empty entry, data is the string DN."""
        if entrydata:
            if isinstance(entrydata, (tuple, LDAPEntry)):
                dn = entrydata[0]
                data = ipautil.CIDict(entrydata[1])
            elif isinstance(entrydata, DN):
                dn = entrydata
                data = ipautil.CIDict()
            elif isinstance(entrydata, basestring):
                dn = DN(entrydata)
                data = ipautil.CIDict()
            elif isinstance(entrydata, dict):
                if hasattr(entrydata, 'dn'):
                    entrydata['dn'] = entrydata.dn
                dn = entrydata['dn']
                del entrydata['dn']
                data = ipautil.CIDict(entrydata)
            else:
                raise TypeError(
                    "entrydata must be 2-tuple, DN, or basestring, got %s" %
                    type(entrydata))
        else:
            dn = DN()
            data = ipautil.CIDict()

        super(Entry, self).__init__(dn, data)


class LDAPConnection(object):
    """LDAP backend class

    This class abstracts a LDAP connection, providing methods that work with
    LADPEntries.

    This class is not intended to be used directly; instead, use one of its
    subclasses, IPAdmin or the ldap2 plugin.
    """
    def __init__(self, ldap_uri):
        self.ldap_uri = ldap_uri
        self.log = log_mgr.get_logger(self)

    def handle_errors(self, e, arg_desc=None):
        """Universal LDAPError handler

        :param e: The error to be raised
        :param url: The URL of the server
        """
        if not isinstance(e, _ldap.TIMEOUT):
            desc = e.args[0]['desc'].strip()
            info = e.args[0].get('info', '').strip()
            if arg_desc is not None:
                info = "%s arguments: %s" % (info, arg_desc)
        else:
            desc = ''
            info = ''

        try:
            # re-raise the error so we can handle it
            raise e
        except _ldap.NO_SUCH_OBJECT:
            raise errors.NotFound(reason=arg_desc or 'no such entry')
        except _ldap.ALREADY_EXISTS:
            raise errors.DuplicateEntry()
        except _ldap.CONSTRAINT_VIOLATION:
            # This error gets thrown by the uniqueness plugin
            _msg = 'Another entry with the same attribute value already exists'
            if info.startswith(_msg):
                raise errors.DuplicateEntry()
            else:
                raise errors.DatabaseError(desc=desc, info=info)
        except _ldap.INSUFFICIENT_ACCESS:
            raise errors.ACIError(info=info)
        except _ldap.INVALID_CREDENTIALS:
            raise errors.ACIError(info="%s %s" % (info, desc))
        except _ldap.NO_SUCH_ATTRIBUTE:
            # this is raised when a 'delete' attribute isn't found.
            # it indicates the previous attribute was removed by another
            # update, making the oldentry stale.
            raise errors.MidairCollision()
        except _ldap.INVALID_SYNTAX:
            raise errors.InvalidSyntax(attr=info)
        except _ldap.OBJECT_CLASS_VIOLATION:
            raise errors.ObjectclassViolation(info=info)
        except _ldap.ADMINLIMIT_EXCEEDED:
            raise errors.LimitsExceeded()
        except _ldap.SIZELIMIT_EXCEEDED:
            raise errors.LimitsExceeded()
        except _ldap.TIMELIMIT_EXCEEDED:
            raise errors.LimitsExceeded()
        except _ldap.NOT_ALLOWED_ON_RDN:
            raise errors.NotAllowedOnRDN(attr=info)
        except _ldap.FILTER_ERROR:
            raise errors.BadSearchFilter(info=info)
        except _ldap.NOT_ALLOWED_ON_NONLEAF:
            raise errors.NotAllowedOnNonLeaf()
        except _ldap.SERVER_DOWN:
            raise errors.NetworkError(uri=self.ldap_uri,
                                      error=u'LDAP Server Down')
        except _ldap.LOCAL_ERROR:
            raise errors.ACIError(info=info)
        except _ldap.SUCCESS:
            pass
        except _ldap.LDAPError, e:
            if 'NOT_ALLOWED_TO_DELEGATE' in info:
                raise errors.ACIError(
                    info="KDC returned NOT_ALLOWED_TO_DELEGATE")
            self.log.info('Unhandled LDAPError: %s' % str(e))
            raise errors.DatabaseError(desc=desc, info=info)


class IPAdmin(LDAPConnection):

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

    def __init__(self, host='', port=389, cacert=None, bindcert=None,
                 bindkey=None, proxydn=None, debug=None, ldapi=False,
                 realm=None, protocol=None, force_schema_updates=True):
        self.conn = None
        log_mgr.get_logger(self, True)
        if debug and debug.lower() == "on":
            ldap.set_option(ldap.OPT_DEBUG_LEVEL,255)
        if cacert is not None:
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE,cacert)
        if bindcert is not None:
            ldap.set_option(ldap.OPT_X_TLS_CERTFILE,bindcert)
        if bindkey is not None:
            ldap.set_option(ldap.OPT_X_TLS_KEYFILE,bindkey)

        self.port = port
        self.host = host
        self.cacert = cacert
        self.bindcert = bindcert
        self.bindkey = bindkey
        self.proxydn = proxydn
        self.ldapi = ldapi
        self.realm = realm
        self.suffixes = {}

        ldap_uri = self.__get_ldap_uri(protocol or self.__guess_protocol())

        LDAPConnection.__init__(self, ldap_uri)

        self.conn = IPASimpleLDAPObject(ldap_uri, force_schema_updates=True)

    def __lateinit(self):
        """
        This is executed after the connection is bound to fill in some useful
        values.
        """
        try:
            ent = self.getEntry(DN(('cn', 'config'), ('cn', 'ldbm database'), ('cn', 'plugins'), ('cn', 'config')),
                                ldap.SCOPE_BASE, '(objectclass=*)',
                                [ 'nsslapd-directory' ])

            self.dbdir = os.path.dirname(ent.getValue('nsslapd-directory'))
        except ldap.LDAPError, e:
            self.__handle_errors(e)

    def __str__(self):
        return self.host + ":" + str(self.port)

    def __get_server_controls(self):
        """Create the proxy user server control. The control has the form
        0x04 = Octet String
        4|0x80 sets the length of the string length field at 4 bytes
        the struct() gets us the length in bytes of string self.proxydn
        self.proxydn is the proxy dn to send"""

        if self.proxydn is not None:
            proxydn = chr(0x04) + chr(4|0x80) + struct.pack('l', socket.htonl(len(self.proxydn))) + self.proxydn;

            # Create the proxy control
            sctrl=[]
            sctrl.append(LDAPControl('2.16.840.1.113730.3.4.18',True,proxydn))
        else:
            sctrl=None

        return sctrl

    def __handle_errors(self, e, **kw):
        return self.handle_errors(e, **kw)

    def __wait_for_connection(self, timeout):
        lurl = ldapurl.LDAPUrl(self.ldap_uri)
        if lurl.urlscheme == 'ldapi':
            wait_for_open_socket(lurl.hostport, timeout)
        else:
            (host,port) = lurl.hostport.split(':')
            wait_for_open_ports(host, int(port), timeout)

    def __bind_with_wait(self, bind_func, timeout, *args, **kwargs):
        try:
            bind_func(*args, **kwargs)
        except (ldap.CONNECT_ERROR, ldap.SERVER_DOWN), e:
            if not timeout or 'TLS' in e.args[0].get('info', ''):
                # No connection to continue on if we have a TLS failure
                # https://bugzilla.redhat.com/show_bug.cgi?id=784989
                raise e
            try:
                self.__wait_for_connection(timeout)
            except:
                raise e
            bind_func(*args, **kwargs)

    def do_simple_bind(self, binddn=DN(('cn', 'directory manager')), bindpw="", timeout=DEFAULT_TIMEOUT):
        self.binddn = binddn    # FIXME, self.binddn & self.bindpwd never referenced.
        self.bindpwd = bindpw
        self.__bind_with_wait(self.simple_bind_s, timeout, binddn, bindpw)
        self.__lateinit()

    def do_sasl_gssapi_bind(self, timeout=DEFAULT_TIMEOUT):
        self.__bind_with_wait(self.sasl_interactive_bind_s, timeout, None, SASL_AUTH)
        self.__lateinit()

    def do_external_bind(self, user_name=None, timeout=DEFAULT_TIMEOUT):
        auth_tokens = ldap.sasl.external(user_name)
        self.__bind_with_wait(self.sasl_interactive_bind_s, timeout, None, auth_tokens)
        self.__lateinit()

    def getEntry(self, base, scope, filterstr='(objectClass=*)', attrlist=None, attrsonly=0):
        """This wraps the search function.  It is common to just get one entry"""

        sctrl = self.__get_server_controls()

        if sctrl is not None:
            self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)

        try:
            res = self.search(base, scope, filterstr, attrlist, attrsonly)
            objtype, obj = self.result(res)
        except ldap.LDAPError, e:
            arg_desc = 'base="%s", scope=%s, filterstr="%s"' % (base, scope, filterstr)
            self.__handle_errors(e, arg_desc=arg_desc)

        if not obj:
            arg_desc = 'base="%s", scope=%s, filterstr="%s"' % (base, scope, filterstr)
            raise errors.NotFound(reason=arg_desc)

        elif isinstance(obj,Entry):
            return obj
        else: # assume list/tuple
            return obj[0]

    def getList(self, base, scope, filterstr='(objectClass=*)', attrlist=None, attrsonly=0):
        """This wraps the search function to find multiple entries."""

        sctrl = self.__get_server_controls()
        if sctrl is not None:
            self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)

        try:
            res = self.search(base, scope, filterstr, attrlist, attrsonly)
            objtype, obj = self.result(res)
        except ldap.LDAPError, e:
            arg_desc = 'base="%s", scope=%s, filterstr="%s"' % (base, scope, filterstr)
            self.__handle_errors(e, arg_desc=arg_desc)

        if not obj:
            arg_desc = 'base="%s", scope=%s, filterstr="%s"' % (base, scope, filterstr)
            raise errors.NotFound(reason=arg_desc)

        entries = []
        for s in obj:
            entries.append(s)

        return entries

    def addEntry(self, entry):
        """This wraps the add function. It assumes that the entry is already
           populated with all of the desired objectclasses and attributes"""

        if not isinstance(entry, Entry):
            raise TypeError('addEntry expected an Entry object, got %s instead' % entry.__class__)

        sctrl = self.__get_server_controls()

        try:
            if sctrl is not None:
                self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)
            self.add_s(entry.dn, entry.toTupleList())
        except ldap.LDAPError, e:
            arg_desc = 'entry=%s: %s' % (entry.dn, entry.toTupleList())
            self.__handle_errors(e, arg_desc=arg_desc)
        return True

    def updateEntry(self,dn,oldentry,newentry):
        """This wraps the mod function. It assumes that the entry is already
           populated with all of the desired objectclasses and attributes"""

        assert isinstance(dn, DN)
        sctrl = self.__get_server_controls()

        modlist = self.generateModList(oldentry, newentry)

        if len(modlist) == 0:
            raise errors.EmptyModlist

        try:
            if sctrl is not None:
                self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)
            self.modify_s(dn, modlist)
        except ldap.LDAPError, e:
            self.__handle_errors(e)
        return True

    def generateModList(self, old_entry, new_entry):
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

    def inactivateEntry(self,dn, has_key):
        """Rather than deleting entries we mark them as inactive.
           has_key defines whether the entry already has nsAccountlock
           set so we can determine which type of mod operation to run."""

        assert isinstance(dn, DN)
        sctrl = self.__get_server_controls()
        modlist=[]

        if has_key:
            operation = ldap.MOD_REPLACE
        else:
            operation = ldap.MOD_ADD

        modlist.append((operation, "nsAccountlock", "TRUE"))

        try:
            if sctrl is not None:
                self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)
            self.modify_s(dn, modlist)
        except ldap.LDAPError, e:
            self.__handle_errors(e)
        return True

    def deleteEntry(self, dn):
        """This wraps the delete function. Use with caution."""

        assert isinstance(dn, DN)
        sctrl = self.__get_server_controls()

        try:
            if sctrl is not None:
                self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)
            self.delete_s(dn)
        except ldap.LDAPError, e:
            arg_desc = 'dn=%s' % (dn)
            self.__handle_errors(e, arg_desc=arg_desc)
        return True

    def waitForEntry(self, dn, timeout=7200, attr='', quiet=True):
        scope = ldap.SCOPE_BASE
        filter = "(objectclass=*)"
        attrlist = []
        if attr:
            filter = "(%s=*)" % attr
            attrlist.append(attr)
        timeout += int(time.time())

        if isinstance(dn, LDAPEntry):
            dn = dn.dn
        assert isinstance(dn, DN)

        # wait for entry and/or attr to show up
        if not quiet:
            sys.stdout.write("Waiting for %s %s:%s " % (self,dn,attr))
            sys.stdout.flush()
        entry = None
        while not entry and int(time.time()) < timeout:
            try:
                entry = self.getEntry(dn, scope, filter, attrlist)
            except ldap.NO_SUCH_OBJECT:
                pass # no entry yet
            except ldap.LDAPError, e: # badness
                print "\nError reading entry", dn, e
                break
            if not entry:
                if not quiet:
                    sys.stdout.write(".")
                    sys.stdout.flush()
                time.sleep(1)

        if not entry and int(time.time()) > timeout:
            print "\nwaitForEntry timeout for %s for %s" % (self,dn)
        elif entry and not quiet:
            print "\nThe waited for entry is:", entry
        elif not entry:
            print "\nError: could not read entry %s from %s" % (dn,self)

        return entry

    def checkTask(self, dn, dowait=False, verbose=False):
        """check task status - task is complete when the nsTaskExitCode attr
           is set return a 2 tuple (true/false,code) first is false if task is
           running, true if done - if true, second is the exit code - if dowait
           is True, this function will block until the task is complete
        """
        assert isinstance(dn, DN)
        attrlist = ['nsTaskLog', 'nsTaskStatus', 'nsTaskExitCode', 'nsTaskCurrentItem', 'nsTaskTotalItems']
        done = False
        exitCode = 0
        while not done:
            try:
                entry = self.getEntry(dn, ldap.SCOPE_BASE, "(objectclass=*)", attrlist)
            except errors.NotFound:
                break
            if verbose:
                print entry
            if entry.getValue('nsTaskExitCode'):
                exitCode = int(entry.getValue('nsTaskExitCode'))
                done = True
            if dowait: time.sleep(1)
            else: break
        return (done, exitCode)

    def get_single_value(self, attr):
        """
        Check the schema to see if the attribute is single-valued.

        If the attribute is in the schema then returns True/False

        If there is a problem loading the schema or the attribute is
        not in the schema return None
        """
        obj = self.schema.get_obj(ldap.schema.AttributeType, attr)
        return obj and obj.single_value

    def get_dns_sorted_by_length(self, entries, reverse=False):
        """
        Sorts a list of entries [(dn, entry_attrs)] based on their DN.
        Entries within the same node are not sorted in any meaningful way.
        If Reverse is set to True, leaf entries are returned first. This is
        useful to perform recursive deletes where you need to delete entries
        starting from the leafs and go up to delete nodes only when all its
        leafs are removed.

        Returns a list of list of dn's. Every dn in the dn list has
        the same number of RDN's. The outer list is sorted according
        to the number of RDN's in each inner list.

        Example:

        [['cn=bob', cn=tom], ['cn=bob,ou=people', cn=tom,ou=people]]

        dn's in list[0] have 1 RDN
        dn's in list[1] have 2 RDN's
        """

        res = dict()

        for e in entries:
            dn = e.dn
            assert isinstance(dn, DN)
            rdn_count = len(dn)
            rdn_count_list = res.setdefault(rdn_count, [])
            if dn not in rdn_count_list:
                rdn_count_list.append(dn)

        keys = res.keys()
        keys.sort(reverse=reverse)

        return map(res.get, keys)

    def __getattr__(self, attrname):
        # This makes IPAdmin classes look like IPASimpleLDAPObjects
        # FIXME: for backwards compatibility only
        return getattr(self.conn, attrname)


# FIXME: Some installer tools depend on ipaldap importing plugins.ldap2.
# The proper plugins should rather be imported explicitly.
import ipaserver.plugins.ldap2
