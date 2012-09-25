# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#   John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
"""
Backend plugin for LDAP.
"""

# Entries are represented as (dn, entry_attrs), where entry_attrs is a dict
# mapping attribute names to values. Values can be a single value or list/tuple
# of virtually any type. Each method passing these values to the python-ldap
# binding encodes them into the appropriate representation. This applies to
# everything except the CrudBackend methods, where dn is part of the entry dict.

import copy
import os
import socket
import string
import shutil
import tempfile
import time
import re
import pwd
import sys
from decimal import Decimal

import krbV
from ipapython.ipa_log_manager import *
import ldap as _ldap
from ldap.ldapobject import SimpleLDAPObject
import ldap.filter as _ldap_filter
import ldap.sasl as _ldap_sasl
from ipapython.dn import DN, RDN
from ipapython.ipautil import CIDict
from collections import namedtuple
from ipalib.errors import NetworkError, DatabaseError


try:
    from ldap.controls.simple import GetEffectiveRightsControl #pylint: disable=F0401,E0611
except ImportError:
    """
    python-ldap 2.4.x introduced a new API for effective rights control, which
    needs to be used or otherwise bind dn is not passed correctly. The following
    class is created for backward compatibility with python-ldap 2.3.x.
    Relevant BZ: https://bugzilla.redhat.com/show_bug.cgi?id=802675
    """
    from ldap.controls import LDAPControl
    class GetEffectiveRightsControl(LDAPControl):
        def __init__(self, criticality, authzId=None):
            LDAPControl.__init__(self, '1.3.6.1.4.1.42.2.27.9.5.2', criticality, authzId)
# for backward compatibility
from ipalib import _

import krbV

from ipalib import api, errors
from ipalib.crud import CrudBackend
from ipalib.request import context

_debug_log_ldap = False

# Make python-ldap tuple style result compatible with Entry and Entity
# objects by allowing access to the dn (tuple index 0) via the 'dn'
# attribute name and the attr dict (tuple index 1) via the 'data'
# attribute name. Thus:
# r = result[0]
# r[0] == r.dn
# r[1] == r.data
LDAPEntry = namedtuple('LDAPEntry', ['dn', 'data'])


# Group Member types
MEMBERS_ALL = 0
MEMBERS_DIRECT = 1
MEMBERS_INDIRECT = 2

# SASL authentication mechanism
SASL_AUTH = _ldap_sasl.sasl({}, 'GSSAPI')

DN_SYNTAX_OID = '1.3.6.1.4.1.1466.115.121.1.12'

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
        log_mgr.get_logger(self, True)
        self.servers = {}

    def get_schema(self, url, conn=None, force_update=False):
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
        self.debug('flushing %s from SchemaCache', url)
        try:
            del self.servers[url]
        except KeyError:
            pass

    def _retrieve_schema_from_server(self, url, conn=None):
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
        has_conn = conn is not None

        self.debug('retrieving schema for SchemaCache url=%s conn=%s', url, conn)

        try:
            if api.env.context == 'server' and conn is None:
                # FIXME: is this really what we want to do?
                # This seems like this logic is in the wrong place and may conflict with other state.
                try:
                    # Create a new credentials cache for this Apache process
                    tmpdir = tempfile.mkdtemp(prefix = "tmp-")
                    ccache_file = 'FILE:%s/ccache' % tmpdir
                    krbcontext = krbV.default_context()
                    principal = str('HTTP/%s@%s' % (api.env.host, api.env.realm))
                    keytab = krbV.Keytab(name='/etc/httpd/conf/ipa.keytab', context=krbcontext)
                    principal = krbV.Principal(name=principal, context=krbcontext)
                    prev_ccache = os.environ.get('KRB5CCNAME')
                    os.environ['KRB5CCNAME'] = ccache_file
                    ccache = krbV.CCache(name=ccache_file, context=krbcontext, primary_principal=principal)
                    ccache.init(principal)
                    ccache.init_creds_keytab(keytab=keytab, principal=principal)
                except krbV.Krb5Error, e:
                    raise StandardError('Unable to retrieve LDAP schema. Error initializing principal %s in %s: %s' % (principal.name, '/etc/httpd/conf/ipa.keytab', str(e)))
                finally:
                    if prev_ccache is not None:
                        os.environ['KRB5CCNAME'] = prev_ccache


            if conn is None:
                conn = IPASimpleLDAPObject(url)
                if url.startswith('ldapi://'):
                    conn.set_option(_ldap.OPT_HOST_NAME, api.env.host)
                conn.sasl_interactive_bind_s(None, SASL_AUTH)

            schema_entry = conn.search_s('cn=schema', _ldap.SCOPE_BASE,
                                         attrlist=['attributetypes', 'objectclasses'])[0]
            if not has_conn:
                conn.unbind_s()
        except _ldap.SERVER_DOWN:
            raise NetworkError(uri=url,
                               error=u'LDAP Server Down, unable to retrieve LDAP schema')
        except _ldap.LDAPError, e:
            desc = e.args[0]['desc'].strip()
            info = e.args[0].get('info', '').strip()
            raise DatabaseError(desc = u'uri=%s' % url,
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

    def __init__(self, uri):
        log_mgr.get_logger(self, True)
        self.uri = uri
        self.conn = SimpleLDAPObject(uri)
        self._schema = None

    def _get_schema(self):
        if self._schema is None:
            # The schema may be updated during install or during
            # updates, make sure we have a current version of the
            # schema, not an out of date cached version.
            force_update = api.env.context in ('installer', 'updates')
            self._schema = schema_cache.get_schema(self.uri, self.conn, force_update=force_update)
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
                    self.error(msg)
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

            ipa_dn = DN(original_dn)
            ipa_attrs = dict()

            for attr, original_values in original_attrs.items():
                target_type = self._SYNTAX_MAPPING.get(self.get_syntax(attr), unicode_from_utf8)
                ipa_attrs[attr.lower()] = self.convert_value_list(attr, target_type, original_values)

            ipa_result.append(LDAPEntry(ipa_dn, ipa_attrs))

        if _debug_log_ldap:
            self.debug('ldap.result: %s', ipa_result)
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

    def rename_s(self, dn, newrdn, newsuperior=None, delold=1, serverctrls=None, clientctrls=None):
        assert isinstance(dn, DN)
        dn = str(dn)
        assert isinstance(newrdn, (DN, RDN))
        newrdn = str(newrdn)
        return self.conn.rename_s(dn, newrdn, newsuperior, delold, serverctrls, clientctrls)

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
            self.debug("ldap.search_ext: dn: %s\nfilter: %s\nattrs_list: %s", base, filterstr, attrlist)


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

class ldap2(CrudBackend):
    """
    LDAP Backend Take 2.
    """
    # attributes in this list cannot be deleted by update_entry
    # only MOD_REPLACE operations are generated for them
    _FORCE_REPLACE_ON_UPDATE_ATTRS = []

    # rules for generating filters from entries
    MATCH_ANY = '|'   # (|(filter1)(filter2))
    MATCH_ALL = '&'   # (&(filter1)(filter2))
    MATCH_NONE = '!'  # (!(filter1)(filter2))

    # search scope for find_entries()
    SCOPE_BASE = _ldap.SCOPE_BASE
    SCOPE_ONELEVEL = _ldap.SCOPE_ONELEVEL
    SCOPE_SUBTREE = _ldap.SCOPE_SUBTREE

    def __init__(self, shared_instance=True, ldap_uri=None, base_dn=None,
                 schema=None):
        log_mgr.get_logger(self, True)
        CrudBackend.__init__(self, shared_instance=shared_instance)
        try:
            self.ldap_uri = ldap_uri or api.env.ldap_uri
        except AttributeError:
            self.ldap_uri = 'ldap://example.com'
        try:
            if base_dn is not None:
                self.base_dn = DN(base_dn)
            else:
                self.base_dn = DN(api.env.basedn)
        except AttributeError:
            self.base_dn = DN()

    def __del__(self):
        if self.isconnected():
            self.disconnect()

    def __str__(self):
        return self.ldap_uri

    def _get_schema(self):
        return self.conn.schema
    schema = property(_get_schema, None, None, 'schema associated with this LDAP server')

    # universal LDAPError handler
    def handle_errors(self, e):
        """
        Centralize error handling in one place.

        e is the error to be raised
        """
        if not isinstance(e, _ldap.TIMEOUT):
            desc = e.args[0]['desc'].strip()
            info = e.args[0].get('info', '').strip()
        else:
            desc = ''
            info = ''

        try:
            # re-raise the error so we can handle it
            raise e
        except _ldap.NO_SUCH_OBJECT:
            raise errors.NotFound(reason='no such entry')
        except _ldap.ALREADY_EXISTS:
            raise errors.DuplicateEntry()
        except _ldap.CONSTRAINT_VIOLATION:
            # This error gets thrown by the uniqueness plugin
            if info.startswith('Another entry with the same attribute value already exists'):
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
        except _ldap.SUCCESS:
            pass
        except _ldap.LDAPError, e:
            if 'NOT_ALLOWED_TO_DELEGATE' in info:
                raise errors.ACIError(info="KDC returned NOT_ALLOWED_TO_DELEGATE")
            self.info('Unhandled LDAPError: %s' % str(e))
            raise errors.DatabaseError(desc=desc, info=info)

    def get_syntax(self, attr, value):
        if self.schema is None:
            return None
        obj = self.schema.get_obj(_ldap.schema.AttributeType, attr)
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
            obj = self.schema.get_obj(_ldap.schema.ObjectClass, oc)
            if obj is not None:
                allowed_attributes += obj.must + obj.may
            elif raise_on_unknown:
                raise errors.NotFound(reason=_('objectclass %s not found') % oc)
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
        obj = self.schema.get_obj(_ldap.schema.AttributeType, attr)
        return obj and obj.single_value

    def create_connection(self, ccache=None, bind_dn=None, bind_pw='',
            tls_cacertfile=None, tls_certfile=None, tls_keyfile=None,
            debug_level=0, autobind=False):
        """
        Connect to LDAP server.

        Keyword arguments:
        ldapuri -- the LDAP server to connect to
        ccache -- Kerberos V5 ccache name
        bind_dn -- dn used to bind to the server
        bind_pw -- password used to bind to the server
        debug_level -- LDAP debug level option
        tls_cacertfile -- TLS CA certificate filename
        tls_certfile -- TLS certificate filename
        tls_keyfile - TLS bind key filename
        autobind - autobind as the current user

        Extends backend.Connectible.create_connection.
        """
        if bind_dn is None:
            bind_dn = DN()
        assert isinstance(bind_dn, DN)
        if tls_cacertfile is not None:
            _ldap.set_option(_ldap.OPT_X_TLS_CACERTFILE, tls_cacertfile)
        if tls_certfile is not None:
            _ldap.set_option(_ldap.OPT_X_TLS_CERTFILE, tls_certfile)
        if tls_keyfile is not None:
            _ldap.set_option(_ldap.OPT_X_TLS_KEYFILE, tls_keyfile)

        if debug_level:
            _ldap.set_option(_ldap.OPT_DEBUG_LEVEL, debug_level)

        try:
            conn = IPASimpleLDAPObject(self.ldap_uri)
            if self.ldap_uri.startswith('ldapi://') and ccache:
                conn.set_option(_ldap.OPT_HOST_NAME, api.env.host)
            minssf = conn.get_option(_ldap.OPT_X_SASL_SSF_MIN)
            maxssf = conn.get_option(_ldap.OPT_X_SASL_SSF_MAX)
            # Always connect with at least an SSF of 56, confidentiality
            # This also protects us from a broken ldap.conf
            if minssf < 56:
                minssf = 56
                conn.set_option(_ldap.OPT_X_SASL_SSF_MIN, minssf)
                if maxssf < minssf:
                    conn.set_option(_ldap.OPT_X_SASL_SSF_MAX, minssf)
            if ccache is not None:
                os.environ['KRB5CCNAME'] = ccache
                conn.sasl_interactive_bind_s(None, SASL_AUTH)
                principal = krbV.CCache(name=ccache,
                            context=krbV.default_context()).principal().name
                setattr(context, 'principal', principal)
            else:
                # no kerberos ccache, use simple bind or external sasl
                if autobind:
                    pent = pwd.getpwuid(os.geteuid())
                    auth_tokens = _ldap.sasl.external(pent.pw_name)
                    conn.sasl_interactive_bind_s(None, auth_tokens)
                else:
                    conn.simple_bind_s(bind_dn, bind_pw)

        except _ldap.LDAPError, e:
            self.handle_errors(e)

        return conn

    def destroy_connection(self):
        """Disconnect from LDAP server."""
        try:
            self.conn.unbind_s()
        except _ldap.LDAPError:
            # ignore when trying to unbind multiple times
            pass

    def normalize_dn(self, dn):
        """
        Normalize distinguished name by assuring it ends with
        the base_dn.

        Note: You don't have to normalize DN's before passing them to
              ldap2 methods. It's done internally for you.
        """

        assert isinstance(dn, DN)

        if not dn.endswith(self.base_dn):
            # DN's are mutable, don't use in-place addtion (+=) which would
            # modify the dn passed in with unintended side-effects. Addition
            # returns a new DN object which is the concatenation of the two.
            dn = dn + self.base_dn

        return dn

    def make_dn_from_attr(self, attr, value, parent_dn=None):
        """
        Make distinguished name from attribute.

        Keyword arguments:
        parent_dn -- DN of the parent entry (default '')
        """
        if parent_dn is None:
            parent_dn = DN()
        assert isinstance(parent_dn, DN)
        parent_dn = self.normalize_dn(parent_dn)

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

        if parent_dn is None:
            parent_dn = DN()

        parent_dn = self.normalize_dn(parent_dn)
        return DN((primary_key, entry_attrs[primary_key]), parent_dn)

    def add_entry(self, dn, entry_attrs, normalize=True):
        """Create a new entry."""

        assert isinstance(dn, DN)

        if normalize:
            dn = self.normalize_dn(dn)
        # remove all None or [] values, python-ldap hates'em
        entry_attrs = dict(
            # FIXME, shouldn't these values be an error?
            (k, v) for (k, v) in entry_attrs.iteritems()
            if v is not None and v != []
        )
        try:
            self.conn.add_s(dn, list(entry_attrs.iteritems()))
        except _ldap.LDAPError, e:
            self.handle_errors(e)

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
        if filters and rules == self.MATCH_NONE: # unary operator
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

    def make_filter_from_attr(self, attr, value, rules='|', exact=True,
            leading_wildcard=True, trailing_wildcard=True):
        """
        Make filter for ldap2.find_entries from attribute.

        Keyword arguments:
        rules -- see ldap2.make_filter
        exact -- boolean, True - make filter as (attr=value)
                          False - make filter as (attr=*value*)
        leading_wildcard -- boolean, True - allow heading filter wildcard when exact=False
                                     False - forbid heading filter wildcard when exact=False
        trailing_wildcard -- boolean, True - allow trailing filter wildcard when exact=False
                                      False - forbid trailing filter wildcard when exact=False
        """
        if isinstance(value, (list, tuple)):
            make_filter_rules = self.MATCH_ANY if rules == self.MATCH_NONE else rules
            flts = [ self.make_filter_from_attr(attr, v, exact=exact,
                            leading_wildcard=leading_wildcard,
                            trailing_wildcard=trailing_wildcard) for v in value ]
            return self.combine_filters(flts, rules)
        elif value is not None:
            value = _ldap_filter.escape_filter_chars(value_to_utf8(value))
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

    def make_filter(self, entry_attrs, attrs_list=None, rules='|', exact=True,
            leading_wildcard=True, trailing_wildcard=True):
        """
        Make filter for ldap2.find_entries from entry attributes.

        Keyword arguments:
        attrs_list -- list of attributes to use, all if None (default None)
        rules -- specifies how to determine a match (default ldap2.MATCH_ANY)
        exact -- boolean, True - make filter as (attr=value)
                          False - make filter as (attr=*value*)
        leading_wildcard -- boolean, True - allow heading filter wildcard when exact=False
                                     False - forbid heading filter wildcard when exact=False
        trailing_wildcard -- boolean, True - allow trailing filter wildcard when exact=False
                                      False - forbid trailing filter wildcard when exact=False

        rules can be one of the following:
        ldap2.MATCH_NONE - match entries that do not match any attribute
        ldap2.MATCH_ALL - match entries that match all attributes
        ldap2.MATCH_ANY - match entries that match any of attribute
        """
        make_filter_rules = self.MATCH_ANY if rules == self.MATCH_NONE else rules
        flts = []
        if attrs_list is None:
            for (k, v) in entry_attrs.iteritems():
                flts.append(
                    self.make_filter_from_attr(k, v, make_filter_rules, exact,
                        leading_wildcard, trailing_wildcard)
                )
        else:
            for a in attrs_list:
                value = entry_attrs.get(a, None)
                if value is not None:
                    flts.append(
                        self.make_filter_from_attr(a, value, make_filter_rules, exact,
                            leading_wildcard, trailing_wildcard)
                    )
        return self.combine_filters(flts, rules)

    def find_entries(self, filter=None, attrs_list=None, base_dn=None,
            scope=_ldap.SCOPE_SUBTREE, time_limit=None, size_limit=None,
            normalize=True, search_refs=False):
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
        size_limit -- size (number of entries returned) limit (default use IPA config values)
        normalize -- normalize the DN (default True)
        search_refs -- allow search references to be returned (default skips these entries)
        """
        if base_dn is None:
            base_dn = DN()
        assert isinstance(base_dn, DN)
        if normalize:
            base_dn = self.normalize_dn(base_dn)
        if not filter:
            filter = '(objectClass=*)'
        res = []
        truncated = False

        if time_limit is None or size_limit is None:
            (cdn, config) = self.get_ipa_config()
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
        try:
            id = self.conn.search_ext(
                base_dn, scope, filter, attrs_list, timeout=time_limit,
                sizelimit=size_limit
            )
            while True:
                (objtype, res_list) = self.conn.result(id, 0)
                if not res_list:
                    break
                if objtype == _ldap.RES_SEARCH_ENTRY or \
                   (search_refs and objtype == _ldap.RES_SEARCH_REFERENCE):
                    res.append(res_list[0])
        except (_ldap.ADMINLIMIT_EXCEEDED, _ldap.TIMELIMIT_EXCEEDED,
                _ldap.SIZELIMIT_EXCEEDED), e:
            truncated = True
        except _ldap.LDAPError, e:
            self.handle_errors(e)

        if not res and not truncated:
            raise errors.NotFound(reason='no such entry')

        if attrs_list and ('memberindirect' in attrs_list or '*' in attrs_list):
            for r in res:
                if not 'member' in r[1]:
                    continue
                else:
                    members = r[1]['member']
                    indirect = self.get_members(r[0], members, membertype=MEMBERS_INDIRECT,
                        time_limit=time_limit, size_limit=size_limit, normalize=normalize)
                    if len(indirect) > 0:
                        r[1]['memberindirect'] = indirect
        if attrs_list and ('memberofindirect' in attrs_list or '*' in attrs_list):
            for r in res:
                if 'memberof' in r[1]:
                    memberof = r[1]['memberof']
                    del r[1]['memberof']
                elif 'memberOf' in r[1]:
                    memberof = r[1]['memberOf']
                    del r[1]['memberOf']
                else:
                    continue
                (direct, indirect) = self.get_memberof(r[0], memberof, time_limit=time_limit,
                                                       size_limit=size_limit, normalize=normalize)
                if len(direct) > 0:
                    r[1]['memberof'] = direct
                if len(indirect) > 0:
                    r[1]['memberofindirect'] = indirect

        return (res, truncated)

    def find_entry_by_attr(self, attr, value, object_class, attrs_list=None, base_dn=None):
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
                  size_limit=None, normalize=True):
        """
        Get entry (dn, entry_attrs) by dn.

        Keyword arguments:
        attrs_list - list of attributes to return, all if None (default None)
        """

        assert isinstance(dn, DN)

        (entry, truncated) = self.find_entries(
            None, attrs_list, dn, self.SCOPE_BASE, time_limit=time_limit,
            size_limit=size_limit, normalize=normalize
        )

        if truncated:
            raise errors.LimitsExceeded()
        return entry[0]

    config_defaults = {'ipasearchtimelimit': [2], 'ipasearchrecordslimit': [0]}
    def get_ipa_config(self, attrs_list=None):
        """Returns the IPA configuration entry (dn, entry_attrs)."""

        odn = api.Object.config.get_dn()
        assert isinstance(odn, DN)
        assert isinstance(api.env.basedn, DN)
        cdn = DN(odn, api.env.basedn)

        try:
            config_entry = getattr(context, 'config_entry')
            return (cdn, copy.deepcopy(config_entry))
        except AttributeError:
            # Not in our context yet
            pass
        try:
            (entry, truncated) = self.find_entries(
                None, attrs_list, base_dn=cdn, scope=self.SCOPE_BASE,
                time_limit=2, size_limit=10
            )
            if truncated:
                raise errors.LimitsExceeded()
            (cdn, config_entry) = entry[0]
        except errors.NotFound:
            config_entry = {}
        for a in self.config_defaults:
            if a not in config_entry:
                config_entry[a] = self.config_defaults[a]
        setattr(context, 'config_entry', copy.deepcopy(config_entry))
        return (cdn, config_entry)

    def has_upg(self):
        """Returns True/False whether User-Private Groups are enabled.
           This is determined based on whether the UPG Template exists.
        """

        upg_dn = DN(('cn', 'UPG Definition'), ('cn', 'Definitions'), ('cn', 'Managed Entries'),
                    ('cn', 'etc'), api.env.basedn)

        try:
            upg_entry = self.conn.search_s(upg_dn, _ldap.SCOPE_BASE,
                                           attrlist=['*'])[0]
            disable_attr = '(objectclass=disable)'
            if 'originfilter' in upg_entry[1]:
                org_filter = upg_entry[1]['originfilter']
                return not bool(re.search(r'%s' % disable_attr, org_filter[0]))
            else:
                return False
        except _ldap.NO_SUCH_OBJECT, e:
            return False

    def get_effective_rights(self, dn, entry_attrs):
        """Returns the rights the currently bound user has for the given DN.

           Returns 2 attributes, the attributeLevelRights for the given list of
           attributes and the entryLevelRights for the entry itself.
        """

        assert isinstance(dn, DN)

        principal = getattr(context, 'principal')
        (binddn, attrs) = self.find_entry_by_attr("krbprincipalname", principal, "krbPrincipalAux")
        assert isinstance(binddn, DN)
        sctrl = [GetEffectiveRightsControl(True, "dn: " + str(binddn))]
        self.conn.set_option(_ldap.OPT_SERVER_CONTROLS, sctrl)
        (dn, attrs) = self.get_entry(dn, entry_attrs)
        # remove the control so subsequent operations don't include GER
        self.conn.set_option(_ldap.OPT_SERVER_CONTROLS, [])
        return (dn, attrs)

    def can_write(self, dn, attr):
        """Returns True/False if the currently bound user has write permissions
           on the attribute. This only operates on a single attribute at a time.
        """

        assert isinstance(dn, DN)

        (dn, attrs) = self.get_effective_rights(dn, [attr])
        if 'attributelevelrights' in attrs:
            attr_rights = attrs.get('attributelevelrights')[0].decode('UTF-8')
            (attr, rights) = attr_rights.split(':')
            if 'w' in rights:
                return True

        return False

    def can_read(self, dn, attr):
        """Returns True/False if the currently bound user has read permissions
           on the attribute. This only operates on a single attribute at a time.
        """
        assert isinstance(dn, DN)

        (dn, attrs) = self.get_effective_rights(dn, [attr])
        if 'attributelevelrights' in attrs:
            attr_rights = attrs.get('attributelevelrights')[0].decode('UTF-8')
            (attr, rights) = attr_rights.split(':')
            if 'r' in rights:
                return True

        return False

    #
    # Entry-level effective rights
    #
    # a - Add
    # d - Delete
    # n - Rename the DN
    # v - View the entry
    #

    def can_delete(self, dn):
        """Returns True/False if the currently bound user has delete permissions
           on the entry.
        """

        assert isinstance(dn, DN)

        (dn, attrs) = self.get_effective_rights(dn, ["*"])
        if 'entrylevelrights' in attrs:
            entry_rights = attrs['entrylevelrights'][0].decode('UTF-8')
            if 'd' in entry_rights:
                return True

        return False

    def can_add(self, dn):
        """Returns True/False if the currently bound user has add permissions
           on the entry.
        """
        assert isinstance(dn, DN)
        (dn, attrs) = self.get_effective_rights(dn, ["*"])
        if 'entrylevelrights' in attrs:
            entry_rights = attrs['entrylevelrights'][0].decode('UTF-8')
            if 'a' in entry_rights:
                return True

        return False

    def update_entry_rdn(self, dn, new_rdn, del_old=True):
        """
        Update entry's relative distinguished name.

        Keyword arguments:
        del_old -- delete old RDN value (default True)
        """

        assert isinstance(dn, DN)
        assert isinstance(new_rdn, RDN)

        dn = self.normalize_dn(dn)
        if dn[0] == new_rdn:
            raise errors.EmptyModlist()
        try:
            self.conn.rename_s(dn, new_rdn, delold=int(del_old))
            time.sleep(.3) # Give memberOf plugin a chance to work
        except _ldap.LDAPError, e:
            self.handle_errors(e)

    def _generate_modlist(self, dn, entry_attrs, normalize):
        assert isinstance(dn, DN)

        # get original entry
        (dn, entry_attrs_old) = self.get_entry(dn, entry_attrs.keys(), normalize=normalize)

        # generate modlist
        # for multi value attributes: no MOD_REPLACE to handle simultaneous
        # updates better
        # for single value attribute: always MOD_REPLACE
        modlist = []
        for (k, v) in entry_attrs.iteritems():
            if v is None and k in entry_attrs_old:
                modlist.append((_ldap.MOD_DELETE, k, None))
            else:
                if not isinstance(v, (list, tuple)):
                    v = [v]
                v = set(filter(lambda value: value is not None, v))
                old_v = set(entry_attrs_old.get(k.lower(), []))

                adds = list(v.difference(old_v))
                rems = list(old_v.difference(v))

                is_single_value = self.get_single_value(k)

                value_count = len(old_v) + len(adds) - len(rems)
                if is_single_value and value_count > 1:
                    raise errors.OnlyOneValueAllowed(attr=k)

                force_replace = False
                if k in self._FORCE_REPLACE_ON_UPDATE_ATTRS or is_single_value:
                    force_replace = True
                elif len(v) > 0 and len(v.intersection(old_v)) == 0:
                    force_replace = True

                if adds:
                    if force_replace:
                        modlist.append((_ldap.MOD_REPLACE, k, adds))
                    else:
                        modlist.append((_ldap.MOD_ADD, k, adds))
                if rems:
                    if not force_replace:
                        modlist.append((_ldap.MOD_DELETE, k, rems))

        return modlist

    def update_entry(self, dn, entry_attrs, normalize=True):
        """
        Update entry's attributes.

        An attribute value set to None deletes all current values.
        """

        assert isinstance(dn, DN)
        if normalize:
            dn = self.normalize_dn(dn)

        # generate modlist
        modlist = self._generate_modlist(dn, entry_attrs, normalize)
        if not modlist:
            raise errors.EmptyModlist()

        # pass arguments to python-ldap
        try:
            self.conn.modify_s(dn, modlist)
        except _ldap.LDAPError, e:
            self.handle_errors(e)

    def delete_entry(self, dn, normalize=True):
        """Delete entry."""

        assert isinstance(dn, DN)
        if normalize:
            dn = self.normalize_dn(dn)

        try:
            self.conn.delete_s(dn)
        except _ldap.LDAPError, e:
            self.handle_errors(e)

    def modify_password(self, dn, new_pass, old_pass=''):
        """Set user password."""

        assert isinstance(dn, DN)
        dn = self.normalize_dn(dn)

        # The python-ldap passwd command doesn't verify the old password
        # so we'll do a simple bind to validate it.
        if old_pass != '':
            try:
                conn = IPASimpleLDAPObject(self.ldap_uri)
                conn.simple_bind_s(dn, old_pass)
                conn.unbind()
            except _ldap.LDAPError, e:
                self.handle_errors(e)

        try:
            self.conn.passwd_s(dn, old_pass, new_pass)
        except _ldap.LDAPError, e:
            self.handle_errors(e)

    def add_entry_to_group(self, dn, group_dn, member_attr='member', allow_same=False):
        """
        Add entry designaed by dn to group group_dn in the member attribute
        member_attr.

        Adding a group as a member of itself is not allowed unless allow_same
        is True.
        """

        assert isinstance(dn, DN)
        assert isinstance(group_dn, DN)

        self.debug("add_entry_to_group: dn=%s group_dn=%s member_attr=%s", dn, group_dn, member_attr)
        # check if the entry exists
        (dn, entry_attrs) = self.get_entry(dn, ['objectclass'])

        # get group entry
        (group_dn, group_entry_attrs) = self.get_entry(group_dn, [member_attr])

        self.debug("add_entry_to_group: group_entry_attrs=%s", group_entry_attrs)
        # check if we're not trying to add group into itself
        if dn == group_dn and not allow_same:
            raise errors.SameGroupError()

        # add dn to group entry's `member_attr` attribute
        members = group_entry_attrs.get(member_attr, [])
        members.append(dn)
        group_entry_attrs[member_attr] = members

        # update group entry
        try:
            self.update_entry(group_dn, group_entry_attrs)
        except errors.EmptyModlist:
            raise errors.AlreadyGroupMember()

    def remove_entry_from_group(self, dn, group_dn, member_attr='member'):
        """Remove entry from group."""

        assert isinstance(dn, DN)
        assert isinstance(group_dn, DN)

        self.debug("remove_entry_from_group: dn=%s group_dn=%s member_attr=%s", dn, group_dn, member_attr)
        # get group entry
        (group_dn, group_entry_attrs) = self.get_entry(group_dn, [member_attr])

        self.debug("remove_entry_from_group: group_entry_attrs=%s", group_entry_attrs)
        # remove dn from group entry's `member_attr` attribute
        members = group_entry_attrs.get(member_attr, [])
        assert all([isinstance(x, DN) for x in members])
        try:
            members.remove(dn)
        except ValueError:
            raise errors.NotGroupMember()
        group_entry_attrs[member_attr] = members

        # update group entry
        self.update_entry(group_dn, group_entry_attrs)

    def get_members(self, group_dn, members, attr_list=[], membertype=MEMBERS_ALL, time_limit=None, size_limit=None, normalize=True):
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

        self.debug("get_members: group_dn=%s members=%s membertype=%s", group_dn, members, membertype)
        search_group_dn = _ldap_filter.escape_filter_chars(str(group_dn))
        searchfilter = "(memberof=%s)" % search_group_dn

        attr_list.append("member")

        # Verify group membership

        results = []
        if membertype == MEMBERS_ALL or membertype == MEMBERS_INDIRECT:
            user_container_dn = DN(api.env.container_user, api.env.basedn) # FIXME, initialize once
            host_container_dn = DN(api.env.container_host, api.env.basedn)
            checkmembers = set(DN(x) for x in members)
            checked = set()
            while checkmembers:
                member_dn = checkmembers.pop()
                checked.add(member_dn)

                # No need to check entry types that are not nested for
                # additional members
                if member_dn.endswith(user_container_dn) or \
                   member_dn.endswith(host_container_dn):
                        results.append([member_dn, {}])
                        continue
                try:
                    (result, truncated) = self.find_entries(searchfilter,
                        attr_list, member_dn, time_limit=time_limit,
                        size_limit=size_limit, scope=_ldap.SCOPE_BASE,
                        normalize=normalize)
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

        (dn, group) = self.get_entry(group_dn, ['dn', 'member'],
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

        self.debug("get_members: result=%s", entries)
        return entries

    def get_memberof(self, entry_dn, memberof, time_limit=None, size_limit=None, normalize=True):
        """
        Examine the objects that an entry is a member of and determine if they
        are a direct or indirect member of that group.

        entry_dn: dn of the entry we want the direct/indirect members of
        memberof: the memberOf attribute for entry_dn

        Returns two memberof lists: (direct, indirect)
        """

        assert isinstance(entry_dn, DN)

        self.debug("get_memberof: entry_dn=%s memberof=%s", entry_dn, memberof)
        if not type(memberof) in (list, tuple):
            return ([], [])
        if len(memberof) == 0:
            return ([], [])

        search_entry_dn = _ldap_filter.escape_filter_chars(str(entry_dn))
        attr_list = ["dn", "memberof"]
        searchfilter = "(|(member=%s)(memberhost=%s)(memberuser=%s))" % (
            search_entry_dn, search_entry_dn, search_entry_dn)

        # Search only the groups for which the object is a member to
        # determine if it is directly or indirectly associated.

        results = []
        for group in memberof:
            assert isinstance(group, DN)
            try:
                (result, truncated) = self.find_entries(searchfilter, attr_list,
                    group, time_limit=time_limit,size_limit=size_limit,
                    scope=_ldap.SCOPE_BASE, normalize=normalize)
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
                self.info('Failed to remove indirect entry %s from %s' % r[0], entry_dn)
                raise e

        self.debug("get_memberof: result direct=%s indirect=%s", direct, indirect)
        return (direct, indirect)

    def set_entry_active(self, dn, active):
        """Mark entry active/inactive."""

        assert isinstance(dn, DN)
        assert isinstance(active, bool)

        # get the entry in question
        (dn, entry_attrs) = self.get_entry(dn, ['nsaccountlock'])

        # check nsAccountLock attribute
        account_lock_attr = entry_attrs.get('nsaccountlock', ['false'])
        account_lock_attr = account_lock_attr[0].lower()
        if active:
            if account_lock_attr == 'false':
                raise errors.AlreadyActive()
        else:
            if account_lock_attr == 'true':
                raise errors.AlreadyInactive()

        # LDAP expects string instead of Bool but it also requires it to be TRUE or FALSE,
        # not True or False as Python stringification does. Thus, we uppercase it.
        account_lock_attr = str(not active).upper()

        entry_attrs['nsaccountlock'] = account_lock_attr
        self.update_entry(dn, entry_attrs)

    def activate_entry(self, dn):
        """Mark entry active."""

        assert isinstance(dn, DN)
        self.set_entry_active(dn, True)

    def deactivate_entry(self, dn):
        """Mark entry inactive."""

        assert isinstance(dn, DN)
        self.set_entry_active(dn, False)

    def remove_principal_key(self, dn):
        """Remove a kerberos principal key."""

        assert isinstance(dn, DN)
        dn = self.normalize_dn(dn)

        # We need to do this directly using the LDAP library because we
        # don't have read access to krbprincipalkey so we need to delete
        # it in the blind.
        mod = [(_ldap.MOD_REPLACE, 'krbprincipalkey', None),
               (_ldap.MOD_REPLACE, 'krblastpwdchange', None)]

        try:
            self.conn.modify_s(dn, mod)
        except _ldap.LDAPError, e:
            self.handle_errors(e)

    # CrudBackend methods

    def _get_normalized_entry_for_crud(self, dn, attrs_list=None):

        assert isinstance(dn, DN)

        (dn, entry_attrs) = self.get_entry(dn, attrs_list)
        entry_attrs['dn'] = dn
        return entry_attrs

    def create(self, **kw):
        """
        Create a new entry and return it as one dict (DN included).

        Extends CrudBackend.create.
        """
        assert 'dn' in kw
        dn = kw['dn']
        assert isinstance(dn, DN)
        del kw['dn']
        self.add_entry(dn, kw)
        return self._get_normalized_entry_for_crud(dn)

    def retrieve(self, primary_key, attributes):
        """
        Get entry by primary_key (DN) as one dict (DN included).

        Extends CrudBackend.retrieve.
        """
        return self._get_normalized_entry_for_crud(primary_key, attributes)

    def update(self, primary_key, **kw):
        """
        Update entry's attributes and return it as one dict (DN included).

        Extends CrudBackend.update.
        """
        self.update_entry(primary_key, kw)
        return self._get_normalized_entry_for_crud(primary_key)

    def delete(self, primary_key):
        """
        Delete entry by primary_key (DN).

        Extends CrudBackend.delete.
        """
        self.delete_entry(primary_key)

    def search(self, **kw):
        """
        Return a list of entries (each entry is one dict, DN included) matching
        the specified criteria.

        Keyword arguments:
        filter -- search filter (default: '')
        attrs_list -- list of attributes to return, all if None (default None)
        base_dn -- dn of the entry at which to start the search (default '')
        scope -- search scope, see LDAP docs (default ldap2.SCOPE_SUBTREE)

        Extends CrudBackend.search.
        """
        # get keyword arguments
        filter = kw.pop('filter', None)
        attrs_list = kw.pop('attrs_list', None)
        base_dn = kw.pop('base_dn', DN())
        assert isinstance(base_dn, DN)
        scope = kw.pop('scope', self.SCOPE_SUBTREE)

        # generate filter
        filter_tmp = self.make_filter(kw)
        if filter:
            filter = self.combine_filters((filter, filter_tmp), self.MATCH_ALL)
        else:
            filter = filter_tmp
        if not filter:
            filter = '(objectClass=*)'

        # find entries and normalize the output for CRUD
        output = []
        (entries, truncated) = self.find_entries(
            filter, attrs_list, base_dn, scope
        )
        for (dn, entry_attrs) in entries:
            entry_attrs['dn'] = [dn]
            output.append(entry_attrs)

        if truncated:
            return (-1, output)
        return (len(output), output)

api.register(ldap2)
