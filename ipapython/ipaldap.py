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

import binascii
import errno
import logging
import time
import datetime
from decimal import Decimal
from copy import deepcopy
import contextlib
import os
import pwd
from urllib.parse import urlparse
import warnings

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization

import ldap
import ldap.sasl
import ldap.filter
from ldap.controls import SimplePagedResultsControl, GetEffectiveRightsControl
import ldapurl
import six

# pylint: disable=ipa-forbidden-import
from ipalib import errors, x509, _
from ipalib.constants import LDAP_GENERALIZED_TIME_FORMAT
# pylint: enable=ipa-forbidden-import
from ipaplatform.paths import paths
from ipapython.ipautil import format_netloc, CIDict
from ipapython.dn import DN
from ipapython.dnsutil import DNSName
from ipapython.kerberos import Principal

# pylint: disable=no-name-in-module, import-error
if six.PY3:
    from collections.abc import MutableMapping
else:
    from collections import MutableMapping
# pylint: enable=no-name-in-module, import-error

if six.PY3:
    unicode = str

logger = logging.getLogger(__name__)

# Global variable to define SASL auth
SASL_GSSAPI = ldap.sasl.sasl({}, 'GSSAPI')
SASL_GSS_SPNEGO = ldap.sasl.sasl({}, 'GSS-SPNEGO')

_debug_log_ldap = False

_missing = object()

# Autobind modes
AUTOBIND_AUTO = 1
AUTOBIND_ENABLED = 2
AUTOBIND_DISABLED = 3

TRUNCATED_SIZE_LIMIT = object()
TRUNCATED_TIME_LIMIT = object()
TRUNCATED_ADMIN_LIMIT = object()

DIRMAN_DN = DN(('cn', 'directory manager'))


if six.PY2 and hasattr(ldap, 'LDAPBytesWarning'):
    # XXX silence python-ldap's BytesWarnings
    warnings.filterwarnings(
        action="ignore",
        category=ldap.LDAPBytesWarning,  # pylint: disable=no-member
    )


def realm_to_serverid(realm_name):
    """Convert Kerberos realm name to 389-DS server id"""
    return "-".join(realm_name.split("."))


def realm_to_ldapi_uri(realm_name):
    """Get ldapi:// URI to 389-DS's Unix socket"""
    serverid = realm_to_serverid(realm_name)
    socketname = paths.SLAPD_INSTANCE_SOCKET_TEMPLATE % (serverid,)
    return 'ldapi://' + ldapurl.ldapUrlEscape(socketname)


def ldap_initialize(uri, cacertfile=None):
    """Wrapper around ldap.initialize()

    The function undoes global and local ldap.conf settings that may cause
    issues or reduce security:

    * Canonization of SASL host names is disabled.
    * With cacertfile=None, the connection uses OpenSSL's default verify
      locations, also known as system-wide trust store.
    * Cert validation is enforced.
    * SSLv2 and SSLv3 are disabled.
    """
    conn = ldap.initialize(uri)

    # Do not perform reverse DNS lookups to canonicalize SASL host names
    conn.set_option(ldap.OPT_X_SASL_NOCANON, ldap.OPT_ON)

    if not uri.startswith('ldapi://'):
        if cacertfile:
            if not os.path.isfile(cacertfile):
                raise IOError(errno.ENOENT, cacertfile)
            conn.set_option(ldap.OPT_X_TLS_CACERTFILE, cacertfile)

        # SSLv3 and SSLv2 are insecure
        conn.set_option(ldap.OPT_X_TLS_PROTOCOL_MIN, 0x301)  # TLS 1.0
        # libldap defaults to cert validation, but the default can be
        # overridden in global or user local ldap.conf.
        conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
        # reinitialize TLS context to materialize settings
        conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)

    return conn


class _ServerSchema:
    '''
    Properties of a schema retrieved from an LDAP server.
    '''

    def __init__(self, server, schema):
        self.server = server
        self.schema = schema
        self.retrieve_timestamp = time.time()


class SchemaCache:
    '''
    Cache the schema's from individual LDAP servers.
    '''

    def __init__(self):
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
        logger.debug('flushing %s from SchemaCache', url)
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
        assert conn is not None

        logger.debug(
            'retrieving schema for SchemaCache url=%s conn=%s', url, conn)

        try:
            try:
                schema_entry = conn.search_s('cn=schema', ldap.SCOPE_BASE,
                    attrlist=['attributetypes', 'objectclasses'])[0]
            except ldap.NO_SUCH_OBJECT:
                # try different location for schema
                # openldap has schema located in cn=subschema
                logger.debug('cn=schema not found, fallback to cn=subschema')
                schema_entry = conn.search_s('cn=subschema', ldap.SCOPE_BASE,
                    attrlist=['attributetypes', 'objectclasses'])[0]
        except ldap.SERVER_DOWN:
            raise errors.NetworkError(uri=url,
                               error=u'LDAP Server Down, unable to retrieve LDAP schema')
        except ldap.LDAPError as e:
            desc = e.args[0]['desc'].strip()
            info = e.args[0].get('info', '').strip()
            raise errors.DatabaseError(desc = u'uri=%s' % url,
                                info = u'Unable to retrieve LDAP schema: %s: %s' % (desc, info))

        # no 'cn=schema' entry in LDAP? some servers use 'cn=subschema'
        # TODO: DS uses 'cn=schema', support for other server?
        #       raise a more appropriate exception

        return ldap.schema.SubSchema(schema_entry[1])

schema_cache = SchemaCache()


class LDAPEntry(MutableMapping):
    __slots__ = ('_conn', '_dn', '_names', '_nice', '_raw', '_sync',
                 '_not_list', '_orig_raw', '_raw_view',
                 '_single_value_view')

    __hash__ = None

    def __init__(self, _conn, _dn=None, _obj=None, **kwargs):
        """
        LDAPEntry constructor.

        Takes 1 to 3 positional arguments and an arbitrary number of keyword
        arguments. The 3 forms of positional arguments are:

          * LDAPEntry(entry) - create a shallow copy of an existing LDAPEntry.
          * LDAPEntry(dn, entry) - create a shallow copy of an existing
            LDAPEntry with a different DN.
          * LDAPEntry(conn, dn, mapping) - create a new LDAPEntry using the
            specified LDAPClient and DN and optionally initialize
            attributes from the specified mapping object.

        Keyword arguments can be used to override values of specific attributes.
        """
        super(LDAPEntry, self).__init__()  # pylint: disable=no-member

        if isinstance(_conn, LDAPEntry):
            assert _dn is None
            _dn = _conn
            _conn = _conn._conn
        assert isinstance(_conn, LDAPClient)

        if isinstance(_dn, LDAPEntry):
            assert _obj is None
            _obj = _dn
            _dn = _dn._dn
        assert isinstance(_dn, DN)

        if _obj is None:
            _obj = {}

        self._conn = _conn
        self._dn = _dn
        self._names = CIDict()
        self._nice = {}
        self._raw = {}
        self._sync = {}
        self._not_list = set()
        self._orig_raw = {}
        self._raw_view = None
        self._single_value_view = None

        if isinstance(_obj, LDAPEntry):
            #pylint: disable=E1103
            self._not_list = set(_obj._not_list)
            self._orig_raw = dict(_obj._orig_raw)
            if _obj.conn is _conn:
                self._names = CIDict(_obj._names)
                self._nice = dict(_obj._nice)
                self._raw = dict(_obj._raw)
                self._sync = dict(_obj._sync)
            else:
                self.raw.update(_obj.raw)

            _obj = {}

        self.update(_obj, **kwargs)

    @property
    def conn(self):
        return self._conn

    @property
    def dn(self):
        return self._dn

    @dn.setter
    def dn(self, value):
        assert isinstance(value, DN)
        self._dn = value

    @property
    def raw(self):
        if self._raw_view is None:
            self._raw_view = RawLDAPEntryView(self)
        return self._raw_view

    @property
    def single_value(self):
        if self._single_value_view is None:
            self._single_value_view = SingleValueLDAPEntryView(self)
        return self._single_value_view

    def __repr__(self):
        data = dict(self._raw)
        data.update((k, v) for k, v in self._nice.items() if v is not None)
        return '%s(%r, %r)' % (type(self).__name__, self._dn, data)

    def copy(self):
        return LDAPEntry(self)

    def _sync_attr(self, name):
        nice = self._nice[name]
        assert isinstance(nice, list)

        raw = self._raw[name]
        assert isinstance(raw, list)

        nice_sync, raw_sync = self._sync.setdefault(name, ([], []))
        if nice == nice_sync and raw == raw_sync:
            return

        nice_adds = set(nice) - set(nice_sync)
        nice_dels = set(nice_sync) - set(nice)
        raw_adds = set(raw) - set(raw_sync)
        raw_dels = set(raw_sync) - set(raw)

        for value in nice_dels:
            value = self._conn.encode(value)
            if value in raw_adds:
                continue
            raw.remove(value)

        for value in raw_dels:
            try:
                value = self._conn.decode(value, name)
            except ValueError as e:
                raise ValueError("{error} in LDAP entry '{dn}'".format(
                    error=e, dn=self._dn))
            if value in nice_adds:
                continue
            nice.remove(value)

        for value in sorted(nice_adds, key=nice.index):
            value = self._conn.encode(value)
            if value in raw_dels:
                continue
            raw.append(value)

        for value in sorted(raw_adds, key=raw.index):
            try:
                value = self._conn.decode(value, name)
            except ValueError as e:
                raise ValueError("{error} in LDAP entry '{dn}'".format(
                    error=e, dn=self._dn))
            if value in nice_dels:
                continue
            nice.append(value)

        self._sync[name] = (deepcopy(nice), deepcopy(raw))

        if len(nice) > 1:
            self._not_list.discard(name)

    def _attr_name(self, name):
        if not isinstance(name, str):
            raise TypeError(
                "attribute name must be unicode or str, got %s object %r" % (
                    name.__class__.__name__, name))

        if isinstance(name, bytes):
            name = name.decode('utf-8')

        return name

    def _add_attr_name(self, name):
        if name in self._names:
            return self._names[name]

        if self._conn.schema is not None:
            if six.PY2:
                encoded_name = name.encode('utf-8')
            else:
                encoded_name = name
            attrtype = self._conn.schema.get_obj(
                ldap.schema.AttributeType, encoded_name)
            if attrtype is not None:
                for altname in attrtype.names:
                    if six.PY2:
                        altname = altname.decode('utf-8')
                    self._names[altname] = name

        self._names[name] = name

        for oldname in list(self._orig_raw):
            if self._names.get(oldname) == name:
                self._orig_raw[name] = self._orig_raw.pop(oldname)
                break

        return name

    def _set_nice(self, name, value):
        name = self._attr_name(name)
        name = self._add_attr_name(name)

        if not isinstance(value, list):
            if value is None:
                value = []
            else:
                value = [value]
            self._not_list.add(name)
        else:
            self._not_list.discard(name)

        if self._nice.get(name) is not value:
            self._nice[name] = value
            self._raw[name] = None
            self._sync.pop(name, None)

        if self._raw[name] is not None:
            self._sync_attr(name)

    def _set_raw(self, name, value):
        name = self._attr_name(name)

        if not isinstance(value, list):
            raise TypeError("%s value must be list, got %s object %r" % (
                name, value.__class__.__name__, value))
        for (i, item) in enumerate(value):
            if not isinstance(item, bytes):
                raise TypeError(
                    "%s[%d] value must be bytes, got %s object %r" % (
                        name, i, item.__class__.__name__, item)
                )

        name = self._add_attr_name(name)

        if self._raw.get(name) is not value:
            self._raw[name] = value
            self._nice[name] = None
            self._sync.pop(name, None)

        if self._nice[name] is not None:
            self._sync_attr(name)

    def __setitem__(self, name, value):
        self._set_nice(name, value)

    def _get_attr_name(self, name):
        name = self._attr_name(name)
        name = self._names[name]
        return name

    def _get_nice(self, name):
        name = self._get_attr_name(name)

        value = self._nice[name]
        if value is None:
            value = self._nice[name] = []
        assert isinstance(value, list)

        if self._raw[name] is not None:
            self._sync_attr(name)

        if name in self._not_list:
            assert len(value) <= 1
            if value:
                value = value[0]
            else:
                value = None

        return value

    def _get_raw(self, name):
        name = self._get_attr_name(name)

        value = self._raw[name]
        if value is None:
            value = self._raw[name] = []
        assert isinstance(value, list)

        if self._nice[name] is not None:
            self._sync_attr(name)

        return value

    def __getitem__(self, name):
        return self._get_nice(name)

    def __delitem__(self, name):
        name = self._get_attr_name(name)

        for (altname, keyname) in list(self._names.items()):
            if keyname == name:
                del self._names[altname]

        del self._nice[name]
        del self._raw[name]
        self._sync.pop(name, None)
        self._not_list.discard(name)

    def clear(self):
        self._names.clear()
        self._nice.clear()
        self._raw.clear()
        self._sync.clear()
        self._not_list.clear()

    def __len__(self):
        return len(self._nice)

    def __contains__(self, name):
        return name in self._names

    def has_key(self, name):
        return name in self

    def __eq__(self, other):
        if not isinstance(other, LDAPEntry):
            return NotImplemented
        return other is self

    def __ne__(self, other):
        if not isinstance(other, LDAPEntry):
            return NotImplemented
        return other is not self

    def reset_modlist(self, other=None):
        if other is None:
            other = self
        assert isinstance(other, LDAPEntry)
        self._orig_raw = deepcopy(dict(other.raw))

    def generate_modlist(self):
        modlist = []

        names = set(self)
        names.update(self._orig_raw)
        for name in names:
            new = self.raw.get(name, [])
            old = self._orig_raw.get(name, [])
            if old and not new:
                modlist.append((ldap.MOD_DELETE, name, None))
                continue
            if not old and new:
                modlist.append((ldap.MOD_REPLACE, name, new))
                continue

            # We used to convert to sets and use difference to calculate
            # the changes but this did not preserve order which is important
            # particularly for schema
            adds = [value for value in new if value not in old]
            dels = [value for value in old if value not in new]
            if adds and self.conn.get_attribute_single_value(name):
                if len(adds) > 1:
                    raise errors.OnlyOneValueAllowed(attr=name)
                modlist.append((ldap.MOD_REPLACE, name, adds))
            else:
                # dels before adds, in case the same value occurs in
                # both due to encoding differences
                # (https://pagure.io/freeipa/issue/7750)
                if dels:
                    modlist.append((ldap.MOD_DELETE, name, dels))
                if adds:
                    modlist.append((ldap.MOD_ADD, name, adds))

        # Usually the modlist order does not matter.
        # However, for schema updates, we want 'attributetypes' before
        # 'objectclasses'.
        # A simple sort will ensure this.
        modlist.sort(key=lambda m: m[1].lower() != 'attributetypes')

        return modlist

    def __iter__(self):
        return iter(self._nice)


class LDAPEntryView(MutableMapping):
    __slots__ = ('_entry',)

    def __init__(self, entry):
        assert isinstance(entry, LDAPEntry)
        self._entry = entry

    def __delitem__(self, name):
        del self._entry[name]

    def clear(self):
        self._entry.clear()

    def __iter__(self):
        return iter(self._entry)

    def __len__(self):
        return len(self._entry)

    def __contains__(self, name):
        return name in self._entry

    def has_key(self, name):
        return name in self

class RawLDAPEntryView(LDAPEntryView):
    def __getitem__(self, name):
        return self._entry._get_raw(name)

    def __setitem__(self, name, value):
        self._entry._set_raw(name, value)

class SingleValueLDAPEntryView(LDAPEntryView):
    def __getitem__(self, name):
        value = self._entry[name]
        if not isinstance(value, list):
            # FIXME: remove when we enforce lists
            return value
        elif not value:
            return None
        elif len(value) == 1:
            return value[0]
        else:
            raise ValueError(
                '%s has %s values, one expected' % (name, len(value)))

    def __setitem__(self, name, value):
        if value is None:
            self._entry[name] = None
        else:
            self._entry[name] = [value]


class LDAPClient:
    """LDAP backend class

    This class abstracts a LDAP connection, providing methods that work with
    LADPEntries.

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
    """

    # rules for generating filters from entries
    MATCH_ANY = '|'   # (|(filter1)(filter2))
    MATCH_ALL = '&'   # (&(filter1)(filter2))
    MATCH_NONE = '!'  # (!(filter1)(filter2))

    # search scope for find_entries()
    SCOPE_BASE = ldap.SCOPE_BASE
    SCOPE_ONELEVEL = ldap.SCOPE_ONELEVEL
    SCOPE_SUBTREE = ldap.SCOPE_SUBTREE

    _SYNTAX_MAPPING = {
        '1.3.6.1.4.1.1466.115.121.1.1'   : bytes, # ACI item
        '1.3.6.1.4.1.1466.115.121.1.4'   : bytes, # Audio
        '1.3.6.1.4.1.1466.115.121.1.5'   : bytes, # Binary
        '1.3.6.1.4.1.1466.115.121.1.8'   : bytes, # Certificate
        '1.3.6.1.4.1.1466.115.121.1.9'   : bytes, # Certificate List
        '1.3.6.1.4.1.1466.115.121.1.10'  : bytes, # Certificate Pair
        '1.3.6.1.4.1.1466.115.121.1.12'  : DN,  # Distinguished Name
        '1.3.6.1.4.1.1466.115.121.1.23'  : bytes, # Fax
        '1.3.6.1.4.1.1466.115.121.1.24'  : datetime.datetime,
        '1.3.6.1.4.1.1466.115.121.1.28'  : bytes, # JPEG
        '1.3.6.1.4.1.1466.115.121.1.40'  : bytes, # OctetString (same as Binary)
        '1.3.6.1.4.1.1466.115.121.1.49'  : bytes, # Supported Algorithm
        '1.3.6.1.4.1.1466.115.121.1.51'  : bytes, # Teletext Terminal Identifier

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

    _SYNTAX_OVERRIDE = CIDict({
        'managedtemplate': DN,
        'managedbase':     DN,
        'memberindirect':  DN,
        'memberofindirect':DN,
        'originscope':     DN,
        'idnsname':        DNSName,
        'idnssoamname':    DNSName,
        'idnssoarname':    DNSName,
        'dnszoneidnsname': DNSName,
        'krbcanonicalname': Principal,
        'krbprincipalname': Principal,
        'usercertificate': crypto_x509.Certificate,
        'usercertificate;binary': crypto_x509.Certificate,
        'cACertificate': crypto_x509.Certificate,
        'cACertificate;binary': crypto_x509.Certificate,
        'nsds5replicalastupdatestart': unicode,
        'nsds5replicalastupdateend': unicode,
        'nsds5replicalastinitstart': unicode,
        'nsds5replicalastinitend': unicode,
    })
    _SINGLE_VALUE_OVERRIDE = CIDict({
        'nsslapd-ssl-check-hostname': True,
        'nsslapd-lookthroughlimit': True,
        'nsslapd-idlistscanlimit': True,
        'nsslapd-anonlimitsdn': True,
        'nsslapd-minssf-exclude-rootdse': True,
    })

    time_limit = -1.0   # unlimited
    size_limit = 0      # unlimited

    def __init__(self, ldap_uri, start_tls=False, force_schema_updates=False,
                 no_schema=False, decode_attrs=True, cacert=None,
                 sasl_nocanon=True):
        """Create LDAPClient object.

        :param ldap_uri: The LDAP URI to connect to
        :param start_tls: Use STARTTLS
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
        if ldap_uri is not None:
            self.ldap_uri = ldap_uri
            self.host = 'localhost'
            self.port = None
            url_data = urlparse(ldap_uri)
            self._protocol = url_data.scheme
            if self._protocol in ('ldap', 'ldaps'):
                self.host = url_data.hostname
                self.port = url_data.port

        self._start_tls = start_tls
        self._force_schema_updates = force_schema_updates
        self._no_schema = no_schema
        self._decode_attrs = decode_attrs
        self._cacert = cacert
        self._sasl_nocanon = sasl_nocanon

        self._has_schema = False
        self._schema = None

        self._conn = self._connect()

    def __str__(self):
        return self.ldap_uri

    def modify_s(self, dn, modlist):
        # FIXME: for backwards compatibility only
        assert isinstance(dn, DN)
        dn = str(dn)
        modlist = [(a, b, self.encode(c)) for a, b, c in modlist]
        return self.conn.modify_s(dn, modlist)

    @property
    def conn(self):
        return self._conn

    def _get_schema(self):
        if self._no_schema:
            return None

        if not self._has_schema:
            try:
                schema = schema_cache.get_schema(
                    self.ldap_uri, self.conn,
                    force_update=self._force_schema_updates)
            except (errors.ExecutionError, IndexError):
                schema = None

            # bypass ldap2's locking
            object.__setattr__(self, '_schema', schema)
            object.__setattr__(self, '_has_schema', True)

        return self._schema

    def _flush_schema(self):
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

        # bypass ldap2's locking
        object.__setattr__(self, '_has_schema', False)
        object.__setattr__(self, '_schema', None)

    def get_attribute_type(self, name_or_oid):
        if not self._decode_attrs:
            return bytes

        if six.PY2:
            if isinstance(name_or_oid, unicode):
                name_or_oid = name_or_oid.encode('utf-8')

        # Is this a special case attribute?
        if name_or_oid in self._SYNTAX_OVERRIDE:
            return self._SYNTAX_OVERRIDE[name_or_oid]

        schema = self._get_schema()
        if schema is not None:
            # Try to lookup the syntax in the schema returned by the server
            obj = schema.get_obj(ldap.schema.AttributeType, name_or_oid)
            if obj is not None and obj.syntax in self._SYNTAX_MAPPING:
                return self._SYNTAX_MAPPING[obj.syntax]

        return unicode

    def has_dn_syntax(self, name_or_oid):
        """
        Check the schema to see if the attribute uses DN syntax.

        Returns True/False
        """
        return self.get_attribute_type(name_or_oid) is DN

    def get_attribute_single_value(self, name_or_oid):
        """
        Check the schema to see if the attribute is single-valued.

        If the attribute is in the schema then returns True/False

        If there is a problem loading the schema or the attribute is
        not in the schema return None
        """
        if six.PY2 and isinstance(name_or_oid, unicode):
            name_or_oid = name_or_oid.encode('utf-8')

        if name_or_oid in self._SINGLE_VALUE_OVERRIDE:
            return self._SINGLE_VALUE_OVERRIDE[name_or_oid]

        schema = self._get_schema()
        if schema is not None:
            obj = schema.get_obj(ldap.schema.AttributeType, name_or_oid)
            if obj is not None:
                return obj.single_value

        return None

    def encode(self, val):
        """
        Encode attribute value to LDAP representation (str/bytes).
        """
        # Booleans are both an instance of bool and int, therefore
        # test for bool before int otherwise the int clause will be
        # entered for a boolean value instead of the boolean clause.
        if isinstance(val, bool):
            if val:
                return b'TRUE'
            else:
                return b'FALSE'
        elif isinstance(val, (unicode, int, Decimal, DN, Principal)):
            return str(val).encode('utf-8')
        elif isinstance(val, DNSName):
            return val.to_text().encode('ascii')
        elif isinstance(val, bytes):
            return val
        elif isinstance(val, list):
            return [self.encode(m) for m in val]
        elif isinstance(val, tuple):
            return tuple(self.encode(m) for m in val)
        elif isinstance(val, dict):
            # key in dict must be str not bytes
            dct = dict((k, self.encode(v)) for k, v in val.items())
            return dct
        elif isinstance(val, datetime.datetime):
            return val.strftime(LDAP_GENERALIZED_TIME_FORMAT).encode('utf-8')
        elif isinstance(val, crypto_x509.Certificate):
            return val.public_bytes(x509.Encoding.DER)
        elif val is None:
            return None
        else:
            raise TypeError("attempt to pass unsupported type to ldap, value=%s type=%s" %(val, type(val)))

    def decode(self, val, attr):
        """
        Decode attribute value from LDAP representation (str/bytes).
        """
        if isinstance(val, bytes):
            target_type = self.get_attribute_type(attr)
            try:
                if target_type is bytes:
                    return val
                elif target_type is unicode:
                    return val.decode('utf-8')
                elif target_type is datetime.datetime:
                    return datetime.datetime.strptime(
                        val.decode('utf-8'), LDAP_GENERALIZED_TIME_FORMAT)
                elif target_type is DNSName:
                    return DNSName.from_text(val.decode('utf-8'))
                elif target_type in (DN, Principal):
                    return target_type(val.decode('utf-8'))
                elif target_type is crypto_x509.Certificate:
                    return x509.load_der_x509_certificate(val)
                else:
                    return target_type(val)
            except Exception:
                msg = 'unable to convert the attribute %r value %r to type %s' % (attr, val, target_type)
                logger.error('%s', msg)
                raise ValueError(msg)
        elif isinstance(val, list):
            return [self.decode(m, attr) for m in val]
        elif isinstance(val, tuple):
            return tuple(self.decode(m, attr) for m in val)
        elif isinstance(val, dict):
            dct = {
                k.decode('utf-8'): self.decode(v, k) for k, v in val.items()
            }
            return dct
        elif val is None:
            return None
        else:
            raise TypeError("attempt to pass unsupported type from ldap, value=%s type=%s" %(val, type(val)))

    def _convert_result(self, result):
        '''
        result is a python-ldap result tuple of the form (dn, attrs),
        where dn is a string containing the dn (distinguished name) of
        the entry, and attrs is a dictionary containing the attributes
        associated with the entry. The keys of attrs are strings, and
        the associated values are lists of strings.

        We convert the tuple to an LDAPEntry object.
        '''

        ipa_result = []
        for dn_tuple in result:
            original_dn = dn_tuple[0]
            original_attrs = dn_tuple[1]

            # original_dn is None if referral instead of an entry was
            # returned from the LDAP server, we need to skip this item
            if original_dn is None:
                log_msg = 'Referral entry ignored: {ref}'\
                          .format(ref=str(original_attrs))
                logger.debug('%s', log_msg)

                continue

            ipa_entry = LDAPEntry(self, DN(original_dn))

            for attr, original_values in original_attrs.items():
                ipa_entry.raw[attr] = original_values
            ipa_entry.reset_modlist()

            ipa_result.append(ipa_entry)

        if _debug_log_ldap:
            logger.debug('ldap.result: %s', ipa_result)
        return ipa_result

    @contextlib.contextmanager
    def error_handler(self, arg_desc=None):
        """Context manager that handles LDAPErrors
        """
        try:
            try:
                yield
            except ldap.TIMEOUT:
                raise errors.DatabaseTimeout()
            except ldap.LDAPError as e:
                desc = e.args[0]['desc'].strip()
                info = e.args[0].get('info', '').strip()
                if arg_desc is not None:
                    info = "%s arguments: %s" % (info, arg_desc)
                raise
        except ldap.NO_SUCH_OBJECT:
            raise errors.NotFound(reason=arg_desc or 'no such entry')
        except ldap.ALREADY_EXISTS:
            # entry already exists
            raise errors.DuplicateEntry()
        except ldap.TYPE_OR_VALUE_EXISTS:
            # attribute type or attribute value already exists, usually only
            # occurs, when two machines try to write at the same time.
            raise errors.DuplicateEntry(message=desc)
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
            raise errors.AdminLimitExceeded()
        except ldap.SIZELIMIT_EXCEEDED:
            raise errors.SizeLimitExceeded()
        except ldap.TIMELIMIT_EXCEEDED:
            raise errors.TimeLimitExceeded()
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
        except ldap.UNWILLING_TO_PERFORM:
            raise errors.DatabaseError(desc=desc, info=info)
        except ldap.AUTH_UNKNOWN:
            raise errors.ACIError(info='%s (%s)' % (info,desc))
        except ldap.LDAPError as e:
            if 'NOT_ALLOWED_TO_DELEGATE' in info:
                raise errors.ACIError(
                    info="KDC returned NOT_ALLOWED_TO_DELEGATE")
            logger.debug(
                'Unhandled LDAPError: %s: %s', type(e).__name__, str(e))
            raise errors.DatabaseError(desc=desc, info=info)

    @staticmethod
    def handle_truncated_result(truncated):
        if not truncated:
            return

        if truncated is TRUNCATED_ADMIN_LIMIT:
            raise errors.AdminLimitExceeded()
        elif truncated is TRUNCATED_SIZE_LIMIT:
            raise errors.SizeLimitExceeded()
        elif truncated is TRUNCATED_TIME_LIMIT:
            raise errors.TimeLimitExceeded()
        else:
            raise errors.LimitsExceeded()

    @property
    def schema(self):
        """schema associated with this LDAP server"""
        return self._get_schema()

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

    def __enter__(self):
        return self


    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        """
        Close the connection.
        """
        self._conn = None

    def _connect(self):
        with self.error_handler():
            conn = ldap_initialize(self.ldap_uri, cacertfile=self._cacert)
            # SASL_NOCANON is set to ON in Fedora's default ldap.conf and
            # in the ldap_initialize() function.
            if not self._sasl_nocanon:
                conn.set_option(ldap.OPT_X_SASL_NOCANON, ldap.OPT_OFF)

            if self._start_tls:
                conn.start_tls_s()

        return conn

    def simple_bind(self, bind_dn, bind_password, server_controls=None,
                    client_controls=None):
        """
        Perform simple bind operation.
        """
        with self.error_handler():
            self._flush_schema()
            assert isinstance(bind_dn, DN)
            bind_dn = str(bind_dn)
            bind_password = self.encode(bind_password)
            self.conn.simple_bind_s(
                bind_dn, bind_password, server_controls, client_controls)

    def external_bind(self, server_controls=None, client_controls=None):
        """
        Perform SASL bind operation using the SASL EXTERNAL mechanism.
        """
        user_name = pwd.getpwuid(os.geteuid()).pw_name
        with self.error_handler():
            auth_tokens = ldap.sasl.external(user_name)
            self._flush_schema()
            self.conn.sasl_interactive_bind_s(
                '', auth_tokens, server_controls, client_controls)

    def gssapi_bind(self, server_controls=None, client_controls=None):
        """
        Perform SASL bind operation using the SASL GSSAPI mechanism.
        """
        with self.error_handler():
            if self._protocol == 'ldapi':
                auth_tokens = SASL_GSS_SPNEGO
            else:
                auth_tokens = SASL_GSSAPI
            self._flush_schema()
            self.conn.sasl_interactive_bind_s(
                '', auth_tokens, server_controls, client_controls)

    def unbind(self):
        """
        Perform unbind operation.
        """
        with self.error_handler():
            self._flush_schema()
            self.conn.unbind_s()

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
        return LDAPEntry(self, _dn, _obj, **kwargs)

    # generating filters for find_entry
    # some examples:
    # f1 = ldap2.make_filter_from_attr(u'firstName', u'Pavel')
    # f2 = ldap2.make_filter_from_attr(u'lastName', u'Zuna')
    # f = ldap2.combine_filters([f1, f2], ldap2.MATCH_ALL)
    # # f should be (&(firstName=Pavel)(lastName=Zuna))
    # # it should be equivalent to:
    # entry_attrs = {u'firstName': u'Pavel', u'lastName': u'Zuna'}
    # f = ldap2.make_filter(entry_attrs, rules=ldap2.MATCH_ALL)

    @classmethod
    def combine_filters(cls, filters, rules='|'):
        """
        Combine filters into one for ldap2.find_entries.

        Keyword arguments:
        rules -- see ldap2.make_filter
        """

        assert isinstance(filters, (list, tuple))

        filters = [fx for fx in filters if fx]
        if filters and rules == cls.MATCH_NONE:  # unary operator
            return '(%s%s)' % (cls.MATCH_NONE,
                               cls.combine_filters(filters, cls.MATCH_ANY))

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

    @classmethod
    def make_filter_from_attr(
            cls, attr, value, rules='|', exact=True,
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
            flts = [
                cls.make_filter_from_attr(
                    attr, v, exact=exact,
                    leading_wildcard=leading_wildcard,
                    trailing_wildcard=trailing_wildcard)
                for v in value
            ]
            return cls.combine_filters(flts, rules)
        elif value is not None:
            if isinstance(value, crypto_x509.Certificate):
                value = value.public_bytes(serialization.Encoding.DER)
            if isinstance(value, bytes):
                value = binascii.hexlify(value).decode('ascii')
                # value[-2:0] is empty string for the initial '\\'
                value = u'\\'.join(
                    value[i:i+2] for i in six.moves.range(-2, len(value), 2))
            else:
                value = str(value)
                value = ldap.filter.escape_filter_chars(value)

            if not exact:
                template = '%s'
                if leading_wildcard:
                    template = '*' + template
                if trailing_wildcard:
                    template = template + '*'
                value = template % value
            if rules == cls.MATCH_NONE:
                return '(!(%s=%s))' % (attr, value)
            return '(%s=%s)' % (attr, value)
        return ''

    @classmethod
    def make_filter(
            cls, entry_attrs, attrs_list=None, rules='|', exact=True,
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
        if rules == cls.MATCH_NONE:
            make_filter_rules = cls.MATCH_ANY
        else:
            make_filter_rules = rules
        flts = []
        if attrs_list is None:
            for (k, v) in entry_attrs.items():
                flts.append(
                    cls.make_filter_from_attr(
                        k, v, make_filter_rules, exact,
                        leading_wildcard, trailing_wildcard)
                )
        else:
            for a in attrs_list:
                value = entry_attrs.get(a, None)
                if value is not None:
                    flts.append(
                        cls.make_filter_from_attr(
                            a, value, make_filter_rules, exact,
                            leading_wildcard, trailing_wildcard)
                    )
        return cls.combine_filters(flts, rules)

    def get_entries(self, base_dn, scope=ldap.SCOPE_SUBTREE, filter=None,
                    attrs_list=None, get_effective_rights=False, **kwargs):
        """Return a list of matching entries.

        :raises: errors.LimitsExceeded if the list is truncated by the server
        :raises: errors.NotFound if result set is empty
                                 or base_dn doesn't exist

        :param base_dn: dn of the entry at which to start the search
        :param scope: search scope, see LDAP docs (default ldap2.SCOPE_SUBTREE)
        :param filter: LDAP filter to apply
        :param attrs_list: ist of attributes to return, all if None (default)
        :param get_effective_rights: use GetEffectiveRights control
        :param kwargs: additional keyword arguments. See find_entries method
        for their description.
        """
        entries, truncated = self.find_entries(
            base_dn=base_dn, scope=scope, filter=filter, attrs_list=attrs_list,
            get_effective_rights=get_effective_rights,
            **kwargs)
        try:
            self.handle_truncated_result(truncated)
        except errors.LimitsExceeded as e:
            logger.error(
                "%s while getting entries (base DN: %s, filter: %s)",
                e, base_dn, filter
            )
            raise

        return entries

    def find_entries(
            self, filter=None, attrs_list=None, base_dn=None,
            scope=ldap.SCOPE_SUBTREE, time_limit=None, size_limit=None,
            paged_search=False, get_effective_rights=False):
        """
        Return a list of entries and indication of whether the results were
        truncated ([(dn, entry_attrs)], truncated) matching specified search
        parameters followed by truncated flag. If the truncated flag is True,
        search hit a server limit and its results are incomplete.

        Keyword arguments:
        :param attrs_list: list of attributes to return, all if None
                           (default None)
        :param base_dn: dn of the entry at which to start the search
                        (default '')
        :param scope: search scope, see LDAP docs (default ldap2.SCOPE_SUBTREE)
        :param time_limit: time limit in seconds (default unlimited)
        :param size_limit: size (number of entries returned) limit
                           (default unlimited)
        :param paged_search: search using paged results control
        :param get_effective_rights: use GetEffectiveRights control

        :raises: errors.NotFound if result set is empty
                                 or base_dn doesn't exist
        """
        if base_dn is None:
            base_dn = DN()
        assert isinstance(base_dn, DN)
        if not filter:
            filter = '(objectClass=*)'
        res = []
        truncated = False

        if time_limit is None:
            time_limit = self.time_limit
        if time_limit == 0:
            time_limit = -1.0

        if size_limit is None:
            size_limit = self.size_limit

        if not isinstance(size_limit, int):
            size_limit = int(size_limit)
        if not isinstance(time_limit, float):
            time_limit = float(time_limit)

        if attrs_list:
            attrs_list = [a.lower() for a in set(attrs_list)]

        base_sctrls = []
        if get_effective_rights:
            base_sctrls.append(self.__get_effective_rights_control())

        cookie = ''
        page_size = (size_limit if size_limit > 0 else 2000) - 1
        if page_size == 0:
            paged_search = False

        # pass arguments to python-ldap
        with self.error_handler():
            if six.PY2:
                filter = self.encode(filter)
                attrs_list = self.encode(attrs_list)

            while True:
                if paged_search:
                    sctrls = base_sctrls + [
                        SimplePagedResultsControl(0, page_size, cookie)
                    ]
                else:
                    sctrls = base_sctrls or None

                try:
                    id = self.conn.search_ext(
                        str(base_dn), scope, filter, attrs_list,
                        serverctrls=sctrls, timeout=time_limit,
                        sizelimit=size_limit
                    )
                    while True:
                        result = self.conn.result3(id, 0)
                        objtype, res_list, _res_id, res_ctrls = result
                        if objtype == ldap.RES_SEARCH_RESULT:
                            break
                        res_list = self._convert_result(res_list)
                        if res_list:
                            res.append(res_list[0])

                    if paged_search:
                        # Get cookie for the next page
                        for ctrl in res_ctrls:
                            if isinstance(ctrl, SimplePagedResultsControl):
                                cookie = ctrl.cookie
                                break
                        else:
                            cookie = ''
                except ldap.ADMINLIMIT_EXCEEDED:
                    truncated = TRUNCATED_ADMIN_LIMIT
                    break
                except ldap.SIZELIMIT_EXCEEDED:
                    truncated = TRUNCATED_SIZE_LIMIT
                    break
                except ldap.TIMELIMIT_EXCEEDED:
                    truncated = TRUNCATED_TIME_LIMIT
                    break
                except ldap.LDAPError as e:
                    # If paged search is in progress, try to cancel it
                    if paged_search and cookie:
                        sctrls = [SimplePagedResultsControl(0, 0, cookie)]
                        try:
                            self.conn.search_ext_s(
                                str(base_dn), scope, filter, attrs_list,
                                serverctrls=sctrls, timeout=time_limit,
                                sizelimit=size_limit)
                        except ldap.LDAPError as e:
                            logger.warning(
                                "Error cancelling paged search: %s", e)
                        cookie = ''

                    try:
                        raise e
                    except (ldap.ADMINLIMIT_EXCEEDED, ldap.TIMELIMIT_EXCEEDED,
                            ldap.SIZELIMIT_EXCEEDED):
                        truncated = True
                        break

                if not paged_search or not cookie:
                    break

        if not res and not truncated:
            raise errors.EmptyResult(reason='no matching entry found')

        return (res, truncated)

    def __get_effective_rights_control(self):
        """Construct a GetEffectiveRights control for current user."""
        bind_dn = self.conn.whoami_s()[4:]
        return GetEffectiveRightsControl(
                True, "dn: {0}".format(bind_dn).encode('utf-8'))

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
        entries = self.get_entries(
            base_dn, filter=filter, attrs_list=attrs_list)

        if len(entries) > 1:
            raise errors.SingleMatchExpected(found=len(entries))

        return entries[0]

    def get_entry(self, dn, attrs_list=None, time_limit=None,
                  size_limit=None, get_effective_rights=False):
        """
        Get entry (dn, entry_attrs) by dn.

        Keyword arguments:
        attrs_list - list of attributes to return, all if None (default None)
        """

        assert isinstance(dn, DN)

        entries = self.get_entries(
            dn, self.SCOPE_BASE, None, attrs_list, time_limit=time_limit,
            size_limit=size_limit, get_effective_rights=get_effective_rights,
        )

        return entries[0]

    def add_entry(self, entry):
        """Create a new entry.

        This should be called as add_entry(entry).
        """
        # remove all [] values (python-ldap hates 'em)
        attrs = dict((k, v) for k, v in entry.raw.items() if v)

        with self.error_handler():
            attrs = self.encode(attrs)
            self.conn.add_s(str(entry.dn), list(attrs.items()))

        entry.reset_modlist()

    def move_entry(self, dn, new_dn, del_old=True):
        """
        Move an entry (either to a new superior or/and changing relative distinguished name)

        Keyword arguments:
        dn: DN of the source entry
        new_dn: DN of the target entry
        del_old -- delete old RDN value (default True)

        :raises:
        errors.NotFound if source entry or target superior entry doesn't exist
        errors.EmptyModlist if source and target are identical
        """
        assert isinstance(dn, DN)
        assert isinstance(new_dn, DN)

        if new_dn == dn:
            raise errors.EmptyModlist()

        new_rdn = new_dn[0]

        if new_dn[1:] == dn[1:]:
            new_superior = None
        else:
            new_superior = str(DN(*new_dn[1:]))

        with self.error_handler():
            self.conn.rename_s(str(dn), str(new_rdn), newsuperior=new_superior,
                               delold=int(del_old))
            time.sleep(.3)  # Give memberOf plugin a chance to work

    def update_entry(self, entry):
        """Update entry's attributes.

        This should be called as update_entry(entry).
        """
        # generate modlist
        modlist = entry.generate_modlist()
        if not modlist:
            raise errors.EmptyModlist()

        # pass arguments to python-ldap
        with self.error_handler():
            modlist = [(a, str(b), self.encode(c))
                       for a, b, c in modlist]
            self.conn.modify_s(str(entry.dn), modlist)

        entry.reset_modlist()

    def delete_entry(self, entry_or_dn):
        """Delete an entry given either the DN or the entry itself"""
        if isinstance(entry_or_dn, DN):
            dn = entry_or_dn
        else:
            dn = entry_or_dn.dn

        with self.error_handler():
            self.conn.delete_s(str(dn))

    def entry_exists(self, dn):
        """
        Test whether the given object exists in LDAP.
        """
        assert isinstance(dn, DN)
        try:
            self.get_entry(dn, attrs_list=[])
        except errors.NotFound:
            return False
        else:
            return True


def get_ldap_uri(host='', port=389, cacert=None, ldapi=False, realm=None,
                 protocol=None):
        if protocol is None:
            if ldapi:
                protocol = 'ldapi'
            elif cacert is not None:
                protocol = 'ldaps'
            else:
                protocol = 'ldap'

        if protocol == 'ldaps':
            return 'ldaps://%s' % format_netloc(host, port)
        elif protocol == 'ldapi':
            return 'ldapi://%%2fvar%%2frun%%2fslapd-%s.socket' % (
                "-".join(realm.split(".")))
        elif protocol == 'ldap':
            return 'ldap://%s' % format_netloc(host, port)
        else:
            raise ValueError('Protocol %r not supported' % protocol)
