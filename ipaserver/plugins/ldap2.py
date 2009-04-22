# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
"""
Backend plugin for LDAP.
"""

# Entries are represented as (dn, entry_attrs), where entry_attrs is a dict
# mapping attribute names to values. Values can be a single value or list/tuple
# of virtually any type. Each method passing these values to the python-ldap
# binding encodes them into the appropriate representation. This applies to
# everything except the CrudBackend methods, where dn is part of the entry dict.
#
# TODO: review raised exceptions
#       consider using CIDicts for entry_attrs for convenience
#       cleanup & polishing
#       write some documention

import copy
import os
import re
import socket
import string

import krbV
import ldap as _ldap
import ldap.filter as _ldap_filter
import ldap.sasl as _ldap_sasl
from ldap.controls import LDAPControl
from ldap.ldapobject import SimpleLDAPObject

from ipalib import api
from ipalib import errors2
from ipalib.crud import CrudBackend

# attribute syntax to python type mapping, 'SYNTAX OID': type
# everything not in this dict is considered human readable unicode
_syntax_mapping = {
    '1.3.6.1.4.1.1466.115.121.1.1': str,  # ACI item
    '1.3.6.1.4.1.1466.115.121.1.4': str,  # Audio
    '1.3.6.1.4.1.1466.115.121.1.5': str,  # Binary
    '1.3.6.1.4.1.1466.115.121.1.7': str, # Boolean
    '1.3.6.1.4.1.1466.115.121.1.8': str,  # Certificate
    '1.3.6.1.4.1.1466.115.121.1.9': str,  # Certificate List
    '1.3.6.1.4.1.1466.115.121.1.10': str, # Certificate Pair
    '1.3.6.1.4.1.1466.115.121.1.23': str, # Fax
    '1.3.6.1.4.1.1466.115.121.1.27': str, # Integer, might not fit into int
    '1.3.6.1.4.1.1466.115.121.1.28': str, # JPEG
    '1.3.6.1.4.1.1466.115.121.1.40': str, # OctetString (same as Binary)
    '1.3.6.1.4.1.1466.115.121.1.49': str, # Supported Algorithm
    '1.3.6.1.4.1.1466.115.121.1.51': str, # Teletext Terminal Identifier
}

# used to identify the Uniqueness plugin error message
_uniqueness_plugin_error = 'Another entry with the same attribute value already exists'

# SASL authentication mechanism
_sasl_auth = _ldap_sasl.sasl({}, 'GSSAPI')


# universal LDAPError handler
def _handle_errors(self, e, **kw):
    """
    Centralize error handling in one place.

    e is the error to be raised
    **kw is an exception-specific list of options
    """
    if not isinstance(e, ldap.TIMEOUT):
        desc = e.args[0]['desc'].strip()
        info = e.args[0].get('info', '').strip()
    else:
        desc = ''
        info = ''

    try:
        # re-raise the error so we can handle it
        raise e
    except _ldap.NO_SUCH_OBJECT, e:
        # args = kw.get('args', '')
        # raise errors2.NotFound(msg=notfound(args))
        raise errors2.NotFound()
    except _ldap.ALREADY_EXISTS, e:
        raise errors2.DuplicateEntry()
    except _ldap.CONSTRAINT_VIOLATION, e:
        # This error gets thrown by the uniqueness plugin
        if info == 'Another entry with the same attribute value already exists':
            raise errors2.DuplicateEntry()
        else:
            raise errors2.DatabaseError(desc=desc, info=info)
    except _ldap.INSUFFICIENT_ACCESS, e:
        raise errors2.ACIError(info=info)
    except _ldap.NO_SUCH_ATTRIBUTE:
        # this is raised when a 'delete' attribute isn't found.
        # it indicates the previous attribute was removed by another
        # update, making the oldentry stale.
        raise errors2.MidairCollision()
    except _ldap.ADMINLIMIT_EXCEEDED, e:
        raise errors2.LimitsExceeded()
    except _ldap.SIZELIMIT_EXCEEDED, e:
        raise errors2.LimitsExceeded()
    except _ldap.TIMELIMIT_EXCEEDED, e:
        raise errors2.LimitsExceeded()
    except _ldap.LDAPError, e:
        raise errors2.DatabaseError(desc=desc, info=info)

# utility function, builds LDAP URL string
def _get_url(host, port, using_cacert=False):
    if using_cacert:
        return 'ldaps://%s:%d' % (host, port)
    return 'ldap://%s:%d' % (host, port)

# retrieves LDAP schema from server
def _load_schema(host, port):
    url = _get_url(host, port)

    try:
        conn = _ldap.initialize(url)
        # assume anonymous access is enabled
        conn.simple_bind_s('', '')
        schema_entry = conn.search_s('cn=schema', _ldap.SCOPE_BASE)[0]
        conn.unbind_s()
    except _ldap.LDAPError, e:
        # TODO: raise a more appropriate exception
        _handle_errors(e, **{})
    except IndexError:
        # no 'cn=schema' entry in LDAP? some servers use 'cn=subschema'
        # TODO: DS uses 'cn=schema', support for other server?
        #       raise a more appropriate exception
        raise

    return _ldap.schema.SubSchema(schema_entry[1])


# cache schema when importing module
_schema = _load_schema(api.env.ldap_host, api.env.ldap_port)

# ldap backend class
class ldap2(CrudBackend):

    # rules for generating filters from entries
    MATCH_ANY = '|'   # (|(filter1)(filter2))
    MATCH_ALL = '&'   # (&(filter1)(filter2))
    MATCH_NONE = '!'  # (!(filter1)(filter2))

    # search scope for find_entries()
    SCOPE_BASE = _ldap.SCOPE_BASE
    SCOPE_ONELEVEL = _ldap.SCOPE_ONELEVEL
    SCOPE_SUBTREE = _ldap.SCOPE_SUBTREE

    def __init__(self):
        self._host = api.env.ldap_host
        self._port = api.env.ldap_port
        self._schema = _schema
        super(ldap2, self).__init__()

    def __del__(self):
        self.disconnect()

    def __str__(self):
        using_cacert = bool(_ldap.get_option(_ldap.OPT_X_TLS_CACERTFILE))
        return _get_url(self._host, self._port, using_cacert)

    # encoding values from unicode to utf-8 strings for the ldap bindings

    def _encode_value(self, value):
        if isinstance(value, unicode):
            return value.encode('utf-8')
        if value is None:
            return None
        if not isinstance(value, (bool, int, float, long, str)):
            raise TypeError('scalar value expected, got %s' % (value,))
        return str(value)

    def _encode_values(self, values):
        if isinstance(values, (list, tuple)):
            return map(self._encode_value, values)
        return self._encode_value(values)

    def _encode_entry_attrs(self, entry_attrs):
        for (k, v) in entry_attrs.iteritems():
            entry_attrs[k] = self._encode_values(v)

    # decoding values from the ldap bindings to the appropriate type

    def _decode_value(self, value):
        return value.decode('utf-8')

    def _decode_values(self, values):
        if isinstance(values, (list, tuple)):
            return map(self._decode_value, values)
        return self._decode_value(values)

    def _decode_entry_attrs(self, entry_attrs):
        for (k, v) in entry_attrs.iteritems():
            attr = self._schema.get_obj(_ldap.schema.AttributeType, k)
            if attr:
                attr_type = _syntax_mapping.get(attr.syntax, unicode)
                if attr_type is unicode:
                    entry_attrs[k] = self._decode_values(v)
                elif isinstance(v, (list, tuple)):
                    entry_attrs[k] = map(attr_type, v)
                else:
                    entry_attrs[k] = attr_type(v)

    def create_connection(self, host=None, port=None, ccache=None,
            bind_dn='', bind_pw='', debug_level=255,
            tls_cacertfile=None, tls_certfile=None, tls_keyfile=None):
        """
        Connect to LDAP server.

        Keyword arguments:
        host -- hostname or IP of the server.
        port -- port number
        ccache -- Kerberos V5 ccache name
        bind_dn -- dn used to bind to the server
        bind_pw -- password used to bind to the server
        debug_level -- LDAP debug level option
        tls_cacertfile -- TLS CA certificate filename
        tls_certfile -- TLS certificate filename
        tls_keyfile - TLS bind key filename

        Extends backend.Connectible.create_connection.
        """
        if host is not None:
            self._host = host
        if port is not None:
            self._port = port

        # if we don't have this server's schema cached, do it now
        if self._host != api.env.ldap_host or self._port != api.env.ldap_port:
            self._schema = _load_schema(self._host, self._port)

        if tls_cacertfile is not None:
            _ldap.set_option(_ldap.OPT_X_TLS_CACERTFILE, tls_cacertfile)
        if tls_certfile is not None:
            _ldap.set_option(_ldap.OPT_X_TLS_CERTFILE, tls_certfile)
        if tls_keyfile is not None:
            _ldap.set_option(_ldap.OPT_X_TLS_KEYFILE, tls_keyfile)

        conn = _ldap.initialize(str(self))
        if ccache is not None:
            os.environ['KRB5CCNAME'] = ccache
            conn.sasl_interactive_bind_s('', _sasl_auth)
        else:
            # no kerberos ccache, use simple bind
            bind_dn = self._encode_value(bind_dn)
            bind_pw = self._encode_value(bind_pw)
            conn.simple_bind_s(bind_dn, bind_pw)
        return conn

    def destroy_connection(self):
        """Disconnect from LDAP server."""
        self.conn.unbind_s()

    # DN manipulation
    # DN's could be generated for example like this:
    # def execute(...):
    #     ldap = self.backend.ldap2
    #     entry_attrs = self.args_options_2_entry(*args, *options)
    #     parent = ldap.get_container_rdn('accounts')
    #     dn = ldap.make_dn(entry_attrs, self.obj.primary_key, parent)
    #     # add entry with generated dn
    #     ldap.add_entry(dn, entry_attrs)

    def normalize_dn(self, dn):
        """
        Normalize distinguished name.

        Note: You don't have to normalize DN's before passing them to
              ldap2 methods. It's done internally for you.
        """
        rdns = _ldap.dn.explode_dn(dn.lower())
        if rdns:
            dn = u','.join(rdns)
            if not dn.endswith(self.api.env.basedn):
                dn = u'%s,%s' % (dn, self.api.env.basedn)
            return dn
        return self.api.env.basedn

    def get_container_rdn(self, name):
        """Get relative distinguished name of cotainer."""
        env_container = 'container_%s' % name
        if env_container in self.api.env:
            return self.api.env[env_container]
        return ''

    def make_rdn_from_attr(self, attr, value):
        """Make relative distinguished name from attribute."""
        if isinstance(value, (list, tuple)):
            value = value[0]
        attr = _ldap.dn.escape_dn_chars(attr)
        value = _ldap.dn.escape_dn_chars(value)
        return u'%s=%s' % (attr, value)

    def make_dn_from_rdn(self, rdn, parent_dn=''):
        """
        Make distinguished name from relative distinguished name.

        Keyword arguments:
        parent_dn -- DN of the parent entry (default '')
        """
        parent_dn = self.normalize_dn(parent_dn)
        return u'%s,%s' % (rdn, parent_dn)

    def make_dn(self, entry_attrs, primary_key='cn', parent_dn=''):
        """
        Make distinguished name from entry attributes.

        Keyword arguments:
        primary_key -- attribute from which to make RDN (default 'cn')
        parent_dn -- DN of the parent entry (default '')
        """
        assert primary_key in entry_attrs
        rdn = self.make_rdn_from_attr(primary_key, entry_attrs[primary_key])
        return self.make_dn_from_rdn(rdn, parent_dn)

    def add_entry(self, dn, entry_attrs):
        """Create a new entry."""
        # encode/normalize arguments
        dn = self.normalize_dn(dn)
        dn = self._encode_value(dn)
        entry_attrs_copy = dict(entry_attrs)
        self._encode_entry_attrs(entry_attrs_copy)

        # pass arguments to python-ldap
        try:
            self.conn.add_s(dn, list(entry_attrs_copy.iteritems()))
        except _ldap.LDAPError, e:
            _handle_errors(e, **{})

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
        if len(filters) > 1:
            flt = '(%s' % rules
        else:
            flt = ''
        for f in filters:
            if not f.startswith('('):
                f = '(%s' % f
            if not f.endswith(')'):
                f = '%s)' % f
            flt = '%s%s' % (flt, f)
        if len(filters) > 1:
            flt = '%s)' % flt
        return flt

    def make_filter_from_attr(self, attr, value, rules='|', exact=True):
        """
        Make filter for ldap2.find_entries from attribute.

        Keyword arguments:
        rules -- see ldap2.make_filter
        exact -- boolean, True - make filter as (attr=value)
                          False - make filter as (attr=*value*)
        """
        if isinstance(value, (list, tuple)):
            flts = []
            for v in value:
                flts.append(self.make_filter_from_attr(attr, v, rules, exact))
            return self.combine_filters(flts, rules)
        else:
            value = _ldap_filter.escape_filter_chars(value)
            attr = self._encode_value(attr)
            value = self._encode_value(value)
            if exact:
                return '(%s=%s)' % (attr, value)
            return '(%s=*%s*)' % (attr, value)

    def make_filter(self, entry_attrs, attrs_list=None, rules='|', exact=True):
        """
        Make filter for ldap2.find_entries from entry attributes.

        Keyword arguments:
        attrs_list -- list of attributes to use, all if None (default None)
        rules -- specifies how to determine a match (default ldap2.MATCH_ANY)
        exact -- boolean, True - make filter as (attr=value)
                          False - make filter as (attr=*value*)

        rules can be one of the following:
        ldap2.MATCH_NONE - match entries that do not match any attribute
        ldap2.MATCH_ALL - match entries that match all attributes
        ldap2.MATCH_ANY - match entries that match any of attribute
        """
        flts = []
        if attrs_list is None:
            for (k, v) in entry_attrs.iteritems():
                flts.append(
                    self.make_filter_from_attr(k, v, rules, exact)
                )
        else:
            for a in attrs_list:
                value = entry_attrs.get(a, None)
                if value is not None:
                    flts.append(
                        self.make_filter_from_attr(a, value, rules, exact)
                    )
        return self.combine_filters(flts, rules)

    def find_entries(self, filter, attrs_list=None, base_dn='',
            scope=_ldap.SCOPE_SUBTREE, time_limit=1, size_limit=3000):
        """
        Return a list of entries [(dn, entry_attrs)] matching specified
        search parameters.

        Keyword arguments:
        attrs_list -- list of attributes to return, all if None (default None)
        base_dn -- dn of the entry at which to start the search (default '')
        scope -- search scope, see LDAP docs (default ldap2.SCOPE_SUBTREE)
        time_limit -- time limit in seconds (default 1)
        size_limit -- size (number of entries returned) limit (default 3000)
        """
        # encode/normalize arguments
        base_dn = self.normalize_dn(base_dn)
        filter = self._encode_value(filter)
        if attrs_list is not None:
            attrs_list = self._encode_values(attrs_list)
        base_dn = self._encode_value(base_dn)

        # pass arguments to python-ldap
        try:
            res = self.conn.search_ext_s(base_dn, scope, filter, attrs_list,
                    timeout=time_limit, sizelimit=size_limit)
        except (_ldap.ADMINLIMIT_EXCEEDED, _ldap.TIMELIMIT_EXCEEDED,
                _ldap.SIZELIMIT_EXCEEDED), e:
            raise e
        except _ldap.LDAPError, e:
            _handle_errors(e, **{})
        if not res:
            raise errors2.NotFound()

        # decode results
        for i in xrange(len(res)):
            dn = self._decode_value(res[i][0])
            self._decode_entry_attrs(res[i][1])
            res[i] = (dn, res[i][1])

        return res

    def get_entry(self, dn, attrs_list=None):
        """
        Get entry (dn, entry_attrs) by dn.

        Keyword arguments:
        attrs_list - list of attributes to return, all if None (default None)
        """
        filter = '(objectClass=*)'
        return self.find_entries(filter, attrs_list, dn, self.SCOPE_BASE)[0]

    def get_ipa_config(self):
        """Returns the IPA configuration entry (dn, entry_attrs)."""
        filter = '(cn=ipaConfig)'
        return self.find_entries(filter, None, 'cn=etc', self.SCOPE_ONELEVEL)[0]

    def get_schema(self):
        """Returns a copy of the current LDAP schema."""
        return copy.deepcopy(self._schema)

    def update_entry_rdn(self, dn, new_rdn, del_old=True):
        """
        Update entry's relative distinguished name.

        Keyword arguments:
        del_old -- delete old RDN value (default True)
        """
        # encode/normalize arguments
        dn = self.normalize_dn(dn)
        dn = self._encode_value(dn)
        new_rdn = self._encode_value(new_rdn)

        # pass arguments to python-ldap
        try:
            self.conn.rename_s(dn, new_rdn, delold=int(del_old))
        except _ldap.LDAPError, e:
            _handle_errors(e, **{})

    def _generate_modlist(self, dn, entry_attrs):
        # get original entry
        (dn, entry_attrs_old) = self.get_entry(dn)
        # get_entry returns a decoded entry, encode it back
        # we could call search_s directly, but this saves a lot of code at
        # the expense of a little bit of performace
        self._encode_entry_attrs(entry_attrs_old)

        # make a copy of the original entry's attribute dict with all
        # attribute names converted to lowercase
        old = dict([(k.lower(), v) for (k, v) in entry_attrs_old.iteritems()])

        # generate modlist, we don't want any MOD_REPLACE operations
        # to handle simultaneous updates better
        modlist = []
        for (k, v) in entry_attrs.iteritems():
            old_v = set(old.get(k.lower(), []))
            if v is None:
                modlist.append((_ldap.MOD_DELETE, k, list(old_v)))
            else:
                if not isinstance(v, (list, tuple)):
                    v = [v]
                v = set(filter(lambda value: value is not None, v))

                adds = list(v.difference(old_v))
                if adds:
                    modlist.append((_ldap.MOD_ADD, k, adds))
                rems = list(old_v.difference(v))
                if rems:
                    modlist.append((_ldap.MOD_DELETE, k, rems))

        return modlist

    def update_entry(self, dn, entry_attrs):
        """
        Update entry's attributes.

        An attribute value set to None deletes all current values.
        """
        # encode/normalize arguments
        dn = self.normalize_dn(dn)
        dn = self._encode_value(dn)
        entry_attrs_copy = dict(entry_attrs)
        self._encode_entry_attrs(entry_attrs_copy)

        # generate modlist
        modlist = self._generate_modlist(dn, entry_attrs_copy)
        if not modlist:
            raise errors2.EmptyModlist()

        # pass arguments to python-ldap
        try:
            self.conn.modify_s(dn, modlist)
        except _ldap.LDAPError, e:
            _handle_errors(e, **{})

    def delete_entry(self, dn):
        """Delete entry."""
        # encode/normalize arguments
        dn = self.normalize_dn(dn)
        dn = self._encode_value(dn)

        # pass arguments to python-ldap
        try:
            self.conn.delete_s(dn)
        except _ldap.LDAPError, e:
            _handle_errors(e, **{})

    def modify_password(self, dn, old_pass, new_pass):
        """Set user password."""
        # encode/normalize arguments
        dn = self.normalize_dn(dn)
        dn = self._encode_value(dn)
        old_pass = self._encode_value(old_pass)
        new_pass = self._encode_value(new_pass)

        # pass arguments to python-ldap
        try:
            self.passwd_s(dn, odl_pass, new_pass)
        except _ldap.LDAPError, e:
            _handle_errors(e, **{})

    def add_entry_to_group(self, dn, group_dn, member_attr='member'):
        """Add entry to group."""
        # encode/normalize arguments
        dn = self.normalize_dn(dn)
        group_dn = self.normalize_dn(group_dn)
        # check if we're not trying to add group into itself
        if dn == group_dn:
            raise errors2.SameGroupError()
        # check if the entry exists
        (dn, entry_attrs) = self.get_entry(dn, ['objectClass'])

        # get group entry
        (group_dn, group_entry_attrs) = self.get_entry(group_dn)

        # add dn to group entry's `member_attr` attribute
        members = group_entry_attrs.get(member_attr, [])
        members.append(dn)
        group_entry_attrs[member_attr] = members

        # update group entry
        try:
            self.update_entry(group_dn, group_entry_attrs)
        except errors2.EmptyModlist:
            raise errors2.AlreadyGroupMember()

    def remove_entry_from_group(self, dn, group_dn, member_attr='member'):
        """Remove entry from group."""
        # encode/normalize arguments
        dn = self.normalize_dn(dn)

        # get group entry
        (group_dn, group_entry_attrs) = self.get_entry(group_dn)

        # remove dn from group entry's `member_attr` attribute
        members = group_entry_attrs.get(member_attr, [])
        try:
            members.remove(dn)
        except ValueError:
            raise errors2.NotGroupMember()
        group_entry_attrs[member_attr] = members

        # update group entry
        self.update_entry(group_dn, group_entry_attrs)

    def set_entry_active(self, dn, active):
        """Mark entry active/inactive."""
        assert isinstance(active, bool)
        # get the entry in question
        (dn, entry_attrs) = self.get_entry(dn, ['nsAccountLock', 'memberOf'])

        # check nsAccountLock attribute
        account_lock_attr = entry_attrs.get('nsAccountLock', ['false'])
        account_lock_attr = account_lock_attr[0].lower()
        if active:
            if account_lock_attr == 'false':
                raise errors2.AlreadyActive()
        else:
            if account_lock_attr == 'true':
                raise errors2.AlreadyInactive()

        # check if nsAccountLock attribute is in the entry itself
        is_member = False
        member_of_attr = entry_attrs.get('memberOf', [])
        for m in member_of_attr:
            if m.find('cn=activated') >= 0 or m.find('cn=inactivated') >=0:
                is_member = True
                break
        if not is_member and entry_attrs.has_key('nsAccountLock'):
            raise errors2.HasNSAccountLock()

        activated_filter = '(cn=activated)'
        inactivated_filter = '(cn=inactivated)'
        parent_rdn = self.get_container_rdn('accounts')

        # try to remove the entry from activated/inactivated group
        if active:
            entries = self.find_entries(inactivated_filter, [], parent_rdn)
        else:
            entries = self.find_entries(activated_filter, [], parent_rdn)
        (group_dn, group_entry_attrs) = entries[0]
        try:
            self.remove_entry_from_group(dn, group_dn)
        except errors2.NotGroupMember:
            pass

        # add the entry to the activated/inactivated group if necessary
        if active:
            (dn, entry_attrs) = self.get_entry(dn, ['nsAccountLock'])

            # check if we still need to add entry to the activated group
            account_lock_attr = entry_attrs.get('nsAccountLock', ['false'])
            account_lock_attr = account_lock_attr[0].lower()
            if account_lock_attr == 'false':
                return  # we don't

            entries = self.find_entries(activated_filter, [], parent_rdn)
        else:
            entries = self.find_entries(inactivated_filter, [], parent_rdn)
        (group_dn, group_entry_attrs) = entries[0]
        try:
            self.add_entry_to_group(dn, group_dn)
        except errors2.EmptyModlist:
            if active:
                raise errors2.AlreadyActive()
            else:
                raise errors2.AlreadyInactive()

    def activate_entry(self, dn):
        """Mark entry active."""
        self.set_entry_active(dn, True)

    def deactivate_entry(self, dn):
        """Mark entry inactive."""
        self.set_entry_active(dn, False)

    # CrudBackend methods

    def _get_normalized_entry_for_crud(self, dn, attrs_list=None):
        (dn, entry_attrs) = self.get_entry(dn, attrs_list)
        entry_attrs['dn'] = [dn]
        return entry_attrs

    def create(self, **kw):
        """
        Create a new entry and return it as one dict (DN included).

        Extends CrudBackend.create.
        """
        assert 'dn' in kw
        dn = kw['dn']
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
        base_dn = kw.pop('base_dn', '')
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
        entries = self.find_entries(filter, attrs_list, base_dn, scope)
        for (dn, entry_attrs) in entries:
            entry_attrs['dn'] = [dn]
            output.append(entry_attrs)

        return output

api.register(ldap2)

