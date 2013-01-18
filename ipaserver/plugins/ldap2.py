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
import time
import re
import pwd

import krbV
import ldap as _ldap
import ldap.filter as _ldap_filter

from ipapython.dn import DN, RDN
from ipaserver.ipaldap import (
    SASL_AUTH, unicode_from_utf8, value_to_utf8, IPASimpleLDAPObject,
    LDAPConnection)


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

from ipalib import api, errors
from ipalib.crud import CrudBackend
from ipalib.request import context

# Group Member types
MEMBERS_ALL = 0
MEMBERS_DIRECT = 1
MEMBERS_INDIRECT = 2


class ldap2(LDAPConnection, CrudBackend):
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
        try:
            ldap_uri = ldap_uri or api.env.ldap_uri
        except AttributeError:
            ldap_uri = 'ldap://example.com'

        CrudBackend.__init__(self, shared_instance=shared_instance)
        LDAPConnection.__init__(self, ldap_uri)

        try:
            if base_dn is not None:
                self.base_dn = DN(base_dn)
            else:
                self.base_dn = DN(api.env.basedn)
        except AttributeError:
            self.base_dn = DN()

    def _init_connection(self):
        # Connectible.conn is a proxy to thread-local storage;
        # do not set it
        pass

    def __del__(self):
        if self.isconnected():
            self.disconnect()

    def __str__(self):
        return self.ldap_uri

    def create_connection(self, ccache=None, bind_dn=None, bind_pw='',
            tls_cacertfile=None, tls_certfile=None, tls_keyfile=None,
            debug_level=0, autobind=False):
        """
        Connect to LDAP server.

        Keyword arguments:
        ldapuri -- the LDAP server to connect to
        ccache -- Kerberos V5 ccache object or name
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
            force_updates = api.env.context in ('installer', 'updates')
            conn = IPASimpleLDAPObject(
                self.ldap_uri, force_schema_updates=force_updates)
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
                if isinstance(ccache, krbV.CCache):
                    principal = ccache.principal().name
                    # Get a fully qualified CCACHE name (schema+name)
                    # As we do not use the krbV.CCache object later,
                    # we can safely overwrite it
                    ccache = "%(type)s:%(name)s" % dict(type=ccache.type,
                                                        name=ccache.name)
                else:
                    principal = krbV.CCache(name=ccache,
                        context=krbV.default_context()).principal().name

                os.environ['KRB5CCNAME'] = ccache
                conn.sasl_interactive_bind_s(None, SASL_AUTH)
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

                # FIXME: Convert all values to either unicode, DN or str
                # before detecting value changes (see IPASimpleLDAPObject for
                # supported types).
                # This conversion will set a common ground for the comparison.
                #
                # This fix can be removed when ticket 2265 is fixed and our
                # encoded entry_attrs' types will match get_entry result
                try:
                    v = set(unicode_from_utf8(self.conn.encode(value))
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
                conn = IPASimpleLDAPObject(
                    self.ldap_uri, force_schema_updates=False)
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

        self.log.debug(
            "add_entry_to_group: dn=%s group_dn=%s member_attr=%s",
            dn, group_dn, member_attr)
        # check if the entry exists
        (dn, entry_attrs) = self.get_entry(dn, ['objectclass'])

        # get group entry
        (group_dn, group_entry_attrs) = self.get_entry(group_dn, [member_attr])

        self.log.debug(
            "add_entry_to_group: group_entry_attrs=%s", group_entry_attrs)
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

        self.log.debug(
            "remove_entry_from_group: dn=%s group_dn=%s member_attr=%s",
            dn, group_dn, member_attr)
        # get group entry
        (group_dn, group_entry_attrs) = self.get_entry(group_dn, [member_attr])

        self.log.debug(
            "remove_entry_from_group: group_entry_attrs=%s", group_entry_attrs)
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

        self.log.debug(
            "get_members: group_dn=%s members=%s membertype=%s",
            group_dn, members, membertype)
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

        self.log.debug("get_members: result=%s", entries)
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

        self.log.debug(
            "get_memberof: entry_dn=%s memberof=%s", entry_dn, memberof)
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
                self.log.info(
                    'Failed to remove indirect entry %s from %s',
                    r[0], entry_dn)
                raise e

        self.log.debug(
            "get_memberof: result direct=%s indirect=%s", direct, indirect)
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
