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
import re
import pwd

import krbV
import ldap as _ldap

from ipapython.dn import DN
from ipaserver.ipaldap import SASL_GSSAPI, IPASimpleLDAPObject, LDAPClient


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


class ldap2(LDAPClient, CrudBackend):
    """
    LDAP Backend Take 2.
    """

    def __init__(self, shared_instance=True, ldap_uri=None, base_dn=None,
                 schema=None):
        try:
            ldap_uri = ldap_uri or api.env.ldap_uri
        except AttributeError:
            ldap_uri = 'ldap://example.com'

        CrudBackend.__init__(self, shared_instance=shared_instance)
        LDAPClient.__init__(self, ldap_uri)

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

    def get_api(self):
        return api

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

        with self.error_handler():
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
                conn.sasl_interactive_bind_s(None, SASL_GSSAPI)
                setattr(context, 'principal', principal)
            else:
                # no kerberos ccache, use simple bind or external sasl
                if autobind:
                    pent = pwd.getpwuid(os.geteuid())
                    auth_tokens = _ldap.sasl.external(pent.pw_name)
                    conn.sasl_interactive_bind_s(None, auth_tokens)
                else:
                    conn.simple_bind_s(bind_dn, bind_pw)

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

        Note: ldap2 methods normalize DNs internally, but relying on this is
            not recommended.
        """

        assert isinstance(dn, DN)

        if not dn.endswith(self.base_dn):
            # DN's are mutable, don't use in-place addtion (+=) which would
            # modify the dn passed in with unintended side-effects. Addition
            # returns a new DN object which is the concatenation of the two.
            dn = dn + self.base_dn

        return dn

    config_defaults = {'ipasearchtimelimit': [2], 'ipasearchrecordslimit': [0]}
    def get_ipa_config(self, attrs_list=None):
        """Returns the IPA configuration entry (dn, entry_attrs)."""

        odn = api.Object.config.get_dn()
        assert isinstance(odn, DN)
        assert isinstance(api.env.basedn, DN)
        cdn = DN(odn, api.env.basedn)

        try:
            config_entry = getattr(context, 'config_entry')
            return copy.deepcopy(config_entry)
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
            config_entry = entry[0]
        except errors.NotFound:
            config_entry = {}
        for a in self.config_defaults:
            if a not in config_entry:
                config_entry[a] = self.config_defaults[a]
        context.config_entry = copy.deepcopy(config_entry)
        return config_entry

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

    def modify_password(self, dn, new_pass, old_pass=''):
        """Set user password."""

        assert isinstance(dn, DN)
        dn = self.normalize_dn(dn)

        # The python-ldap passwd command doesn't verify the old password
        # so we'll do a simple bind to validate it.
        if old_pass != '':
            with self.error_handler():
                conn = IPASimpleLDAPObject(
                    self.ldap_uri, force_schema_updates=False)
                conn.simple_bind_s(dn, old_pass)
                conn.unbind()

        with self.error_handler():
            self.conn.passwd_s(dn, old_pass, new_pass)

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

        with self.error_handler():
            self.conn.modify_s(dn, mod)

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
