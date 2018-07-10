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

from __future__ import absolute_import

import logging
import os

import ldap as _ldap

from ipalib import krb_utils
from ipaplatform.paths import paths
from ipapython.dn import DN
from ipapython.ipaldap import (LDAPClient, AUTOBIND_AUTO, AUTOBIND_ENABLED,
                               AUTOBIND_DISABLED)

from ipalib import Registry, errors, _
from ipalib.crud import CrudBackend
from ipalib.request import context

logger = logging.getLogger(__name__)

register = Registry()

_missing = object()


@register()
class ldap2(CrudBackend, LDAPClient):
    """
    LDAP Backend Take 2.
    """

    def __init__(self, api):
        force_schema_updates = api.env.context in ('installer', 'updates')

        CrudBackend.__init__(self, api)
        LDAPClient.__init__(self, None,
                            force_schema_updates=force_schema_updates)

        self._time_limit = float(LDAPClient.time_limit)
        self._size_limit = int(LDAPClient.size_limit)

    @property
    def ldap_uri(self):
        return self.api.env.ldap_uri

    @property
    def time_limit(self):
        if self._time_limit is None:
            return float(self.get_ipa_config().single_value.get(
                'ipasearchtimelimit', 2))
        return self._time_limit

    @time_limit.setter
    def time_limit(self, val):
        if val is not None:
            val = float(val)
        object.__setattr__(self, '_time_limit', val)

    @time_limit.deleter
    def time_limit(self):
        object.__setattr__(self, '_time_limit', int(LDAPClient.size_limit))

    @property
    def size_limit(self):
        if self._size_limit is None:
            return int(self.get_ipa_config().single_value.get(
                'ipasearchrecordslimit', 0))
        return self._size_limit

    @size_limit.setter
    def size_limit(self, val):
        if val is not None:
            val = int(val)
        object.__setattr__(self, '_size_limit', val)

    @size_limit.deleter
    def size_limit(self):
        object.__setattr__(self, '_size_limit', float(LDAPClient.time_limit))

    def _connect(self):
        # Connectible.conn is a proxy to thread-local storage;
        # do not set it
        pass

    def close(self):
        if self.isconnected():
            self.disconnect()

    def __str__(self):
        return self.ldap_uri

    def create_connection(
            self, ccache=None, bind_dn=None, bind_pw='', cacert=None,
            autobind=AUTOBIND_AUTO, serverctrls=None, clientctrls=None,
            time_limit=_missing, size_limit=_missing):
        """
        Connect to LDAP server.

        Keyword arguments:
        ldapuri -- the LDAP server to connect to
        ccache -- Kerberos ccache name
        bind_dn -- dn used to bind to the server
        bind_pw -- password used to bind to the server
        debug_level -- LDAP debug level option
        cacert -- TLS CA certificate filename
        autobind - autobind as the current user
        time_limit, size_limit -- maximum time and size limit for LDAP
            possible options:
                - value - sets the given value
                - None - reads value from ipaconfig
                - _missing - keeps previously configured settings
                             (unlimited set by default in constructor)

        Extends backend.Connectible.create_connection.
        """
        if bind_dn is None:
            bind_dn = DN(('cn', 'directory manager'))
        assert isinstance(bind_dn, DN)

        if cacert is None:
            cacert = paths.IPA_CA_CRT

        if time_limit is not _missing:
            object.__setattr__(self, 'time_limit', time_limit)
        if size_limit is not _missing:
            object.__setattr__(self, 'size_limit', size_limit)

        client = LDAPClient(self.ldap_uri,
                            force_schema_updates=self._force_schema_updates,
                            cacert=cacert)
        conn = client._conn

        with client.error_handler():
            minssf = conn.get_option(_ldap.OPT_X_SASL_SSF_MIN)
            maxssf = conn.get_option(_ldap.OPT_X_SASL_SSF_MAX)
            # Always connect with at least an SSF of 56, confidentiality
            # This also protects us from a broken ldap.conf
            if minssf < 56:
                minssf = 56
                conn.set_option(_ldap.OPT_X_SASL_SSF_MIN, minssf)
                if maxssf < minssf:
                    conn.set_option(_ldap.OPT_X_SASL_SSF_MAX, minssf)

        ldapi = self.ldap_uri.startswith('ldapi://')

        if bind_pw:
            client.simple_bind(bind_dn, bind_pw,
                               server_controls=serverctrls,
                               client_controls=clientctrls)
        elif autobind != AUTOBIND_DISABLED and os.getegid() == 0 and ldapi:
            try:
                client.external_bind(server_controls=serverctrls,
                                     client_controls=clientctrls)
            except errors.NotFound:
                if autobind == AUTOBIND_ENABLED:
                    # autobind was required and failed, raise
                    # exception that it failed
                    raise
        else:
            if ldapi:
                with client.error_handler():
                    conn.set_option(_ldap.OPT_HOST_NAME, self.api.env.host)
            if ccache is None:
                os.environ.pop('KRB5CCNAME', None)
            else:
                os.environ['KRB5CCNAME'] = ccache

            principal = krb_utils.get_principal(ccache_name=ccache)

            client.gssapi_bind(server_controls=serverctrls,
                               client_controls=clientctrls)
            setattr(context, 'principal', principal)

        return conn

    def destroy_connection(self):
        """Disconnect from LDAP server."""
        try:
            if self.conn is not None:
                self.unbind()
        except errors.PublicError:
            # ignore when trying to unbind multiple times
            pass

        object.__delattr__(self, 'time_limit')
        object.__delattr__(self, 'size_limit')

    def get_ipa_config(self, attrs_list=None):
        """Returns the IPA configuration entry (dn, entry_attrs)."""

        dn = self.api.Object.config.get_dn()
        assert isinstance(dn, DN)

        try:
            config_entry = getattr(context, 'config_entry')
            if config_entry.conn.conn is self.conn:
                return config_entry
        except AttributeError:
            # Not in our context yet
            pass
        try:
            # use find_entries here lest we hit an infinite recursion when
            # ldap2.get_entries tries to determine default time/size limits
            (entries, truncated) = self.find_entries(
                None, attrs_list, base_dn=dn, scope=self.SCOPE_BASE,
                time_limit=2, size_limit=10
            )
            self.handle_truncated_result(truncated)
            config_entry = entries[0]
        except errors.NotFound:
            config_entry = self.make_entry(dn)

        context.config_entry = config_entry
        return config_entry

    def has_upg(self):
        """Returns True/False whether User-Private Groups are enabled.

        This is determined based on whether the UPG Definition's originfilter
        contains "(objectclass=disable)".

        If the UPG Definition or its originfilter is not readable,
        an ACI error is raised.
        """

        upg_dn = DN(('cn', 'UPG Definition'), ('cn', 'Definitions'), ('cn', 'Managed Entries'),
                    ('cn', 'etc'), self.api.env.basedn)

        try:
            with self.error_handler():
                upg_entries = self.conn.search_s(str(upg_dn), _ldap.SCOPE_BASE,
                                                 attrlist=['*'])
                upg_entries = self._convert_result(upg_entries)
        except errors.NotFound:
            upg_entries = None
        if not upg_entries or 'originfilter' not in upg_entries[0]:
            raise errors.ACIError(info=_(
                'Could not read UPG Definition originfilter. '
                'Check your permissions.'))
        org_filter = upg_entries[0].single_value['originfilter']
        return '(objectclass=disable)' not in org_filter

    def get_effective_rights(self, dn, attrs_list):
        """Returns the rights the currently bound user has for the given DN.

           Returns 2 attributes, the attributeLevelRights for the given list of
           attributes and the entryLevelRights for the entry itself.
        """
        assert isinstance(dn, DN)
        return self.get_entry(dn, attrs_list, get_effective_rights=True)

    def can_write(self, dn, attr):
        """Returns True/False if the currently bound user has write permissions
           on the attribute. This only operates on a single attribute at a time.
        """

        assert isinstance(dn, DN)

        attrs = self.get_effective_rights(dn, [attr])
        if 'attributelevelrights' in attrs:
            attr_rights = attrs.get('attributelevelrights')[0]
            (attr, rights) = attr_rights.split(':')
            if 'w' in rights:
                return True

        return False

    def can_read(self, dn, attr):
        """Returns True/False if the currently bound user has read permissions
           on the attribute. This only operates on a single attribute at a time.
        """
        assert isinstance(dn, DN)

        attrs = self.get_effective_rights(dn, [attr])
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

        attrs = self.get_effective_rights(dn, ["*"])
        if 'entrylevelrights' in attrs:
            entry_rights = attrs['entrylevelrights'][0]
            if 'd' in entry_rights:
                return True

        return False

    def can_add(self, parent_dn, objectclass):
        """
        Returns True/False if the currently bound user has
        permission to add an entry with the given objectclass
        immediately below the entry with the given DN.

        For example, to check if an entry with objectclass=ipaca
        can be added under cn=cas,cn=ca,{basedn}, you should call
        ``can_add(DN('cn=cas,...'), 'ipaca')``.

        """
        assert isinstance(parent_dn, DN)

        # the rules for how to request the template entry, and
        # the expectations about how 389 constructs the template
        # entry, are described here:
        #
        #   https://pagure.io/389-ds-base/issue/49278#comment-480856
        #
        try:
            entry = self.get_entries(
                parent_dn,
                _ldap.SCOPE_ONELEVEL,
                # rdn value of template entry is: template_<objcls>_objectclass
                '(cn=template_{}_objectclass)'.format(objectclass),
                # request tempalate entry with given objectclass
                ['cn@{}'.format(objectclass)],
                get_effective_rights=True,
            )[0]
            return 'a' in entry['entrylevelrights'][0]
        except errors.NotFound:
            return False

    def modify_password(self, dn, new_pass, old_pass='', otp='', skip_bind=False):
        """Set user password."""

        assert isinstance(dn, DN)

        # The python-ldap passwd command doesn't verify the old password
        # so we'll do a simple bind to validate it.
        if not skip_bind and old_pass != '':
            pw = old_pass
            if (otp):
                pw = old_pass+otp

            with LDAPClient(self.ldap_uri, force_schema_updates=False) as conn:
                conn.simple_bind(dn, pw)
                conn.unbind()

        with self.error_handler():
            old_pass = self.encode(old_pass)
            new_pass = self.encode(new_pass)
            self.conn.passwd_s(str(dn), old_pass, new_pass)

    def add_entry_to_group(self, dn, group_dn, member_attr='member', allow_same=False):
        """
        Add entry designaed by dn to group group_dn in the member attribute
        member_attr.

        Adding a group as a member of itself is not allowed unless allow_same
        is True.
        """

        assert isinstance(dn, DN)
        assert isinstance(group_dn, DN)

        logger.debug(
            "add_entry_to_group: dn=%s group_dn=%s member_attr=%s",
            dn, group_dn, member_attr)

        # check if the entry exists
        entry = self.get_entry(dn, [''])
        dn = entry.dn

        # check if we're not trying to add group into itself
        if dn == group_dn and not allow_same:
            raise errors.SameGroupError()

        # add dn to group entry's `member_attr` attribute
        modlist = [(_ldap.MOD_ADD, member_attr, [dn])]

        # update group entry
        try:
            with self.error_handler():
                modlist = [(a, b, self.encode(c))
                           for a, b, c in modlist]
                self.conn.modify_s(str(group_dn), modlist)
        except errors.DuplicateEntry:
            # TYPE_OR_VALUE_EXISTS
            raise errors.AlreadyGroupMember()

    def remove_entry_from_group(self, dn, group_dn, member_attr='member'):
        """Remove entry from group."""

        assert isinstance(dn, DN)
        assert isinstance(group_dn, DN)

        logger.debug(
            "remove_entry_from_group: dn=%s group_dn=%s member_attr=%s",
            dn, group_dn, member_attr)

        # remove dn from group entry's `member_attr` attribute
        modlist = [(_ldap.MOD_DELETE, member_attr, [dn])]

        # update group entry
        try:
            with self.error_handler():
                modlist = [(a, b, self.encode(c))
                           for a, b, c in modlist]
                self.conn.modify_s(str(group_dn), modlist)
        except errors.MidairCollision:
            raise errors.NotGroupMember()

    def set_entry_active(self, dn, active):
        """Mark entry active/inactive."""

        assert isinstance(dn, DN)
        assert isinstance(active, bool)

        # get the entry in question
        entry_attrs = self.get_entry(dn, ['nsaccountlock'])

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
        self.update_entry(entry_attrs)

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

        # We need to do this directly using the LDAP library because we
        # don't have read access to krbprincipalkey so we need to delete
        # it in the blind.
        mod = [(_ldap.MOD_REPLACE, 'krbprincipalkey', None),
               (_ldap.MOD_REPLACE, 'krblastpwdchange', None)]

        with self.error_handler():
            self.conn.modify_s(str(dn), mod)

    # CrudBackend methods

    def _get_normalized_entry_for_crud(self, dn, attrs_list=None):

        assert isinstance(dn, DN)

        entry_attrs = self.get_entry(dn, attrs_list)
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
        self.add_entry(self.make_entry(dn, kw))
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
        self.update_entry(self.make_entry(primary_key, kw))
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
        for entry_attrs in entries:
            output.append(entry_attrs)

        if truncated:
            return (-1, output)
        return (len(output), output)
