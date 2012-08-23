# Authors:
#     Sumit Bose <sbose@redhat.com>
#
# Copyright (C) 2012  Red Hat
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

from ipalib.plugins.baseldap import *
from ipalib import api, Str, Password, DefaultFrom, _, ngettext, Object
from ipalib.parameters import Enum
from ipalib import Command
from ipalib import errors
from ipapython import ipautil
from ipalib import util
from ipapython.dn import DN


__doc__ = _("""
Manage ID ranges
""")

class idrange(LDAPObject):
    """
    Range object.
    """

    range_type = ('domain', 'ad', 'ipa')
    container_dn = api.env.container_ranges
    object_name = ('range')
    object_name_plural = ('ranges')
    object_class = ['ipaIDrange']
    possible_objectclasses = ['ipadomainidrange', 'ipatrustedaddomainrange']
    default_attributes = ['cn', 'ipabaseid', 'ipaidrangesize', 'ipabaserid',
                          'ipasecondarybaserid', 'ipanttrusteddomainsid',
                          'iparangetype']

    label = _('ID Ranges')
    label_singular = _('ID Range')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Range name'),
            primary_key=True,
        ),
        Int('ipabaseid',
            cli_name='base_id',
            label=_("First Posix ID of the range"),
        ),
        Int('ipaidrangesize',
            cli_name='range_size',
            label=_("Number of IDs in the range"),
        ),
        Int('ipabaserid',
            cli_name='rid_base',
            label=_('First RID of the corresponding RID range'),
        ),
        Int('ipasecondarybaserid?',
            cli_name='secondary_rid_base',
            label=_('First RID of the secondary RID range'),
        ),
        Str('ipanttrusteddomainsid?',
            cli_name='dom_sid',
            label=_('Domain SID of the trusted domain'),
        ),
        Str('iparangetype?',
            label=_('Range type'),
            flags=['no_option'],
        )
    )

    def handle_iparangetype(self, entry_attrs, options, keep_objectclass=False):
        if not options.get('pkey_only', False):
            if 'ipatrustedaddomainrange' in entry_attrs.get('objectclass', []):
                entry_attrs['iparangetype'] = [unicode(_('Active Directory domain range'))]
            else:
                entry_attrs['iparangetype'] = [unicode(_(u'local domain range'))]
        if not keep_objectclass:
            if not options.get('all', False) or options.get('pkey_only', False):
                entry_attrs.pop('objectclass', None)

    def check_ids_in_modified_range(self, old_base, old_size, new_base, new_size):
        if new_base is None and new_size is None:
            # nothing to check
            return
        if new_base is None:
            new_base = old_base
        if new_size is None:
            new_size = old_size
        old_interval = (old_base, old_base + old_size - 1)
        new_interval = (new_base, new_base + new_size - 1)
        checked_intervals = []
        low_diff = new_interval[0] - old_interval[0]
        if low_diff > 0:
            checked_intervals.append(
                    (old_interval[0], min(old_interval[1], new_interval[0] - 1)))
        high_diff = old_interval[1] - new_interval[1]
        if high_diff > 0:
            checked_intervals.append(
                    (max(old_interval[0], new_interval[1] + 1), old_interval[1]))

        if not checked_intervals:
            # range is equal or covers the entire old range, nothing to check
            return

        ldap = self.backend
        id_filter_base = ["(objectclass=posixAccount)",
                          "(objectclass=posixGroup)",
                          "(objectclass=ipaIDObject)"]
        id_filter_ids = []

        for id_low, id_high in checked_intervals:
            id_filter_ids.append("(&(uidNumber>=%(low)d)(uidNumber<=%(high)d))"
                                 % dict(low=id_low, high=id_high))
            id_filter_ids.append("(&(gidNumber>=%(low)d)(gidNumber<=%(high)d))"
                                 % dict(low=id_low, high=id_high))
        id_filter = ldap.combine_filters(
                        [ldap.combine_filters(id_filter_base, "|"),
                          ldap.combine_filters(id_filter_ids, "|")],
                        "&")

        try:
            (objects, truncated) = ldap.find_entries(filter=id_filter,
                    attrs_list=['uid', 'cn'],
                    base_dn=DN(api.env.container_accounts, api.env.basedn))
        except errors.NotFound:
            # no objects in this range found, allow the command
            pass
        else:
            raise errors.ValidationError(name="ipabaseid,ipaidrangesize",
                    error=_('range modification leaving objects with ID out '
                            'of the defined range is not allowed'))

class idrange_add(LDAPCreate):
    __doc__ = _('Add new ID range.')

    msg_summary = _('Added ID range "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        if ('ipanttrusteddomainsid' not in options and
            'ipasecondarybaserid' not in options):
            raise errors.ValidationError(name=_('Range setup'),
                error=_('Ranges for local domain ' \
                         'must have a secondary RID base'))

        if 'ipanttrusteddomainsid' in options:
            entry_attrs['objectclass'].append('ipatrustedaddomainrange')
        else:
            entry_attrs['objectclass'].append('ipadomainidrange')

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.handle_iparangetype(entry_attrs, options, keep_objectclass=True)
        return dn

class idrange_del(LDAPDelete):
    __doc__ = _('Delete an ID range.')

    msg_summary = _('Deleted ID range "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        try:
            (old_dn, old_attrs) = ldap.get_entry(dn, ['ipabaseid', 'ipaidrangesize'])
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        old_base_id = int(old_attrs.get('ipabaseid', [0])[0])
        old_range_size = int(old_attrs.get('ipaidrangesize', [0])[0])
        self.obj.check_ids_in_modified_range(
                old_base_id, old_range_size, 0, 0)
        return dn

class idrange_find(LDAPSearch):
    __doc__ = _('Search for ranges.')

    msg_summary = ngettext(
        '%(count)d range matched', '%(count)d ranges matched', 0
    )

    # Since all range types are stored within separate containers under
    # 'cn=ranges,cn=etc' search can be done on a one-level scope
    def pre_callback(self, ldap, filters, attrs_list, base_dn, scope, *args, **options):
        assert isinstance(base_dn, DN)
        attrs_list.append('objectclass')
        return (filters, base_dn, ldap.SCOPE_ONELEVEL)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        for dn,entry in entries:
            self.obj.handle_iparangetype(entry, options)
        return truncated

class idrange_show(LDAPRetrieve):
    __doc__ = _('Display information about a range.')

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        attrs_list.append('objectclass')
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.handle_iparangetype(entry_attrs, options)
        return dn

class idrange_mod(LDAPUpdate):
    __doc__ = _('Modify ID range.')

    msg_summary = _('Modified ID range "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        attrs_list.append('objectclass')

        try:
            (old_dn, old_attrs) = ldap.get_entry(dn, ['ipabaseid', 'ipaidrangesize'])
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        old_base_id = int(old_attrs.get('ipabaseid', [0])[0])
        old_range_size = int(old_attrs.get('ipaidrangesize', [0])[0])
        new_base_id = entry_attrs.get('ipabaseid')
        if new_base_id is not None:
            new_base_id = int(new_base_id)
        new_range_size = entry_attrs.get('ipaidrangesize')
        if new_range_size is not None:
            new_range_size = int(new_range_size)
        self.obj.check_ids_in_modified_range(old_base_id, old_range_size,
                                             new_base_id, new_range_size)

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.handle_iparangetype(entry_attrs, options)
        return dn

api.register(idrange)
api.register(idrange_add)
api.register(idrange_mod)
api.register(idrange_del)
api.register(idrange_find)
api.register(idrange_show)
