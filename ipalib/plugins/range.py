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


__doc__ = _("""
Manage ID ranges
""")

class range(LDAPObject):
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

    label = _('Ranges')
    label_singular = _('Range')

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

class range_add(LDAPCreate):
    __doc__ = _('Add new ID range.')

    msg_summary = _('Added ID range "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
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

class range_del(LDAPDelete):
    __doc__ = _('Delete an ID range.')

    msg_summary = _('Deleted ID range "%(value)s"')

class range_find(LDAPSearch):
    __doc__ = _('Search for ranges.')

    msg_summary = ngettext(
        '%(count)d range matched', '%(count)d ranges matched', 0
    )

    # Since all range types are stored within separate containers under
    # 'cn=ranges,cn=etc' search can be done on a one-level scope
    def pre_callback(self, ldap, filters, attrs_list, base_dn, scope, *args, **options):
        return (filters, base_dn, ldap.SCOPE_ONELEVEL)

class range_show(LDAPRetrieve):
    __doc__ = _('Display information about a range.')

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        attrs_list.append('objectclass')
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if 'ipatrustedaddomainrange' in entry_attrs['objectclass']:
            entry_attrs['iparangetype']=(u'Active Directory domain range')
        else:
            entry_attrs['iparangetype']=(u'local domain range')
        del entry_attrs['objectclass']
        return dn

api.register(range)
api.register(range_add)
#api.register(range_mod)
api.register(range_del)
api.register(range_find)
api.register(range_show)

