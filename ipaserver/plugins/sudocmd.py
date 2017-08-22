# Authors:
#   Jr Aquino <jr.aquino@citrixonline.com>
#
# Copyright (C) 2010  Red Hat
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

from ipalib import api, errors
from ipalib import Str
from ipalib.plugable import Registry
from .baseldap import (
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPUpdate,
    LDAPSearch,
    LDAPRetrieve)
from ipalib import _, ngettext
from ipapython.dn import DN

__doc__ = _("""
Sudo Commands

Commands used as building blocks for sudo

EXAMPLES:

 Create a new command
   ipa sudocmd-add --desc='For reading log files' /usr/bin/less

 Remove a command
   ipa sudocmd-del /usr/bin/less

""")

register = Registry()

topic = 'sudo'

@register()
class sudocmd(LDAPObject):
    """
    Sudo Command object.
    """
    container_dn = api.env.container_sudocmd
    object_name = _('sudo command')
    object_name_plural = _('sudo commands')
    object_class = ['ipaobject', 'ipasudocmd']
    permission_filter_objectclasses = ['ipasudocmd']
    # object_class_config = 'ipahostobjectclasses'
    search_attributes = [
        'sudocmd', 'description',
    ]
    default_attributes = [
        'sudocmd', 'description', 'memberof',
    ]
    attribute_members = {
        'memberof': ['sudocmdgroup'],
    }
    uuid_attribute = 'ipauniqueid'
    rdn_attribute = 'ipauniqueid'
    managed_permissions = {
        'System: Read Sudo Commands': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'description', 'ipauniqueid', 'memberof', 'objectclass',
                'sudocmd',
            },
        },
        'System: Add Sudo Command': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///sudocmd=*,cn=sudocmds,cn=sudo,$SUFFIX")(version 3.0;acl "permission:Add Sudo command";allow (add) groupdn = "ldap:///cn=Add Sudo command,cn=permissions,cn=pbac,$SUFFIX";)',
                '(targetfilter = "(objectclass=ipasudocmd)")(target = "ldap:///cn=sudocmds,cn=sudo,$SUFFIX")(version 3.0;acl "permission:Add Sudo command";allow (add) groupdn = "ldap:///cn=Add Sudo command,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Sudo Administrator'},
        },
        'System: Delete Sudo Command': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///sudocmd=*,cn=sudocmds,cn=sudo,$SUFFIX")(version 3.0;acl "permission:Delete Sudo command";allow (delete) groupdn = "ldap:///cn=Delete Sudo command,cn=permissions,cn=pbac,$SUFFIX";)',
                '(targetfilter = "(objectclass=ipasudocmd)")(target = "ldap:///cn=sudocmds,cn=sudo,$SUFFIX")(version 3.0;acl "permission:Delete Sudo command";allow (delete) groupdn = "ldap:///cn=Delete Sudo command,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Sudo Administrator'},
        },
        'System: Modify Sudo Command': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'description'},
            'replaces': [
                '(targetattr = "description")(target = "ldap:///sudocmd=*,cn=sudocmds,cn=sudo,$SUFFIX")(version 3.0;acl "permission:Modify Sudo command";allow (write) groupdn = "ldap:///cn=Modify Sudo command,cn=permissions,cn=pbac,$SUFFIX";)',
                '(targetfilter = "(objectclass=ipasudocmd)")(targetattr = "description")(target = "ldap:///cn=sudocmds,cn=sudo,$SUFFIX")(version 3.0;acl "permission:Modify Sudo command";allow (write) groupdn = "ldap:///cn=Modify Sudo command,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Sudo Administrator'},
        },
    }

    label = _('Sudo Commands')
    label_singular = _('Sudo Command')

    takes_params = (
        Str('sudocmd',
            cli_name='command',
            label=_('Sudo Command'),
            primary_key=True,
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
            doc=_('A description of this command'),
        ),
    )

    def get_dn(self, *keys, **options):
        if keys[-1].endswith('.'):
            keys = (keys[:-1] + (keys[-1][:-1], ))
        dn = super(sudocmd, self).get_dn(*keys, **options)
        try:
            self.backend.get_entry(dn, [''])
        except errors.NotFound:
            try:
                entry_attrs = self.backend.find_entry_by_attr(
                    'sudocmd', keys[-1], self.object_class, [''],
                    DN(self.container_dn, api.env.basedn))
                dn = entry_attrs.dn
            except errors.NotFound:
                pass
        return dn


@register()
class sudocmd_add(LDAPCreate):
    __doc__ = _('Create new Sudo Command.')

    msg_summary = _('Added Sudo Command "%(value)s"')


@register()
class sudocmd_del(LDAPDelete):
    __doc__ = _('Delete Sudo Command.')

    msg_summary = _('Deleted Sudo Command "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        filters = [
            ldap.make_filter_from_attr(attr, dn)
            for attr in ('memberallowcmd', 'memberdenycmd')]
        filter = ldap.combine_filters(filters, ldap.MATCH_ANY)
        filter = ldap.combine_filters(
            (filter, ldap.make_filter_from_attr('objectClass', 'ipasudorule')),
            ldap.MATCH_ALL)
        dependent_sudorules = []
        try:
            entries, _truncated = ldap.find_entries(
                filter, ['cn'],
                base_dn=DN(api.env.container_sudorule, api.env.basedn))
        except errors.NotFound:
            pass
        else:
            for entry_attrs in entries:
                [cn] = entry_attrs['cn']
                dependent_sudorules.append(cn)

        if dependent_sudorules:
            raise errors.DependentEntry(
                key=keys[0], label='sudorule',
                dependent=', '.join(dependent_sudorules))
        return dn


@register()
class sudocmd_mod(LDAPUpdate):
    __doc__ = _('Modify Sudo Command.')

    msg_summary = _('Modified Sudo Command "%(value)s"')


@register()
class sudocmd_find(LDAPSearch):
    __doc__ = _('Search for Sudo Commands.')

    msg_summary = ngettext(
        '%(count)d Sudo Command matched', '%(count)d Sudo Commands matched', 0
    )


@register()
class sudocmd_show(LDAPRetrieve):
    __doc__ = _('Display Sudo Command.')
