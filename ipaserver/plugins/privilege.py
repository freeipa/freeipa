# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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

from .baseldap import (
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPUpdate,
    LDAPSearch,
    LDAPRetrieve,
    LDAPAddMember,
    LDAPRemoveMember,
    LDAPAddReverseMember,
    LDAPRemoveReverseMember)
from ipalib import api, _, ngettext, errors
from ipalib.plugable import Registry
from ipalib import Str
from ipalib import output
from ipapython.dn import DN

__doc__ = _("""
Privileges

A privilege combines permissions into a logical task. A permission provides
the rights to do a single task. There are some IPA operations that require
multiple permissions to succeed. A privilege is where permissions are
combined in order to perform a specific task.

For example, adding a user requires the following permissions:
 * Creating a new user entry
 * Resetting a user password
 * Adding the new user to the default IPA users group

Combining these three low-level tasks into a higher level task in the
form of a privilege named "Add User" makes it easier to manage Roles.

A privilege may not contain other privileges.

See role and permission for additional information.
""")

register = Registry()


def validate_permission_to_privilege(api, permission):
    ldap = api.Backend.ldap2
    ldapfilter = ldap.combine_filters(rules='&', filters=[
        '(objectClass=ipaPermissionV2)', '(!(ipaPermBindRuleType=permission))',
        ldap.make_filter_from_attr('cn', permission, rules='|')])
    try:
        entries, _truncated = ldap.find_entries(
            filter=ldapfilter,
            attrs_list=['cn', 'ipapermbindruletype'],
            base_dn=DN(api.env.container_permission, api.env.basedn),
            size_limit=1)
    except errors.NotFound:
        pass
    else:
        entry = entries[0]
        message = _('cannot add permission "%(perm)s" with bindtype '
                    '"%(bindtype)s" to a privilege')
        raise errors.ValidationError(
            name='permission',
            error=message % {
                'perm': entry.single_value['cn'],
                'bindtype': entry.single_value.get(
                    'ipapermbindruletype', 'permission')})


@register()
class privilege(LDAPObject):
    """
    Privilege object.
    """
    container_dn = api.env.container_privilege
    object_name = _('privilege')
    object_name_plural = _('privileges')
    object_class = ['nestedgroup', 'groupofnames']
    permission_filter_objectclasses = ['groupofnames']
    default_attributes = ['cn', 'description', 'member', 'memberof']
    attribute_members = {
        'member': ['role'],
        'memberof': ['permission'],
    }
    reverse_members = {
        'member': ['permission'],
    }
    allow_rename = True
    managed_permissions = {
        'System: Read Privileges': {
            'replaces_global_anonymous_aci': True,
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'businesscategory', 'cn', 'description', 'member', 'memberof',
                'o', 'objectclass', 'ou', 'owner', 'seealso', 'memberuser',
                'memberhost',
            },
            'default_privileges': {'RBAC Readers'},
        },
        'System: Add Privileges': {
            'ipapermright': {'add'},
            'default_privileges': {'Delegation Administrator'},
        },
        'System: Modify Privileges': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'businesscategory',  'cn', 'description', 'o', 'ou', 'owner',
                'seealso',
            },
            'default_privileges': {'Delegation Administrator'},
        },
        'System: Remove Privileges': {
            'ipapermright': {'delete'},
            'default_privileges': {'Delegation Administrator'},
        },
    }

    label = _('Privileges')
    label_singular = _('Privilege')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Privilege name'),
            primary_key=True,
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
            doc=_('Privilege description'),
        ),
    )


@register()
class privilege_add(LDAPCreate):
    __doc__ = _('Add a new privilege.')

    msg_summary = _('Added privilege "%(value)s"')


@register()
class privilege_del(LDAPDelete):
    __doc__ = _('Delete a privilege.')

    msg_summary = _('Deleted privilege "%(value)s"')


@register()
class privilege_mod(LDAPUpdate):
    __doc__ = _('Modify a privilege.')

    msg_summary = _('Modified privilege "%(value)s"')


@register()
class privilege_find(LDAPSearch):
    __doc__ = _('Search for privileges.')

    msg_summary = ngettext(
        '%(count)d privilege matched', '%(count)d privileges matched', 0
    )


@register()
class privilege_show(LDAPRetrieve):
    __doc__ = _('Display information about a privilege.')


@register()
class privilege_add_member(LDAPAddMember):
    __doc__ = _('Add members to a privilege.')

    NO_CLI=True


@register()
class privilege_remove_member(LDAPRemoveMember):
    __doc__ = _('Remove members from a privilege')
    NO_CLI=True


@register()
class privilege_add_permission(LDAPAddReverseMember):
    __doc__ = _('Add permissions to a privilege.')

    show_command = 'privilege_show'
    member_command = 'permission_add_member'
    reverse_attr = 'permission'
    member_attr = 'privilege'

    has_output = (
        output.Entry('result'),
        output.Output('failed',
            type=dict,
            doc=_('Members that could not be added'),
        ),
        output.Output('completed',
            type=int,
            doc=_('Number of permissions added'),
        ),
    )

    def pre_callback(self, ldap, dn, *keys, **options):
        if options.get('permission'):
            # We can only add permissions with bind rule type set to
            # "permission" (or old-style permissions)
            validate_permission_to_privilege(self.api, options['permission'])
        return dn


@register()
class privilege_remove_permission(LDAPRemoveReverseMember):
    __doc__ = _('Remove permissions from a privilege.')

    show_command = 'privilege_show'
    member_command = 'permission_remove_member'
    reverse_attr = 'permission'
    member_attr = 'privilege'

    permission_count_out = ('%i permission removed.', '%i permissions removed.')

    has_output = (
        output.Entry('result'),
        output.Output('failed',
            type=dict,
            doc=_('Members that could not be added'),
        ),
        output.Output(
            'completed',
            type=int,
            doc=_('Number of permissions removed'),
        ),
    )
