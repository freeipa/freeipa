# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
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

from ipalib.plugable import Registry
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
from ipalib import api, Str, _, ngettext
from ipalib import output

__doc__ = _("""
Roles

A role is used for fine-grained delegation. A permission grants the ability
to perform given low-level tasks (add a user, modify a group, etc.). A
privilege combines one or more permissions into a higher-level abstraction
such as useradmin. A useradmin would be able to add, delete and modify users.

Privileges are assigned to Roles.

Users, groups, hosts and hostgroups may be members of a Role.

Roles can not contain other roles.

EXAMPLES:

 Add a new role:
   ipa role-add --desc="Junior-level admin" junioradmin

 Add some privileges to this role:
   ipa role-add-privilege --privileges=addusers junioradmin
   ipa role-add-privilege --privileges=change_password junioradmin
   ipa role-add-privilege --privileges=add_user_to_default_group junioradmin

 Add a group of users to this role:
   ipa group-add --desc="User admins" useradmins
   ipa role-add-member --groups=useradmins junioradmin

 Display information about a role:
   ipa role-show junioradmin

 The result of this is that any users in the group 'junioradmin' can
 add users, reset passwords or add a user to the default IPA user group.
""")

register = Registry()

@register()
class role(LDAPObject):
    """
    Role object.
    """
    container_dn = api.env.container_rolegroup
    object_name = _('role')
    object_name_plural = _('roles')
    object_class = ['groupofnames', 'nestedgroup']
    permission_filter_objectclasses = ['groupofnames']
    default_attributes = ['cn', 'description', 'member', 'memberof']
    # Role could have a lot of indirect members, but they are not in
    # attribute_members therefore they don't have to be in default_attributes
    # 'memberindirect', 'memberofindirect',

    attribute_members = {
        'member': ['user', 'group', 'host', 'hostgroup', 'service'],
        'memberof': ['privilege'],
    }
    reverse_members = {
        'member': ['privilege'],
    }
    allow_rename = True
    managed_permissions = {
        'System: Read Roles': {
            'replaces_global_anonymous_aci': True,
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'businesscategory', 'cn', 'description', 'member', 'memberof',
                'o', 'objectclass', 'ou', 'owner', 'seealso', 'memberuser',
                'memberhost',
            },
            'default_privileges': {'RBAC Readers'},
        },
        'System: Add Roles': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///cn=*,cn=roles,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Add Roles";allow (add) groupdn = "ldap:///cn=Add Roles,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Delegation Administrator'},
        },
        'System: Modify Role Membership': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'member'},
            'replaces': [
                '(targetattr = "member")(target = "ldap:///cn=*,cn=roles,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Modify Role membership";allow (write) groupdn = "ldap:///cn=Modify Role membership,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Delegation Administrator'},
        },
        'System: Modify Roles': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'cn', 'description'},
            'replaces': [
                '(targetattr = "cn || description")(target = "ldap:///cn=*,cn=roles,cn=accounts,$SUFFIX")(version 3.0; acl "permission:Modify Roles";allow (write) groupdn = "ldap:///cn=Modify Roles,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Delegation Administrator'},
        },
        'System: Remove Roles': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///cn=*,cn=roles,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Remove Roles";allow (delete) groupdn = "ldap:///cn=Remove Roles,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Delegation Administrator'},
        },
    }

    label = _('Roles')
    label_singular = _('Role')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Role name'),
            primary_key=True,
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
            doc=_('A description of this role-group'),
        ),
    )



@register()
class role_add(LDAPCreate):
    __doc__ = _('Add a new role.')

    msg_summary = _('Added role "%(value)s"')



@register()
class role_del(LDAPDelete):
    __doc__ = _('Delete a role.')

    msg_summary = _('Deleted role "%(value)s"')



@register()
class role_mod(LDAPUpdate):
    __doc__ = _('Modify a role.')

    msg_summary = _('Modified role "%(value)s"')



@register()
class role_find(LDAPSearch):
    __doc__ = _('Search for roles.')

    msg_summary = ngettext(
        '%(count)d role matched', '%(count)d roles matched', 0
    )



@register()
class role_show(LDAPRetrieve):
    __doc__ = _('Display information about a role.')



@register()
class role_add_member(LDAPAddMember):
    __doc__ = _('Add members to a role.')



@register()
class role_remove_member(LDAPRemoveMember):
    __doc__ = _('Remove members from a role.')



@register()
class role_add_privilege(LDAPAddReverseMember):
    __doc__ = _('Add privileges to a role.')

    show_command = 'role_show'
    member_command = 'privilege_add_member'
    reverse_attr = 'privilege'
    member_attr = 'role'

    has_output = (
        output.Entry('result'),
        output.Output('failed',
            type=dict,
            doc=_('Members that could not be added'),
        ),
        output.Output('completed',
            type=int,
            doc=_('Number of privileges added'),
        ),
    )



@register()
class role_remove_privilege(LDAPRemoveReverseMember):
    __doc__ = _('Remove privileges from a role.')

    show_command = 'role_show'
    member_command = 'privilege_remove_member'
    reverse_attr = 'privilege'
    member_attr = 'role'

    has_output = (
        output.Entry('result'),
        output.Output(
            'failed',
            type=dict,
            doc=_('Members that could not be added'),
        ),
        output.Output(
            'completed',
            type=int,
            doc=_('Number of privileges removed'),
        ),
    )
