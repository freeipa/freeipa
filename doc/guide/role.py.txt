from ipalib.plugins.baseldap import *
from ipalib import api, Str, _, ngettext
from ipalib import Command
from ipalib.plugins import privilege

class role(LDAPObject):
    """
    Role object.
    """
    container_dn = api.env.container_rolegroup
    object_name = _('role')
    object_name_plural = _('roles')
    object_class = ['groupofnames', 'nestedgroup']
    default_attributes = ['cn', 'description', 'member', 'memberof',
        'memberindirect', 'memberofindirect',
    ]
    attribute_members = {
        'member': ['user', 'group', 'host', 'hostgroup'],
        'memberof': ['privilege'],
    }
    reverse_members = {
        'member': ['privilege'],
    }
    rdnattr='cn'

    label = _('Roles')
    label_singular = _('Role')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Role name'),
            primary_key=True,
        ),
        Str('description',
            cli_name='desc',
            label=_('Description'),
            doc=_('A description of this role-group'),
        ),
    )

api.register(role)


class role_add(LDAPCreate):
    __doc__ = _('Add a new role.')

    msg_summary = _('Added role "%(value)s"')

api.register(role_add)


class role_del(LDAPDelete):
    __doc__ = _('Delete a role.')

    msg_summary = _('Deleted role "%(value)s"')

api.register(role_del)


class role_mod(LDAPUpdate):
    __doc__ = _('Modify a role.')

    msg_summary = _('Modified role "%(value)s"')

api.register(role_mod)


class role_find(LDAPSearch):
    __doc__ = _('Search for roles.')

    msg_summary = ngettext(
        '%(count)d role matched', '%(count)d roles matched', 0
    )

api.register(role_find)


class role_show(LDAPRetrieve):
    __doc__ = _('Display information about a role.')

api.register(role_show)


class role_add_member(LDAPAddMember):
    __doc__ = _('Add members to a role.')

api.register(role_add_member)


class role_remove_member(LDAPRemoveMember):
    __doc__ = _('Remove members from a role.')

api.register(role_remove_member)


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

api.register(role_add_privilege)


class role_remove_privilege(LDAPRemoveReverseMember):
    __doc__ = _('Remove privileges from a role.')

    show_command = 'role_show'
    member_command = 'privilege_remove_member'
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
            doc=_('Number of privileges removed'),
        ),
    )

api.register(role_remove_privilege)
