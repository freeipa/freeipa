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
"""
Permissions

A permission enables fine-grained delegation of permissions. Access Control
Rules, or instructions (ACIs), grant permission to permissions to perform
given tasks such as adding a user, modifying a group, etc.

A permission may not be members of other permissions.

* A permissions grants access to read, write, add or delete.
* A privilege combines similar permissions (for example all the permissions
  needed to add a user).
* A role grants a set of privileges to users, groups, hosts or hostgroups.

A permission is made up of a number of different parts:

1. The name of the permission.
2. The description of the permission.
3. The target of the permission.
4. The permissions granted by the permission.

The permissions define what operations are allowed and are one or more of:
1. write - write one or more attributes
2. read - read one or more attributes
3. add - add a new entry to the tree
4. delete - delete an existing entry
5. all - all permissions are granted

Note the distinction between attributes and entries. The permissions are
independent, so being able to add a user does not mean that the user will
be editabe.

There are a number of allowed targets:
1. type: a type of object (user, group, etc).
2. memberof: a memberof a group or hostgroup
3. filter: an LDAP filter
4. subtree: an LDAP filter specifying part of the LDAP DIT
5. targetgroup

EXAMPLES:

 Add a permission that grants the creation of users:
   ipa permission-add --desc="Add a User" --type=user --permissions=add adduser

 Add a permission that grants the ability to manage group membership:
   ipa permission-add --desc='Manage group members' --attrs=member --permissions=-write --type=group manage_group_members
"""

import copy
from ipalib.plugins.baseldap import *
from ipalib import api, _, ngettext
from ipalib import Flag, Str, StrEnum
from ipalib.request import context


class permission(LDAPObject):
    """
    Permission object.
    """
    container_dn = api.env.container_permission
    object_name = 'permission'
    object_name_plural = 'permissions'
    object_class = ['groupofnames']
    default_attributes = ['cn', 'description', 'member', 'memberof',
        'memberindirect',
    ]
    aci_attributes = ['group', 'permissions', 'attrs', 'type',
        'filter', 'subtree', 'targetgroup',
    ]
    attribute_members = {
        'member': ['privilege'],
#        'memberindirect': ['user', 'group', 'role'],
    }
    rdnattr='cn'

    label = _('Permissions')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Permission name'),
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description',
            cli_name='desc',
            label=_('Description'),
            doc=_('Permission description'),
        ),
        List('permissions',
            cli_name='permissions',
            label=_('Permissions'),
            doc=_('Comma-separated list of permissions to grant ' \
                '(read, write, add, delete, all)'),
        ),
        List('attrs?',
            cli_name='attrs',
            label=_('Attributes'),
            doc=_('Comma-separated list of attributes'),
            normalizer=lambda value: value.lower(),
            alwaysask=True,
        ),
        StrEnum('type?',
            cli_name='type',
            label=_('Type'),
            doc=_('Type of IPA object (user, group, host, hostgroup, service, netgroup, dns)'),
            values=(u'user', u'group', u'host', u'service', u'hostgroup', u'netgroup', u'dns',),
            alwaysask=True,
        ),
        Str('memberof?',
            cli_name='memberof',
            label=_('Member of group'),  # FIXME: Does this label make sense?
            doc=_('Target members of a group'),
            alwaysask=True,
        ),
        Str('filter?',
            cli_name='filter',
            label=_('Filter'),
            doc=_('Legal LDAP filter (e.g. ou=Engineering)'),
            alwaysask=True,
        ),
        Str('subtree?',
            cli_name='subtree',
            label=_('Subtree'),
            doc=_('Subtree to apply permissions to'),
            alwaysask=True,
        ),
        Str('targetgroup?',
            cli_name='targetgroup',
            label=_('Target group'),
            doc=_('User group to apply permissions to'),
            alwaysask=True,
        ),
    )

api.register(permission)


class permission_add(LDAPCreate):
    """
    Add a new permission.
    """

    msg_summary = _('Added permission "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        # Test the ACI before going any further
        opts = copy.copy(options)
        del opts['description']
        opts['test'] = True
        opts['permission'] = keys[-1]
        try:
            self.api.Command.aci_add(options['description'], **opts)
        except Exception, e:
            raise e

        # Clear the aci attributes out of the permission entry
        for o in options:
            try:
                if o not in ['description', 'objectclass']:
                    del entry_attrs[o]
            except:
                pass
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        # Now actually add the aci.
        opts = copy.copy(options)
        del opts['description']
        opts['test'] = False
        opts['permission'] = keys[-1]
        try:
            result = self.api.Command.aci_add(options['description'], **opts)['result']
            for attr in self.obj.aci_attributes:
                if attr in result:
                    entry_attrs[attr] = result[attr]
        except errors.InvalidSyntax, e:
            # A syntax error slipped past our attempt at validation, clean up
            self.api.Command.permission_del(keys[-1])
            raise e
        except Exception, e:
            # Something bad happened, clean up as much as we can and return
            # that error
            try:
                self.api.Command.permission_del(keys[-1])
            except Exception, ignore:
                pass
            try:
                self.api.Command.aci_del(keys[-1])
            except Exception, ignore:
                pass
            raise e
        return dn

api.register(permission_add)


class permission_del(LDAPDelete):
    """
    Delete a permission.
    """

    msg_summary = _('Deleted permission "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        (dn, entry_attrs) = ldap.get_entry(dn, ['*'])
        if 'description' in entry_attrs:
            try:
                self.api.Command.aci_del(entry_attrs['description'][0])
            except errors.NotFound:
                pass
        return dn

api.register(permission_del)


class permission_mod(LDAPUpdate):
    """
    Modify a permission.
    """

    msg_summary = _('Modified permission "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        try:
            (dn, attrs) = ldap.get_entry(
                dn, attrs_list, normalize=self.obj.normalize_dn
            )
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        opts = copy.copy(options)
        if 'description' in opts:
            del opts['description']
        for o in ['all', 'raw', 'rights', 'description']:
            if o in opts:
                del opts[o]
        setattr(context, 'aciupdate', False)
        # If there are no options left we don't need to do anything to the
        # underlying ACI.
        if len(opts) > 0:
            opts['test'] = False
            opts['permission'] = keys[-1]
            try:
                self.api.Command.aci_mod(attrs['description'][0], **opts)
                setattr(context, 'aciupdate', True)
            except Exception, e:
                raise e

        # Clear the aci attributes out of the permission entry
        for o in self.obj.aci_attributes:
            try:
                del entry_attrs[o]
            except:
                pass

        if 'description' in options:
            if attrs['description'][0] != options['description']:
                self.api.Command.aci_rename(attrs['description'][0], newname=options['description'])

        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        if isinstance(exc, errors.EmptyModlist):
            aciupdate = getattr(context, 'aciupdate')
            opts = copy.copy(options)
            # Clear the aci attributes out of the permission entry
            for o in self.obj.aci_attributes + ['all', 'raw', 'rights']:
                try:
                    del opts[o]
                except:
                    pass

            if len(opts) > 0 and not aciupdate:
                raise exc
        else:
            raise exc

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        result = self.api.Command.permission_show(keys[-1])['result']
        for r in result:
            if not r.startswith('member'):
                entry_attrs[r] = result[r]
        return dn

api.register(permission_mod)


class permission_find(LDAPSearch):
    """
    Search for permissions.
    """

    msg_summary = ngettext(
        '%(count)d permission matched', '%(count)d permissions matched'
    )

    def post_callback(self, ldap, entries, truncated, *args, **options):
        newentries = []
        for entry in entries:
            (dn, attrs) = entry
            try:
                aci = self.api.Command.aci_show(attrs['description'][0])['result']
                for attr in self.obj.aci_attributes:
                    if attr in aci:
                        attrs[attr] = aci[attr]
            except errors.NotFound:
                self.debug('ACI not found for %s' % attrs['description'][0])

        # Now find all the ACIs that match. Once we find them, add any that
        # aren't already in the list along with their permission info.
        aciresults = self.api.Command.aci_find(*args, **options)
        truncated = truncated or aciresults['truncated']
        results = aciresults['result']
        for aci in results:
            found = False
            if 'permission' in aci:
                for entry in entries:
                    (dn, attrs) = entry
                    if aci['permission'] == attrs['cn']:
                        found = True
                        break
                if not found:
                    permission = self.api.Command.permission_show(aci['permission'])
                    attrs = permission['result']
                    for attr in self.obj.aci_attributes:
                        if attr in aci:
                            attrs[attr] = aci[attr]
                    dn = attrs['dn']
                    del attrs['dn']
                    if (dn, attrs) not in entries:
                        newentries.append((dn, attrs))

        return newentries

api.register(permission_find)


class permission_show(LDAPRetrieve):
    """
    Display information about a permission.
    """
    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        try:
            aci = self.api.Command.aci_show(entry_attrs['description'][0])['result']
            for attr in self.obj.aci_attributes:
                if attr in aci:
                    entry_attrs[attr] = aci[attr]
        except errors.NotFound:
            self.debug('ACI not found for %s' % entry_attrs['description'][0])
        return dn

api.register(permission_show)


class permission_add_member(LDAPAddMember):
    """
    Add members to a permission.
    """
    NO_CLI = True

api.register(permission_add_member)


class permission_remove_member(LDAPRemoveMember):
    """
    Remove members from a permission.
    """
    NO_CLI = True

api.register(permission_remove_member)
