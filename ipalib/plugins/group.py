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
"""
Groups of users

Manage groups of users. By default, new groups are POSIX groups. You
can add the --nonposix option to the group-add command to mark a new group
as non-POSIX, and you can use the same argument to the group-mod command
to convert a non-POSIX group to a POSIX group. POSIX groups cannot be
converted to non-POSIX groups.

Every group must have a description.

POSIX groups must have a Group ID (GID) number. Changing a GID is
supported but can have an impact on your file permissions. It is not necessary
to supply a GID when creating a group. IPA will generate one automatically
if it is not provided.

EXAMPLES:

 Add a new group:
   ipa group-add --desc='local administrators' localadmins

 Add a new non-POSIX group:
   ipa group-add --nonposix --desc='remote administrators' remoteadmins

 Convert a non-POSIX group to posix:
   ipa group-mod --posix remoteadmins

 Add a new POSIX group with a specific Group ID number:
   ipa group-add --gid=500 --desc='unix admins' unixadmins

 Add a new POSIX group and let IPA assign a Group ID number:
   ipa group-add --desc='printer admins' printeradmins

 Remove a group:
   ipa group-del unixadmins

 To add the "remoteadmins" group to the "localadmins" group:
   ipa group-add-member --groups=remoteadmins localadmins

 Add a list of users to the "localadmins" group:
   ipa group-add-member --users=test1,test2 localadmins

 Remove a user from the "localadmins" group:
   ipa group-remove-member --users=test2 localadmins

 Display information about a named group.
   ipa group-show localadmins
"""

from ipalib import api
from ipalib import Int, Str
from ipalib.plugins.baseldap import *
from ipalib import _, ngettext


class group(LDAPObject):
    """
    Group object.
    """
    container_dn = api.env.container_group
    object_name = _('group')
    object_name_plural = _('groups')
    object_class = ['ipausergroup']
    object_class_config = 'ipagroupobjectclasses'
    possible_objectclasses = ['posixGroup', 'mepManagedEntry']
    search_attributes_config = 'ipagroupsearchfields'
    default_attributes = [
        'cn', 'description', 'gidnumber', 'member', 'memberof',
        'memberindirect', 'memberofindirect',
    ]
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'member': ['user', 'group'],
        'memberof': ['group', 'netgroup', 'role', 'hbacrule', 'sudorule'],
        'memberindirect': ['user', 'group'],
        'memberofindirect': ['group', 'netgroup', 'role', 'hbacrule',
        'sudorule'],
    }
    rdnattr = 'cn'

    label = _('User Groups')
    label_singular = _('User Group')

    takes_params = (
        Str('cn',
            pattern='^[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,252}[a-zA-Z0-9_.$-]?$',
            pattern_errmsg='may only include letters, numbers, _, -, . and $',
            maxlength=255,
            cli_name='group_name',
            label=_('Group name'),
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description',
            cli_name='desc',
            label=_('Description'),
            doc=_('Group description'),
        ),
        Int('gidnumber?',
            cli_name='gid',
            label=_('GID'),
            doc=_('GID (use this option to set it manually)'),
        ),
    )

api.register(group)


class group_add(LDAPCreate):
    """
    Create a new group.
    """

    msg_summary = _('Added group "%(value)s"')

    takes_options = LDAPCreate.takes_options + (
        Flag('nonposix',
             cli_name='nonposix',
             doc=_('Create as a non-POSIX group'),
             default=False,
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        if not options['nonposix']:
            entry_attrs['objectclass'].append('posixgroup')
            if not 'gidnumber' in options:
                entry_attrs['gidnumber'] = 999
        return dn


api.register(group_add)


class group_del(LDAPDelete):
    """
    Delete group.
    """

    msg_summary = _('Deleted group "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        config = ldap.get_ipa_config()[1]
        def_primary_group = config.get('ipadefaultprimarygroup', '')
        def_primary_group_dn = group_dn = self.obj.get_dn(def_primary_group)
        if dn == def_primary_group_dn:
            raise errors.DefaultGroupError()
        group_attrs = self.obj.methods.show(
            self.obj.get_primary_key_from_dn(dn), all=True
        )['result']

        if 'mepmanagedby' in group_attrs:
            raise errors.ManagedGroupError()
        return dn

    def post_callback(self, ldap, dn, *keys, **options):
        try:
            api.Command['pwpolicy_del'](keys[-1])
        except errors.NotFound:
            pass

        return True

api.register(group_del)


class group_mod(LDAPUpdate):
    """
    Modify a group.
    """
    msg_summary = _('Modified group "%(value)s"')

    takes_options = LDAPUpdate.takes_options + (
        Flag('posix',
             cli_name='posix',
             doc=_('change to a POSIX group'),
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if options['posix'] or 'gidnumber' in options:
            (dn, old_entry_attrs) = ldap.get_entry(dn, ['objectclass'])
            if 'posixgroup' in old_entry_attrs['objectclass']:
                if options['posix']:
                    raise errors.AlreadyPosixGroup()
            else:
                old_entry_attrs['objectclass'].append('posixgroup')
                entry_attrs['objectclass'] = old_entry_attrs['objectclass']
                if not 'gidnumber' in options:
                    entry_attrs['gidnumber'] = 999
        return dn

api.register(group_mod)


class group_find(LDAPSearch):
    """
    Search for groups.
    """
    member_attributes = ['member', 'memberof']

    msg_summary = ngettext(
        '%(count)d group matched', '%(count)d groups matched', 0
    )

    takes_options = LDAPSearch.takes_options + (
        Flag('private',
            cli_name='private',
            doc=_('search for private groups'),
        ),
    )

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args, **options):
        # if looking for private groups, we need to create a new search filter,
        # because private groups have different object classes
        if options['private']:
            # filter based on options, oflt
            search_kw = self.args_options_2_entry(**options)
            search_kw['objectclass'] = ['posixGroup', 'mepManagedEntry']
            oflt = ldap.make_filter(search_kw, rules=ldap.MATCH_ALL)

            # filter based on 'criteria' argument
            search_kw = {}
            config = ldap.get_ipa_config()[1]
            attrs = config.get(self.obj.search_attributes_config, [])
            if len(attrs) == 1 and isinstance(attrs[0], basestring):
                search_attrs = attrs[0].split(',')
                for a in search_attrs:
                    search_kw[a] = args[-1]
            cflt = ldap.make_filter(search_kw, exact=False)

            filter = ldap.combine_filters((oflt, cflt), rules=ldap.MATCH_ALL)
        return (filter, base_dn, scope)

api.register(group_find)


class group_show(LDAPRetrieve):
    """
    Display information about a named group.
    """

api.register(group_show)


class group_add_member(LDAPAddMember):
    """
    Add members to a group.
    """

api.register(group_add_member)


class group_remove_member(LDAPRemoveMember):
    """
    Remove members from a group.
    """

api.register(group_remove_member)


class group_detach(LDAPQuery):
    """
    Detach a managed group from a user
    """
    has_output = output.standard_value
    msg_summary = _('Detached group "%(value)s" from user "%(value)s"')

    def execute(self, *keys, **options):
        """
        This requires updating both the user and the group. We first need to
        verify that both the user and group can be updated, then we go
        about our work. We don't want a situation where only the user or
        group can be modified and we're left in a bad state.
        """
        ldap = self.obj.backend

        group_dn = self.obj.get_dn(*keys, **options)
        user_dn = self.api.Object['user'].get_dn(*keys)

        try:
            (user_dn, user_attrs) = ldap.get_entry(user_dn)
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        is_managed = self.obj.has_objectclass(user_attrs['objectclass'], 'mepmanagedentry')
        if (not ldap.can_write(user_dn, "objectclass") or
            not (ldap.can_write(user_dn, "mepManagedEntry")) and is_managed):
            raise errors.ACIError(info=_('not allowed to modify user entries'))

        (group_dn, group_attrs) = ldap.get_entry(group_dn)
        is_managed = self.obj.has_objectclass(group_attrs['objectclass'], 'mepmanagedby')
        if (not ldap.can_write(group_dn, "objectclass") or
            not (ldap.can_write(group_dn, "mepManagedBy")) and is_managed):
            raise errors.ACIError(info=_('not allowed to modify group entries'))

        objectclasses = user_attrs['objectclass']
        try:
            i = objectclasses.index('mepOriginEntry')
            del objectclasses[i]
            update_attrs = {'objectclass': objectclasses, 'mepManagedEntry': None}
            ldap.update_entry(user_dn, update_attrs)
        except ValueError:
            # Somehow the user isn't managed, let it pass for now. We'll
            # let the group throw "Not managed".
            pass

        (group_dn, group_attrs) = ldap.get_entry(group_dn)
        objectclasses = group_attrs['objectclass']
        try:
            i = objectclasses.index('mepManagedEntry')
        except ValueError:
            # this should never happen
            raise errors.NotFound(reason=_('Not a managed group'))
        del objectclasses[i]

        # Make sure the resulting group has the default group objectclasses
        config = ldap.get_ipa_config()[1]
        def_objectclass = config.get(
            self.obj.object_class_config, objectclasses
        )
        objectclasses = list(set(def_objectclass + objectclasses))

        update_attrs = {'objectclass': objectclasses, 'mepManagedBy': None}
        ldap.update_entry(group_dn, update_attrs)

        return dict(
            result=True,
            value=keys[0],
        )

api.register(group_detach)
