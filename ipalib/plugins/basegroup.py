# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
Base plugin for groups.
"""

from ipalib import api, crud, errors
from ipalib import Command, Object
from ipalib import Flag, Int, List, Str

_default_attributes = ['cn', 'description', 'member', 'memberof']
_default_class = 'groupofnames'


def find_members(ldap, failed, members, attr, object_class, parent_dn=''):
    """
    Search for a list of members to operate on.

    Returns a tuple of 2 lists: a list of DNs found, a list of errors

    :param ldap: The ldap connection
    :param failed: The current list of failed entries
    :param members: list of members to find DNs for
    :param attr: The primary key attribute (cn, uid, etc)
    :param object_class: type of entry we're looking for
    :param parent_dn: base DN for the search
    """
    found = []
    for m in members:
        if not m: continue
        try:
            (member_dn, entry_attrs) = ldap.find_entry_by_attr(
                attr, m, object_class, parent_dn
            )
            found.append(member_dn)
        except errors.NotFound:
            failed.append(m)

    return (found, failed)

def add_members(ldap, completed, members, add_failed, group_dn, memberattr):
    """
    Add members to a group.

    Returns a tuple of the # completed and those that weren't added

    :param ldap: The ldap connection
    :param completed: number of entries successfully added
    :param members: list of member DNs to add
    :param add_failed: members who failed to be added
    :param dn: DN of group to add members to
    :param membetattr: The attribute where members are stored
    """
    for member_dn in members:
        if not member_dn:
            continue
        try:
            ldap.add_entry_to_group(member_dn, group_dn, memberattr)
            completed += 1
        except:
            add_failed.append(member_dn)

    return (completed, add_failed)

def del_members(ldap, completed, members, rem_failed, group_dn, memberattr):
    """
    Remove members from group.

    Returns a tuple of the # completed and those that weren't removed

    :param ldap: The ldap connection
    :param completed: number of entries successfully removed
    :param members: list of member DNs to remove
    :param remove_failed: members who failed to be removed
    :param dn: DN of group to remove members from
    :param membetattr: The attribute where members are stored
    """
    for member_dn in members:
        if not member_dn: continue
        try:
            ldap.remove_entry_from_group(member_dn, group_dn, memberattr)
            completed += 1
        except:
            rem_failed.append(member_dn)

    return (completed, rem_failed)


class basegroup(Object):
    """
    Basic Group object.
    """
    container = None

    takes_params = (
        Str('cn',
            cli_name='name',
            doc='group name',
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description',
            cli_name='desc',
            doc='A description of this group',
        ),
    )

    def get_dn(self, ldap, cn):
        """
        Construct group dn from cn.
        """
        assert self.container
        return ldap.make_dn_from_attr('cn', cn, self.container)


class basegroup_add(crud.Create):
    """
    Create new group.
    """
    base_classes = ('top', _default_class)

    def execute(self, cn, **kw):
        """
        Execute a group add operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry as it will be created in LDAP.

        :param cn: The name of the group being added.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'cn' not in kw
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap2
        entry_attrs = self.args_options_2_entry(cn, **kw)
        dn = self.obj.get_dn(ldap, cn)

        if kw.get('objectclass'):
            entry_attrs['objectclass'] = kw['objectclass']
        else:
            entry_attrs['objectclass'] = self.base_classes

        ldap.add_entry(dn, entry_attrs)

        return ldap.get_entry(dn, entry_attrs.keys())

    def output_for_cli(self, textui, result, cn, **options):
        """
        Output result of this command to command line interface.
        """
        (dn, entry_attrs) = result

        textui.print_name(self.name)
        textui.print_attribute('dn', dn)
        textui.print_entry(entry_attrs)
        textui.print_dashed('Created group "%s".' % cn)


class basegroup_del(crud.Delete):
    """
    Delete group.
    """
    filter_class = _default_class
    container = None

    def execute(self, cn):
        """
        Delete a group

        The memberOf plugin handles removing the group from any other
        groups.

        :param cn: The name of the group being removed
        :param kw: Unused
        """
        assert self.container
        ldap = self.api.Backend.ldap2

        (dn, entry_attrs) = ldap.find_entry_by_attr(
            'cn', cn, self.filter_class, self.container
        )

        ldap.delete_entry(dn)

        return True

    def output_for_cli(self, textui, result, cn):
        """
        Output result of this command to command line interface.
        """
        textui.print_name(self.name)
        textui.print_dashed('Deleted group "%s"' % cn)


class basegroup_mod(crud.Update):
    """
    Modify group.
    """
    filter_class = _default_class
    container = None

    def execute(self, cn, **kw):
        """
        Execute the group-mod operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param cn: The name of the group to update.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'cn' not in kw
        assert 'dn' not in kw
        assert self.container
        assert self.filter_class
        ldap = self.api.Backend.ldap2

        (dn, entry_attrs) = ldap.find_entry_by_attr(
            'cn', cn, self.filter_class, self.container_dn
        )

        entry_attrs = self.args_options_2_entry(cn, **kw)
        if 'objectclass' in kw:
            entry_attrs['objectclass'] = kw['objectclass']

        ldap.update_entry(dn, entry_attrs)

        return ldap.get_entry(dn, entry_attrs.keys())

    def output_for_cli(self, textui, result, cn, **options):
        """
        Output result of this command to command line interface.
        """
        (dn, entry_attrs) = result

        textui.print_name(self.name)
        textui.print_attribute('dn', dn)
        textui.print_entry(entry_attrs)
        textui.print_dashed('Modified group "%s"' % cn)


class basegroup_find(crud.Search):
    """
    Search for groups.
    """
    filter_class = _default_class
    searchfields = []
    container = None

    takes_options = (
        Flag('all',
            cli_name='all',
            doc='Retrieve all attributes'
        ),
    )

    def execute(self, term, **kw):
        ldap = self.api.Backend.ldap2

        search_kw = self.args_options_2_entry(**kw)
        if self.filter_class:
            search_kw['objectclass'] = self.filter_class
        filter = ldap.make_filter(search_kw, rules=ldap.MATCH_ALL)
        if term:
            if not self.searchfields:
                # Pull the list of searchable attributes out of the IPA config.
                conf = ldap.get_ipa_config()[1]
                search_fields = conf.get('ipagroupsearchfields')[0].split(',')
            else:
                search_fields = self.searchfields

            search_kw = {}
            for s in search_fields:
                search_kw[s] = term
            term_filter = ldap.make_filter(search_kw, exact=False)
            filter = ldap.combine_filters(
                (filter, term_filter), ldap.MATCH_ALL
            )

        if kw['all']:
            attrs_list = ['*']
        else:
            attrs_list = _default_attributes

        parent_dn = self.container or ''

        try:
            (entries, truncated) = ldap.find_entries(
                filter, attrs_list, parent_dn
            )
        except errors.NotFound:
            (entries, truncated) = (tuple(), False)

        return (entries, truncated)

    def output_for_cli(self, textui, result, criteria, **options):
        (entries, truncated) = result

        textui.print_name(self.name)
        for (dn, entry_attrs) in entries:
            textui.print_attribute('dn', dn)
            textui.print_entry(entry_attrs)
            textui.print_plain('')
        textui.print_count(
            len(result), '%i group matched.', '%i groups matched.'
        )
        if truncated:
            textui.print_dashed('These results are truncated.', below=False)
            textui.print_dashed(
                'Please refine your search and try again.', above=False
            )


class basegroup_show(crud.Retrieve):
    """
    Display group.
    """
    filter_class = _default_class
    default_attributes = _default_attributes
    container = None

    takes_options = (
        Flag('all',
            doc='Retrieve all attributes'
        ),
    )

    def execute(self, cn, **kw):
        """
        Execute the group-show operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param cn: The group name to retrieve.
        :param kw: Not used.
        """
        assert self.container
        ldap = self.api.Backend.ldap2

        (dn, entry_attrs) = ldap.find_entry_by_attr(
            'cn', cn, self.filter_class, self.container
        )

        if kw['all']:
            attrs_list = ['*']
        else:
            attrs_list = self.default_attributes

        return ldap.get_entry(dn, attrs_list)

    def output_for_cli(self, textui, result, *args, **options):
        (dn, entry_attrs) = result

        textui.print_name(self.name)
        textui.print_attribute('dn', dn)
        textui.print_entry(entry_attrs)


class basegroup_add_member(Command):
    """
    Add members to group.
    """
    filter_class = _default_class
    default_attributes = _default_attributes
    container = None

    takes_args = (
        Str('cn',
            cli_name='name',
            doc='group name',
        ),
    )

    takes_options = (
        List('users?',
            cli_name='users',
            doc='comma-separated list of users to add',
        ),
        List('groups?',
            cli_name='groups',
            doc='comma-separated list of user groups to add',
        ),
    )

    def execute(self, cn, **kw):
        """
        Execute the group-add-member operation.

        Returns a tuple containing the number of members added
        and the updated entry.

        :param cn: The group name to add new members to.
        :param kw: groups is a comma-separated list of groups to add
        :param kw: users is a comma-separated list of users to add
        """
        assert self.container
        ldap = self.api.Backend.ldap2
        to_add = []
        add_failed = []
        completed = 0

        (dn, entry_attrs) = ldap.find_entry_by_attrs(
            'cn', cn, self.filter_class, self.container
        )

        members = kw.get('groups', [])
        (to_add, add_failed) = find_members(
            ldap, add_failed, members, 'cn', 'ipausergroup',
            self.api.env.container_group
        )
        (completed, add_failed) = add_members(
            ldap, completed, to_add, add_failed, dn, 'member'
        )

        members = kw.get('users', [])
        (to_add, add_failed) = find_members(
            ldap, add_failed, members, 'uid', 'posixaccount',
            self.api.env.container_user
        )
        (completed, add_failed) = add_members(
            ldap, completed, to_add, add_failed, dn, 'member'
        )

        return (completed, ldap.get_entry(dn, self.default_attributes))

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        (total, (dn, entry_attrs)) = result

        textui.print_name(self.name)
        textui.print_attribute('dn', dn)
        textui.print_entry(entry_attrs)
        textui.print_count(total, '%i member added.', '%i members added.')


class basegroup_del_member(Command):
    """
    Remove members from group.
    """
    filter_class = _default_class
    default_attributes = _default_attributes
    container = None

    takes_args = (
        Str('cn',
            cli_name='name',
            doc='group name',
        ),
    )

    takes_options = (
        List('users?',
            cli_name='users',
            doc='comma-separated list of users to remove',
        ),
        List('groups?',
            cli_name='groups',
            doc='comma-separated list of user groups to remove',
        ),
    )

    def execute(self, cn, **kw):
        """
        Execute the group-del-member operation.

        Returns a tuple containing the number of members removed
        and the updated entry.

        :param cn: The group name to add new members to.
        :param kw: groups is a comma-separated list of groups to remove
        :param kw: users is a comma-separated list of users to remove
        """
        assert self.container
        ldap = self.api.Backend.ldap2
        to_remove = []
        remove_failed = []
        completed = 0

        (dn, entry_attrs) = ldap.find_entry_by_attrs(
            'cn', cn, self.filter_class, self.container
        )

        members = kw.get('groups', [])
        (to_remove, remove_failed) = find_members(
            ldap, remove_failed, members, 'cn', 'ipausergroup',
            self.api.env.container_group
        )
        (completed, remove_failed) = del_members(
            ldap, completed, to_remove, remove_failed, dn, 'member'
        )

        members = kw.get('users', [])
        (to_remove, remove_failed) = find_members(
            ldap, remove_failed, members, 'uid', 'posixaccount',
            self.api.env.container_user
        )
        (completed, remove_failed) = del_members(
            ldap, completed, to_remove, remove_failed, dn, 'member'
        )

        return (completed, ldap.get_entry(dn, self.default_attributes))

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        (total, (dn, entry_attrs)) = result

        textui.print_name(self.name)
        textui.print_attribute('dn', dn)
        textui.print_entry(entry_attrs)
        textui.print_count(total, '%i member removed.', '%i members removed.')

