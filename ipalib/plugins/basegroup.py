# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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

from ipalib import api, crud, errors, errors2
from ipalib import Object, Command  # Plugin base classes
from ipalib import Str, Int, Flag, List  # Parameter types
from ldap.dn import escape_dn_chars


default_attributes = ('cn','description','member','memberof')
default_class = "groupofnames"


def find_members(ldap, failed, members, attribute, filter=None, base=None):
    """
    Search for a list of members to operate on.

    Returns a tuple of 2 lists: a list of DNs found, a list of errors

    :param ldap: The ldap connection
    :param failed: The current list of failed entries
    :param members: list of members to find DNs for
    :param attribute: The primary key attribute (cn, uid, etc)
    :param filter: An LDAP filter to narrow the search
    :param base: The search base DN
    """
    found = []
    for m in members:
        if not m: continue
        try:
            member_dn = ldap.find_entry_dn(attribute, m, filter, base)
            found.append(member_dn)
        except errors2.NotFound:
            failed.append(m)

    return found, failed


class BaseGroup(Object):
    """
    Basic Group object.
    """
    takes_params = (
        Str('description',
            doc='A description of this group',
            attribute=True,
        ),
        Str('cn',
            cli_name='name',
            primary_key=True,
            normalizer=lambda value: value.lower(),
            attribute=True,
        ),
    )

    def get_dn(self, cn):
        """
        Construct group dn from cn.
        """
        assert self.container
        return 'cn=%s,%s,%s' % (
            escape_dn_chars(cn),
            self.container,
            api.env.basedn,
        )


class basegroup_add(crud.Add):
    'Add a new group.'

    base_classes = ("top", default_class)

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
        ldap = self.api.Backend.ldap
        entry = self.args_options_2_entry(cn, **kw)
        entry['dn'] = self.obj.get_dn(cn)

        if  kw.get('objectclass'):
            entry['objectclass'] = kw['objectclass']
        else:
            entry['objectclass'] = self.base_classes


        return ldap.create(**entry)

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_name(self.name)
        textui.print_entry(result)
        textui.print_dashed('Added group "%s"' % result['cn'])


class basegroup_del(crud.Del):
    'Delete an existing group.'
    filter_class = default_class
    container = None

    def execute(self, cn, **kw):
        """
        Delete a group

        The memberOf plugin handles removing the group from any other
        groups.

        :param cn: The name of the group being removed
        :param kw: Unused
        """
        assert self.container
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, self.filter_class, self.container)

        return ldap.delete(dn)

    def output_for_cli(self, textui, result, cn):
        """
        Output result of this command to command line interface.
        """
        textui.print_plain("Deleted group %s" % cn)


class basegroup_mod(crud.Mod):
    'Edit an existing group.'
    filter_class = default_class
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

        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, self.filter_class, self.container)

        return ldap.update(dn, **kw)

    def output_for_cli(self, textui, result, cn, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_plain("Group updated")


class basegroup_find(crud.Find):
    'Search the groups.'
    filter_class = default_class
    searchfields = []
    container = None
    def execute(self, term, **kw):
        ldap = self.api.Backend.ldap

        if not self.searchfields:
            # Pull the list of searchable attributes out of the configuration.
            config = ldap.get_ipa_config()
            search_fields_conf_str = config.get('ipagroupsearchfields')
            search_fields = search_fields_conf_str.split(",")
        else:
            search_fields = self.searchfields

        search_kw = {}
        for s in search_fields:
            search_kw[s] = term

        if self.filter_class and not kw.get('objectclass'):
            search_kw['objectclass'] = self.filter_class

        if self.container and not kw.get('base'):
            search_kw['base'] = self.container

        return ldap.search(**search_kw)

    def output_for_cli(self, textui, result, criteria, **options):
        counter = result[0]
        groups = result[1:]
        if counter == 0 or len(groups) == 0:
            textui.print_plain("No entries found")
            return
        if len(groups) == 1:
            textui.print_entry(groups[0])
            return
        textui.print_name(self.name)

        for g in groups:
            textui.print_entry(g)
            textui.print_plain('')
        if counter == -1:
            textui.print_plain("These results are truncated.")
            textui.print_plain("Please refine your search and try again.")
        textui.print_count(groups, '%d groups matched')


class basegroup_show(crud.Get):
    'Examine an existing group.'
    filter_class = default_class
    default_attributes = default_attributes
    container = None
    takes_options = (
        Flag('all', doc='Retrieve all attributes'),
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
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, self.filter_class, self.container)

        # FIXME: should kw contain the list of attributes to display?
        if kw.get('all', False):
            return ldap.retrieve(dn)
        else:
            return ldap.retrieve(dn, self.default_attributes)

    def output_for_cli(self, textui, result, *args, **options):
        textui.print_entry(result)


class basegroup_add_member(Command):
    'Add a member to a group.'
    takes_args = (
        Str('group', primary_key=True),
    )
    takes_options = (
        List('users?', doc='comma-separated list of users to add'),
        List('groups?', doc='comma-separated list of user groups to add'),
    )
    container = None
    filter_class = default_class

    def _find_members(self, ldap, failed, members, attribute, filter=None, base=None):
        return find_members(ldap, failed, members, attribute, filter, base)

    def _add_members(self, ldap, completed, members, add_failed, dn, memberattr):
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
            if not member_dn: continue
            try:
                ldap.add_member_to_group(member_dn, dn, memberattr)
                completed+=1
            except:
                add_failed.append(member_dn)

        return completed, add_failed

    def execute(self, cn, **kw):
        """
        Execute the group-add-member operation.

        Returns the updated group entry

        :param cn: The group name to add new members to.
        :param kw: groups is a comma-separated list of groups to add
        :param kw: users is a comma-separated list of users to add
        """
        assert self.container
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, self.filter_class, self.container)
        add_failed = []
        to_add = []
        completed = 0

        members = kw.get('groups', [])
        (to_add, add_failed) = self._find_members(ldap, add_failed, members, "cn", "ipaUserGroup", self.api.env.container_group)
        (completed, add_failed) = self._add_members(ldap, completed, to_add, add_failed, dn, "member")

        members = kw.get('users', [])
        (to_add, add_failed) = self._find_members(ldap, add_failed, members, "uid", "posixAccount", self.api.env.container_user)
        (completed, add_failed) = self._add_members(ldap, completed, to_add, add_failed, dn, "member")

        return add_failed

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        if result:
            textui.print_plain("These entries failed to add to the group:")
            for a in result:
                textui.print_plain("\t'%s'" % a)
        else:
            textui.print_plain("members added.")


class basegroup_remove_member(Command):
    'Remove a member from a group.'
    container = None
    filter_class = default_class
    takes_args = (
        Str('group', primary_key=True),
    )
    takes_options = (
        List('users?', doc='comma-separated list of users to remove'),
        List('groups?', doc='comma-separated list of user groups to remove'),
    )

    def _find_members(self, ldap, failed, members, attribute, filter=None, base=None):
        return find_members(ldap, failed, members, attribute, filter, base)

    def _remove_members(self, ldap, completed, members, remove_failed, dn, memberattr):
        """
        Add members to a group.

        Returns a tuple of the # completed and those that weren't added

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
                ldap.remove_member_from_group(member_dn, dn, memberattr)
                completed+=1
            except:
                remove_failed.append(member_dn)

        return completed, remove_failed

    def execute(self, cn, **kw):
        """
        Execute the group-remove-member operation.

        Returns the members that could not be added

        :param cn: The group name to add new members to.
        :param kw: groups is a comma-separated list of groups to remove
        :param kw: users is a comma-separated list of users to remove
        """
        assert self.container
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, self.filter_class, self.container)
        to_remove = []
        remove_failed = []
        completed = 0

        members = kw.get('groups', [])
        (to_remove, remove_failed) = self._find_members(ldap, remove_failed, members, "cn", "ipaUserGroup", self.api.env.container_group)
        (completed, remove_failed) = self._remove_members(ldap, completed, to_remove, remove_failed, dn, "member")

        members = kw.get('users', [])
        (to_remove, remove_failed) = self._find_members(ldap, remove_failed, members, "uid", "posixAccount", self.api.env.container_user)
        (completed, remove_failed) = self._remove_members(ldap, completed, to_remove, remove_failed, dn, "member")

        return remove_failed

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        if result:
            textui.print_plain("These entries failed to be removed from the group:")
            for a in result:
                textui.print_plain("\t'%s'" % a)
        else:
            textui.print_plain("members removed.")
