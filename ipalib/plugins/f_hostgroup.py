# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
Frontend plugins for groups of hosts
"""

from ipalib import api, crud, errors
from ipalib import Object, Command  # Plugin base classes
from ipalib import Str  # Parameter types


hostgroup_filter = "groupofnames)(!(objectclass=posixGroup)"

def get_members(members):
    """
    Return a list of members.

    It is possible that the value passed in is None.
    """
    if members:
        members = members.split(',')
    else:
        members = []

    return members

class hostgroup(Object):
    """
    Host Group object.
    """
    takes_params = (
        Str('description',
            doc='A description of this group',
        ),
        Str('cn',
            cli_name='name',
            primary_key=True,
            normalizer=lambda value: value.lower(),
        )
    )
api.register(hostgroup)


class hostgroup_add(crud.Add):
    'Add a new group of hosts.'

    def execute(self, cn, **kw):
        """
        Execute the hostgroup-add operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry as it will be created in LDAP.

        No need to explicitly set gidNumber. The dna_plugin will do this
        for us if the value isn't provided by the caller.

        :param cn: The name of the host group being added.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'cn' not in kw
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap
        kw['cn'] = cn
        kw['dn'] = ldap.make_hostgroup_dn(cn)

        # Get our configuration
        #config = ldap.get_ipa_config()

        # some required objectclasses
        # FIXME:  get this out of config
        kw['objectClass'] = ['groupofnames']

        return ldap.create(**kw)

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_plain("Group added")

api.register(hostgroup_add)


class hostgroup_del(crud.Del):
    'Delete an existing group of hosts.'
    def execute(self, cn, **kw):
        """
        Delete a group of hosts

        The memberOf plugin handles removing the group from any other
        groups.

        :param cn: The name of the group being removed
        :param kw: Unused
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, hostgroup_filter)

        return ldap.delete(dn)

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_plain("Group deleted")

api.register(hostgroup_del)


class hostgroup_mod(crud.Mod):
    'Edit an existing group of hosts.'
    def execute(self, cn, **kw):
        """
        Execute the hostgroup-mod operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param cn: The name of the group to update.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'cn' not in kw
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, hostgroup_filter)
        return ldap.update(dn, **kw)

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        texui.print_plain("Group updated")

api.register(hostgroup_mod)


class hostgroup_find(crud.Find):
    'Search the groups of hosts.'
    def execute(self, term, **kw):
        ldap = self.api.Backend.ldap

        # Pull the list of searchable attributes out of the configuration.
        config = ldap.get_ipa_config()

        # FIXME: for now use same search fields as user groups
        search_fields_conf_str = config.get('ipagroupsearchfields')
        search_fields = search_fields_conf_str.split(",")

        search_kw = {}
        for s in search_fields:
            search_kw[s] = term

        search_kw['objectclass'] = hostgroup_filter
        return ldap.search(**search_kw)

    def output_for_cli(self, textui, result, *args, **options):
        counter = result[0]
        groups = result[1:]
        if counter == 0:
            textui.print_plain("No entries found")
            return

        for g in groups:
            textui.print_entry(g)

        if counter == -1:
            textui.print_plain("These results are truncated.")
            textui.print_plain("Please refine your search and try again.")

api.register(hostgroup_find)


class hostgroup_show(crud.Get):
    'Examine an existing group of hosts.'
    def execute(self, cn, **kw):
        """
        Execute the hostgroup-show operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param cn: The group name to retrieve.
        :param kw: Not used.
        """
        ldap = self.api.Backend.ldap
        # FIXME: this works for now but the plan is to add a new objectclass
        # type.
        dn = ldap.find_entry_dn("cn", cn, hostgroup_filter)
        # FIXME: should kw contain the list of attributes to display?
        return ldap.retrieve(dn)

    def output_for_cli(self, textui, result, *args, **options):
        textui.print_entry(result)

api.register(hostgroup_show)


class hostgroup_add_member(Command):
    'Add a member to a group.'
    takes_args = (
        Str('group', primary_key=True),
    )
    takes_options = (
        Str('groups?', doc='comma-separated list of host groups to add'),
        Str('hosts?', doc='comma-separated list of hosts to add'),
    )
    def execute(self, cn, **kw):
        """
        Execute the hostgroup-add-member operation.

        Returns the updated group entry

        :param cn: The group name to add new members to.
        :param kw: groups is a comma-separated list of host groups to add
        :param kw: hosts is a comma-separated list of hosts to add
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, hostgroup_filter)
        add_failed = []
        to_add = []
        completed = 0

        members = get_members(kw.get('groups', ''))
        for m in members:
            if not m: continue
            try:
                member_dn = ldap.find_entry_dn("cn", m, hostgroup_filter)
                to_add.append(member_dn)
            except errors.NotFound:
                add_failed.append(m)
                continue

        members = get_members(kw.get('hosts', ''))
        for m in members:
            if not m: continue
            try:
                member_dn = ldap.find_entry_dn("cn", m, "ipaHost")
                to_add.append(member_dn)
            except errors.NotFound:
                add_failed.append(m)
                continue

        for member_dn in to_add:
            try:
                ldap.add_member_to_group(member_dn, dn)
                completed+=1
            except:
                add_failed.append(member_dn)

        return add_failed

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        if result:
            textui.print_plain("These entries failed to add to the group:")
            for a in result:
                print "\t'%s'" % a
        else:
            textui.print_entry("Group membership updated.")

api.register(hostgroup_add_member)


class hostgroup_remove_member(Command):
    'Remove a member from a group.'
    takes_args = (
        Str('group', primary_key=True),
    )
    takes_options = (
        Str('hosts?', doc='comma-separated list of hosts to add'),
        Str('groups?', doc='comma-separated list of groups to remove'),
    )
    def execute(self, cn, **kw):
        """
        Execute the group-remove-member operation.

        Returns the members that could not be added

        :param cn: The group name to add new members to.
        :param kw: groups is a comma-separated list of groups to remove
        :param kw: hosts is a comma-separated list of hosts to add
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, hostgroup_filter)
        to_remove = []
        remove_failed = []
        completed = 0

        members = get_members(kw.get('groups', ''))
        for m in members:
            if not m: continue
            try:
                member_dn = ldap.find_entry_dn("cn", m, hostgroup_filter)
                to_remove.append(member_dn)
            except errors.NotFound:
                remove_failed.append(m)
                continue

        members = get_members(kw.get('hosts', ''))
        for m in members:
            if not m: continue
            try:
                member_dn = ldap.find_entry_dn("cn", m, "ipaHost")
                to_remove.append(member_dn)
            except errors.NotFound:
                remove_failed.append(m)
                continue

        for member_dn in to_remove:
            try:
                ldap.remove_member_from_group(member_dn, dn)
                completed+=1
            except:
                remove_failed.append(member_dn)

        return remove_failed

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        if result:
            textui.print_plain("These entries failed to be removed from the group:")
            for a in result:
                print "\t'%s'" % a
        else:
            textui.print_plain("Group membership updated.")

api.register(hostgroup_remove_member)
