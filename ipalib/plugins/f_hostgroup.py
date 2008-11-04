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

from ipalib import frontend
from ipalib import crud
from ipalib.frontend import Param
from ipalib import api
from ipalib import errors
from ipalib import ipa_types

hostgroup_filter = "groupofnames)(!(objectclass=posixGroup)"

class hostgroup(frontend.Object):
    """
    Host Group object.
    """
    takes_params = (
        Param('description',
            doc='A description of this group',
        ),
        Param('cn',
            cli_name='name',
            primary_key=True,
            normalize=lambda value: value.lower(),
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

    def output_for_cli(self, ret):
        """
        Output result of this command to command line interface.
        """
        if ret:
            print "Group added"

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

    def output_for_cli(self, ret):
        """
        Output result of this command to command line interface.
        """
        if ret:
            print "Group deleted"

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

    def output_for_cli(self, ret):
        """
        Output result of this command to command line interface.
        """
        if ret:
            print "Group updated"

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

        for s in search_fields:
            kw[s] = term

        kw['objectclass'] = hostgroup_filter
        return ldap.search(**kw)

    def output_for_cli(self, groups):
        if not groups:
            return

        counter = groups[0]
        groups = groups[1:]
        if counter == 0:
            print "No entries found"
            return
        elif counter == -1:
            print "These results are truncated."
            print "Please refine your search and try again."

        for g in groups:
            for a in g.keys():
                print "%s: %s" % (a, g[a])

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

    def output_for_cli(self, group):
        if not group:
            return

        for a in group.keys():
            print "%s: %s" % (a, group[a])

api.register(hostgroup_show)


class hostgroup_add_member(frontend.Command):
    'Add a member to a group.'
    takes_args = (
        Param('group', primary_key=True),
    )
    takes_options = (
        Param('groups?', doc='comma-separated list of host groups to add'),
        Param('hosts?', doc='comma-separated list of hosts to add'),
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

        members = kw.get('groups', '').split(',')
        for m in members:
            if not m: continue
            try:
                member_dn = ldap.find_entry_dn("cn", m, hostgroup_filter)
                to_add.append(member_dn)
            except errors.NotFound:
                add_failed.append(m)
                continue

        members = kw.get('hosts', '').split(',')
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

    def output_for_cli(self, add_failed):
        """
        Output result of this command to command line interface.
        """
        if add_failed:
            print "These entries failed to add to the group:"
            for a in add_failed:
                print "\t'%s'" % a
        else:
            print "Group membership updated."

api.register(hostgroup_add_member)


class hostgroup_remove_member(frontend.Command):
    'Remove a member from a group.'
    takes_args = (
        Param('group', primary_key=True),
    )
    takes_options = (
        Param('hosts?', doc='comma-separated list of hosts to add'),
        Param('groups?', doc='comma-separated list of groups to remove'),
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

        members = kw.get('groups', '').split(',')
        for m in members:
            if not m: continue
            try:
                member_dn = ldap.find_entry_dn("cn", m, hostgroup_filter)
                to_remove.append(member_dn)
            except errors.NotFound:
                remove_failed.append(m)
                continue

        members = kw.get('hosts', '').split(',')
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

    def output_for_cli(self, remove_failed):
        """
        Output result of this command to command line interface.
        """
        if remove_failed:
            print "These entries failed to be removed from the group:"
            for a in remove_failed:
                print "\t'%s'" % a
        else:
            print "Group membership updated."

api.register(hostgroup_remove_member)
