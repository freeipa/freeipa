# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
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
Frontend plugins for group (Identity).
"""

from ipalib import api, crud, errors
from ipalib import Object, Command  # Plugin base classes
from ipalib import Str, Int # Parameter types


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

class group(Object):
    """
    Group object.
    """
    takes_params = (
        Str('description',
            doc='A description of this group',
        ),
        Int('gidnumber?',
            cli_name='gid',
            doc='The gid to use for this group. If not included one is automatically set.',
        ),
        Str('cn',
            cli_name='name',
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
    )
api.register(group)


class group_add(crud.Add):
    'Add a new group.'

    def execute(self, cn, **kw):
        """
        Execute the group-add operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry as it will be created in LDAP.

        No need to explicitly set gidNumber. The dna_plugin will do this
        for us if the value isn't provided by the caller.

        :param cn: The name of the group being added.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'cn' not in kw
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap
        kw['cn'] = cn
        kw['dn'] = ldap.make_group_dn(cn)

        # Get our configuration
        config = ldap.get_ipa_config()

        # some required objectclasses
        kw['objectClass'] =  config.get('ipagroupobjectclasses')

        return ldap.create(**kw)

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_name(self.name)
        textui.print_entry(result)
        textui.print_dashed('Added group "%s"' % result['cn'])

api.register(group_add)


class group_del(crud.Del):
    'Delete an existing group.'
    def execute(self, cn, **kw):
        """
        Delete a group

        The memberOf plugin handles removing the group from any other
        groups.

        :param cn: The name of the group being removed
        :param kw: Unused
        """
        # We have 2 special groups, don't allow them to be removed
#        if "admins" == cn.lower() or "editors" == cn.lower():
#            raise ipaerror.gen_exception(ipaerror.CONFIG_REQUIRED_GROUPS)

        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, "posixGroup")
        self.log.info("IPA: group-del '%s'" % dn)

        # Don't allow the default user group to be removed
        config=ldap.get_ipa_config()
        default_group = ldap.find_entry_dn("cn", config.get('ipadefaultprimarygroup'), "posixGroup")
        if dn == default_group:
            raise errors.DefaultGroup

        return ldap.delete(dn)

    def output_for_cli(self, textui, result, cn):
        """
        Output result of this command to command line interface.
        """
        textui.print_plain("Deleted group %s" % cn)

api.register(group_del)


class group_mod(crud.Mod):
    'Edit an existing group.'
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
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, "posixGroup")
        return ldap.update(dn, **kw)

    def output_for_cli(self, textui, result, cn, **options):
        """
        Output result of this command to command line interface.
        """
        if result:
            textui.print_plain("Group updated")

api.register(group_mod)


class group_find(crud.Find):
    'Search the groups.'
    def execute(self, term, **kw):
        ldap = self.api.Backend.ldap

        # Pull the list of searchable attributes out of the configuration.
        config = ldap.get_ipa_config()
        search_fields_conf_str = config.get('ipagroupsearchfields')
        search_fields = search_fields_conf_str.split(",")

        search_kw = {}
        for s in search_fields:
            search_kw[s] = term

        object_type = ldap.get_object_type("cn")
        if object_type and not kw.get('objectclass'):
            search_kw['objectclass'] = object_type
        return ldap.search(**search_kw)

    def output_for_cli(self, textui, result, uid, **options):
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

api.register(group_find)


class group_show(crud.Get):
    'Examine an existing group.'
    def execute(self, cn, **kw):
        """
        Execute the group-show operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param cn: The group name to retrieve.
        :param kw: Not used.
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, "posixGroup")
        # FIXME: should kw contain the list of attributes to display?
        return ldap.retrieve(dn)

    def output_for_cli(self, textui, result, *args, **options):
        counter = result[0]
        groups = result[1:]
        if counter == 0 or len(groups) == 0:
            textui.print_plain("No entries found")
            return
        if len(groups) == 1:
            textui.print_entry(groups[0])
            return
        textui.print_name(self.name)
        for u in groups:
            textui.print_plain('%(givenname)s %(sn)s:' % u)
            textui.print_entry(u)
            textui.print_plain('')
        if counter == -1:
            textui.print_plain('These results are truncated.')
            textui.print_plain('Please refine your search and try again.')
        textui.print_count(groups, '%d groups matched')

api.register(group_show)


class group_add_member(Command):
    'Add a member to a group.'
    takes_args = (
        Str('group', primary_key=True),
    )
    takes_options = (
        Str('users?', doc='comma-separated list of users to add'),
        Str('groups?', doc='comma-separated list of groups to add'),
    )
    def execute(self, cn, **kw):
        """
        Execute the group-add-member operation.

        Returns the updated group entry

        :param cn: The group name to add new members to.
        :param kw: groups is a comma-separated list of groups to add
        :parem kw: users is a comma-separated list of users to add
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn)
        add_failed = []
        to_add = []
        completed = 0

        members = get_members(kw.get('groups', ''))
        for m in members:
            if not m: continue
            try:
                member_dn = ldap.find_entry_dn("cn", m)
                to_add.append(member_dn)
            except errors.NotFound:
                add_failed.append(m)
                continue

        members = get_members(kw.get('users', ''))
        for m in members:
            if not m: continue
            try:
                member_dn = ldap.find_entry_dn("uid", m)
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
            print "These entries failed to add to the group:"
            for a in add_failed:
                print "\t'%s'" % a


api.register(group_add_member)


class group_remove_member(Command):
    'Remove a member from a group.'
    takes_args = (
        Str('group', primary_key=True),
    )
    takes_options = (
        Str('users?', doc='comma-separated list of users to remove'),
        Str('groups?', doc='comma-separated list of groups to remove'),
    )
    def execute(self, cn, **kw):
        """
        Execute the group-remove-member operation.

        Returns the members that could not be added

        :param cn: The group name to add new members to.
        :param kw: groups is a comma-separated list of groups to remove
        :parem kw: users is a comma-separated list of users to remove
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn)
        to_remove = []
        remove_failed = []
        completed = 0

        members = get_members(kw.get('groups', ''))
        for m in members:
            if not m: continue
            try:
                member_dn = ldap.find_entry_dn("cn", m)
                to_remove.append(member_dn)
            except errors.NotFound:
                remove_failed.append(m)
                continue

        members = get_members(kw.get('users', ''))
        for m in members:
            try:
                member_dn = ldap.find_entry_dn("uid", m,)
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
            print "These entries failed to be removed from the group:"
            for a in remove_failed:
                print "\t'%s'" % a

api.register(group_remove_member)
