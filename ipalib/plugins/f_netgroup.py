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
Frontend plugin for netgroups.
"""

from ipalib import api, crud, errors
from ipalib import Object, Command  # Plugin base classes
from ipalib import Str  # Parameter types
from ipalib import uuid

netgroup_base = "cn=ng, cn=alt"
netgroup_filter = "ipaNISNetgroup"
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

def find_members(ldap, failed, members, attribute, filter=None):
    """
    Return 2 lists: one a list of DNs found, one a list of errors
    """
    found = []
    for m in members:
        if not m: continue
        try:
            member_dn = ldap.find_entry_dn(attribute, m, filter)
            found.append(member_dn)
        except errors.NotFound:
            failed.append(m)
            continue

    return found, failed

def add_members(ldap, completed, members, dn, memberattr):
    add_failed = []
    for member_dn in members:
        try:
            ldap.add_member_to_group(member_dn, dn, memberattr)
            completed+=1
        except:
            add_failed.append(member_dn)

    return completed, add_failed

def add_external(ldap, completed, members, cn):
    failed = []
    netgroup = api.Command['netgroup_show'](cn)
    external = netgroup.get('externalhost', [])
    if not isinstance(external, list):
        external = [external]
    external_len = len(external)
    for m in members:
        if not m in external:
            external.append(m)
            completed+=1
        else:
            failed.append(m)
    if len(external) > external_len:
        kw = {'externalhost': external}
        ldap.update(netgroup['dn'], **kw)

    return completed, failed

def remove_members(ldap, completed, members, dn, memberattr):
    remove_failed = []
    for member_dn in members:
        try:
            ldap.remove_member_from_group(member_dn, dn, memberattr)
            completed+=1
        except:
            remove_failed.append(member_dn)

    return completed, remove_failed

def remove_external(ldap, completed, members, cn):
    failed = []
    netgroup = api.Command['netgroup_show'](cn)
    external = netgroup.get('externalhost', [])
    if not isinstance(external, list):
        external = [external]
    external_len = len(external)
    for m in members:
        try:
            external.remove(m)
            completed+=1
        except ValueError:
            failed.append(m)
    if len(external) < external_len:
        kw = {'externalhost': external}
        ldap.update(netgroup['dn'], **kw)

    return completed, failed

class netgroup(Object):
    """
    netgroups object.
    """
    takes_params = (
        Str('cn',
            cli_name='name',
            primary_key=True
        ),
        Str('description',
            doc='Description',
        ),
        Str('nisdomainname?',
            cli_name='domainname',
            doc='Domain name',
        ),
    )
api.register(netgroup)


class netgroup_add(crud.Add):
    'Add a new netgroup.'

    def execute(self, cn, **kw):
        """
        Execute the netgroup-add operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry as it will be created in LDAP.

        :param cn: The name of the netgroup
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        self.log.info("IPA: netgroup-add '%s'" % cn)
        assert 'cn' not in kw
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap
        kw['cn'] = cn
#        kw['dn'] = ldap.make_netgroup_dn()
        kw['ipauniqueid'] = str(uuid.uuid1())
        kw['dn'] = "ipauniqueid=%s,%s,%s" % (kw['ipauniqueid'], netgroup_base, api.env.basedn)

        if not kw.get('nisdomainname', False):
            kw['nisdomainname'] = api.env.domain

        # some required objectclasses
        kw['objectClass'] = ['top', 'ipaAssociation', 'ipaNISNetgroup']

        return ldap.create(**kw)

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_name(self.name)
        textui.print_entry(result)
        textui.print_dashed('Added netgroup "%s"' % result.get('cn'))

api.register(netgroup_add)


class netgroup_del(crud.Del):
    'Delete an existing netgroup.'

    def execute(self, cn, **kw):
        """Delete a netgroup.

           cn is the cn of the netgroup to delete

           The memberOf plugin handles removing the netgroup from any other
           groups.

           :param cn: The name of the netgroup being removed.
           :param kw: Not used.
        """
        self.log.info("IPA: netgroup-del '%s'" % cn)

        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, netgroup_filter, netgroup_base)
        return ldap.delete(dn)

    def output_for_cli(self, textui, result, cn):
        """
        Output result of this command to command line interface.
        """
        textui.print_plain('Deleted net group "%s"' % cn)

api.register(netgroup_del)


class netgroup_mod(crud.Mod):
    'Edit an existing netgroup.'
    def execute(self, cn, **kw):
        """
        Execute the netgroup-mod operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param cn: The name of the netgroup to retrieve.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        self.log.info("IPA: netgroup-mod '%s'" % cn)
        assert 'cn' not in kw
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, netgroup_filter, netgroup_base)
        return ldap.update(dn, **kw)

    def output_for_cli(self, textui, result, cn, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_name(self.name)
        textui.print_entry(result)
        textui.print_dashed('Updated netgroup "%s"' % result['cn'])

api.register(netgroup_mod)


class netgroup_find(crud.Find):
    'Search the netgroups.'
    def execute(self, term, **kw):
        ldap = self.api.Backend.ldap

        search_fields = ['ipauniqueid','description','nisdomainname','cn']

        search_kw = {}
        for s in search_fields:
            search_kw[s] = term

        search_kw['objectclass'] = netgroup_filter
        search_kw['base'] = netgroup_base
        return ldap.search(**search_kw)

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
        for g in groups:
            textui.print_entry(g)
            textui.print_plain('')
        if counter == -1:
            textui.print_plain('These results are truncated.')
            textui.print_plain('Please refine your search and try again.')
        textui.print_count(groups, '%d netgroups matched')

api.register(netgroup_find)


class netgroup_show(crud.Get):
    'Examine an existing netgroup.'
    def execute(self, cn, **kw):
        """
        Execute the netgroup-show operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param cn: The name of the netgroup to retrieve.
        :param kw: Unused
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, netgroup_filter, netgroup_base)
        return ldap.retrieve(dn)

    def output_for_cli(self, textui, result, *args, **options):
        textui.print_entry(result)

api.register(netgroup_show)

class netgroup_add_member(Command):
    'Add a member to a group.'
    takes_args = (
        Str('cn',
            cli_name='name',
            primary_key=True
        ),
    )
    takes_options = (
        Str('hosts?', doc='comma-separated list of hosts to add'),
        Str('hostgroups?', doc='comma-separated list of host groups to add'),
        Str('users?', doc='comma-separated list of users to add'),
        Str('groups?', doc='comma-separated list of groups to add'),
    )

    def execute(self, cn, **kw):
        """
        Execute the netgroup-add-member operation.

        Returns the updated group entry

        :param cn: The netgroup name to add new members to.
        :param kw: hosts is a comma-separated list of hosts to add
        :param kw: hostgroups is a comma-separated list of host groups to add
        :param kw: users is a comma-separated list of users to add
        :param kw: groups is a comma-separated list of host to add
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, netgroup_filter, netgroup_base)
        add_failed = []
        to_add = []
        completed = 0

        # Hosts
        members = get_members(kw.get('hosts', ''))
        (to_add, add_failed) = find_members(ldap, add_failed, members, "cn", "ipaHost")

        # If a host is not found we'll consider it an externalHost. It will
        # be up to the user to handle typos
        if add_failed:
            (completed, failed) = add_external(ldap, completed, add_failed, cn)
            add_failed = failed

        (completed, failed) = add_members(ldap, completed, to_add, dn, 'memberhost')
        add_failed+=failed

        # Host groups
        members = get_members(kw.get('hostgroups', ''))
        (to_add, add_failed) = find_members(ldap, add_failed, members, "cn", hostgroup_filter)
        (completed, failed) = add_members(ldap, completed, to_add, dn, 'memberhost')
        add_failed+=failed

        # User
        members = get_members(kw.get('users', ''))
        (to_add, add_failed) = find_members(ldap, add_failed, members, "uid")
        (completed, failed) = add_members(ldap, completed, to_add, dn, 'memberuser')
        add_failed+=failed

        # Groups
        members = get_members(kw.get('groups', ''))
        (to_add, add_failed) = find_members(ldap, add_failed, members, "cn", "posixGroup")
        (completed, failed) = add_members(ldap, completed, to_add, dn, 'memberuser')
        add_failed+=failed

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
            textui.print_plain("netgroup membership updated.")

api.register(netgroup_add_member)


class netgroup_remove_member(Command):
    'Remove a member from a group.'
    takes_args = (
        Str('cn',
            cli_name='name',
            primary_key=True
        ),
    )
    takes_options = (
        Str('hosts?', doc='comma-separated list of hosts to remove'),
        Str('hostgroups?', doc='comma-separated list of groups to remove'),
        Str('users?', doc='comma-separated list of users to remove'),
        Str('groups?', doc='comma-separated list of groups to remove'),
    )
    def execute(self, cn, **kw):
        """
        Execute the group-remove-member operation.

        Returns the members that could not be added

        :param cn: The group name to add new members to.
        :param kw: hosts is a comma-separated list of hosts to remove
        :param kw: hostgroups is a comma-separated list of host groups to remove
        :param kw: users is a comma-separated list of users to remove
        :param kw: groups is a comma-separated list of host to remove
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, netgroup_filter, netgroup_base)
        remove_failed = []
        to_remove = []
        completed = 0

        # Hosts
        members = get_members(kw.get('hosts', ''))
        (to_remove, remove_failed) = find_members(ldap, remove_failed, members, "cn", "ipaHost")

        # If a host is not found we'll consider it an externalHost. It will
        # be up to the user to handle typos
        if remove_failed:
            (completed, failed) = remove_external(ldap, completed, remove_failed, cn)
            remove_failed = failed

        (completed, failed) = remove_members(ldap, completed, to_remove, dn, 'memberhost')
        remove_failed+=failed

        # Host groups
        members = get_members(kw.get('hostgroups', ''))
        (to_remove, remove_failed) = find_members(ldap, remove_failed, members, "cn", hostgroup_filter)
        (completed, failed) = remove_members(ldap, completed, to_remove, dn, 'memberhost')
        remove_failed+=failed

        # User
        members = get_members(kw.get('users', ''))
        (to_remove, remove_failed) = find_members(ldap, remove_failed, members, "uid")
        (completed, failed) = remove_members(ldap, completed, to_remove, dn, 'memberuser')
        remove_failed+=failed

        # Groups
        members = get_members(kw.get('groups', ''))
        (to_remove, remove_failed) = find_members(ldap, remove_failed, members, "cn", "posixGroup")
        (completed, failed) = remove_members(ldap, completed, to_remove, dn, 'memberuser')
        remove_failed+=failed

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
            textui.print_plain("netgroup membership updated.")

api.register(netgroup_remove_member)
