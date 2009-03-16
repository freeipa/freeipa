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
Frontend plugins for taskgroups.
"""

from ipalib import api, crud, errors, errors2
from ipalib import Object, Command  # Plugin base classes
from ipalib import Str, Int, Flag  # Parameter types

default_attributes = ['cn','description']
container_taskgroup = "cn=taskgroups"

def make_taskgroup_dn(cn):
    """
    Construct group dn from cn.
    """
    import ldap
    return 'cn=%s,%s,%s' % (
        ldap.dn.escape_dn_chars(cn),
        container_taskgroup,
        api.env.basedn,
    )

class taskgroup(Object):
    """
    taskgroup object.
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
api.register(taskgroup)


class taskgroup_add(crud.Add):
    'Add a new group.'

    def execute(self, cn, **kw):
        """
        Execute the taskgroup-add operation.

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
        entry = self.args_options_2_entry(cn, **kw)
        entry['dn'] = make_taskgroup_dn(cn)

        # some required objectclasses
        entry['objectClass'] = ['top','groupofnames']

        return ldap.create(**entry)

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_name(self.name)
        textui.print_entry(result)
        textui.print_dashed('Added group "%s"' % result['cn'])

api.register(taskgroup_add)


class taskgroup_del(crud.Del):
    'Delete an existing group.'
    def execute(self, cn, **kw):
        """
        Delete a group

        :param cn: The name of the group being removed
        :param kw: Unused
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, "groupofnames", container_taskgroup)
        self.log.info("IPA: taskgroup-del '%s'" % dn)

        return ldap.delete(dn)

    def output_for_cli(self, textui, result, cn):
        """
        Output result of this command to command line interface.
        """
        textui.print_plain("Deleted group %s" % cn)

api.register(taskgroup_del)


class taskgroup_mod(crud.Mod):
    'Edit an existing group.'
    def execute(self, cn, **kw):
        """
        Execute the taskgroup-mod operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param cn: The name of the group to update.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'cn' not in kw
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, "groupofnames", container_taskgroup)

        return ldap.update(dn, **kw)

    def output_for_cli(self, textui, result, cn, **options):
        """
        Output result of this command to command line interface.
        """
        if result:
            textui.print_plain("Group updated")

api.register(taskgroup_mod)


class taskgroup_find(crud.Find):
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
        search_kw['base'] = container_taskgroup
        search_kw['objectclass'] = "groupofnames"
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

api.register(taskgroup_find)


class taskgroup_show(crud.Get):
    'Examine an existing group.'
    takes_options = (
        Flag('all', doc='Retrieve all attributes'),
    )
    def execute(self, cn, **kw):
        """
        Execute the taskgroup-show operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param cn: The group name to retrieve.
        :param kw: Not used.
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, "groupofnames", container_taskgroup)

        # FIXME: should kw contain the list of attributes to display?
        if kw.get('all', False):
            return ldap.retrieve(dn)
        else:
            return ldap.retrieve(dn, default_attributes)

    def output_for_cli(self, textui, result, *args, **options):
        textui.print_entry(result)

api.register(taskgroup_show)
