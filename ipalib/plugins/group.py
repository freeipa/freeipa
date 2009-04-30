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
Frontend plugins for groups.
"""

from ipalib import api
from ipalib.plugins.basegroup import *

container_group = api.env.container_group
display_attributes = ['cn','description','gidnumber','member','memberof']
default_class = 'ipaUserGroup'

class group(BaseGroup):
    """
    group object.
    """
    container=container_group
    takes_params =  BaseGroup.takes_params + (
        Int('gidnumber?',
            cli_name='gid',
            doc='The gid to use for this group. If not included one is automatically set.',
            attribute=True,
        ),
    )

api.register(group)


class group_add(basegroup_add):
    'Add a new group.'
    takes_options = (
        Flag('posix',
             doc='Create as a posix group',
             attribute=False,
        ),
    )

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
        """
        entry = self.args_options_2_entry(cn, **kw)
        entry['dn'] = ldap.make_group_dn(cn)
        """

        # Get our configuration
        config = ldap.get_ipa_config()

        # some required objectclasses
        kw['objectclass'] = config.get('ipagroupobjectclasses')
        if kw.get('posix') or kw.get('gidnumber'):
            kw['objectclass'].append('posixGroup')
            if kw.has_key('posix'):
                del kw['posix']

        return super(group_add, self).execute(cn, **kw)

api.register(group_add)


class group_del(basegroup_del):
    'Delete an existing group.'
    container = container_group
    filter_class = default_class

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
        dn = ldap.find_entry_dn("cn", cn, self.filter_class)

        # Don't allow the default user group to be removed
        try:
            config=ldap.get_ipa_config()
            default_group = ldap.find_entry_dn("cn", config.get('ipadefaultprimarygroup'), self.filter_class)
            if dn == default_group:
                raise errors.DefaultGroup
        except errors.NotFound:
            pass

        return super(group_del, self).execute(cn, **kw)

api.register(group_del)


class group_mod(basegroup_mod):
    'Edit an existing group.'
    container = container_group
    filter_class = default_class

    takes_options = (
        Flag('posix',
             doc='Make this group a posix group',
             attribute=False,
        ),
    )
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
        oldgroup = None

        if kw.has_key('gidnumber') or kw.get('posix'):
            groupkw = {'all': True}
            oldgroup = api.Command['group_show'](cn, **groupkw)

        # Are we promoting a non-posix group into a posix one? We just
        # need to add the posixGroup objectclass to the list and the
        # DNA plugin will handle assigning a new gidNumber for us.
        if kw.get('posix'):
            if oldgroup.get('gidnumber'):
                raise errors.AlreadyPosixGroup
            else:
                oldgroup['objectclass'].append('posixgroup')
                kw['objectclass'] = oldgroup['objectclass']

        if kw.has_key('gidnumber') and not oldgroup.has_key('gidnumber'):
            oldgroup['objectclass'].append('posixgroup')
            kw['objectclass'] = oldgroup['objectclass']

        if kw.has_key('posix'):
            # we want this gone whether it is True or False
            del kw['posix']

        if isinstance(kw.get('gidnumber',''), int):
            # python-ldap wants this as a string
            kw['gidnumber'] = str(kw['gidnumber'])

        return super(group_mod, self).execute(cn, **kw)

api.register(group_mod)


class group_find(basegroup_find):
    'Search the groups.'
    default_attributes = display_attributes
    container = container_group
    filter_class = default_class

api.register(group_find)


class group_show(basegroup_show):
    'Examine an existing group.'
    default_attributes = display_attributes
    container = container_group

api.register(group_show)


class group_add_member(basegroup_add_member):
    'Add a member to a group.'
    container = container_group

api.register(group_add_member)


class group_remove_member(basegroup_remove_member):
    'Remove a member from a group.'
    container = container_group

api.register(group_remove_member)
