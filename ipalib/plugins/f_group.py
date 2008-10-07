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

from ipalib import frontend
from ipalib import crud
from ipalib.frontend import Param
from ipalib import api
from ipa_server import servercore
from ipa_server import ipaldap
import ldap


class group(frontend.Object):
    """
    Group object.
    """
    takes_params = (
        'description',
        Param('cn',
            primary_key=True,
            normalize=lambda value: value.lower(),
        )
    )
api.register(group)


class group_add(crud.Add):
    'Add a new group.'
    def execute(self, *args, **kw):
        """args[0] = uid of the group to add
           kw{container} is the location in the DIT to add the group, not
           required
           kw otherwise contains all the attributes 
        """
        # FIXME: ug, really?
        if not kw.get('container'):
            group_container = servercore.DefaultGroupContainer
        else:
            group_container = kw['container']
            del kw['container']

        group = kw

        group['cn'] = args[0]

        # Get our configuration
        config = servercore.get_ipa_config()

        dn="cn=%s,%s,%s" % (ldap.dn.escape_dn_chars(group['cn']),
                            group_container,servercore.basedn)

        entry = ipaldap.Entry(dn)

        # some required objectclasses
        entry.setValues('objectClass', (config.get('ipagroupobjectclasses')))

        # No need to explicitly set gidNumber. The dna_plugin will do this
        # for us if the value isn't provided by the user.

        # fill in our new entry with everything sent by the user
        for g in group:
            entry.setValues(g, group[g])

        result = servercore.add_entry(entry)
        return result


api.register(group_add)


class group_del(crud.Del):
    'Delete an existing group.'
api.register(group_del)


class group_mod(crud.Mod):
    'Edit an existing group.'
api.register(group_mod)


class group_find(crud.Find):
    'Search the groups.'
    def execute(self, *args, **kw):
        cn=args[0]
        result = servercore.get_sub_entry(servercore.basedn, "cn=%s" % cn, ["*"])
        return result
    def forward(self, *args, **kw):
        result = super(crud.Find, self).forward(*args, **kw)
        for a in result:
            print a, ": ", result[a]
api.register(group_find)


class group_show(crud.Get):
    'Examine an existing group.'
api.register(group_show)
