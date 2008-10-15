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
from ipa_server import ipautil
import ldap


class group(frontend.Object):
    """
    Group object.
    """
    takes_params = (
        'description',
        Param('cn',
            cli_name='name',
            primary_key=True,
            normalize=lambda value: value.lower(),
        )
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
        config = servercore.get_ipa_config()

        # some required objectclasses
        kw['objectClass'] =  config.get('ipagroupobjectclasses')

        return ldap.create(**kw)

    def output_for_cli(self, ret):
        """
        Output result of this command to command line interface.
        """
        if ret:
            print "Group added"

api.register(group_add)


class group_del(crud.Del):
    'Delete an existing group.'
    def execute(self, *args, **kw):
        """args[0] = dn of the group to remove

           Delete a group

           The memberOf plugin handles removing the group from any other
           groups.
        """
        group_dn = args[0]

        group = servercore.get_entry_by_dn(group_dn, ['dn', 'cn'])
        if group is None:
            raise errors.NotFound
#        logging.info("IPA: delete_group '%s'" % group_dn)

        # We have 2 special groups, don't allow them to be removed
        # FIXME
#        if "admins" in group.get('cn') or "editors" in group.get('cn'):
#            raise ipaerror.gen_exception(ipaerror.CONFIG_REQUIRED_GROUPS)

        # Don't allow the default user group to be removed
        config=servercore.get_ipa_config()
        default_group = servercore.get_entry_by_cn(config.get('ipadefaultprimarygroup'), None)
        if group_dn == default_group.get('dn'):
            raise errors.DefaultGroup

        return servercore.delete_entry(group_dn)
    def forward(self, *args, **kw):
        group = self.api.Command['group_show'](ipautil.utf8_encode_value(args[0]))
        if not group:
            print "nothing found"
            return False
        a = group.get('dn')
        result = super(crud.Del, self).forward(a)
api.register(group_del)


class group_mod(crud.Mod):
    'Edit an existing group.'
    def execute(self, *args, **kw):
        group_cn=args[0]
        result = servercore.get_entry_by_cn(group_cn, ["*"])

        group = kw
        dn = result.get('dn')
        del result['dn']
        entry = ipaldap.Entry((dn, servercore.convert_scalar_values(result)))

        for g in group:
            entry.setValues(g, group[g])

        result = servercore.update_entry(entry.toDict())

        return result
    def forward(self, *args, **kw):
        result = super(crud.Mod, self).forward(*args, **kw)
        if result:
            print "Group %s modified" % args[0]
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
    def execute(self, *args, **kw):
        cn=args[0]
        result = servercore.get_sub_entry(servercore.basedn, "cn=%s" % cn, ["*"])
        return result
    def forward(self, *args, **kw):
        result = super(crud.Get, self).forward(*args, **kw)
        return result
api.register(group_show)
