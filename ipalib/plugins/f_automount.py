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
Frontend plugins for automount.

RFC 2707bis http://www.padl.com/~lukeh/rfc2307bis.txt
"""

from ipalib import frontend
from ipalib import crud
from ipalib.frontend import Param
from ipalib import api
from ipalib import errors
from ipalib import ipa_types
from ldap import explode_dn

map_attributes = ['automountMapName', 'description', ]
key_attributes = ['description', 'automountKey', 'automountInformation']

def display_entry(entry):
    # FIXME: for now delete dn here. In the future pass in the kw to
    # output_for_cli()
    attr = sorted(entry.keys())

    for a in attr:
        if a != 'dn':
            print "%s: %s" % (a, entry[a])

def make_automount_dn(mapname):
    """
    Construct automount dn from map name.
    """
    # FIXME, should this be in b_ldap?
    # Experimenting to see what a plugin looks like for a 3rd party who can't
    # modify the backend.
    import ldap
    return 'automountmapname=%s,%s,%s' % (
        ldap.dn.escape_dn_chars(mapname),
        api.env.container_accounts,
        api.env.basedn,
    )

class automount(frontend.Object):
    """
    Automount object.
    """
    takes_params = (
        Param('automountmapname',
            cli_name='mapname',
            primary_key=True,
            doc='A group of related automount objects',
        ),
    )
api.register(automount)


class automount_addmap(crud.Add):
    'Add a new automount map.'
    takes_options = (
        Param('description?',
            doc='A description of the automount map'),
    )

    def execute(self, mapname, **kw):
        """
        Execute the automount-addmap operation.

        Returns the entry as it will be created in LDAP.

        :param mapname: The map name being added.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'automountmapname' not in kw
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap
        kw['automountmapname'] = mapname
        kw['dn'] = make_automount_dn(mapname)

        kw['objectClass'] = ['automountMap']

        return ldap.create(**kw)
    def output_for_cli(self, ret):
        """
        Output result of this command to command line interface.
        """
        if ret:
            print "Automount map added"

api.register(automount_addmap)


class automount_addkey(crud.Add):
    'Add a new automount key.'
    takes_options = (
        Param('automountkey',
            cli_name='key',
            doc='An entry in an automount map'),
        Param('automountinformation',
            cli_name='info',
            doc='Mount information for this key'),
        Param('description?',
            doc='A description of the mount'),
    )

    def execute(self, mapname, **kw):
        """
        Execute the automount-addkey operation.

        Returns the entry as it will be created in LDAP.

        :param mapname: The map name being added to.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'automountmapname' not in kw
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap
        # use find_entry_dn instead of make_automap_dn so we can confirm that
        # the map exists
        map_dn = ldap.find_entry_dn("automountmapname", mapname, "automountmap")
        kw['dn'] = "automountkey=%s,%s" % (kw['automountkey'], map_dn)

        kw['objectClass'] = ['automount']

        return ldap.create(**kw)
    def output_for_cli(self, ret):
        """
        Output result of this command to command line interface.
        """
        if ret:
            print "Automount key added"

api.register(automount_addkey)


class automount_delmap(crud.Del):
    'Delete an automount map.'
    def execute(self, mapname, **kw):
        """Delete an automount map. This will also remove all of the keys
           associated with this map.

           mapname is the automount map to remove

           :param mapname: The map to be removed
           :param kw: Not used.
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("automountmapname", mapname, "automountmap")
        keys = api.Command['automount_getkeys'](mapname)
        if keys:
            for k in keys:
                ldap.delete(k.get('dn'))
        return ldap.delete(dn)
    def output_for_cli(self, ret):
        """
        Output result of this command to command line interface.
        """
        if ret:
            print "Automount map and associated keys deleted"

api.register(automount_delmap)


class automount_delkey(crud.Del):
    'Delete an automount key.'
    takes_options = (
        Param('automountkey',
            cli_name='key',
            doc='The automount key to remove'),
    )
    def execute(self, mapname, **kw):
        """Delete an automount key.

           key is the automount key to remove

           :param mapname: The automount map containing the key to be removed
           :param kw: "key" the key to be removed
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("automountmapname", mapname, "automountmap")
        keys = api.Command['automount_getkeys'](mapname)
        keydn = None
        keyname = kw.get('automountkey').lower()
        if keys:
            for k in keys:
                if k.get('automountkey').lower() == keyname:
                    keydn = k.get('dn')
                    break
        if not keydn:
            raise errors.NotFound
        return ldap.delete(keydn)
    def output_for_cli(self, ret):
        """
        Output result of this command to command line interface.
        """
        if ret:
            print "Automount key deleted"

api.register(automount_delkey)

class automount_modmap(crud.Mod):
    'Edit an existing automount map.'
    takes_options = (
        Param('description?',
            doc='A description of the automount map'),
    )
    def execute(self, mapname, **kw):
        """
        Execute the automount-modmap operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param mapname: The map name to update.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'automountmapname' not in kw
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("automountmapname", mapname, "automountmap")
        return ldap.update(dn, **kw)

    def output_for_cli(self, ret):
        """
        Output result of this command to command line interface.
        """
        if ret:
            print "Automount map updated"

api.register(automount_modmap)


class automount_modkey(crud.Mod):
    'Edit an existing automount key.'
    takes_options = (
        Param('automountkey',
            cli_name='key',
            doc='An entry in an automount map'),
        Param('automountinformation?',
            cli_name='info',
            doc='Mount information for this key'),
        Param('description?',
            doc='A description of the automount map'),
    )
    def execute(self, mapname, **kw):
        """
        Execute the automount-modkey operation.

        Returns the entry

        :param mapname: The map name to update.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'automountmapname' not in kw
        assert 'dn' not in kw
        keyname = kw.get('automountkey').lower()
        del kw['automountkey']
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("automountmapname", mapname, "automountmap")
        keys = api.Command['automount_getkeys'](mapname)
        keydn = None
        if keys:
            for k in keys:
                if k.get('automountkey').lower() == keyname:
                    keydn = k.get('dn')
                    break
        if not keydn:
            raise errors.NotFound
        return ldap.update(keydn, **kw)

    def output_for_cli(self, ret):
        """
        Output result of this command to command line interface.
        """
        if ret:
            print "Automount key updated"
api.register(automount_modkey)


class automount_findmap(crud.Find):
    'Search automount maps.'
    takes_options = (
        Param('all?', type=ipa_types.Bool(), doc='Retrieve all attributes'),
    )
    def execute(self, term, **kw):
        ldap = self.api.Backend.ldap

        search_fields = map_attributes

        for s in search_fields:
            kw[s] = term

        kw['objectclass'] = 'automountMap'
        if kw.get('all', False):
            kw['attributes'] = ['*']
        else:
            kw['attributes'] = map_attributes
        return ldap.search(**kw)
    def output_for_cli(self, entries):
        if not entries:
            return
        counter = entries[0]
        entries = entries[1:]
        if counter == 0:
            print "No entries found"
            return
        elif counter == -1:
            print "These results are truncated."
            print "Please refine your search and try again."

        for e in entries:
            display_entry(e)
            print ""
api.register(automount_findmap)


class automount_findkey(crud.Find):
    'Search automount keys.'
    takes_options = (
        Param('all?', type=ipa_types.Bool(), doc='Retrieve all attributes'),
    )
    def get_args(self):
        return (Param('automountkey',
                   cli_name='key',
                   doc='An entry in an automount map'),)
    def execute(self, term, **kw):
        ldap = self.api.Backend.ldap

        search_fields = key_attributes

        for s in search_fields:
            kw[s] = term

        kw['objectclass'] = 'automount'
        if kw.get('all', False):
            kw['attributes'] = ['*']
        else:
            kw['attributes'] = key_attributes
        return ldap.search(**kw)
    def output_for_cli(self, entries):
        if not entries:
            return
        counter = entries[0]
        entries = entries[1:]
        if counter == 0:
            print "No entries found"
            return
        elif counter == -1:
            print "These results are truncated."
            print "Please refine your search and try again."

        for e in entries:
            display_entry(e)
            print ""
api.register(automount_findkey)


class automount_showmap(crud.Get):
    'Examine an existing automount map.'
    takes_options = (
        Param('all?', type=ipa_types.Bool(), doc='Retrieve all attributes'),
    )
    def execute(self, mapname, **kw):
        """
        Execute the automount-showmap operation.

        Returns the entry

        :param mapname: The automount map to retrieve
        :param kw: "all" set to True = return all attributes
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("automountmapname", mapname, "automountmap")
        # FIXME: should kw contain the list of attributes to display?
        if kw.get('all', False):
            return ldap.retrieve(dn)
        else:
            return ldap.retrieve(dn, map_attributes)
    def output_for_cli(self, entry):
        if entry:
            display_entry(entry)

api.register(automount_showmap)


class automount_showkey(crud.Get):
    'Examine an existing automount key.'
    takes_options = (
        Param('automountkey',
            cli_name='key',
            doc='The automount key to display'),
        Param('all?', type=ipa_types.Bool(), doc='Retrieve all attributes'),
    )
    def execute(self, mapname, **kw):
        """
        Execute the automount-showkey operation.

        Returns the entry

        :param mapname: The mapname to examine
        :param kw: "automountkey" the key to retrieve
        :param kw: "all" set to True = return all attributes
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("automountmapname", mapname, "automountmap")
        keys = api.Command['automount_getkeys'](mapname)
        keyname = kw.get('automountkey').lower()
        keydn = None
        if keys:
            for k in keys:
                if k.get('automountkey').lower() == keyname:
                    keydn = k.get('dn')
                    break
        if not keydn:
            raise errors.NotFound
        # FIXME: should kw contain the list of attributes to display?
        if kw.get('all', False):
            return ldap.retrieve(keydn)
        else:
            return ldap.retrieve(keydn, key_attributes)
    def output_for_cli(self, entry):
        # The automount map name associated with this key is available only
        # in the dn. Add it as an attribute to display instead.
        if entry and not entry.get('automountmapname'):
            elements = explode_dn(entry.get('dn').lower())
            for e in elements:
                (attr, value) = e.split('=',1)
                if attr == 'automountmapname':
                    entry['automountmapname'] = value
            display_entry(entry)

api.register(automount_showkey)


class automount_getkeys(frontend.Command):
    'Retrieve all keys for an automount map.'
    takes_args = (
        Param('automountmapname',
            cli_name='mapname',
            primary_key=True,
            doc='A group of related automount objects',
        ),
    )
    def execute(self, mapname, **kw):
        """
        Execute the automount-getkeys operation.

        Return a list of all automount keys for this mapname

        :param mapname: Retrieve all keys for this mapname
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("automountmapname", mapname, "automountmap")
        try:
            keys = ldap.get_one_entry(dn, 'objectclass=*', ['automountkey'])
        except errors.NotFound:
            keys = []

        return keys
    def output_for_cli(self, keys):
        if keys:
            for k in keys:
                print k.get('automountkey')

api.register(automount_getkeys)
