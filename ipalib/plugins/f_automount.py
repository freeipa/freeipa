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

A few notes on automount:
- It was a design decision to not support different maps by location
- The default parent when adding an indirect map is auto.master
- This uses the short format for automount maps instead of the
  URL format. Support for ldap as a map source in nsswitch.conf was added
  in autofs version 4.1.3-197.  Any version prior to that is not expected
  to work.

As an example, the following automount files:

auto.master:
/-	auto.direct
/mnt	auto.mnt

auto.mnt:
stuff -ro,soft,rsize=8192,wsize=8192 nfs.example.com:/vol/archive/stuff

are equivalent to the following LDAP entries:

# auto.master, automount, example.com
dn: automountmapname=auto.master,cn=automount,dc=example,dc=com
objectClass: automountMap
objectClass: top
automountMapName: auto.master

# auto.direct, automount, example.com
dn: automountmapname=auto.direct,cn=automount,dc=example,dc=com
objectClass: automountMap
objectClass: top
automountMapName: auto.direct

# /-, auto.master, automount, example.com
dn: automountkey=/-,automountmapname=auto.master,cn=automount,dc=example,dc=co
 m
objectClass: automount
objectClass: top
automountKey: /-
automountInformation: auto.direct

# auto.mnt, automount, example.com
dn: automountmapname=auto.mnt,cn=automount,dc=example,dc=com
objectClass: automountMap
objectClass: top
automountMapName: auto.mnt

# /mnt, auto.master, automount, example.com
dn: automountkey=/mnt,automountmapname=auto.master,cn=automount,dc=example,dc=
 com
objectClass: automount
objectClass: top
automountKey: /mnt
automountInformation: auto.mnt

# stuff, auto.mnt, automount, example.com
dn: automountkey=stuff,automountmapname=auto.mnt,cn=automount,dc=example,dc=com
objectClass: automount
objectClass: top
automountKey: stuff
automountInformation: -ro,soft,rsize=8192,wsize=8192 nfs.example.com:/vol/arch
 ive/stuff

"""

from ldap import explode_dn
from ipalib import crud, errors2
from ipalib import api, Str, Flag, Object, Command

map_attributes = ['automountMapName', 'description', ]
key_attributes = ['description', 'automountKey', 'automountInformation']

def display_entry(textui, entry):
    # FIXME: for now delete dn here. In the future pass in the kw to
    # output_for_cli()
    attr = sorted(entry.keys())

    for a in attr:
        if a != 'dn':
            textui.print_plain("%s: %s" % (a, entry[a]))

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
        api.env.container_automount,
        api.env.basedn,
    )


def make_ldap_map(ldapuri, mapname):
    """
    Convert a map name into an LDAP name.

    Note: This is unused currently. This would return map names as a
    quasi ldap URL which will work with older autofs clients. We are
    not currently supporting them.
    """
    if not ldapuri:
        return mapname
    if mapname.find('ldap:') >= 0:
        return mapname

    return 'ldap:%s:%s' % (api.env.host, make_automount_dn(mapname))


class automount(Object):
    """
    Automount object.
    """
    takes_params = (
        Str('automountmapname',
            cli_name='mapname',
            primary_key=True,
            doc='A group of related automount objects',
        ),
    )
api.register(automount)


class automount_addmap(crud.Add):
    'Add a new automount map.'

    takes_options = (
        Str('description?',
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

    def output_for_cli(self, textui, result, map, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_plain("Automount map %s added" % map)

api.register(automount_addmap)


class automount_addkey(crud.Add):
    'Add a new automount key.'
    takes_options = (
        Str('automountkey',
            cli_name='key',
            doc='An entry in an automount map'),
        Str('automountinformation',
            cli_name='info',
            doc='Mount information for this key'),
        Str('description?',
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
        config = ldap.get_ipa_config()
        # use find_entry_dn instead of make_automap_dn so we can confirm that
        # the map exists
        map_dn = ldap.find_entry_dn("automountmapname", mapname, "automountmap", api.env.container_automount)
        kw['dn'] = "automountkey=%s,%s" % (kw['automountkey'], map_dn)

        kw['automountinformation'] = make_ldap_map(config.get('automountldapuri', False), kw['automountinformation'])

        kw['objectClass'] = ['automount']

        return ldap.create(**kw)

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_plain("Automount key added")

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
        dn = ldap.find_entry_dn("automountmapname", mapname, "automountmap", api.env.container_automount)

        # First remove all the keys for this map so we don't leave orphans
        keys = api.Command['automount_getkeys'](mapname)
        for k in keys:
                ldap.delete(k.get('dn'))

        # Now remove the parental connection
        try:
            infodn = ldap.find_entry_dn("automountinformation", mapname, "automount", api.env.container_automount)
            ldap.delete(infodn)
        except errors2.NotFound:
            # direct maps may not have this
            pass

        return ldap.delete(dn)
    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        print "Automount map and associated keys deleted"

api.register(automount_delmap)


class automount_delkey(crud.Del):
    'Delete an automount key.'
    takes_options = (
        Str('automountkey',
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
        dn = ldap.find_entry_dn("automountmapname", mapname, "automountmap", api.env.container_automount)
        keys = api.Command['automount_getkeys'](mapname)
        keydn = None
        keyname = kw.get('automountkey').lower()
        if keys:
            for k in keys:
                if k.get('automountkey').lower() == keyname:
                    keydn = k.get('dn')
                    break
        if not keydn:
            raise errors2.NotFound(msg='Entry not found')
        return ldap.delete(keydn)
    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        print "Automount key deleted"

api.register(automount_delkey)

class automount_modmap(crud.Mod):
    'Edit an existing automount map.'
    takes_options = (
        Str('description?',
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
        dn = ldap.find_entry_dn("automountmapname", mapname, "automountmap", api.env.container_automount)
        return ldap.update(dn, **kw)

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        print "Automount map updated"

api.register(automount_modmap)


class automount_modkey(crud.Mod):
    'Edit an existing automount key.'
    takes_options = (
        Str('automountkey',
            cli_name='key',
            doc='An entry in an automount map'),
        Str('automountinformation?',
            cli_name='info',
            doc='Mount information for this key'),
        Str('description?',
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
        dn = ldap.find_entry_dn("automountmapname", mapname, "automountmap", api.env.container_automount)
        keys = api.Command['automount_getkeys'](mapname)
        keydn = None
        if keys:
            for k in keys:
                if k.get('automountkey').lower() == keyname:
                    keydn = k.get('dn')
                    break
        if not keydn:
            raise errors2.NotFound(msg='Entry not found')
        return ldap.update(keydn, **kw)

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        print "Automount key updated"

api.register(automount_modkey)


class automount_findmap(crud.Find):
    'Search automount maps.'
    takes_options = (
        Flag('all', doc='Retrieve all attributes'),
    )
    def execute(self, term, **kw):
        ldap = self.api.Backend.ldap

        search_fields = map_attributes

        for s in search_fields:
            kw[s] = term

        kw['objectclass'] = 'automountMap'
        kw['base'] = api.env.container_automount
        if kw.get('all', False):
            kw['attributes'] = ['*']
        else:
            kw['attributes'] = map_attributes
        return ldap.search(**kw)

    def output_for_cli(self, textui, result, *args, **options):
        counter = result[0]
        entries = result[1:]
        if counter == 0:
            textui.print_plain("No entries found")
            return
        elif counter == -1:
            textui.print_plain("These results are truncated.")
            textui.print_plain("Please refine your search and try again.")

        for e in entries:
            display_entry(textui, e)
            textui.print_plain("")

api.register(automount_findmap)


class automount_findkey(crud.Find):
    'Search automount keys.'
    takes_options = (
        Flag('all?', doc='Retrieve all attributes'),
    )
    def get_args(self):
        return (Str('automountkey',
                   cli_name='key',
                   doc='An entry in an automount map'),)
    def execute(self, term, **kw):
        ldap = self.api.Backend.ldap

        search_fields = key_attributes

        for s in search_fields:
            kw[s] = term

        kw['objectclass'] = 'automount'
        kw['base'] = api.env.container_automount
        if kw.get('all', False):
            kw['attributes'] = ['*']
        else:
            kw['attributes'] = key_attributes
        return ldap.search(**kw)
    def output_for_cli(self, textui, result, *args, **options):
        counter = result[0]
        entries = result[1:]
        if counter == 0:
            textui.print_plain("No entries found")
            return
        elif counter == -1:
            textui.print_plain("These results are truncated.")
            textui.print_plain("Please refine your search and try again.")

        for e in entries:
            display_entry(textui, e)
            textui.print_plain("")

api.register(automount_findkey)


class automount_showmap(crud.Get):
    'Examine an existing automount map.'
    takes_options = (
        Flag('all?', doc='Retrieve all attributes'),
    )
    def execute(self, mapname, **kw):
        """
        Execute the automount-showmap operation.

        Returns the entry

        :param mapname: The automount map to retrieve
        :param kw: "all" set to True = return all attributes
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("automountmapname", mapname, "automountmap", api.env.container_automount)
        # FIXME: should kw contain the list of attributes to display?
        if kw.get('all', False):
            return ldap.retrieve(dn)
        else:
            return ldap.retrieve(dn, map_attributes)
    def output_for_cli(self, textui, result, *args, **options):
        if result:
            display_entry(textui, result)

api.register(automount_showmap)


class automount_showkey(crud.Get):
    'Examine an existing automount key.'
    takes_options = (
        Str('automountkey',
            cli_name='key',
            doc='The automount key to display'),
        Flag('all?', doc='Retrieve all attributes'),
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
        dn = ldap.find_entry_dn("automountmapname", mapname, "automountmap", api.env.container_automount)
        keys = api.Command['automount_getkeys'](mapname)
        keyname = kw.get('automountkey').lower()
        keydn = None
        if keys:
            for k in keys:
                if k.get('automountkey').lower() == keyname:
                    keydn = k.get('dn')
                    break
        if not keydn:
            raise errors2.NotFound(msg='Entry not found')
        # FIXME: should kw contain the list of attributes to display?
        if kw.get('all', False):
            return ldap.retrieve(keydn)
        else:
            return ldap.retrieve(keydn, key_attributes)
    def output_for_cli(self, textui, result, *args, **options):
        # The automount map name associated with this key is available only
        # in the dn. Add it as an attribute to display instead.
        if result and not result.get('automountmapname'):
            elements = explode_dn(result.get('dn').lower())
            for e in elements:
                (attr, value) = e.split('=',1)
                if attr == 'automountmapname':
                    result['automountmapname'] = value
            display_entry(textui, result)

api.register(automount_showkey)


class automount_getkeys(Command):
    'Retrieve all keys for an automount map.'
    takes_args = (
        Str('automountmapname',
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
        dn = ldap.find_entry_dn("automountmapname", mapname, "automountmap", api.env.container_automount)
        try:
            keys = ldap.get_one_entry(dn, 'objectclass=*', ['*'])
        except errors2.NotFound:
            keys = []

        return keys
    def output_for_cli(self, textui, result, *args, **options):
        for k in result:
            textui.print_plain('%s' % k.get('automountkey'))

api.register(automount_getkeys)


class automount_getmaps(Command):
    'Retrieve all automount maps'
    takes_args = (
        Str('automountmapname?',
            cli_name='mapname',
            primary_key=True,
            doc='A group of related automount objects',
            default=u'auto.master',
        ),
    )
    def execute(self, mapname, **kw):
        """
        Execute the automount-getmaps operation.

        Return a list of all automount maps.
        """

        ldap = self.api.Backend.ldap
        base = api.env.container_automount + "," + api.env.basedn

        search_base = "automountmapname=%s,%s" % (mapname, base)
        maps = ldap.get_one_entry(search_base, "objectClass=*", ["*"])

        return maps
    def output_for_cli(self, textui, result, *args, **options):
        for k in result:
            textui.print_plain('%s: %s' % (k.get('automountinformation'), k.get('automountkey')))

api.register(automount_getmaps)

class automount_addindirectmap(crud.Add):
    """
    Add a new automap indirect mount point.
    """

    takes_options = (
        Str('parentmap?',
            cli_name='parentmap',
            default=u'auto.master',
            doc='The parent map to connect this to.',
        ),
        Str('automountkey',
            cli_name='key',
            doc='An entry in an automount map',
        ),
        Str('description?',
            doc='A description of the automount map',
        ),
    )

    def execute(self, mapname, **kw):
        """
        Execute the automount-addindirectmap operation.

        Returns the key entry as it will be created in LDAP.

        This function creates 2 LDAP entries. It creates an
        automountmapname entry and an automountkey entry.

        :param mapname: The map name being added.
        :param kw['parentmap'] is the top-level map to add this to.
           defaulting to auto.master
        :param kw['automountkey'] is the mount point
        :param kw['description'] is a textual description of this map
        """
        mapkw = {}
        if kw.get('description'):
            mapkw['description'] = kw.get('description')
        newmap = api.Command['automount_addmap'](mapname, **mapkw)

        keykw = {'automountkey': kw['automountkey'], 'automountinformation': mapname}
        if kw.get('description'):
            keykw['description'] = kw.get('description')
        newkey = api.Command['automount_addkey'](kw['parentmap'], **keykw)

        return newkey
    def output_for_cli(self, textui, result, map, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_plain("Indirect automount map %s added" % map)

api.register(automount_addindirectmap)


class automount_tofiles(Command):
    'Generate the automount maps as they would be in the filesystem'
    def execute(self, **kw):
        """
        Execute the automount-getmaps operation.

        Return a list of all automount maps.
        """

        ldap = self.api.Backend.ldap
        base = api.env.container_automount + "," + api.env.basedn

        search_base = "automountmapname=auto.master,%s" % base
        maps = ldap.get_one_entry(search_base, "objectClass=autoMount", ["*"])

        mapkeys = {}
        for m in maps:
            keys = api.Command['automount_getkeys'](m.get('automountinformation').decode('UTF-8'))
            mapkeys[m.get('automountinformation')] = keys

        return maps, mapkeys
    def output_for_cli(self, textui, result, **options):
        maps = result[0]
        keys = result[1]
        textui.print_plain("/etc/auto.master:")
        for m in maps:
            textui.print_plain('%s\t/etc/%s' % (m.get('automountkey'), m.get('automountinformation')))
        for m in maps:
            textui.print_plain('---------------------------')
            textui.print_plain('/etc/%s:' % m.get('automountinformation'))
            mapkeys = keys.get(m.get('automountinformation'))
            for k in mapkeys:
                textui.print_plain('%s\t%s' % (k.get('automountkey'), k.get('automountinformation')))

api.register(automount_tofiles)
