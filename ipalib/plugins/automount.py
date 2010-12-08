# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
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
Automount

Stores automount(8) configuration for autofs(8) in IPA.

The base of an automount configuration is the configuration file auto.master.
This is also the base location in IPA. Multiple auto.master configurations
can be stored in separate locations. A location is implementation-specific
with the default being a location named 'default'. For example, you can have
locations by geographic region, by floor, by type, etc.

Automount has three basic object types: locations, maps and keys.

A location defines a set of maps anchored in auto.master. This allows you
to store multiple automount configurations. A location in itself isn't
very interesting, it is just a point to start a new automount map.

A map is roughly equivalent to discrete automount files. It is storage
location for keys.

A key is a mount point associated to a map.

When a new location is created two maps are automatically created for
it: auto.master and auto.direct. auto.master is the root map for all
automount maps for the location. auto.direct is the default map for
direct mounts and is mounted on /-.

EXAMPLES:

Locations:

  Create a named location, "Baltimore":
    ipa automountlocation-add baltimore

  Display the new locations:
    ipa automountlocation-show baltimore

  Find available locations:
    ipa automountlocation-find

  Remove a named automount location:
    ipa automountlocation-del baltimore

  Show what the automount maps would look like if they were in the filesystem:
    ipa automountlocation-tofiles baltimore

  Import an existing configuration into a location:
    ipa automountlocation-import baltimore /etc/auto.master

    The import will fail if any duplicate entries are found. For
    continous operation where errors are ignored use the --continue
    option.

Maps:

  Create a new map, "auto.share":
    ipa automountmap-add baltimore auto.share

  Display the new map:
    ipa automountmap-show baltimore auto.share

  Find maps in the location baltimore:
    ipa automountmap-find baltimore

  Remove the auto.share map:
    ipa automountmap-del baltimore auto.share

Keys:

  Create a new key for the auto.share map in location baltimore. This ties
  the map we previously created to auto.master:
  ipa automountkey-add baltimore auto.master /share --info=auto.share

  Create a new key for our auto.share map, an NFS mount for man pages:
    ipa automountkey-add baltimore auto.share man --info="-ro,soft,rsize=8192,wsize=8192 ipa.example.com:/shared/man"

  Find all keys for the auto.share map:
    ipa automountkey-find baltimore auto.share

  Remove the man key from the auto.share map:
    ipa automountkey-del baltimore auto.share man
"""

"""
Developer notes:

RFC 2707bis http://www.padl.com/~lukeh/rfc2307bis.txt

A few notes on automount:
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
from ipalib import api, errors
from ipalib import Object, Command
from ipalib import Flag, Str, IA5Str
from ipalib.plugins.baseldap import *
from ipalib import _, ngettext
import os


class automountlocation(LDAPObject):
    """
    Location container for automount maps.
    """
    container_dn = api.env.container_automount
    object_name = 'automount location'
    object_name_plural = 'automount locations'
    object_class = ['nscontainer']
    default_attributes = ['cn']
    label = _('Automount')


    takes_params = (
        Str('cn',
            cli_name='location',
            label=_('Location'),
            doc=_('Automount location name'),
            primary_key=True,
        ),
    )

api.register(automountlocation)


class automountlocation_add(LDAPCreate):
    """
    Create new automount location.
    """
    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        # create auto.master for the new location
        self.api.Command['automountmap_add'](keys[-1], u'auto.master')
        self.api.Command['automountmap_add_indirect'](
            keys[-1], u'auto.direct', key=u'/-'
        )
        return dn

api.register(automountlocation_add)


class automountlocation_del(LDAPDelete):
    """
    Delete automount location.
    """

api.register(automountlocation_del)


class automountlocation_show(LDAPRetrieve):
    """
    Display automount location.
    """

api.register(automountlocation_show)


class automountlocation_find(LDAPSearch):
    """
    Search for automount locations.
    """

api.register(automountlocation_find)


class automountlocation_tofiles(LDAPQuery):
    """
    Generate automount files for a specific location.
    """
    def execute(self, *args, **options):
        ldap = self.obj.backend

        location = self.api.Command['automountlocation_show'](args[0])

        maps = []
        result = self.api.Command['automountkey_find'](args[0], u'auto.master')
        truncated = result['truncated']
        maps = result['result']

        # maps, truncated
        # TODO: handle truncated results
        #       ?use ldap.find_entries instead of automountkey_find?

        keys = {}
        for m in maps:
            info = m['automountinformation'][0]
            key = info.split(None)
            result = self.api.Command['automountkey_find'](args[0], key[0])
            truncated = result['truncated']
            keys[info] = result['result']
            # TODO: handle truncated results, same as above

        return dict(result=dict(maps=maps, keys=keys))

    def output_for_cli(self, textui, result, *keys, **options):
        maps = result['result']['maps']
        keys = result['result']['keys']

        textui.print_plain('/etc/auto.master:')
        for m in maps:
            if m['automountinformation'][0].startswith('-'):
                textui.print_plain(
                    '%s\t%s' % (
                        m['automountkey'][0], m['automountinformation'][0]
                    )
                )
            else:
                textui.print_plain(
                    '%s\t/etc/%s' % (
                        m['automountkey'][0], m['automountinformation'][0]
                    )
                )
        for m in maps:
            if m['automountinformation'][0].startswith('-'):
                continue
            info = m['automountinformation'][0]
            textui.print_plain('---------------------------')
            textui.print_plain('/etc/%s:' % info)
            for k in keys[info]:
                textui.print_plain(
                    '%s\t%s' % (
                        k['automountkey'][0], k['automountinformation'][0]
                    )
                )

api.register(automountlocation_tofiles)


class automountlocation_import(LDAPQuery):
    """
    Import automount files for a specific location.
    """

    takes_args = (
        Str('masterfile',
            label=_('Master file'),
            doc=_('Automount master file'),
        ),
    )

    takes_options = (
        Flag('continue?',
             cli_name='continue',
             doc=_('Continous operation mode. Errors are reported but the process continues'),
        ),
    )

    def __read_mapfile(self, filename):
        try:
            fp = open(filename, 'r')
            map = fp.readlines()
            fp.close()
        except IOError, e:
            if e.errno == 2:
                raise errors.NotFound(reason=_('File %(file)s not found' % {'file':filename}))
            else:
                raise e
        return map

    def forward(self, *args, **options):
        """
        The basic idea is to read the master file and create all the maps
        we need, then read each map file and add all the keys for the map.
        """
        location = self.api.Command['automountlocation_show'](args[0])

        result = {'maps':[], 'keys':[], 'skipped':[], 'duplicatekeys':[], 'duplicatemaps':[]}
        maps = {}
        master = self.__read_mapfile(args[1])
        for m in master:
            if m.startswith('#'):
                continue
            m = m.rstrip()
            if m.startswith('+'):
                result['skipped'].append([m,args[1]])
                continue
            if len(m) == 0:
                continue
            am = m.split(None)
            if len(am) < 2:
                continue

            if am[1].startswith('/'):
                mapfile = am[1].replace('"','')
                am[1] = os.path.basename(am[1])
                maps[am[1]] = mapfile
            info = ' '.join(am[1:])

            # Add a new key to the auto.master map for the new map file
            try:
                api.Command['automountkey_add'](args[0], u'auto.master', unicode(am[0]), automountinformation=unicode(' '.join(am[1:])))
                result['keys'].append([am[0], u'auto.master'])
            except errors.DuplicateEntry, e:
                if options.get('continue', False):
                    result['duplicatekeys'].append(am[0])
                    pass
                else:
                    raise errors.DuplicateEntry(message=unicode('key %(key)s already exists' % {'key':am[0]}))
            # Add the new map
            if not am[1].startswith('-'):
                try:
                    api.Command['automountmap_add'](args[0], unicode(am[1]))
                    result['maps'].append(am[1])
                except errors.DuplicateEntry, e:
                    if options.get('continue', False):
                        result['duplicatemaps'].append(am[0])
                        pass
                    else:
                        raise errors.DuplicateEntry(message=unicode('map %(map)s already exists' % {'map':am[1]}))
                except errors.DuplicateEntry:
                    # This means the same map is used on several mount points.
                    pass

        # Now iterate over the map files and add the keys. To handle
        # continuation lines I'll make a pass through it to skip comments
        # etc and also to combine lines.
        for m in maps:
            map = self.__read_mapfile(maps[m])
            lines = []
            cont = ''
            for x in map:
                if x.startswith('#'):
                    continue
                x = x.rstrip()
                if x.startswith('+'):
                    result['skipped'].append([m, maps[m]])
                    continue
                if len(x) == 0:
                    continue
                if x.endswith("\\"):
                    cont = cont + x[:-1] + ' '
                else:
                    lines.append(cont + x)
                    cont=''
            for x in lines:
                am = x.split(None)
                key = unicode(am[0].replace('"',''))
                try:
                    api.Command['automountkey_add'](args[0], unicode(m), key, automountinformation=unicode(' '.join(am[1:])))
                    result['keys'].append([key,m])
                except errors.DuplicateEntry, e:
                    if options.get('continue', False):
                        result['duplicatekeys'].append(am[0])
                        pass
                    else:
                        raise e

        return dict(result=result)

    def output_for_cli(self, textui, result, *keys, **options):
        maps = result['result']['maps']
        keys = result['result']['keys']
        duplicatemaps = result['result']['duplicatemaps']
        duplicatekeys = result['result']['duplicatekeys']
        skipped = result['result']['skipped']

        textui.print_plain('Imported maps:')
        for m in maps:
            textui.print_plain(
                'Added %s' % m
            )
        textui.print_plain('')

        textui.print_plain('Imported keys:')
        for k in keys:
            textui.print_plain(
                'Added %s to %s' % (
                    k[0], k[1]
                )
            )
        textui.print_plain('')

        if len(skipped) > 0:
            textui.print_plain('Ignored keys:')
            for k in skipped:
                textui.print_plain(
                    'Ignored %s to %s' % (
                        k[0], k[1]
                    )
                )


        if options.get('continue', False) and len(duplicatemaps) > 0:
            textui.print_plain('')
            textui.print_plain('Duplicate maps skipped:')
            for m in duplicatemaps:
                textui.print_plain(
                    'Skipped %s' % m
                )


        if options.get('continue', False) and len(duplicatekeys) > 0:
            textui.print_plain('')
            textui.print_plain('Duplicate keys skipped:')
            for k in duplicatekeys:
                textui.print_plain(
                    'Skipped %s' % k
                )


api.register(automountlocation_import)

class automountmap(LDAPObject):
    """
    Automount map object.
    """
    parent_object = 'automountlocation'
    container_dn = api.env.container_automount
    object_name = 'automount map'
    object_name_plural = 'automount maps'
    object_class = ['automountmap']
    default_attributes = ['automountmapname', 'description']

    takes_params = (
        IA5Str('automountmapname',
               cli_name='map',
               label=_('Map'),
               doc=_('Automount map name'),
               primary_key=True,
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
        ),
    )

    label = _('Automount Maps')

api.register(automountmap)


class automountmap_add(LDAPCreate):
    """
    Create new automount map.
    """

api.register(automountmap_add)


class automountmap_del(LDAPDelete):
    """
    Delete automount map.
    """
    def post_callback(self, ldap, dn, *keys, **options):
        # delete optional parental connection (direct maps may not have this)
        try:
            (dn_, entry_attrs) = ldap.find_entry_by_attr(
                'automountinformation', keys[0], 'automount',
                base_dn=self.obj.container_dn
            )
            ldap.delete_entry(dn_)
        except errors.NotFound:
            pass
        return True

api.register(automountmap_del)


class automountmap_mod(LDAPUpdate):
    """
    Modify automount map.
    """

api.register(automountmap_mod)


class automountmap_find(LDAPSearch):
    """
    Search for automount maps.
    """

api.register(automountmap_find)


class automountmap_show(LDAPRetrieve):
    """
    Display automount map.
    """

api.register(automountmap_show)


class automountkey(LDAPObject):
    """
    Automount key object.
    """
    parent_object = 'automountmap'
    container_dn = api.env.container_automount
    object_name = 'automount key'
    object_name_plural = 'automount keys'
    object_class = ['automount']
    default_attributes = [
        'automountkey', 'automountinformation', 'description'
    ]

    takes_params = (
        IA5Str('automountkey',
               cli_name='key',
               label=_('Key'),
               doc=_('Automount key name'),
               primary_key=True,
        ),
        IA5Str('automountinformation',
               cli_name='info',
               label=_('Mount information'),
        ),
        Str('description?',
            cli_name='desc',
            label=_('description'),
        ),
    )

    label = _('Automount Keys')

api.register(automountkey)


class automountkey_add(LDAPCreate):
    """
    Create new automount key.
    """

api.register(automountkey_add)


class automountmap_add_indirect(LDAPCreate):
    """
    Create new indirect mount point.
    """
    takes_options = LDAPCreate.takes_options + (
        Str('key',
            cli_name='mount',
            label=_('Mount point'),
        ),
        Str('parentmap?',
            cli_name='parentmap',
            label=_('Parent map'),
            doc=_('Name of parent automount map (default: auto.master)'),
            default=u'auto.master',
            autofill=True,
        ),
    )

    def execute(self, *keys, **options):
        result = self.api.Command['automountmap_add'](*keys, **options)
        options['automountinformation'] = keys[1]
        self.api.Command['automountkey_add'](
            keys[0], options['parentmap'], options['key'], **options
        )
        return result

api.register(automountmap_add_indirect)


class automountkey_del(LDAPDelete):
    """
    Delete automount key.
    """

api.register(automountkey_del)


class automountkey_mod(LDAPUpdate):
    """
    Modify automount key.
    """

api.register(automountkey_mod)


class automountkey_find(LDAPSearch):
    """
    Modify automount key.
    """

api.register(automountkey_find)


class automountkey_show(LDAPRetrieve):
    """
    Display automount key.
    """

api.register(automountkey_show)
