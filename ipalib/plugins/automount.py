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
from ipalib import api, errors
from ipalib import Object, Command
from ipalib import Flag, Str
from ipalib.plugins.baseldap import *


class automountlocation(LDAPObject):
    """
    Location container for automount maps.
    """
    container_dn = api.env.container_automount
    object_name = 'automount location'
    object_name_plural = 'automount locations'
    object_class = ['nscontainer']
    default_attributes = ['cn']
    attribute_names = {
        'cn': 'name',
    }

    takes_params = (
        Str('cn',
            cli_name='location',
            doc='automount location name',
            primary_key=True,
        ),
    )

api.register(automountlocation)


class automountlocation_add(LDAPCreate):
    """
    Create new automount location.
    """

api.register(automountlocation_add)


class automountlocation_del(LDAPDelete):
    """
    Delete automount location.
    """

api.register(automountlocation_del)


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

        maps = []
        (maps, truncated) = self.api.Command['automountkey_find'](
            cn=args[0], automountmapname=u'auto.master'
        )
        # TODO: handle truncated results
        #       ?use ldap.find_entries instead of automountkey_find?

        keys = {}
        for (dn, m) in maps:
            info = m['automountinformation'][0]
            (keys[info], truncated) = self.api.Command['automountkey_find'](
                cn=args[0], automountmapname=info
            )
            # TODO: handle truncated results, same as above

        return (maps, keys)

    def output_for_cli(self, textui, result, *keys, **options):
        (maps, keys) = result

        textui.print_plain('/etc/auto.master:')
        for (dn, m) in maps:
            textui.print_plain(
                '%s\t/etc/%s' % (
                    m['automountkey'][0], m['automountinformation'][0]
                )
            )
        for (dn, m) in maps:
            info = m['automountinformation'][0]
            textui.print_plain('---------------------------')
            textui.print_plain('/etc/%s:' % info)
            for (dn, k) in keys[info]:
                textui.print_plain(
                    '%s\t%s' % (
                        k['automountkey'][0], k['automountinformation'][0]
                    )
                )

api.register(automountlocation_tofiles)


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
    attribute_names = {
        'automountmapname': 'name',
    }

    takes_params = (
        Str('automountmapname',
            cli_name='map',
            primary_key=True,
            doc='automount map name',
        ),
        Str('description?',
            cli_name='desc',
            doc='description',
        ),
    )

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
    attribute_names = {
        'automountkey': 'key',
        'automountinformation': 'mount information',
    }
    attribute_order = ['automountkey', 'automountinformation']

    takes_params = (
        Str('automountkey',
            cli_name='key',
            doc='key name',
            primary_key=True,
        ),
        Str('automountinformation',
            cli_name='info',
            doc='mount information',
        ),
        Str('description?',
            cli_name='desc',
            doc='description',
        ),
    )

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
    takes_options = (
        Str('key',
            cli_name='mount',
            doc='mount point',
        ),
        Str('parentmap?',
            cli_name='parentmap',
            doc='name of parent automount map (default: auto.master)',
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

