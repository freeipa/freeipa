# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import six

from ipalib import api, errors
from ipalib import Str, IA5Str
from ipalib.plugable import Registry
from .baseldap import (
    pkey_to_value,
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPQuery,
    LDAPUpdate,
    LDAPSearch,
    LDAPRetrieve)
from ipalib import _, ngettext
from ipapython.dn import DN

if six.PY3:
    unicode = str

__doc__ = _("""
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

A map is roughly equivalent to a discrete automount file and provides
storage for keys.

A key is a mount point associated with a map.

When a new location is created, two maps are automatically created for
it: auto.master and auto.direct. auto.master is the root map for all
automount maps for the location. auto.direct is the default map for
direct mounts and is mounted on /-.

An automount map may contain a submount key. This key defines a mount
location within the map that references another map. This can be done
either using automountmap-add-indirect --parentmap or manually
with automountkey-add and setting info to "-type=autofs :<mapname>".

EXAMPLES:

Locations:

  Create a named location, "Baltimore":
    ipa automountlocation-add baltimore

  Display the new location:
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
    continuous operation where errors are ignored, use the --continue
    option.

Maps:

  Create a new map, "auto.share":
    ipa automountmap-add baltimore auto.share

  Display the new map:
    ipa automountmap-show baltimore auto.share

  Find maps in the location baltimore:
    ipa automountmap-find baltimore

  Create an indirect map with auto.share as a submount:
    ipa automountmap-add-indirect baltimore --parentmap=auto.share --mount=sub auto.man

    This is equivalent to:

    ipa automountmap-add-indirect baltimore --mount=/man auto.man
    ipa automountkey-add baltimore auto.man --key=sub --info="-fstype=autofs ldap:auto.share"

  Remove the auto.share map:
    ipa automountmap-del baltimore auto.share

Keys:

  Create a new key for the auto.share map in location baltimore. This ties
  the map we previously created to auto.master:
    ipa automountkey-add baltimore auto.master --key=/share --info=auto.share

  Create a new key for our auto.share map, an NFS mount for man pages:
    ipa automountkey-add baltimore auto.share --key=man --info="-ro,soft,rsize=8192,wsize=8192 ipa.example.com:/shared/man"

  Find all keys for the auto.share map:
    ipa automountkey-find baltimore auto.share

  Find all direct automount keys:
    ipa automountkey-find baltimore --key=/-

  Remove the man key from the auto.share map:
    ipa automountkey-del baltimore auto.share --key=man
""")

"""
Developer notes:

RFC 2707bis http://www.padl.com/~lukeh/rfc2307bis.txt

A few notes on automount:
- The default parent when adding an indirect map is auto.master
- This uses the short format for automount maps instead of the
  URL format. Support for ldap as a map source in nsswitch.conf was added
  in autofs version 4.1.3-197.  Any version prior to that is not expected
  to work.
- An indirect key should not begin with /

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

register = Registry()

DIRECT_MAP_KEY = u'/-'

@register()
class automountlocation(LDAPObject):
    """
    Location container for automount maps.
    """
    container_dn = api.env.container_automount
    object_name = _('automount location')
    object_name_plural = _('automount locations')
    object_class = ['nscontainer']
    default_attributes = ['cn']
    label = _('Automount Locations')
    label_singular = _('Automount Location')
    permission_filter_objectclasses = ['nscontainer']
    managed_permissions = {
        'System: Read Automount Configuration': {
            # Single permission for all automount-related entries
            'non_object': True,
            'ipapermlocation': DN(container_dn, api.env.basedn),
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'anonymous',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'objectclass',
                'automountinformation', 'automountkey', 'description',
                'automountmapname', 'description',
            },
        },
        'System: Add Automount Locations': {
            'ipapermright': {'add'},
            'default_privileges': {'Automount Administrators'},
        },
        'System: Remove Automount Locations': {
            'ipapermright': {'delete'},
            'default_privileges': {'Automount Administrators'},
        },
    }

    takes_params = (
        Str('cn',
            cli_name='location',
            label=_('Location'),
            doc=_('Automount location name.'),
            primary_key=True,
        ),
    )


@register()
class automountlocation_add(LDAPCreate):
    __doc__ = _('Create a new automount location.')

    msg_summary = _('Added automount location "%(value)s"')

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        # create auto.master for the new location
        self.api.Command['automountmap_add'](keys[-1], u'auto.master')

        # add additional pre-created maps and keys
        # IMPORTANT: add pre-created maps/keys to DEFAULT_MAPS/DEFAULT_KEYS
        # so that they do not cause conflicts during import operation
        self.api.Command['automountmap_add_indirect'](
            keys[-1], u'auto.direct', key=DIRECT_MAP_KEY
        )
        return dn


@register()
class automountlocation_del(LDAPDelete):
    __doc__ = _('Delete an automount location.')

    msg_summary = _('Deleted automount location "%(value)s"')


@register()
class automountlocation_show(LDAPRetrieve):
    __doc__ = _('Display an automount location.')


@register()
class automountlocation_find(LDAPSearch):
    __doc__ = _('Search for an automount location.')

    msg_summary = ngettext(
        '%(count)d automount location matched',
        '%(count)d automount locations matched', 0
    )


@register()
class automountlocation_tofiles(LDAPQuery):
    __doc__ = _('Generate automount files for a specific location.')

    def execute(self, *args, **options):
        self.api.Command['automountlocation_show'](args[0])

        result = self.api.Command['automountkey_find'](args[0], u'auto.master')
        maps = result['result']

        # maps, truncated
        # TODO: handle truncated results
        #       ?use ldap.find_entries instead of automountkey_find?

        keys = {}
        mapnames = [u'auto.master']
        for m in maps:
            info = m['automountinformation'][0]
            mapnames.append(info)
            key = info.split(None)
            result = self.api.Command['automountkey_find'](args[0], key[0])
            keys[info] = result['result']
            # TODO: handle truncated results, same as above

        allmaps = self.api.Command['automountmap_find'](args[0])['result']
        orphanmaps = []
        for m in allmaps:
            if m['automountmapname'][0] not in mapnames:
                orphanmaps.append(m)

        orphankeys = []
        # Collect all the keys for the orphaned maps
        for m in orphanmaps:
            key = m['automountmapname']
            result = self.api.Command['automountkey_find'](args[0], key[0])
            orphankeys.append(result['result'])

        return dict(result=dict(maps=maps, keys=keys,
                    orphanmaps=orphanmaps, orphankeys=orphankeys))


@register()
class automountmap(LDAPObject):
    """
    Automount map object.
    """
    parent_object = 'automountlocation'
    container_dn = api.env.container_automount
    object_name = _('automount map')
    object_name_plural = _('automount maps')
    object_class = ['automountmap']
    permission_filter_objectclasses = ['automountmap']
    default_attributes = ['automountmapname', 'description']

    takes_params = (
        IA5Str('automountmapname',
               cli_name='map',
               label=_('Map'),
               doc=_('Automount map name.'),
               primary_key=True,
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
        ),
    )

    managed_permissions = {
        'System: Add Automount Maps': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///automountmapname=*,cn=automount,$SUFFIX")(version 3.0;acl "permission:Add Automount maps";allow (add) groupdn = "ldap:///cn=Add Automount maps,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Automount Administrators'},
        },
        'System: Modify Automount Maps': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'automountmapname', 'description'},
            'replaces': [
                '(targetattr = "automountmapname || description")(target = "ldap:///automountmapname=*,cn=automount,$SUFFIX")(version 3.0;acl "permission:Modify Automount maps";allow (write) groupdn = "ldap:///cn=Modify Automount maps,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Automount Administrators'},
        },
        'System: Remove Automount Maps': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///automountmapname=*,cn=automount,$SUFFIX")(version 3.0;acl "permission:Remove Automount maps";allow (delete) groupdn = "ldap:///cn=Remove Automount maps,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Automount Administrators'},
        },
    }

    label = _('Automount Maps')
    label_singular = _('Automount Map')


@register()
class automountmap_add(LDAPCreate):
    __doc__ = _('Create a new automount map.')

    msg_summary = _('Added automount map "%(value)s"')


@register()
class automountmap_del(LDAPDelete):
    __doc__ = _('Delete an automount map.')

    msg_summary = _('Deleted automount map "%(value)s"')

    def post_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        # delete optional parental connection (direct maps may not have this)
        try:
            entry_attrs = ldap.find_entry_by_attr(
                'automountinformation', keys[0], 'automount',
                base_dn=DN(self.obj.container_dn, api.env.basedn)
            )
            ldap.delete_entry(entry_attrs)
        except errors.NotFound:
            pass
        return True


@register()
class automountmap_mod(LDAPUpdate):
    __doc__ = _('Modify an automount map.')

    msg_summary = _('Modified automount map "%(value)s"')


@register()
class automountmap_find(LDAPSearch):
    __doc__ = _('Search for an automount map.')

    msg_summary = ngettext(
        '%(count)d automount map matched',
        '%(count)d automount maps matched', 0
    )


@register()
class automountmap_show(LDAPRetrieve):
    __doc__ = _('Display an automount map.')


@register()
class automountkey(LDAPObject):
    __doc__ = _('Automount key object.')

    parent_object = 'automountmap'
    container_dn = api.env.container_automount
    object_name = _('automount key')
    object_name_plural = _('automount keys')
    object_class = ['automount']
    permission_filter_objectclasses = ['automount']
    default_attributes = [
        'automountkey', 'automountinformation', 'description'
    ]
    allow_rename = True
    rdn_separator = ' '

    takes_params = (
        IA5Str('automountkey',
               cli_name='key',
               label=_('Key'),
               doc=_('Automount key name.'),
               flags=('req_update',),
        ),
        IA5Str('automountinformation',
               cli_name='info',
               label=_('Mount information'),
        ),
        Str('description',
            label=_('description'),
            primary_key=True,
            required=False,
            flags=['no_create', 'no_update', 'no_search', 'no_output'],
            exclude='webui',
        ),
    )

    managed_permissions = {
        'System: Add Automount Keys': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///automountkey=*,automountmapname=*,cn=automount,$SUFFIX")(version 3.0;acl "permission:Add Automount keys";allow (add) groupdn = "ldap:///cn=Add Automount keys,cn=permissions,cn=pbac,$SUFFIX";)',
                '(targetfilter = "(objectclass=automount)")(target = "ldap:///automountmapname=*,cn=automount,$SUFFIX")(version 3.0;acl "permission:Add Automount keys";allow (add) groupdn = "ldap:///cn=Add Automount keys,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Automount Administrators'},
        },
        'System: Modify Automount Keys': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'automountinformation', 'automountkey', 'description',
            },
            'replaces': [
                '(targetattr = "automountkey || automountinformation || description")(targetfilter = "(objectclass=automount)")(target = "ldap:///automountmapname=*,cn=automount,$SUFFIX")(version 3.0;acl "permission:Modify Automount keys";allow (write) groupdn = "ldap:///cn=Modify Automount keys,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Automount Administrators'},
        },
        'System: Remove Automount Keys': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///automountkey=*,automountmapname=*,cn=automount,$SUFFIX")(version 3.0;acl "permission:Remove Automount keys";allow (delete) groupdn = "ldap:///cn=Remove Automount keys,cn=permissions,cn=pbac,$SUFFIX";)',
                '(targetfilter = "(objectclass=automount)")(target = "ldap:///automountmapname=*,cn=automount,$SUFFIX")(version 3.0;acl "permission:Remove Automount keys";allow (delete) groupdn = "ldap:///cn=Remove Automount keys,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Automount Administrators'},
        },
    }

    num_parents = 2
    label = _('Automount Keys')
    label_singular = _('Automount Key')
    already_exists_msg = _('The key,info pair must be unique. A key named %(key)s with info %(info)s already exists')
    key_already_exists_msg = _('key named %(key)s already exists')
    object_not_found_msg = _('The automount key %(key)s with info %(info)s does not exist')

    def get_dn(self, *keys, **kwargs):
        # all commands except for create send pk in keys, too
        # create cannot due to validation in frontend.py
        ldap = self.backend
        if len(keys) == self.num_parents:
            try:
                pkey = kwargs[self.primary_key.name]
            except KeyError:
                raise ValueError('Not enough keys and pkey not in kwargs')
            parent_keys = keys
        else:
            pkey = keys[-1]
            parent_keys = keys[:-1]

        parent_dn = self.api.Object[self.parent_object].get_dn(*parent_keys)
        dn = self.backend.make_dn_from_attr(
            self.primary_key.name,
            pkey,
            parent_dn
        )
        # If we're doing an add then just return the dn we created, there
        # is no need to check for it.
        if kwargs.get('add_operation', False):
            return dn
        # We had an older mechanism where description consisted of
        # 'automountkey automountinformation' so we could support multiple
        # direct maps. This made showing keys nearly impossible since it
        # required automountinfo to show, which if you had you didn't need
        # to look at the key. We still support existing entries but now
        # only create this type of dn when the key is /-
        #
        # First we look with the information given, then try to search for
        # the right entry.
        try:
            dn = ldap.get_entry(dn, ['*']).dn
        except errors.NotFound:
            if kwargs.get('automountinformation', False):
                sfilter = '(&(automountkey=%s)(automountinformation=%s))' % \
                    (kwargs['automountkey'], kwargs['automountinformation'])
            else:
                sfilter = '(automountkey=%s)' % kwargs['automountkey']
            basedn = DN(('automountmapname', parent_keys[1]),
                        ('cn', parent_keys[0]), self.container_dn,
                        api.env.basedn)
            attrs_list = ['*']
            entries = ldap.get_entries(
                basedn, ldap.SCOPE_ONELEVEL, sfilter, attrs_list)
            if len(entries) > 1:
                raise errors.NotFound(reason=_('More than one entry with key %(key)s found, use --info to select specific entry.') % dict(key=pkey))
            dn = entries[0].dn

        return dn

    def handle_not_found(self, *keys, **kwargs):
        pkey = keys[-1]
        key = pkey.split(self.rdn_separator)[0]
        info = self.rdn_separator.join(pkey.split(self.rdn_separator)[1:])
        raise errors.NotFound(
            reason=self.object_not_found_msg % {
                'key': key, 'info': info,
            }
        )

    def handle_duplicate_entry(self, *keys):
        pkey = keys[-1]
        key = pkey.split(self.rdn_separator)[0]
        info = self.rdn_separator.join(pkey.split(self.rdn_separator)[1:])
        if info:
            raise errors.DuplicateEntry(
                message=self.already_exists_msg % {
                    'key': key, 'info': info,
                }
            )
        else:
            raise errors.DuplicateEntry(
                message=self.key_already_exists_msg % {
                    'key': key,
                }
            )

    def get_pk(self, key, info=None):
        if key == DIRECT_MAP_KEY and info:
            return self.rdn_separator.join((key,info))
        else:
            return key

    def check_key_uniqueness(self, location, map, **keykw):
        info = None
        key = keykw.get('automountkey')
        if key is None:
            return

        entries = self.methods.find(location, map, automountkey=key)['result']
        if len(entries) > 0:
            if key == DIRECT_MAP_KEY:
                info = keykw.get('automountinformation')
                entries = self.methods.find(location, map, **keykw)['result']
                if len(entries) > 0:
                    self.handle_duplicate_entry(location, map, self.get_pk(key, info))
                else: return
            self.handle_duplicate_entry(location, map, self.get_pk(key, info))


@register()
class automountkey_add(LDAPCreate):
    __doc__ = _('Create a new automount key.')

    msg_summary = _('Added automount key "%(value)s"')

    internal_options = ['description', 'add_operation']

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        options.pop('add_operation', None)
        options.pop('description', None)
        self.obj.check_key_uniqueness(keys[-2], keys[-1], **options)
        return dn

    def get_args(self):
        for key in self.obj.get_ancestor_primary_keys():
            yield key

    def execute(self, *keys, **options):
        key = options['automountkey']
        info = options.get('automountinformation', None)
        options[self.obj.primary_key.name] = self.obj.get_pk(key, info)
        options['add_operation'] = True
        result = super(automountkey_add, self).execute(*keys, **options)
        result['value'] = pkey_to_value(options['automountkey'], options)
        return result


@register()
class automountmap_add_indirect(LDAPCreate):
    __doc__ = _('Create a new indirect mount point.')

    msg_summary = _('Added automount indirect map "%(value)s"')

    takes_options = LDAPCreate.takes_options + (
        Str('key',
            cli_name='mount',
            label=_('Mount point'),
        ),
        Str('parentmap?',
            cli_name='parentmap',
            label=_('Parent map'),
            doc=_('Name of parent automount map (default: auto.master).'),
            default=u'auto.master',
            autofill=True,
        ),
    )

    def execute(self, *keys, **options):
        parentmap = options.pop('parentmap', None)
        key = options.pop('key')
        result = self.api.Command['automountmap_add'](*keys, **options)
        try:
            if parentmap != u'auto.master':
                if key.startswith('/'):
                    raise errors.ValidationError(name='mount',
                        error=_('mount point is relative to parent map, '
                            'cannot begin with /'))
                location = keys[0]
                map = keys[1]
                options['automountinformation'] = map

                # Ensure the referenced map exists
                self.api.Command['automountmap_show'](location, parentmap)
                # Add a submount key
                self.api.Command['automountkey_add'](
                    location, parentmap, automountkey=key,
                    automountinformation='-fstype=autofs ldap:%s' % map)
            else: # adding to auto.master
                # Ensure auto.master exists
                self.api.Command['automountmap_show'](keys[0], parentmap)
                self.api.Command['automountkey_add'](
                    keys[0], u'auto.master', automountkey=key,
                    automountinformation=keys[1])
        except Exception:
            # The key exists, drop the map
            self.api.Command['automountmap_del'](*keys)
            raise
        return result


@register()
class automountkey_del(LDAPDelete):
    __doc__ = _('Delete an automount key.')

    msg_summary = _('Deleted automount key "%(value)s"')

    takes_options = LDAPDelete.takes_options + (
        IA5Str('automountkey',
               cli_name='key',
               label=_('Key'),
               doc=_('Automount key name.'),
        ),
        IA5Str('automountinformation?',
               cli_name='info',
               label=_('Mount information'),
        ),
    )
    def get_options(self):
        for option in super(automountkey_del, self).get_options():
            if option.name == 'continue':
                # TODO: hide for now - remove in future major release
                yield option.clone(exclude='webui',
                                   flags=['no_option', 'no_output'])
            else:
                yield option

    def get_args(self):
        for key in self.obj.get_ancestor_primary_keys():
            yield key

    def execute(self, *keys, **options):
        keys += (self.obj.get_pk(options['automountkey'],
                                 options.get('automountinformation', None)),)
        options[self.obj.primary_key.name] = self.obj.get_pk(
                                            options['automountkey'],
                                            options.get('automountinformation', None))
        result = super(automountkey_del, self).execute(*keys, **options)
        result['value'] = pkey_to_value([options['automountkey']], options)
        return result


@register()
class automountkey_mod(LDAPUpdate):
    __doc__ = _('Modify an automount key.')

    msg_summary = _('Modified automount key "%(value)s"')

    internal_options = ['newautomountkey']

    takes_options = LDAPUpdate.takes_options + (
        IA5Str('newautomountinformation?',
               cli_name='newinfo',
               label=_('New mount information'),
        ),
    )

    def get_args(self):
        for key in self.obj.get_ancestor_primary_keys():
            yield key

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        if 'newautomountkey' in options:
            entry_attrs['automountkey'] = options['newautomountkey']
        if 'newautomountinformation' in options:
            entry_attrs['automountinformation'] = options['newautomountinformation']
        return dn

    def execute(self, *keys, **options):
        ldap = self.api.Backend.ldap2
        key = options['automountkey']
        info = options.get('automountinformation', None)
        keys += (self.obj.get_pk(key, info), )

        # handle RDN changes
        if 'rename' in options or 'newautomountinformation' in options:
            new_key = options.get('rename', key)
            new_info = options.get('newautomountinformation', info)

            if new_key == DIRECT_MAP_KEY and not new_info:
                # automountinformation attribute of existing LDAP object needs
                # to be retrieved so that RDN can be generated
                dn = self.obj.get_dn(*keys, **options)
                entry_attrs_ = ldap.get_entry(dn, ['automountinformation'])
                new_info = entry_attrs_.get('automountinformation', [])[0]

            # automounkey attribute cannot be overwritten so that get_dn()
            # still works right
            options['newautomountkey'] = new_key

            new_rdn = self.obj.get_pk(new_key, new_info)
            if new_rdn != keys[-1]:
                options['rename'] = new_rdn

        result = super(automountkey_mod, self).execute(*keys, **options)
        result['value'] = pkey_to_value(options['automountkey'], options)
        return result


@register()
class automountkey_find(LDAPSearch):
    __doc__ = _('Search for an automount key.')

    msg_summary = ngettext(
        '%(count)d automount key matched',
        '%(count)d automount keys matched', 0
    )


@register()
class automountkey_show(LDAPRetrieve):
    __doc__ = _('Display an automount key.')

    takes_options = LDAPRetrieve.takes_options + (
        IA5Str('automountkey',
               cli_name='key',
               label=_('Key'),
               doc=_('Automount key name.'),
        ),
        IA5Str('automountinformation?',
               cli_name='info',
               label=_('Mount information'),
        ),
    )

    def get_args(self):
        for key in self.obj.get_ancestor_primary_keys():
            yield key

    def execute(self, *keys, **options):
        keys += (self.obj.get_pk(options['automountkey'],
                                 options.get('automountinformation', None)), )
        options[self.obj.primary_key.name] = self.obj.get_pk(
                                            options['automountkey'],
                                            options.get('automountinformation', None))

        result = super(automountkey_show, self).execute(*keys, **options)
        result['value'] = pkey_to_value(options['automountkey'], options)
        return result
