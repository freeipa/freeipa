# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2013  Red Hat
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

import logging
import re
import traceback

import six

from . import baseldap
from .privilege import validate_permission_to_privilege
from ipalib import errors
from ipalib.parameters import Str, StrEnum, DNParam, Flag
from ipalib import api, _, ngettext
from ipalib.plugable import Registry
from ipalib.capabilities import client_has_capability
from ipalib.aci import ACI
from ipapython.dn import DN
from ipalib.request import context

if six.PY3:
    unicode = str

__doc__ = _("""
Permissions
""") + _("""
A permission enables fine-grained delegation of rights. A permission is
a human-readable wrapper around a 389-ds Access Control Rule,
or instruction (ACI).
A permission grants the right to perform a specific task such as adding a
user, modifying a group, etc.
""") + _("""
A permission may not contain other permissions.
""") + _("""
* A permission grants access to read, write, add, delete, read, search,
  or compare.
* A privilege combines similar permissions (for example all the permissions
  needed to add a user).
* A role grants a set of privileges to users, groups, hosts or hostgroups.
""") + _("""
A permission is made up of a number of different parts:

1. The name of the permission.
2. The target of the permission.
3. The rights granted by the permission.
""") + _("""
Rights define what operations are allowed, and may be one or more
of the following:
1. write - write one or more attributes
2. read - read one or more attributes
3. search - search on one or more attributes
4. compare - compare one or more attributes
5. add - add a new entry to the tree
6. delete - delete an existing entry
7. all - all permissions are granted
""") + _("""
Note the distinction between attributes and entries. The permissions are
independent, so being able to add a user does not mean that the user will
be editable.
""") + _("""
There are a number of allowed targets:
1. subtree: a DN; the permission applies to the subtree under this DN
2. target filter: an LDAP filter
3. target: DN with possible wildcards, specifies entries permission applies to
""") + _("""
Additionally, there are the following convenience options.
Setting one of these options will set the corresponding attribute(s).
1. type: a type of object (user, group, etc); sets subtree and target filter.
2. memberof: apply to members of a group; sets target filter
3. targetgroup: grant access to modify a specific group (such as granting
   the rights to manage group membership); sets target.
""") + _("""
Managed permissions
""") + _("""
Permissions that come with IPA by default can be so-called "managed"
permissions. These have a default set of attributes they apply to,
but the administrator can add/remove individual attributes to/from the set.
""") + _("""
Deleting or renaming a managed permission, as well as changing its target,
is not allowed.
""") + _("""
EXAMPLES:
""") + _("""
 Add a permission that grants the creation of users:
   ipa permission-add --type=user --permissions=add "Add Users"
""") + _("""
 Add a permission that grants the ability to manage group membership:
   ipa permission-add --attrs=member --permissions=write --type=group "Manage Group Members"
""")

logger = logging.getLogger(__name__)

register = Registry()

_DEPRECATED_OPTION_ALIASES = {
    'permissions': 'ipapermright',
    'filter': 'extratargetfilter',
    'subtree': 'ipapermlocation',
}

KNOWN_FLAGS = {'SYSTEM', 'V2', 'MANAGED'}


def strip_ldap_prefix(uri):
    prefix = 'ldap:///'
    if not uri.startswith(prefix):
        raise ValueError('%r does not start with %r' % (uri, prefix))
    return uri[len(prefix):]


def prevalidate_filter(ugettext, value):
    if not value.startswith('(') or not value.endswith(')'):
        return _('must be enclosed in parentheses')
    return None


class DNOrURL(DNParam):
    """DN parameter that allows, and strips, a "ldap:///" prefix on input

    Used for ``subtree`` to maintain backward compatibility.
    """

    def _convert_scalar(self, value, index=None):
        if isinstance(value, str) and value.startswith('ldap:///'):
            value = strip_ldap_prefix(value)
        return super(DNOrURL, self)._convert_scalar(value)


def validate_type(ugettext, typestr):
    try:
        obj = api.Object[typestr]
    except KeyError:
        return _('"%s" is not an object type') % typestr
    if not getattr(obj, 'permission_filter_objectclasses', None):
        return _('"%s" is not a valid permission type') % typestr
    return None


def _disallow_colon(option):
    """Given a "cn" option, return a new "cn" option with ':' disallowed

    Used in permission-add and for --rename in permission-mod to prevent user
    from creating new permissions with ":" in the name.
    """
    return option.clone(
        pattern='^[-_ a-zA-Z0-9.]+$',
        pattern_errmsg="May only contain letters, numbers, -, _, ., and space",
    )


_ipapermissiontype_param = Str(
    'ipapermissiontype+',
    label=_('Permission flags'),
    flags={'no_create', 'no_update', 'no_search'},
)


@register()
class permission(baseldap.LDAPObject):
    """
    Permission object.
    """
    container_dn = api.env.container_permission
    object_name = _('permission')
    object_name_plural = _('permissions')
    # For use the complete object_class list, including 'top', so
    # the updater doesn't try to delete 'top' every time.
    object_class = ['top', 'groupofnames', 'ipapermission', 'ipapermissionv2']
    permission_filter_objectclasses = ['ipapermission']
    default_attributes = ['cn', 'member', 'memberof',
        'memberindirect', 'ipapermissiontype', 'objectclass',
        'ipapermdefaultattr', 'ipapermincludedattr', 'ipapermexcludedattr',
        'ipapermbindruletype', 'ipapermlocation', 'ipapermright',
        'ipapermtargetfilter', 'ipapermtarget'
    ]
    attribute_members = {
        'member': ['privilege'],
        'memberindirect': ['role'],
    }
    allow_rename = True
    managed_permissions = {
        'System: Read Permissions': {
            'replaces_global_anonymous_aci': True,
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'businesscategory', 'cn', 'description', 'ipapermissiontype',
                'o', 'objectclass', 'ou', 'owner', 'seealso',
                'ipapermdefaultattr', 'ipapermincludedattr',
                'ipapermexcludedattr', 'ipapermbindruletype', 'ipapermtarget',
                'ipapermlocation', 'ipapermright', 'ipapermtargetfilter',
                'member', 'memberof', 'memberuser', 'memberhost',
            },
            'default_privileges': {'RBAC Readers'},
        },
        'System: Read ACIs': {
            # Readable ACIs are needed for reading legacy permissions.
            'non_object': True,
            'ipapermlocation': api.env.basedn,
            'replaces_global_anonymous_aci': True,
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {'aci'},
            'default_privileges': {'RBAC Readers'},
        },
        'System: Modify Privilege Membership': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'member'},
            'replaces': [
                '(targetattr = "member")(target = "ldap:///cn=*,cn=permissions,cn=pbac,$SUFFIX")(version 3.0;acl "permission:Modify privilege membership";allow (write) groupdn = "ldap:///cn=Modify privilege membership,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Delegation Administrator'},
        },
    }

    label = _('Permissions')
    label_singular = _('Permission')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Permission name'),
            primary_key=True,
            pattern='^[-_ a-zA-Z0-9.:/]+$',
            pattern_errmsg="May only contain letters, numbers, "
                           "-, _, ., :, /, and space",
        ),
        StrEnum(
            'ipapermright*',
            cli_name='right',
            label=_('Granted rights'),
            doc=_('Rights to grant '
                  '(read, search, compare, write, add, delete, all)'),
            values=(u'read', u'search', u'compare',
                    u'write', u'add', u'delete', u'all'),
            flags={'ask_create'},
        ),
        Str('attrs*',
            label=_('Effective attributes'),
            doc=_('All attributes to which the permission applies'),
            flags={'virtual_attribute', 'allow_mod_for_managed_permission'},
        ),
        Str('ipapermincludedattr*',
            cli_name='includedattrs',
            label=_('Included attributes'),
            doc=_('User-specified attributes to which the permission applies'),
            flags={'no_create', 'allow_mod_for_managed_permission'},
        ),
        Str('ipapermexcludedattr*',
            cli_name='excludedattrs',
            label=_('Excluded attributes'),
            doc=_('User-specified attributes to which the permission '
                  'explicitly does not apply'),
            flags={'no_create', 'allow_mod_for_managed_permission'},
        ),
        Str('ipapermdefaultattr*',
            cli_name='defaultattrs',
            label=_('Default attributes'),
            doc=_('Attributes to which the permission applies by default'),
            flags={'no_create', 'no_update'},
        ),
        StrEnum(
            'ipapermbindruletype',
            cli_name='bindtype',
            label=_('Bind rule type'),
            doc=_('Bind rule type'),
            autofill=True,
            values=(u'permission', u'all', u'anonymous'),
            default=u'permission',
            flags={'allow_mod_for_managed_permission'},
        ),
        DNOrURL(
            'ipapermlocation?',
            cli_name='subtree',
            label=_('Subtree'),
            doc=_('Subtree to apply permissions to'),
            # force server-side conversion
            normalizer=lambda x: x,
            flags={'ask_create'},
        ),
        Str(
            'extratargetfilter*', prevalidate_filter,
            cli_name='filter',
            label=_('Extra target filter'),
            doc=_('Extra target filter'),
            flags={'virtual_attribute'},
        ),
        Str(
            'ipapermtargetfilter*', prevalidate_filter,
            cli_name='rawfilter',
            label=_('Raw target filter'),
            doc=_('All target filters, including those implied by '
                  'type and memberof'),
        ),

        DNParam(
            'ipapermtarget?',
            cli_name='target',
            label=_('Target DN'),
            doc=_('Optional DN to apply the permission to '
                  '(must be in the subtree, but may not yet exist)'),
        ),

        DNParam(
            'ipapermtargetto?',
            cli_name='targetto',
            label=_('Target DN subtree'),
            doc=_('Optional DN subtree where an entry can be moved to '
                  '(must be in the subtree, but may not yet exist)'),
        ),

        DNParam(
            'ipapermtargetfrom?',
            cli_name='targetfrom',
            label=_('Origin DN subtree'),
            doc=_('Optional DN subtree from where an entry can be moved '
                  '(must be in the subtree, but may not yet exist)'),
        ),

        Str('memberof*',
            label=_('Member of group'),  # FIXME: Does this label make sense?
            doc=_('Target members of a group (sets memberOf targetfilter)'),
            flags={'ask_create', 'virtual_attribute'},
        ),
        Str('targetgroup?',
            label=_('Target group'),
            doc=_('User group to apply permissions to (sets target)'),
            flags={'ask_create', 'virtual_attribute'},
        ),
        Str(
            'type?', validate_type,
            label=_('Type'),
            doc=_('Type of IPA object '
                  '(sets subtree and objectClass targetfilter)'),
            flags={'ask_create', 'virtual_attribute'},
        ),
    ) + tuple(
        Str(old_name + '*',
            doc=_('Deprecated; use %s' % new_name),
            flags={'no_option', 'virtual_attribute'})
        for old_name, new_name in _DEPRECATED_OPTION_ALIASES.items()
    ) + (
        _ipapermissiontype_param,
        Str('aci',
            label=_('ACI'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
    )

    def reject_system(self, entry):
        """Raise if permission entry has unknown flags, or is a SYSTEM perm"""
        flags = entry.get('ipapermissiontype', [])
        for flag in flags:
            if flag not in KNOWN_FLAGS:
                raise errors.ACIError(
                    info=_('Permission with unknown flag %s may not be '
                            'modified or removed') % flag)
        if list(flags) == [u'SYSTEM']:
            raise errors.ACIError(
                info=_('A SYSTEM permission may not be modified or removed'))

    def _get_filter_attr_info(self, entry):
        """Get information on filter-related virtual attributes

        Returns a dict with this information:
        'implicit_targetfilters': targetfilters implied by memberof and type
        'memberof': list of names of groups from memberof
        'type': the type
        """
        ipapermtargetfilter = entry.get('ipapermtargetfilter', [])
        ipapermlocation = entry.single_value.get('ipapermlocation')

        implicit_targetfilters = set()
        result = {'implicit_targetfilters': implicit_targetfilters}

        # memberof
        memberof = []
        for targetfilter in ipapermtargetfilter:
            match = re.match('^\(memberof=(.*)\)$', targetfilter, re.I)
            if match:
                try:
                    dn = DN(match.group(1))
                except ValueError:
                    # Malformed DN; e.g. (memberof=*)
                    continue
                groups_dn = DN(self.api.Object.group.container_dn,
                                self.api.env.basedn)
                if dn[1:] == groups_dn[:] and dn[0].attr == 'cn':
                    memberof.append(dn[0].value)
                    implicit_targetfilters.add(match.group(0))
        if memberof:
            result['memberof'] = memberof

        # type
        if ipapermtargetfilter and ipapermlocation:
            for obj in self.api.Object():
                filt = self.make_type_filter(obj)
                if not filt:
                    continue

                wantdn = DN(obj.container_dn, self.api.env.basedn)
                if DN(ipapermlocation) != wantdn:
                    continue

                if filt in ipapermtargetfilter:
                    result['type'] = [unicode(obj.name)]
                    implicit_targetfilters.add(filt)
                    break

        return result

    def postprocess_result(self, entry, options):
        """Update a permission entry for output (in place)

        :param entry: The entry to update
        :param options:
            Command options. Contains keys such as ``raw``, ``all``,
            ``pkey_only``, ``version``.
        """
        old_client = not client_has_capability(
            options['version'], 'permissions2')

        if not options.get('raw') and not options.get('pkey_only'):
            ipapermtargetfilter = entry.get('ipapermtargetfilter', [])
            ipapermtarget = entry.single_value.get('ipapermtarget')

            # targetgroup
            if ipapermtarget:
                dn = DN(ipapermtarget)
                if (dn[1:] == DN(self.api.Object.group.container_dn,
                                self.api.env.basedn)[:] and
                        dn[0].attr == 'cn' and dn[0].value != '*'):
                    entry.single_value['targetgroup'] = dn[0].value

            filter_attr_info = self._get_filter_attr_info(entry)
            if 'type' in filter_attr_info:
                entry['type'] = filter_attr_info['type']
            if 'memberof' in filter_attr_info:
                entry['memberof'] = filter_attr_info['memberof']
            if 'implicit_targetfilters' in filter_attr_info:
                extratargetfilter = sorted(
                    set(ipapermtargetfilter) -
                    filter_attr_info['implicit_targetfilters'])
                if extratargetfilter:
                        entry['extratargetfilter'] = extratargetfilter

            # old output names
            if old_client:
                for old_name, new_name in _DEPRECATED_OPTION_ALIASES.items():
                    if new_name in entry:
                        entry[old_name] = entry[new_name]
                        del entry[new_name]

        rights = entry.get('attributelevelrights')
        if rights:
            if 'ipapermtarget' in rights:
                rights['targetgroup'] = rights['ipapermtarget']
            if 'ipapermtargetfilter' in rights:
                rights['memberof'] = rights['ipapermtargetfilter']

                type_rights = set(rights['ipapermtargetfilter'])
                location_rights = set(rights.get('ipapermlocation', ''))
                type_rights.intersection_update(location_rights)
                rights['type'] = ''.join(sorted(
                    type_rights, key=rights['ipapermtargetfilter'].index))

            if 'ipapermincludedattr' in rights:
                rights['attrs'] = ''.join(sorted(
                    set(rights['ipapermincludedattr']) &
                    set(rights.get('ipapermexcludedattr', '')),
                    key=rights['ipapermincludedattr'].index))

            if old_client:
                for old_name, new_name in _DEPRECATED_OPTION_ALIASES.items():
                    if new_name in rights:
                        rights[old_name] = rights[new_name]
                        del rights[new_name]

        if options.get('raw'):
            # Retreive the ACI from LDAP to ensure we get the real thing
            try:
                _acientry, acistring = self._get_aci_entry_and_string(entry)
            except errors.NotFound:
                if list(entry.get('ipapermissiontype')) == ['SYSTEM']:
                    # SYSTEM permissions don't have normal ACIs
                    pass
                else:
                    raise
            else:
                entry.single_value['aci'] = acistring
        else:
            effective_attrs = self.get_effective_attrs(entry)
            if effective_attrs:
                entry['attrs'] = effective_attrs
            if (not options.get('all') and
                    not entry.get('ipapermexcludedattr') and
                    not entry.get('ipapermdefaultattr')):
                entry.pop('ipapermincludedattr', None)

        if old_client:
            # Legacy clients expect some attributes as a single value
            for attr in 'type', 'targetgroup', 'aci':
                if attr in entry:
                    entry[attr] = entry.single_value[attr]
            # memberof was also single-valued, but not any more
            if entry.get('memberof'):
                joined_value = u', '.join(str(m) for m in entry['memberof'])
                entry['memberof'] = joined_value
            if 'subtree' in entry:
                # Legacy clients expect subtree as a URL
                dn = entry.single_value['subtree']
                entry['subtree'] = u'ldap:///%s' % dn
            if 'filter' in entry:
                # Legacy clients expect filter without parentheses
                new_filter = []
                for flt in entry['filter']:
                    assert flt[0] == '(' and flt[-1] == ')'
                    new_filter.append(flt[1:-1])
                entry['filter'] = new_filter

        if not options['raw'] and not options['all']:
            # Don't return the raw target filter by default
            entry.pop('ipapermtargetfilter', None)

    def get_effective_attrs(self, entry):
        attrs = set(entry.get('ipapermdefaultattr', ()))
        attrs.update(entry.get('ipapermincludedattr', ()))
        if ('read' in entry.get('ipapermright', ()) and
                'objectclass' in (x.lower() for x in attrs)):
            # Add special-cased operational attributes
            # We want to allow reading these whenever reading the objectclass
            # is allowed.
            # (But they can still be excluded explicitly, at least in managed
            # permissions).
            attrs.update((u'entryusn', u'createtimestamp', u'modifytimestamp'))
        attrs.difference_update(entry.get('ipapermexcludedattr', ()))
        return sorted(attrs)

    def make_aci(self, entry):
        """Make an ACI string from the given permission entry"""

        aci_parts = []
        name = entry.single_value['cn']

        # targetattr
        attrs = self.get_effective_attrs(entry)
        if attrs:
            aci_parts.append("(targetattr = \"%s\")" % ' || '.join(attrs))

        # target
        ipapermtarget = entry.single_value.get('ipapermtarget')
        if ipapermtarget:
            aci_parts.append("(target = \"%s\")" %
                             'ldap:///%s' % ipapermtarget)

        # target_to
        ipapermtargetto = entry.single_value.get('ipapermtargetto')
        if ipapermtargetto:
            aci_parts.append("(target_to = \"%s\")" %
                             'ldap:///%s' % ipapermtargetto)

        # target_from
        ipapermtargetfrom = entry.single_value.get('ipapermtargetfrom')
        if ipapermtargetfrom:
            aci_parts.append("(target_from = \"%s\")" %
                             'ldap:///%s' % ipapermtargetfrom)

        # targetfilter
        ipapermtargetfilter = entry.get('ipapermtargetfilter')
        if ipapermtargetfilter:
            assert all(f.startswith('(') and f.endswith(')')
                       for f in ipapermtargetfilter)
            if len(ipapermtargetfilter) == 1:
                filter = ipapermtargetfilter[0]
            else:
                filter = '(&%s)' % ''.join(sorted(ipapermtargetfilter))
            aci_parts.append("(targetfilter = \"%s\")" % filter)

        # version, name, rights, bind rule
        ipapermbindruletype = entry.single_value.get('ipapermbindruletype',
                                                     'permission')
        if ipapermbindruletype == 'permission':
            dn = DN(('cn', name), self.container_dn, self.api.env.basedn)
            bindrule = 'groupdn = "ldap:///%s"' % dn
        elif ipapermbindruletype == 'all':
            bindrule = 'userdn = "ldap:///all"'
        elif ipapermbindruletype == 'anonymous':
            bindrule = 'userdn = "ldap:///anyone"'
        else:
            raise ValueError(ipapermbindruletype)

        aci_parts.append('(version 3.0;acl "permission:%s";allow (%s) %s;)' % (
            name, ','.join(sorted(entry['ipapermright'])), bindrule))

        return ''.join(aci_parts)

    def add_aci(self, permission_entry):
        """Add the ACI coresponding to the given permission entry"""
        ldap = self.api.Backend.ldap2
        acistring = self.make_aci(permission_entry)
        location = permission_entry.single_value.get('ipapermlocation',
                                                     self.api.env.basedn)

        logger.debug('Adding ACI %r to %s', acistring, location)
        try:
            entry = ldap.get_entry(location, ['aci'])
        except errors.NotFound:
            raise errors.NotFound(reason=_('Entry %s not found') % location)
        entry.setdefault('aci', []).append(acistring)
        ldap.update_entry(entry)

    def remove_aci(self, permission_entry):
        """Remove the ACI corresponding to the given permission entry

        :return: tuple:
            - entry
            - removed ACI string, or None if none existed previously
        """
        return self._replace_aci(permission_entry)

    def update_aci(self, permission_entry, old_name=None):
        """Update the ACI corresponding to the given permission entry

        :return: tuple:
            - entry
            - removed ACI string, or None if none existed previously
        """
        new_acistring = self.make_aci(permission_entry)
        return self._replace_aci(permission_entry, old_name, new_acistring)

    def _replace_aci(self, permission_entry, old_name=None, new_acistring=None):
        """Replace ACI corresponding to permission_entry

        :param old_name: the old name of the permission, if different from new
        :param new_acistring: new ACI string; if None the ACI is just deleted
        :return: tuple:
            - entry
            - removed ACI string, or None if none existed previously
        """
        ldap = self.api.Backend.ldap2
        acientry, acistring = self._get_aci_entry_and_string(
            permission_entry, old_name, notfound_ok=True)

        # (pylint thinks `acientry` is just a dict, but it's an LDAPEntry)
        acidn = acientry.dn  # pylint: disable=E1103

        if acistring is not None:
            logger.debug('Removing ACI %r from %s', acistring, acidn)
            acientry['aci'].remove(acistring)
        if new_acistring:
            logger.debug('Adding ACI %r to %s', new_acistring, acidn)
            acientry.setdefault('aci', []).append(new_acistring)
        try:
            ldap.update_entry(acientry)
        except errors.EmptyModlist:
            logger.debug('No changes to ACI')
        return acientry, acistring

    def _get_aci_entry_and_string(self, permission_entry, name=None,
                                  notfound_ok=False, cached_acientry=None):
        """Get the entry and ACI corresponding to the permission entry

        :param name: The name of the permission, or None for the cn
        :param notfound_ok:
            If true, (acientry, None) will be returned on missing ACI, rather
            than raising exception
        :param cached_acientry: See upgrade_permission()
        """
        ldap = self.api.Backend.ldap2
        if name is None:
            name = permission_entry.single_value['cn']
        location = permission_entry.single_value.get('ipapermlocation',
                                                     self.api.env.basedn)
        wanted_aciname = 'permission:%s' % name

        if (cached_acientry and
                cached_acientry.dn == location and
                'aci' in cached_acientry):
            acientry = cached_acientry
        else:
            try:
                acientry = ldap.get_entry(location, ['aci'])
            except errors.NotFound:
                acientry = ldap.make_entry(location)

        acis = acientry.get('aci', ())
        for acistring in acis:
            try:
                aci = ACI(acistring)
            except SyntaxError as e:
                logger.warning('Unparseable ACI %s: %s (at %s)',
                               acistring, e, location)
                continue
            if aci.name == wanted_aciname:
                return acientry, acistring

        if notfound_ok:
            return acientry, None
        raise errors.NotFound(
            reason=_('The ACI for permission %(name)s was not found '
                     'in %(dn)s ') % {'name': name, 'dn': location})

    def upgrade_permission(self, entry, target_entry=None,
                           output_only=False, cached_acientry=None):
        """Upgrade the given permission entry to V2, in-place

        The entry is only upgraded if it is a plain old-style permission,
        that is, it has no flags set.

        :param target_entry:
            If given, ``target_entry`` is filled from information taken
            from the ACI corresponding to ``entry``.
            If None, ``entry`` itself is filled
        :param output_only:
            If true, the flags & objectclass are not updated to V2.
            Used for the -find and -show commands.
        :param cached_acientry:
            Optional pre-retreived entry that contains the existing ACI.
            If it is None or its DN does not match the location DN,
            cached_acientry is ignored and the entry is retreived from LDAP.
        """
        if entry.get('ipapermissiontype'):
            # Only convert old-style, non-SYSTEM permissions -- i.e. no flags
            return
        base, acistring = self._get_aci_entry_and_string(
            entry, cached_acientry=cached_acientry)

        if not target_entry:
            target_entry = entry

        # The DN of old permissions is always basedn
        # (pylint thinks `base` is just a dict, but it's an LDAPEntry)
        assert base.dn == self.api.env.basedn, base  # pylint: disable=E1103

        aci = ACI(acistring)

        if 'target' in aci.target:
            target_entry.single_value['ipapermtarget'] = DN(strip_ldap_prefix(
                aci.target['target']['expression']))
        if 'targetfilter' in aci.target:
            target_entry.single_value['ipapermtargetfilter'] = unicode(
                aci.target['targetfilter']['expression'])
        if aci.bindrule['expression'] == 'ldap:///all':
            target_entry.single_value['ipapermbindruletype'] = u'all'
        elif aci.bindrule['expression'] == 'ldap:///anyone':
            target_entry.single_value['ipapermbindruletype'] = u'anonymous'
        else:
            target_entry.single_value['ipapermbindruletype'] = u'permission'
        target_entry['ipapermright'] = aci.permissions
        if 'targetattr' in aci.target:
            target_entry['ipapermincludedattr'] = [
                unicode(a) for a in aci.target['targetattr']['expression']]

        if not output_only:
            target_entry['ipapermissiontype'] = ['SYSTEM', 'V2']
            if 'ipapermissionv2' not in entry['objectclass']:
                target_entry['objectclass'] = list(entry['objectclass']) + [
                    u'ipapermissionv2']

        target_entry['ipapermlocation'] = [self.api.env.basedn]

        # Make sure we're not losing *any info* by the upgrade
        new_acistring = self.make_aci(target_entry)
        if not ACI(new_acistring).isequal(aci):
            raise ValueError('Cannot convert ACI, %r != %r' % (new_acistring,
                                                               acistring))

    def make_type_filter(self, obj):
        """Make a filter for a --type based permission from an Object"""
        objectclasses = getattr(obj, 'permission_filter_objectclasses', None)
        if not objectclasses:
            return None
        filters = [u'(objectclass=%s)' % o for o in objectclasses]
        if len(filters) == 1:
            return filters[0]
        else:
            return '(|%s)' % ''.join(sorted(filters))

    def preprocess_options(self, options,
                           return_filter_ops=False,
                           merge_targetfilter=False):
        """Preprocess options (in-place)

        :param options: A dictionary of options
        :param return_filter_ops:
            If false, assumes there is no pre-existing entry;
            additional values of ipapermtargetfilter are added to options.
            If true, a dictionary of operations on ipapermtargetfilter is
            returned.
            These operations must be performed after the existing entry
            is retrieved.
            The dict has the following keys:
                - remove: list of regular expression objects;
                    implicit values that match any of them should be removed
                - add: list of values to be added, after any removals
        :merge_targetfilter:
            If true, the extratargetfilter is copied into ipapermtargetfilter.
        """

        if 'extratargetfilter' in options:
            if 'ipapermtargetfilter' in options:
                raise errors.ValidationError(
                    name='ipapermtargetfilter',
                    error=_('cannot specify full target filter '
                            'and extra target filter simultaneously'))
            if merge_targetfilter:
                options['ipapermtargetfilter'] = options['extratargetfilter']

        filter_ops = {'add': [], 'remove': []}

        if options.get('subtree'):
            if isinstance(options['subtree'], (list, tuple)):
                [options['subtree']] = options['subtree']
            try:
                options['subtree'] = strip_ldap_prefix(options['subtree'])
            except ValueError:
                raise errors.ValidationError(
                    name='subtree',
                    error='does not start with "ldap:///"')

        # Handle old options
        for old_name, new_name in _DEPRECATED_OPTION_ALIASES.items():
            if old_name in options:
                if client_has_capability(options['version'], 'permissions2'):
                    raise errors.ValidationError(
                        name=old_name,
                        error=_('option was renamed; use %s') % new_name)
                if new_name in options:
                    raise errors.ValidationError(
                        name=old_name,
                        error=(_('Cannot use %(old_name)s with %(new_name)s') %
                                {'old_name': old_name, 'new_name': new_name}))
                options[new_name] = options[old_name]
                del options[old_name]

        # memberof
        if 'memberof' in options:
            filter_ops['remove'].append(re.compile(r'\(memberOf=.*\)', re.I))
            memberof = options.pop('memberof')
            for group in (memberof or ()):
                try:
                    groupdn = self.api.Object.group.get_dn_if_exists(group)
                except errors.NotFound:
                    raise errors.NotFound(
                        reason=_('%s: group not found') % group)
                filter_ops['add'].append(u'(memberOf=%s)' % groupdn)

        # targetgroup
        if 'targetgroup' in options:
            targetgroup = options.pop('targetgroup')
            if targetgroup:
                if 'ipapermtarget' in options:
                    raise errors.ValidationError(
                        name='ipapermtarget',
                        error=_('target and targetgroup are mutually exclusive'))
                try:
                    groupdn = self.api.Object.group.get_dn_if_exists(targetgroup)
                except errors.NotFound:
                    raise errors.NotFound(
                        reason=_('%s: group not found') % targetgroup)
                options['ipapermtarget'] = groupdn
            else:
                if 'ipapermtarget' not in options:
                    options['ipapermtarget'] = None

        # type
        if 'type' in options:
            objtype = options.pop('type')
            filter_ops['remove'].append(re.compile(r'\(objectclass=.*\)', re.I))
            filter_ops['remove'].append(re.compile(
                r'\(\|(\(objectclass=[^(]*\))+\)', re.I))
            if objtype:
                if 'ipapermlocation' in options:
                    raise errors.ValidationError(
                        name='ipapermlocation',
                        error=_('subtree and type are mutually exclusive'))
                obj = self.api.Object[objtype.lower()]
                filt = self.make_type_filter(obj)
                if not filt:
                    raise errors.ValidationError(
                        _('"%s" is not a valid permission type') % objtype)
                filter_ops['add'].append(filt)
                container_dn = DN(obj.container_dn, self.api.env.basedn)
                options['ipapermlocation'] = container_dn
            else:
                if 'ipapermlocation' not in options:
                    options['ipapermlocation'] = None

        if return_filter_ops:
            return filter_ops
        elif filter_ops['add']:
            options['ipapermtargetfilter'] = list(options.get(
                'ipapermtargetfilter') or []) + filter_ops['add']

        return None

    def validate_permission(self, entry):
        ldap = self.Backend.ldap2

        # Rough filter validation by a search
        if entry.get('ipapermtargetfilter'):
            try:
                ldap.find_entries(
                    filter=ldap.combine_filters(entry['ipapermtargetfilter'],
                                                rules='&'),
                    base_dn=self.env.basedn,
                    scope=ldap.SCOPE_BASE,
                    size_limit=1)
            except errors.NotFound:
                pass
            except errors.BadSearchFilter:
                raise errors.ValidationError(
                    name='ipapermtargetfilter',
                    error=_('Bad search filter'))

        # Ensure location exists
        if entry.get('ipapermlocation'):
            location = DN(entry.single_value['ipapermlocation'])
            try:
                ldap.get_entry(location, attrs_list=[])
            except errors.NotFound:
                raise errors.ValidationError(
                    name='ipapermlocation',
                    error=_('Entry %s does not exist') % location)

        # Ensure there's something in the ACI's filter
        needed_attrs = (
            'ipapermtarget', 'ipapermtargetfilter',
            'ipapermincludedattr', 'ipapermexcludedattr', 'ipapermdefaultattr')
        if not any(v for a in needed_attrs for v in (entry.get(a) or ())):
            raise errors.ValidationError(
                name='target',
                error=_('there must be at least one target entry specifier '
                        '(e.g. target, targetfilter, attrs)'))

        # Ensure there's a right
        if not entry.get('ipapermright'):
            raise errors.RequirementError(name='ipapermright')


@register()
class permission_add_noaci(baseldap.LDAPCreate):
    __doc__ = _('Add a system permission without an ACI (internal command)')

    msg_summary = _('Added permission "%(value)s"')
    NO_CLI = True

    takes_options = (
        _ipapermissiontype_param,
    )

    def get_options(self):
        perm_options = set(o.name for o in self.obj.takes_params)
        for option in super(permission_add_noaci, self).get_options():
            # From new options, only cn & ipapermissiontype are supported
            if option.name in ['ipapermissiontype']:
                yield option.clone()
            # Other options such as raw, version are supported
            elif option.name not in perm_options:
                yield option.clone()

    def pre_callback(self, ldap, dn, entry, attrs_list, *keys, **options):
        entry['ipapermissiontype'] = list(options['ipapermissiontype'])
        entry['objectclass'] = [oc for oc in entry['objectclass']
                                if oc.lower() != 'ipapermissionv2']
        return dn


@register()
class permission_add(baseldap.LDAPCreate):
    __doc__ = _('Add a new permission.')

    msg_summary = _('Added permission "%(value)s"')

    # Need to override execute so that processed options apply to
    # the whole command, not just the callbacks
    def execute(self, *keys, **options):
        self.obj.preprocess_options(options, merge_targetfilter=True)
        return super(permission_add, self).execute(*keys, **options)

    def get_args(self):
        for arg in super(permission_add, self).get_args():
            if arg.name == 'cn':
                yield _disallow_colon(arg)
            else:
                yield arg

    def pre_callback(self, ldap, dn, entry, attrs_list, *keys, **options):
        entry['ipapermissiontype'] = ['SYSTEM', 'V2']
        entry['cn'] = list(keys)
        if not entry.get('ipapermlocation'):
            entry.setdefault('ipapermlocation', [api.env.basedn])

        if 'attrs' in options:
            if 'ipapermincludedattr' in options:
                raise errors.ValidationError(
                    name='attrs',
                    error=_('attrs and included attributes are '
                            'mutually exclusive'))
            entry['ipapermincludedattr'] = list(options.pop('attrs') or ())

        self.obj.validate_permission(entry)
        return dn

    def post_callback(self, ldap, dn, entry, *keys, **options):
        try:
            self.obj.add_aci(entry)
        except Exception as e:
            # Adding the ACI failed.
            # We want to be 100% sure the ACI is not there, so try to
            # remove it. (This is a no-op if the ACI was not added.)
            self.obj.remove_aci(entry)
            # Remove the entry.
            # The permission entry serves as a "lock" tho prevent
            # permission-add commands started at the same time from
            # interfering. As long as the entry is there, the other
            # permission-add will fail with DuplicateEntry.
            # So deleting entry ("releasing the lock") must be the last
            # thing we do here.
            try:
                self.api.Backend['ldap2'].delete_entry(entry)
            except errors.NotFound:
                pass
            if isinstance(e, errors.NotFound):
                # add_aci may raise NotFound if the subtree is only virtual
                # like cn=compat,SUFFIX and thus passes the LDAP get entry test
                location = DN(entry.single_value['ipapermlocation'])
                raise errors.ValidationError(
                    name='ipapermlocation',
                    error=_('Cannot store permission ACI to %s') % location)
            # Re-raise original exception
            raise
        self.obj.postprocess_result(entry, options)
        return dn


@register()
class permission_del(baseldap.LDAPDelete):
    __doc__ = _('Delete a permission.')

    msg_summary = _('Deleted permission "%(value)s"')

    takes_options = baseldap.LDAPDelete.takes_options + (
        Flag('force',
             label=_('Force'),
             flags={'no_option', 'no_output'},
             doc=_('force delete of SYSTEM permissions'),
        ),
    )

    def pre_callback(self, ldap, dn, *keys, **options):
        try:
            entry = ldap.get_entry(dn, attrs_list=self.obj.default_attributes)
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        if not options.get('force'):
            self.obj.reject_system(entry)
            if entry.get('ipapermdefaultattr'):
                raise errors.ACIError(
                    info=_('cannot delete managed permissions'))

        try:
            self.obj.remove_aci(entry)
        except errors.NotFound:
            raise errors.NotFound(
                reason=_('ACI of permission %s was not found') % keys[0])

        return dn


@register()
class permission_mod(baseldap.LDAPUpdate):
    __doc__ = _('Modify a permission.')

    msg_summary = _('Modified permission "%(value)s"')

    def execute(self, *keys, **options):
        context.filter_ops = self.obj.preprocess_options(
            options, return_filter_ops=True)
        return super(permission_mod, self).execute(*keys, **options)

    def get_options(self):
        for opt in super(permission_mod, self).get_options():
            if opt.name == 'rename':
                yield _disallow_colon(opt)
            else:
                yield opt

    def pre_callback(self, ldap, dn, entry, attrs_list, *keys, **options):
        if 'rename' in options and not options['rename']:
            raise errors.ValidationError(name='rename',
                                         error='New name can not be empty')

        try:
            attrs_list = self.obj.default_attributes
            old_entry = ldap.get_entry(dn, attrs_list=attrs_list)
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        self.obj.reject_system(old_entry)
        self.obj.upgrade_permission(old_entry)

        if 'MANAGED' in old_entry.get('ipapermissiontype', ()):
            for option_name in sorted(options):
                if option_name == 'rename':
                    raise errors.ValidationError(
                        name=option_name,
                        error=_('cannot rename managed permissions'))
                option = self.options[option_name]
                allow_mod = 'allow_mod_for_managed_permission' in option.flags
                if (option.attribute and not allow_mod or
                        option_name == 'extratargetfilter'):
                    raise errors.ValidationError(
                        name=option_name,
                        error=_('not modifiable on managed permissions'))
            if context.filter_ops.get('add'):
                raise errors.ValidationError(
                    name='ipapermtargetfilter',
                    error=_('not modifiable on managed permissions'))
        else:
            if options.get('ipapermexcludedattr'):
                # prevent setting excluded attributes on normal permissions
                # (but do allow deleting them all)
                raise errors.ValidationError(
                    name='ipapermexcludedattr',
                    error=_('only available on managed permissions'))

        if 'attrs' in options:
            if any(a in options for a in ('ipapermincludedattr',
                                          'ipapermexcludedattr')):
                raise errors.ValidationError(
                    name='attrs',
                    error=_('attrs and included/excluded attributes are '
                            'mutually exclusive'))
            attrs = set(options.pop('attrs') or ())
            defaults = set(old_entry.get('ipapermdefaultattr', ()))
            entry['ipapermincludedattr'] = list(attrs - defaults)
            entry['ipapermexcludedattr'] = list(defaults - attrs)

        # Check setting bindtype for an assigned permission
        if options.get('ipapermbindruletype') and old_entry.get('member'):
            raise errors.ValidationError(
                name='ipapermbindruletype',
                error=_('cannot set bindtype for a permission that is '
                        'assigned to a privilege'))

        # Since `entry` only contains the attributes we are currently changing,
        # it cannot be used directly to generate an ACI.
        # First we need to copy the original data into it.
        for key, value in old_entry.items():
            if (key not in options and
                    key != 'cn' and
                    key not in self.obj.attribute_members):
                entry.setdefault(key, value)

        # For extratargetfilter, add it to the implicit filters
        # to get the full target filter
        if 'extratargetfilter' in options:
            filter_attr_info = self.obj._get_filter_attr_info(entry)
            entry['ipapermtargetfilter'] = (
                list(options['extratargetfilter'] or []) +
                list(filter_attr_info['implicit_targetfilters']))

        filter_ops = context.filter_ops
        old_filter_attr_info = self.obj._get_filter_attr_info(old_entry)
        old_implicit_filters = old_filter_attr_info['implicit_targetfilters']
        removes = filter_ops.get('remove', [])
        new_filters = set(
            filt for filt in (entry.get('ipapermtargetfilter') or [])
            if filt not in old_implicit_filters or
                not any(rem.match(filt) for rem in removes))
        new_filters.update(filter_ops.get('add', []))
        new_filters.update(options.get('ipapermtargetfilter') or [])
        entry['ipapermtargetfilter'] = list(new_filters)

        if not entry.get('ipapermlocation'):
            entry['ipapermlocation'] = [self.api.env.basedn]

        self.obj.validate_permission(entry)

        old_location = old_entry.single_value.get('ipapermlocation',
                                                  self.api.env.basedn)
        if old_location == options.get('ipapermlocation', old_location):
            context.permision_moving_aci = False
        else:
            context.permision_moving_aci = True
            try:
                context.old_aci_info = self.obj.remove_aci(old_entry)
            except errors.NotFound as e:
                logger.error('permission ACI not found: %s', e)

        # To pass data to postcallback, we currently need to use the context
        context.old_entry = old_entry

        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        if call_func.__name__ == 'update_entry':
            self._revert_aci()
        raise exc

    def _revert_aci(self):
        old_aci_info = getattr(context, 'old_aci_info', None)
        if old_aci_info:
            # Try to roll back the old ACI
            entry, old_aci_string = old_aci_info
            if old_aci_string:
                logger.warning('Reverting ACI on %s to %s', entry.dn,
                               old_aci_string)
                entry['aci'].append(old_aci_string)
                self.Backend.ldap2.update_entry(entry)

    def post_callback(self, ldap, dn, entry, *keys, **options):
        old_entry = context.old_entry

        try:
            if context.permision_moving_aci:
                self.obj.add_aci(entry)
            else:
                self.obj.update_aci(entry, old_entry.single_value['cn'])
        except Exception:
            # Don't revert attribute which doesn't exist in LDAP
            entry.pop('attributelevelrights', None)

            logger.error('Error updating ACI: %s', traceback.format_exc())
            logger.warning('Reverting entry')
            old_entry.reset_modlist(entry)
            ldap.update_entry(old_entry)
            self._revert_aci()
            raise
        self.obj.postprocess_result(entry, options)
        entry['dn'] = entry.dn
        return dn


@register()
class permission_find(baseldap.LDAPSearch):
    __doc__ = _('Search for permissions.')

    msg_summary = ngettext(
        '%(count)d permission matched', '%(count)d permissions matched', 0)

    def execute(self, *keys, **options):
        self.obj.preprocess_options(options, merge_targetfilter=True)
        return super(permission_find, self).execute(*keys, **options)

    def pre_callback(self, ldap, filters, attrs_list, base_dn, scope,
                     *args, **options):
        if 'attrs' in options and 'ipapermincludedattr' in options:
            raise errors.ValidationError(
                name='attrs',
                error=_('attrs and included/excluded attributes are '
                        'mutually exclusive'))

        if options.get('attrs'):
            # Effective attributes:
            # each attr must be in either default or included,
            # but not in excluded
            filters = ldap.combine_filters(
                [filters] + [
                    '(&'
                        '(|'
                            '(ipapermdefaultattr=%(attr)s)'
                            '(ipapermincludedattr=%(attr)s))'
                        '(!(ipapermexcludedattr=%(attr)s)))' % {'attr': attr}
                    for attr in options['attrs']
                ],
                ldap.MATCH_ALL,
            )

        return filters, base_dn, scope

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if 'attrs' in options:
            options['ipapermincludedattr'] = options['attrs']

        attribute_options = [o for o in options
                             if (o in self.options and
                                 self.options[o].attribute)]

        if not options.get('pkey_only'):
            for entry in entries:
                # Old-style permissions might have matched (e.g. by name)
                self.obj.upgrade_permission(entry, output_only=True)

        if not truncated:
            max_entries = options.get(
                'sizelimit', self.api.Backend.ldap2.size_limit
            )

            if max_entries > 0:
                # should we get more entries than current sizelimit, fail
                assert len(entries) <= max_entries

            filters = ['(objectclass=ipaPermission)',
                       '(!(ipaPermissionType=V2))']
            if 'name' in options:
                filters.append(ldap.make_filter_from_attr('cn',
                                                          options['name'],
                                                          exact=False))
            index = tuple(self.args).index('criteria')
            try:
                term = args[index]
                filters.append(self.get_term_filter(ldap, term))
            except IndexError:
                term = None

            attrs_list = list(self.obj.default_attributes)
            attrs_list += list(self.obj.attribute_members)
            if options.get('all'):
                attrs_list.append('*')
            try:
                legacy_entries, truncated = ldap.find_entries(
                    base_dn=DN(self.obj.container_dn, self.api.env.basedn),
                    filter=ldap.combine_filters(filters, rules=ldap.MATCH_ALL),
                    attrs_list=attrs_list, size_limit=max_entries)
                # Retrieve the root entry (with all legacy ACIs) at once
                root_entry = ldap.get_entry(DN(api.env.basedn), ['aci'])
            except errors.NotFound:
                legacy_entries = ()
            logger.debug('potential legacy entries: %s', len(legacy_entries))
            nonlegacy_names = {e.single_value['cn'] for e in entries}
            for entry in legacy_entries:
                if entry.single_value['cn'] in nonlegacy_names:
                    continue
                self.obj.upgrade_permission(entry, output_only=True,
                                            cached_acientry=root_entry)
                # If all given options match, include the entry
                # Do a case-insensitive match, on any value if multi-valued
                for opt in attribute_options:
                    optval = options[opt]
                    if not isinstance(optval, (tuple, list)):
                        optval = [optval]
                    value = entry.get(opt)
                    if not value:
                        break
                    if not all(any(str(ov).lower() in str(v).lower()
                                for v in value) for ov in optval):
                        break
                else:
                    # Each search term must be present in some
                    # attribute value
                    for arg in args:
                        if arg:
                            arg = arg.lower()
                            if not any(arg in str(value).lower()
                                       for values in entry.values()
                                       for value in values):
                                break
                    else:
                        if max_entries > 0 and len(entries) == max_entries:
                            # We've reached the limit, set truncated flag
                            # (max_entries <= 0 means unlimited)
                            truncated = True
                            break
                        entries.append(entry)

        for entry in entries:
            if options.get('pkey_only'):
                for opt_name in list(entry):
                    if opt_name != self.obj.primary_key.name:
                        del entry[opt_name]
            else:
                self.obj.postprocess_result(entry, options)

        return truncated


@register()
class permission_show(baseldap.LDAPRetrieve):
    __doc__ = _('Display information about a permission.')

    def post_callback(self, ldap, dn, entry, *keys, **options):
        self.obj.upgrade_permission(entry, output_only=True)
        self.obj.postprocess_result(entry, options)
        return dn


@register()
class permission_add_member(baseldap.LDAPAddMember):
    __doc__ = _('Add members to a permission.')
    NO_CLI = True

    def pre_callback(self, ldap, dn, member_dns, failed, *keys, **options):
        # We can only add permissions with bind rule type set to
        # "permission" (or old-style permissions)
        validate_permission_to_privilege(self.api, keys[-1])
        return dn


@register()
class permission_remove_member(baseldap.LDAPRemoveMember):
    __doc__ = _('Remove members from a permission.')
    NO_CLI = True
