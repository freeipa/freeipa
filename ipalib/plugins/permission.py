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

import re
import traceback

from ipalib.plugins import baseldap
from ipalib import errors
from ipalib.parameters import Str, StrEnum, DNParam, Flag
from ipalib import api, _, ngettext
from ipalib.plugable import Registry
from ipalib.capabilities import client_has_capability
from ipalib.aci import ACI
from ipapython.dn import DN
from ipalib.request import context

__doc__ = _("""
Permissions
""" + """
A permission enables fine-grained delegation of rights. A permission is
a human-readable wrapper around a 389-ds Access Control Rule,
or instruction (ACI).
A permission grants the right to perform a specific task such as adding a
user, modifying a group, etc.
""" + """
A permission may not contain other permissions.
""" + """
* A permission grants access to read, write, add, delete, read, search,
  or compare.
* A privilege combines similar permissions (for example all the permissions
  needed to add a user).
* A role grants a set of privileges to users, groups, hosts or hostgroups.
""" + """
A permission is made up of a number of different parts:

1. The name of the permission.
2. The target of the permission.
3. The rights granted by the permission.
""" + """
Rights define what operations are allowed, and may be one or more
of the following:
1. write - write one or more attributes
2. read - read one or more attributes
3. search - search on one or more attributes
4. compare - compare one or more attributes
5. add - add a new entry to the tree
6. delete - delete an existing entry
7. all - all permissions are granted
""" + """
Note the distinction between attributes and entries. The permissions are
independent, so being able to add a user does not mean that the user will
be editable.
""" + """
There are a number of allowed targets:
1. subtree: a DN; the permission applies to the subtree under this DN
2. target filter: an LDAP filter
3. target: DN with possible wildcards, specifies entries permission applies to
""" + """
Additionally, there are the following convenience options.
Setting one of these options will set the corresponding attribute(s).
1. type: a type of object (user, group, etc); sets subtree and target filter.
2. memberof: apply to members of a group; sets target filter
3. targetgroup: grant access to modify a specific group (such as granting
   the rights to manage group membership); sets target.
""" + """
EXAMPLES:
""" + """
 Add a permission that grants the creation of users:
   ipa permission-add --type=user --permissions=add "Add Users"
""" + """
 Add a permission that grants the ability to manage group membership:
   ipa permission-add --attrs=member --permissions=write --type=group "Manage Group Members"
""")

register = Registry()

VALID_OBJECT_TYPES = (u'user', u'group', u'host', u'service', u'hostgroup',
                      u'netgroup', u'dnsrecord',)

_DEPRECATED_OPTION_ALIASES = {
    'permissions': 'ipapermright',
    'attrs': 'ipapermallowedattr',
    'filter': 'ipapermtargetfilter',
    'subtree': 'ipapermlocation',
}

KNOWN_FLAGS = {'SYSTEM', 'V2'}

output_params = (
    Str('aci',
        label=_('ACI'),
    ),
)


def strip_ldap_prefix(uri):
    prefix = 'ldap:///'
    if not uri.startswith(prefix):
        raise ValueError('%r does not start with %r' % (uri, prefix))
    return uri[len(prefix):]


class DNOrURL(DNParam):
    """DN parameter that allows, and strips, a "ldap:///" prefix on input

    Used for ``subtree`` to maintain backward compatibility.
    """

    def _convert_scalar(self, value, index=None):
        if isinstance(value, basestring) and value.startswith('ldap:///'):
            value = strip_ldap_prefix(value)
        return super(DNOrURL, self)._convert_scalar(value, index=index)


@register()
class permission(baseldap.LDAPObject):
    """
    Permission object.
    """
    container_dn = api.env.container_permission
    object_name = _('permission')
    object_name_plural = _('permissions')
    object_class = ['groupofnames', 'ipapermission', 'ipapermissionv2']
    default_attributes = ['cn', 'member', 'memberof',
        'memberindirect', 'ipapermissiontype', 'objectclass',
        'ipapermdefaultattr', 'ipapermallowedattr', 'ipapermexcludedattr',
        'ipapermbindruletype', 'ipapermlocation', 'ipapermright',
        'ipapermtargetfilter', 'ipapermtarget'
    ]
    attribute_members = {
        'member': ['privilege'],
        'memberindirect': ['role'],
    }
    rdn_is_primary_key = True

    label = _('Permissions')
    label_singular = _('Permission')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Permission name'),
            primary_key=True,
            pattern='^[-_ a-zA-Z0-9.]+$',
            pattern_errmsg="May only contain letters, numbers, -, _, ., and space",
        ),
        StrEnum(
            'ipapermright*',
            cli_name='permissions',
            label=_('Permissions'),
            doc=_('Rights to grant '
                  '(read, search, compare, write, add, delete, all)'),
            values=(u'read', u'search', u'compare',
                    u'write', u'add', u'delete', u'all'),
        ),
        Str('ipapermallowedattr*',
            cli_name='attrs',
            label=_('Attributes'),
            doc=_('Attributes to which the permission applies'),
        ),
        StrEnum(
            'ipapermbindruletype',
            cli_name='bindtype',
            label=_('Bind rule type'),
            doc=_('Bind rule type'),
            autofill=True,
            values=(u'permission', u'all', u'anonymous'),
            default=u'permission',
        ),
        DNOrURL(
            'ipapermlocation?',
            cli_name='subtree',
            label=_('Subtree'),
            doc=_('Subtree to apply permissions to'),
            flags={'ask_create'},
        ),
        Str(
            'ipapermtargetfilter?',
            cli_name='filter',
            label=_('ACI target filter'),
            doc=_('ACI target filter'),
        ),

        DNParam(
            'ipapermtarget?',
            cli_name='target',
            label=_('ACI target DN'),
            flags={'no_option'}
        ),

        Str('memberof?',
            label=_('Member of group'),  # FIXME: Does this label make sense?
            doc=_('Target members of a group (sets targetfilter)'),
            flags={'ask_create', 'virtual_attribute'},
        ),
        Str('targetgroup?',
            label=_('Target group'),
            doc=_('User group to apply permissions to (sets target)'),
            flags={'ask_create', 'virtual_attribute'},
        ),
        StrEnum(
            'type?',
            label=_('Type'),
            doc=_('Type of IPA object (sets subtree and filter)'),
            values=VALID_OBJECT_TYPES,
            flags={'ask_create', 'virtual_attribute'},
        ),
    ) + tuple(
        Str(old_name + '*',
            doc=_('Deprecated; use %s' % new_name),
            flags={'no_option', 'virtual_attribute'})
        for old_name, new_name in _DEPRECATED_OPTION_ALIASES.items()
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

    def postprocess_result(self, entry, options):
        """Update a permission entry for output (in place)

        :param entry: The entry to update
        :param options:
            Command options. Contains keys such as ``raw``, ``all``,
            ``pkey_only``, ``version``.
        """
        if not options.get('raw') and not options.get('pkey_only'):
            ipapermtargetfilter = entry.single_value.get('ipapermtargetfilter',
                                                         '')
            ipapermtarget = entry.single_value.get('ipapermtarget')
            ipapermlocation = entry.single_value.get('ipapermlocation')

            # memberof
            match = re.match('^\(memberof=(.*)\)$', ipapermtargetfilter, re.I)
            if match:
                dn = DN(match.group(1))
                if dn[1:] == DN(self.api.Object.group.container_dn,
                                self.api.env.basedn)[:] and dn[0].attr == 'cn':
                    entry.single_value['memberof'] = dn[0].value

            # targetgroup
            if ipapermtarget:
                dn = DN(ipapermtarget)
                if (dn[1:] == DN(self.api.Object.group.container_dn,
                                self.api.env.basedn)[:] and
                        dn[0].attr == 'cn' and dn[0].value != '*'):
                    entry.single_value['targetgroup'] = dn[0].value

            # type
            if ipapermtarget and ipapermlocation:
                for objname in VALID_OBJECT_TYPES:
                    obj = self.api.Object[objname]
                    wantdn = DN(obj.container_dn, self.api.env.basedn)
                    if DN(ipapermlocation) == wantdn:
                        targetdn = DN(
                            (obj.rdn_attribute or obj.primary_key.name, '*'),
                            obj.container_dn,
                            self.api.env.basedn)
                        if ipapermtarget == targetdn:
                            entry.single_value['type'] = objname
                        break

            # old output names
            if not client_has_capability(options['version'], 'permissions2'):
                for old_name, new_name in _DEPRECATED_OPTION_ALIASES.items():
                    if new_name in entry:
                        entry[old_name] = entry[new_name]
                        del entry[new_name]

        rights = entry.get('attributelevelrights')
        if rights:
            rights['memberof'] = rights['ipapermtargetfilter']
            rights['targetgroup'] = rights['ipapermtarget']

            type_rights = set(rights['ipapermtarget'])
            type_rights.intersection_update(rights['ipapermlocation'])
            rights['type'] = ''.join(sorted(type_rights,
                                            key=rights['ipapermtarget'].index))

            if not client_has_capability(options['version'], 'permissions2'):
                for old_name, new_name in _DEPRECATED_OPTION_ALIASES.items():
                    if new_name in entry:
                        rights[old_name] = rights[new_name]
                        del rights[new_name]

        if options.get('raw'):
            # Retreive the ACI from LDAP to ensure we get the real thing
            try:
                acientry, acistring = self._get_aci_entry_and_string(entry)
            except errors.NotFound:
                if list(entry.get('ipapermissiontype')) == ['SYSTEM']:
                    # SYSTEM permissions don't have normal ACIs
                    pass
                else:
                    raise
            else:
                entry.single_value['aci'] = acistring

        if not client_has_capability(options['version'], 'permissions2'):
            # Legacy clients expect some attributes as a single value
            for attr in 'type', 'targetgroup', 'memberof', 'aci':
                if attr in entry:
                    entry[attr] = entry.single_value[attr]
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

    def make_aci(self, entry):
        """Make an ACI string from the given permission entry"""

        aci = ACI()
        name = entry.single_value['cn']
        aci.name = 'permission:%s' % name
        ipapermtarget = entry.single_value.get('ipapermtarget')
        if ipapermtarget:
            aci.set_target('ldap:///%s' % ipapermtarget)
        ipapermtargetfilter = entry.single_value.get('ipapermtargetfilter')
        if ipapermtargetfilter:
            aci.set_target_filter(ipapermtargetfilter)

        ipapermbindruletype = entry.single_value.get('ipapermbindruletype',
                                                     'permission')
        if ipapermbindruletype == 'permission':
            dn = DN(('cn', name), self.container_dn, self.api.env.basedn)
            aci.set_bindrule('groupdn = "ldap:///%s"' % dn)
        elif ipapermbindruletype == 'all':
            aci.set_bindrule('userdn = "ldap:///all"')
        elif ipapermbindruletype == 'anonymous':
            aci.set_bindrule('userdn = "ldap:///anyone"')
        else:
            raise ValueError(ipapermbindruletype)
        aci.permissions = entry['ipapermright']
        aci.set_target_attr(entry.get('ipapermallowedattr', []))

        return aci.export_to_string()

    def add_aci(self, permission_entry):
        """Add the ACI coresponding to the given permission entry"""
        ldap = self.api.Backend.ldap2
        acistring = self.make_aci(permission_entry)
        location = permission_entry.single_value.get('ipapermlocation',
                                                     self.api.env.basedn)

        self.log.debug('Adding ACI %r to %s' % (acistring, location))
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
            self.log.debug('Removing ACI %r from %s' % (acistring, acidn))
            acientry['aci'].remove(acistring)
        if new_acistring:
            self.log.debug('Adding ACI %r to %s' % (new_acistring, acidn))
            acientry['aci'].append(new_acistring)
        try:
            ldap.update_entry(acientry)
        except errors.EmptyModlist:
            self.log.info('No changes to ACI')
        return acientry, acistring

    def _get_aci_entry_and_string(self, permission_entry, name=None,
                                  notfound_ok=False):
        """Get the entry and ACI corresponding to the permission entry

        :param name: The name of the permission, or None for the cn
        :param notfound_ok:
            If true, (acientry, None) will be returned on missing ACI, rather
            than raising exception
        """
        ldap = self.api.Backend.ldap2
        if name is None:
            name = permission_entry.single_value['cn']
        location = permission_entry.single_value.get('ipapermlocation',
                                                     self.api.env.basedn)
        wanted_aciname = 'permission:%s' % name

        try:
            acientry = ldap.get_entry(location, ['aci'])
        except errors.NotFound:
            acientry = ldap.make_entry(location)
        acis = acientry.get('aci', ())
        for acistring in acis:
            aci = ACI(acistring)
            if aci.name == wanted_aciname:
                return acientry, acistring
        else:
            if notfound_ok:
                return acientry, None
            raise errors.NotFound(
                reason=_('The ACI for permission %(name)s was not found '
                         'in %(dn)s ') % {'name': name, 'dn': location})

    def upgrade_permission(self, entry, target_entry=None,
                           output_only=False):
        """Upgrade the given permission entry to V2, in-place

        The entry is only upgraded if it is a plain old-style permission,
        that is, it has no flags set.

        :param target_entry:
            If given, ``target_entry`` is filled from information taken
            from the ACI corresponding to ``entry``.
            If None, ``entry`` itself is filled
        :param output_only:
            If true, the flags are not updated to V2.
            Used for the -find and -show commands.
        """
        if entry.get('ipapermissiontype'):
            # Only convert old-style, non-SYSTEM permissions -- i.e. no flags
            return
        base, acistring = self._get_aci_entry_and_string(entry)

        if not target_entry:
            target_entry = entry

        # The DN of old permissions is always basedn
        # (pylint thinks `base` is just a dict, but it's an LDAPEntry)
        assert base.dn == self.api.env.basedn, base  # pylint: disable=E1103

        aci = ACI(acistring)

        if 'targetattr' in aci.target:
            target_entry['ipapermallowedattr'] = (
                aci.target['targetattr']['expression'])
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
            target_entry['ipapermallowedattr'] = [
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

    def preprocess_options(self, options):
        """Preprocess options (in-place)"""

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
            memberof = options.pop('memberof')
            if memberof:
                if 'ipapermtargetfilter' in options:
                    raise errors.ValidationError(
                        name='ipapermtargetfilter',
                        error=_('filter and memberof are mutually exclusive'))
                try:
                    groupdn = self.api.Object.group.get_dn_if_exists(memberof)
                except errors.NotFound:
                    raise errors.NotFound(
                        reason=_('%s: group not found') % memberof)
                options['ipapermtargetfilter'] = u'(memberOf=%s)' % groupdn
            else:
                if 'ipapermtargetfilter' not in options:
                    options['ipapermtargetfilter'] = None

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
            if objtype:
                if 'ipapermlocation' in options:
                    raise errors.ValidationError(
                        name='ipapermlocation',
                        error=_('subtree and type are mutually exclusive'))
                if 'ipapermtarget' in options:
                    raise errors.ValidationError(
                        name='ipapermtarget',
                        error=_('target and type are mutually exclusive'))
                obj = self.api.Object[objtype.lower()]
                container_dn = DN(obj.container_dn, self.api.env.basedn)
                options['ipapermtarget'] = DN(
                    (obj.rdn_attribute or obj.primary_key.name, '*'),
                    container_dn)
                options['ipapermlocation'] = container_dn
            else:
                if 'ipapermtarget' not in options:
                    options['ipapermtarget'] = None
                if 'ipapermlocation' not in options:
                    options['ipapermlocation'] = None

    def validate_permission(self, entry):
        ldap = self.Backend.ldap2

        # Rough filter validation by a search
        if 'ipapermtargetfilter' in entry:
            try:
                ldap.find_entries(
                    filter=entry.single_value['ipapermtargetfilter'],
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
            'ipapermtarget', 'ipapermtargetfilter', 'ipapermallowedattr')
        if not any(entry.single_value.get(a) for a in needed_attrs):
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
    has_output_params = baseldap.LDAPCreate.has_output_params + output_params

    takes_options = (
        Str('ipapermissiontype+',
            label=_('Permission flags'),
        ),
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
    has_output_params = baseldap.LDAPCreate.has_output_params + output_params

    # Need to override args_options_2_params so that processed options apply to
    # the whole command, not just the callbacks
    def args_options_2_params(self, *args, **options):
        if self.env.in_server:
            self.obj.preprocess_options(options)

        return super(permission_add, self).args_options_2_params(
            *args, **options)

    def pre_callback(self, ldap, dn, entry, attrs_list, *keys, **options):
        entry['ipapermissiontype'] = ['SYSTEM', 'V2']
        entry['cn'] = list(keys)
        if not entry.get('ipapermlocation'):
            entry.setdefault('ipapermlocation', [api.env.basedn])

        self.obj.validate_permission(entry)
        return dn

    def post_callback(self, ldap, dn, entry, *keys, **options):
        self.obj.add_aci(entry)
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
            self.obj.handle_not_found(*keys)

        if not options.get('force'):
            self.obj.reject_system(entry)

        try:
            self.obj.remove_aci(entry)
        except errors.NotFound:
            errors.NotFound('ACI of permission %s was not found' % keys[0])

        return dn


@register()
class permission_mod(baseldap.LDAPUpdate):
    __doc__ = _('Modify a permission.')

    msg_summary = _('Modified permission "%(value)s"')
    has_output_params = baseldap.LDAPUpdate.has_output_params + output_params

    def args_options_2_params(self, *args, **options):
        if self.env.in_server:
            self.obj.preprocess_options(options)

        return super(permission_mod, self).args_options_2_params(
            *args, **options)

    def pre_callback(self, ldap, dn, entry, attrs_list, *keys, **options):
        if 'rename' in options and not options['rename']:
            raise errors.ValidationError(name='rename',
                                         error='New name can not be empty')

        try:
            attrs_list = self.obj.default_attributes
            old_entry = ldap.get_entry(dn, attrs_list=attrs_list)
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        self.obj.reject_system(old_entry)
        self.obj.upgrade_permission(old_entry)

        # Check setting bindtype for an assigned permission
        if options.get('ipapermbindruletype') and old_entry.get('member'):
            raise errors.ValidationError(
                name='ipapermbindruletype',
                error=_('cannot set bindtype for a permission that is '
                        'assigned to a privilege'))

        # Since `entry` only contains the attributes we are currently changing,
        # it cannot be used directly to generate an ACI.
        # First we need to copy the original data into it.
        for key, value in old_entry.iteritems():
            if key not in options and key != 'cn':
                entry.setdefault(key, value)

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
            except errors.NotFound, e:
                self.log.error('permission ACI not found: %s' % e)

        # To pass data to postcallback, we currently need to use the context
        context.old_entry = old_entry

        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        if call_func.func_name == 'update_entry':
            self._revert_aci()
        raise exc

    def _revert_aci(self):
        old_aci_info = getattr(context, 'old_aci_info', None)
        if old_aci_info:
            # Try to roll back the old ACI
            entry, old_aci_string = old_aci_info
            if old_aci_string:
                self.log.warn('Reverting ACI on %s to %s' % (entry.dn,
                                                            old_aci_string))
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
            self.log.error('Error updating ACI: %s' % traceback.format_exc())
            self.log.warn('Reverting entry')
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
    has_output_params = baseldap.LDAPSearch.has_output_params + output_params

    def args_options_2_params(self, *args, **options):
        if self.env.in_server:
            self.obj.preprocess_options(options)

        return super(permission_find, self).args_options_2_params(
            *args, **options)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        attribute_options = [o for o in options
                             if (o in self.options and
                                 self.options[o].attribute)]

        if not options.get('pkey_only'):
            for entry in entries:
                # Old-style permissions might have matched (e.g. by name)
                self.obj.upgrade_permission(entry, output_only=True)

        if not truncated:
            if 'sizelimit' in options:
                max_entries = options['sizelimit']
            else:
                config = ldap.get_ipa_config()
                max_entries = int(config.single_value['ipasearchrecordslimit'])

            filters = ['(objectclass=ipaPermission)',
                       '(!(ipaPermissionType=V2))']
            if args:
                filters.append(ldap.make_filter_from_attr('cn', args[0],
                                                          exact=False))
            attrs_list = list(self.obj.default_attributes)
            attrs_list += list(self.obj.attribute_members)
            if options.get('all'):
                attrs_list.append('*')
            try:
                legacy_entries = ldap.get_entries(
                    base_dn=DN(self.obj.container_dn, self.api.env.basedn),
                    filter=ldap.combine_filters(filters, rules=ldap.MATCH_ALL),
                    attrs_list=attrs_list)
            except errors.NotFound:
                legacy_entries = ()
            self.log.debug('potential legacy entries: %s', len(legacy_entries))
            nonlegacy_names = {e.single_value['cn'] for e in entries}
            for entry in legacy_entries:
                if entry.single_value['cn'] in nonlegacy_names:
                    continue
                if max_entries > 0 and len(entries) > max_entries:
                    # We've over the limit, pop the last entry and set
                    # truncated flag
                    # (this is easier to do than checking before adding
                    # the entry to results)
                    # (max_entries <= 0 means unlimited)
                    entries.pop()
                    truncated = True
                    break
                self.obj.upgrade_permission(entry, output_only=True)
                cn = entry.single_value['cn']
                if any(a.lower() in cn.lower() for a in args if a):
                    entries.append(entry)
                else:
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
                        entries.append(entry)

        for entry in entries:
            if options.get('pkey_only'):
                for opt_name in entry.keys():
                    if opt_name != self.obj.primary_key.name:
                        del entry[opt_name]
            else:
                self.obj.postprocess_result(entry, options)

        return truncated


@register()
class permission_show(baseldap.LDAPRetrieve):
    __doc__ = _('Display information about a permission.')
    has_output_params = baseldap.LDAPRetrieve.has_output_params + output_params

    def post_callback(self, ldap, dn, entry, *keys, **options):
        self.obj.upgrade_permission(entry, output_only=True)
        self.obj.postprocess_result(entry, options)
        return dn


@register()
class permission_add_member(baseldap.LDAPAddMember):
    """Add members to a permission."""
    NO_CLI = True


@register()
class permission_remove_member(baseldap.LDAPRemoveMember):
    """Remove members from a permission."""
    NO_CLI = True
