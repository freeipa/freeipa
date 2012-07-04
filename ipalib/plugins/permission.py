# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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

from ipalib.plugins.baseldap import *
from ipalib import api, _, ngettext
from ipalib import Flag, Str, StrEnum
from ipalib.request import context
from ipalib import errors
from ipapython.dn import DN, EditableDN

__doc__ = _("""
Permissions

A permission enables fine-grained delegation of rights. A permission is
a human-readable form of a 389-ds Access Control Rule, or instruction (ACI).
A permission grants the right to perform a specific task such as adding a
user, modifying a group, etc.

A permission may not contain other permissions.

* A permission grants access to read, write, add or delete.
* A privilege combines similar permissions (for example all the permissions
  needed to add a user).
* A role grants a set of privileges to users, groups, hosts or hostgroups.

A permission is made up of a number of different parts:

1. The name of the permission.
2. The target of the permission.
3. The rights granted by the permission.

Rights define what operations are allowed, and may be one or more
of the following:
1. write - write one or more attributes
2. read - read one or more attributes
3. add - add a new entry to the tree
4. delete - delete an existing entry
5. all - all permissions are granted

Read permission is granted for most attributes by default so the read
permission is not expected to be used very often.

Note the distinction between attributes and entries. The permissions are
independent, so being able to add a user does not mean that the user will
be editable.

There are a number of allowed targets:
1. type: a type of object (user, group, etc).
2. memberof: a member of a group or hostgroup
3. filter: an LDAP filter
4. subtree: an LDAP filter specifying part of the LDAP DIT. This is a
   super-set of the "type" target.
5. targetgroup: grant access to modify a specific group (such as granting
   the rights to manage group membership)

EXAMPLES:

 Add a permission that grants the creation of users:
   ipa permission-add --type=user --permissions=add "Add Users"

 Add a permission that grants the ability to manage group membership:
   ipa permission-add --attrs=member --permissions=write --type=group "Manage Group Members"
""")

ACI_PREFIX=u"permission"

output_params = (
    Str('ipapermissiontype',
        label=_('Permission Type'),
    ),
    Str('aci',
        label=_('ACI'),
    ),
)

def filter_options(options, keys):
    """Return a dict that includes entries from `options` that are in `keys`

    example:
    >>> filtered = filter_options({'a': 1, 'b': 2, 'c': 3}, ['a', 'c'])
    >>> filtered == {'a': 1, 'c': 3}
    True
    """
    return dict((k, options[k]) for k in keys if k in options)

class permission(LDAPObject):
    """
    Permission object.
    """
    container_dn = api.env.container_permission
    object_name = _('permission')
    object_name_plural = _('permissions')
    object_class = ['groupofnames', 'ipapermission']
    default_attributes = ['cn', 'member', 'memberof',
        'memberindirect', 'ipapermissiontype',
    ]
    aci_attributes = ['aci', 'group', 'permissions', 'attrs', 'type',
        'filter', 'subtree', 'targetgroup', 'memberof',
    ]
    attribute_members = {
        'member': ['privilege'],
    }
    rdn_is_primary_key = True

    label = _('Permissions')
    label_singular = _('Permission')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Permission name'),
            primary_key=True,
            pattern='^[-_ a-zA-Z0-9]+$',
            pattern_errmsg="May only contain letters, numbers, -, _, and space",
        ),
        Str('permissions+',
            cli_name='permissions',
            label=_('Permissions'),
            doc=_('Comma-separated list of permissions to grant ' \
                '(read, write, add, delete, all)'),
            csv=True,
        ),
        Str('attrs*',
            cli_name='attrs',
            label=_('Attributes'),
            doc=_('Comma-separated list of attributes'),
            csv=True,
            normalizer=lambda value: value.lower(),
            flags=('ask_create'),
        ),
        StrEnum('type?',
            cli_name='type',
            label=_('Type'),
            doc=_('Type of IPA object (user, group, host, hostgroup, service, netgroup, dns)'),
            values=(u'user', u'group', u'host', u'service', u'hostgroup', u'netgroup', u'dnsrecord',),
            flags=('ask_create'),
        ),
        Str('memberof?',
            cli_name='memberof',
            label=_('Member of group'),  # FIXME: Does this label make sense?
            doc=_('Target members of a group'),
            flags=('ask_create'),
        ),
        Str('filter?',
            cli_name='filter',
            label=_('Filter'),
            doc=_('Legal LDAP filter (e.g. ou=Engineering)'),
            flags=('ask_create'),
        ),
        Str('subtree?',
            cli_name='subtree',
            label=_('Subtree'),
            doc=_('Subtree to apply permissions to'),
            flags=('ask_create'),
        ),
        Str('targetgroup?',
            cli_name='targetgroup',
            label=_('Target group'),
            doc=_('User group to apply permissions to'),
            flags=('ask_create'),
        ),
    )

    # Don't allow SYSTEM permissions to be modified or removed
    def check_system(self, ldap, dn, *keys):
        try:
            (dn, entry_attrs) = ldap.get_entry(dn, ['ipapermissiontype'])
        except errors.NotFound:
            self.handle_not_found(*keys)
        if 'ipapermissiontype' in entry_attrs:
            if 'SYSTEM' in entry_attrs['ipapermissiontype']:
                return False
        return True

    def filter_aci_attributes(self, options):
        """Return option dictionary that only includes ACI attributes"""
        return dict((k, v) for k, v in options.items() if
            k in self.aci_attributes)

api.register(permission)


class permission_add(LDAPCreate):
    __doc__ = _('Add a new permission.')

    msg_summary = _('Added permission "%(value)s"')
    has_output_params = LDAPCreate.has_output_params + output_params

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        # Test the ACI before going any further
        opts = self.obj.filter_aci_attributes(options)
        opts['test'] = True
        opts['permission'] = keys[-1]
        opts['aciprefix'] = ACI_PREFIX
        self.api.Command.aci_add(keys[-1], **opts)

        # Clear the aci attributes out of the permission entry
        for o in options:
            try:
                if o not in ['objectclass']:
                    del entry_attrs[o]
            except:
                pass
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        # Now actually add the aci.
        opts = self.obj.filter_aci_attributes(options)
        opts['test'] = False
        opts['permission'] = keys[-1]
        opts['aciprefix'] = ACI_PREFIX
        try:
            result = self.api.Command.aci_add(keys[-1], **opts)['result']
            for attr in self.obj.aci_attributes:
                if attr in result:
                    entry_attrs[attr] = result[attr]
        except errors.InvalidSyntax, e:
            # A syntax error slipped past our attempt at validation, clean up
            self.api.Command.permission_del(keys[-1])
            raise e
        except Exception, e:
            # Something bad happened, clean up as much as we can and return
            # that error
            try:
                self.api.Command.permission_del(keys[-1])
            except Exception, ignore:
                pass
            try:
                self.api.Command.aci_del(keys[-1], aciprefix=ACI_PREFIX)
            except Exception, ignore:
                pass
            raise e
        return dn

api.register(permission_add)

class permission_add_noaci(LDAPCreate):
    __doc__ = _('Add a system permission without an ACI')

    msg_summary = _('Added permission "%(value)s"')
    has_output_params = LDAPCreate.has_output_params + output_params
    NO_CLI = True

    takes_options = (
        StrEnum('permissiontype?',
            label=_('Permission type'),
            values=(u'SYSTEM',),
        ),
    )

    def get_args(self):
        # do not validate system permission names
        yield self.obj.primary_key.clone(pattern=None, pattern_errmsg=None)

    def get_options(self):
        for option in super(permission_add_noaci, self).get_options():
            # filter out ACI options
            if option.name in self.obj.aci_attributes:
                continue
            yield option

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        permission_type = options.get('permissiontype')
        if permission_type:
            entry_attrs['ipapermissiontype'] = [ permission_type ]
        return dn

api.register(permission_add_noaci)


class permission_del(LDAPDelete):
    __doc__ = _('Delete a permission.')

    msg_summary = _('Deleted permission "%(value)s"')

    takes_options = LDAPDelete.takes_options + (
        Flag('force',
             label=_('Force'),
             flags=['no_option', 'no_output'],
             doc=_('force delete of SYSTEM permissions'),
        ),
    )

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        if not options.get('force') and not self.obj.check_system(ldap, dn, *keys):
            raise errors.ACIError(
                info=_('A SYSTEM permission may not be removed'))
        # remove permission even when the underlying ACI is missing
        try:
            self.api.Command.aci_del(keys[-1], aciprefix=ACI_PREFIX)
        except errors.NotFound:
            pass
        return dn

api.register(permission_del)


class permission_mod(LDAPUpdate):
    __doc__ = _('Modify a permission.')

    msg_summary = _('Modified permission "%(value)s"')
    has_output_params = LDAPUpdate.has_output_params + output_params

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        if not self.obj.check_system(ldap, dn, *keys):
            raise errors.ACIError(
                info=_('A SYSTEM permission may not be modified'))

        # check if permission is in LDAP
        try:
            (dn, attrs) = ldap.get_entry(
                dn, attrs_list, normalize=self.obj.normalize_dn
            )
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        # when renaming permission, check if the target permission does not
        # exists already. Then, make changes to underlying ACI
        if 'rename' in options:
            if options['rename']:
                try:
                    try:
                        new_dn = EditableDN(dn)
                        new_dn[0]['cn'] # assure the first RDN has cn as it's type
                    except (IndexError, KeyError), e:
                        raise ValueError("expected dn starting with 'cn=' but got '%s'" % dn)
                    new_dn[0].value = options['rename']
                    (new_dn, attrs) = ldap.get_entry(new_dn, attrs_list, normalize=self.obj.normalize_dn)
                    raise errors.DuplicateEntry()
                except errors.NotFound:
                    pass    # permission may be renamed, continue
            else:
                raise errors.ValidationError(
                    name='rename', error=_('New name can not be empty'))

        opts = self.obj.filter_aci_attributes(options)
        setattr(context, 'aciupdate', False)
        # If there are no options left we don't need to do anything to the
        # underlying ACI.
        if len(opts) > 0:
            opts['permission'] = keys[-1]
            opts['aciprefix'] = ACI_PREFIX
            self.api.Command.aci_mod(keys[-1], **opts)
            setattr(context, 'aciupdate', True)

        # Clear the aci attributes out of the permission entry
        for o in self.obj.aci_attributes:
            try:
                del entry_attrs[o]
            except:
                pass

        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        if call_func.func_name == 'update_entry':
            if isinstance(exc, errors.EmptyModlist):
                aciupdate = getattr(context, 'aciupdate')
                if aciupdate:
                    return
        raise exc

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        # rename the underlying ACI after the change to permission
        cn = keys[-1]

        if 'rename' in options:
            self.api.Command.aci_mod(cn,aciprefix=ACI_PREFIX,
                        permission=options['rename'])

            self.api.Command.aci_rename(cn, aciprefix=ACI_PREFIX,
                        newname=options['rename'])

            cn = options['rename']     # rename finished

        # all common options to permission-mod and show need to be listed here
        common_options = filter_options(options, ['all', 'raw', 'rights'])
        result = self.api.Command.permission_show(cn, **common_options)['result']

        for r in result:
            if not r.startswith('member_'):
                entry_attrs[r] = result[r]
        return dn

api.register(permission_mod)


class permission_find(LDAPSearch):
    __doc__ = _('Search for permissions.')

    msg_summary = ngettext(
        '%(count)d permission matched', '%(count)d permissions matched', 0
    )
    has_output_params = LDAPSearch.has_output_params + output_params

    def post_callback(self, ldap, entries, truncated, *args, **options):

        # There is an option/param overlap: "cn" must be passed as "aciname"
        # to aci-find. Besides that we don't need cn anymore so pop it
        aciname = options.pop('cn', None)

        pkey_only = options.pop('pkey_only', False)
        if not pkey_only:
            for entry in entries:
                (dn, attrs) = entry
                try:
                    common_options = filter_options(options, ['all', 'raw'])
                    aci = self.api.Command.aci_show(attrs['cn'][0],
                        aciprefix=ACI_PREFIX, **common_options)['result']

                    # copy information from respective ACI to permission entry
                    for attr in self.obj.aci_attributes:
                        if attr in aci:
                            attrs[attr] = aci[attr]
                except errors.NotFound:
                    self.debug('ACI not found for %s' % attrs['cn'][0])
        if truncated:
            # size/time limit met, no need to search acis
            return truncated

        if 'sizelimit' in options:
            max_entries = options['sizelimit']
        else:
            config = ldap.get_ipa_config()[1]
            max_entries = config['ipasearchrecordslimit']

        # Now find all the ACIs that match. Once we find them, add any that
        # aren't already in the list along with their permission info.

        opts = self.obj.filter_aci_attributes(options)
        if aciname:
            opts['aciname'] = aciname
        opts['aciprefix'] = ACI_PREFIX
        # permission ACI attribute is needed
        aciresults = self.api.Command.aci_find(*args, **opts)
        truncated = truncated or aciresults['truncated']
        results = aciresults['result']

        for aci in results:
            found = False
            if 'permission' in aci:
                for entry in entries:
                    (dn, attrs) = entry
                    if aci['permission'] == attrs['cn'][0]:
                        found = True
                        break
                if not found:
                    common_options = filter_options(options, ['all', 'raw'])
                    permission = self.api.Command.permission_show(
                        aci['permission'], **common_options)['result']
                    dn = permission['dn']
                    del permission['dn']
                    if pkey_only:
                        new_entry = (dn, {self.obj.primary_key.name: \
                                          permission[self.obj.primary_key.name]})
                    else:
                        new_entry = (dn, permission)

                    if (dn, permission) not in entries:
                       if len(entries) < max_entries:
                           entries.append(new_entry)
                       else:
                           truncated = True
                           break
        return truncated

api.register(permission_find)


class permission_show(LDAPRetrieve):
    __doc__ = _('Display information about a permission.')

    has_output_params = LDAPRetrieve.has_output_params + output_params
    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        try:
            common_options = filter_options(options, ['all', 'raw'])
            aci = self.api.Command.aci_show(keys[-1], aciprefix=ACI_PREFIX,
                **common_options)['result']
            for attr in self.obj.aci_attributes:
                if attr in aci:
                    entry_attrs[attr] = aci[attr]
        except errors.NotFound:
            self.debug('ACI not found for %s' % entry_attrs['cn'][0])
        if options.get('rights', False) and options.get('all', False):
            # The ACI attributes are just broken-out components of aci so
            # the rights should all match it.
            for attr in self.obj.aci_attributes:
                entry_attrs['attributelevelrights'][attr] = entry_attrs['attributelevelrights']['aci']
        return dn

api.register(permission_show)


class permission_add_member(LDAPAddMember):
    """
    Add members to a permission.
    """
    NO_CLI = True

api.register(permission_add_member)


class permission_remove_member(LDAPRemoveMember):
    """
    Remove members from a permission.
    """
    NO_CLI = True

api.register(permission_remove_member)
