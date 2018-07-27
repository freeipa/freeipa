# Authors:
#   Jr Aquino <jr.aquino@citrixonline.com>
#
# Copyright (C) 2010-2014  Red Hat
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

import netaddr
import six

from ipalib import api, errors
from ipalib import Str, StrEnum, Bool, Int
from ipalib.plugable import Registry
from .baseldap import (LDAPObject, LDAPCreate, LDAPDelete,
                                     LDAPUpdate, LDAPSearch, LDAPRetrieve,
                                     LDAPQuery, LDAPAddMember, LDAPRemoveMember,
                                     add_external_pre_callback,
                                     add_external_post_callback,
                                     remove_external_post_callback,
                                     output, entry_to_dict, pkey_to_value,
                                     external_host_param)
from .hbacrule import is_all
from ipalib import _, ngettext
from ipalib.util import validate_hostmask
from ipapython.dn import DN

if six.PY3:
    unicode = str

__doc__ = _("""
Sudo Rules
""") + _("""
Sudo (su "do") allows a system administrator to delegate authority to
give certain users (or groups of users) the ability to run some (or all)
commands as root or another user while providing an audit trail of the
commands and their arguments.
""") + _("""
FreeIPA provides a means to configure the various aspects of Sudo:
   Users: The user(s)/group(s) allowed to invoke Sudo.
   Hosts: The host(s)/hostgroup(s) which the user is allowed to to invoke Sudo.
   Allow Command: The specific command(s) permitted to be run via Sudo.
   Deny Command: The specific command(s) prohibited to be run via Sudo.
   RunAsUser: The user(s) or group(s) of users whose rights Sudo will be invoked with.
   RunAsGroup: The group(s) whose gid rights Sudo will be invoked with.
   Options: The various Sudoers Options that can modify Sudo's behavior.
""") + _("""
An order can be added to a sudorule to control the order in which they
are evaluated (if the client supports it). This order is an integer and
must be unique.
""") + _("""
FreeIPA provides a designated binddn to use with Sudo located at:
uid=sudo,cn=sysaccounts,cn=etc,dc=example,dc=com
""") + _("""
To enable the binddn run the following command to set the password:
LDAPTLS_CACERT=/etc/ipa/ca.crt /usr/bin/ldappasswd -S -W \
-h ipa.example.com -ZZ -D "cn=Directory Manager" \
uid=sudo,cn=sysaccounts,cn=etc,dc=example,dc=com
""") + _("""
EXAMPLES:
""") + _("""
 Create a new rule:
   ipa sudorule-add readfiles
""") + _("""
 Add sudo command object and add it as allowed command in the rule:
   ipa sudocmd-add /usr/bin/less
   ipa sudorule-add-allow-command readfiles --sudocmds /usr/bin/less
""") + _("""
 Add a host to the rule:
   ipa sudorule-add-host readfiles --hosts server.example.com
""") + _("""
 Add a user to the rule:
   ipa sudorule-add-user readfiles --users jsmith
""") + _("""
 Add a special Sudo rule for default Sudo server configuration:
   ipa sudorule-add defaults
""") + _("""
 Set a default Sudo option:
   ipa sudorule-add-option defaults --sudooption '!authenticate'
""") + _("""
 Set SELinux type and role transitions on a rule:
   ipa sudorule-add-option sysadmin_sudo --sudooption type=unconfined_t
   ipa sudorule-add-option sysadmin_sudo --sudooption role=unconfined_r
""")

register = Registry()

topic = 'sudo'


def deprecated(attribute):
    raise errors.ValidationError(
        name=attribute,
        error=_('this option has been deprecated.'))


hostmask_membership_param = Str('hostmask?', validate_hostmask,
                                label=_('host masks of allowed hosts'),
                                flags=['no_create', 'no_update', 'no_search'],
                                multivalue=True,
                                )

def validate_externaluser(ugettext, value):
    deprecated('externaluser')


def validate_runasextuser(ugettext, value):
    deprecated('runasexternaluser')


def validate_runasextgroup(ugettext, value):
    deprecated('runasexternalgroup')


@register()
class sudorule(LDAPObject):
    """
    Sudo Rule object.
    """
    container_dn = api.env.container_sudorule
    object_name = _('sudo rule')
    object_name_plural = _('sudo rules')
    object_class = ['ipaassociation', 'ipasudorule']
    permission_filter_objectclasses = ['ipasudorule']
    default_attributes = [
        'cn', 'ipaenabledflag', 'externaluser',
        'description', 'usercategory', 'hostcategory',
        'cmdcategory', 'memberuser', 'memberhost',
        'memberallowcmd', 'memberdenycmd', 'ipasudoopt',
        'ipasudorunas', 'ipasudorunasgroup',
        'ipasudorunasusercategory', 'ipasudorunasgroupcategory',
        'sudoorder', 'hostmask', 'externalhost', 'ipasudorunasextusergroup',
        'ipasudorunasextgroup', 'ipasudorunasextuser'
    ]
    uuid_attribute = 'ipauniqueid'
    rdn_attribute = 'ipauniqueid'
    allow_rename = True
    attribute_members = {
        'memberuser': ['user', 'group'],
        'memberhost': ['host', 'hostgroup'],
        'memberallowcmd': ['sudocmd', 'sudocmdgroup'],
        'memberdenycmd': ['sudocmd', 'sudocmdgroup'],
        'ipasudorunas': ['user', 'group'],
        'ipasudorunasgroup': ['group'],
    }
    managed_permissions = {
        'System: Read Sudo Rules': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cmdcategory', 'cn', 'description', 'externalhost',
                'externaluser', 'hostcategory', 'hostmask', 'ipaenabledflag',
                'ipasudoopt', 'ipasudorunas', 'ipasudorunasextgroup',
                'ipasudorunasextuser', 'ipasudorunasextusergroup',
                'ipasudorunasgroup',
                'ipasudorunasgroupcategory', 'ipasudorunasusercategory',
                'ipauniqueid', 'memberallowcmd', 'memberdenycmd',
                'memberhost', 'memberuser', 'sudonotafter', 'sudonotbefore',
                'sudoorder', 'usercategory', 'objectclass', 'member',
            },
        },
        'System: Read Sudoers compat tree': {
            'non_object': True,
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN('ou=sudoers', api.env.basedn),
            'ipapermbindruletype': 'anonymous',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass', 'cn', 'ou',
                'sudouser', 'sudohost', 'sudocommand', 'sudorunas',
                'sudorunasuser', 'sudorunasgroup', 'sudooption',
                'sudonotbefore', 'sudonotafter', 'sudoorder', 'description',
            },
        },
        'System: Add Sudo rule': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///ipauniqueid=*,cn=sudorules,cn=sudo,$SUFFIX")(version 3.0;acl "permission:Add Sudo rule";allow (add) groupdn = "ldap:///cn=Add Sudo rule,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Sudo Administrator'},
        },
        'System: Delete Sudo rule': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///ipauniqueid=*,cn=sudorules,cn=sudo,$SUFFIX")(version 3.0;acl "permission:Delete Sudo rule";allow (delete) groupdn = "ldap:///cn=Delete Sudo rule,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Sudo Administrator'},
        },
        'System: Modify Sudo rule': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'description', 'ipaenabledflag', 'usercategory',
                'hostcategory', 'cmdcategory', 'ipasudorunasusercategory',
                'ipasudorunasgroupcategory', 'externaluser',
                'ipasudorunasextusergroup',
                'ipasudorunasextuser', 'ipasudorunasextgroup', 'memberdenycmd',
                'memberallowcmd', 'memberuser', 'memberhost', 'externalhost',
                'sudonotafter', 'hostmask', 'sudoorder', 'sudonotbefore',
                'ipasudorunas', 'externalhost', 'ipasudorunasgroup',
                'ipasudoopt', 'memberhost',
            },
            'replaces': [
                '(targetattr = "description || ipaenabledflag || usercategory || hostcategory || cmdcategory || ipasudorunasusercategory || ipasudorunasgroupcategory || externaluser || ipasudorunasextuser || ipasudorunasextgroup || memberdenycmd || memberallowcmd || memberuser")(target = "ldap:///ipauniqueid=*,cn=sudorules,cn=sudo,$SUFFIX")(version 3.0;acl "permission:Modify Sudo rule";allow (write) groupdn = "ldap:///cn=Modify Sudo rule,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Sudo Administrator'},
        },
    }

    label = _('Sudo Rules')
    label_singular = _('Sudo Rule')

    takes_params = (
        Str('cn',
            cli_name='sudorule_name',
            label=_('Rule name'),
            primary_key=True,
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
        ),
        Bool('ipaenabledflag?',
             label=_('Enabled'),
             flags=['no_option'],
        ),
        StrEnum('usercategory?',
            cli_name='usercat',
            label=_('User category'),
            doc=_('User category the rule applies to'),
            values=(u'all', ),
        ),
        StrEnum('hostcategory?',
            cli_name='hostcat',
            label=_('Host category'),
            doc=_('Host category the rule applies to'),
            values=(u'all', ),
        ),
        StrEnum('cmdcategory?',
            cli_name='cmdcat',
            label=_('Command category'),
            doc=_('Command category the rule applies to'),
            values=(u'all', ),
        ),
        StrEnum('ipasudorunasusercategory?',
            cli_name='runasusercat',
            label=_('RunAs User category'),
            doc=_('RunAs User category the rule applies to'),
            values=(u'all', ),
        ),
        StrEnum('ipasudorunasgroupcategory?',
            cli_name='runasgroupcat',
            label=_('RunAs Group category'),
            doc=_('RunAs Group category the rule applies to'),
            values=(u'all', ),
        ),
        Int('sudoorder?',
            cli_name='order',
            label=_('Sudo order'),
            doc=_('integer to order the Sudo rules'),
            default=0,
            minvalue=0,
        ),
        Str('memberuser_user?',
            label=_('Users'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberuser_group?',
            label=_('User Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('externaluser?', validate_externaluser,
            cli_name='externaluser',
            label=_('External User'),
            doc=_('External User the rule applies to (sudorule-find only)'),
        ),
        Str('memberhost_host?',
            label=_('Hosts'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberhost_hostgroup?',
            label=_('Host Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('hostmask', validate_hostmask,
            normalizer=lambda x: unicode(netaddr.IPNetwork(x).cidr),
            label=_('Host Masks'),
            flags=['no_create', 'no_update', 'no_search'],
            multivalue=True,
        ),
        external_host_param,
        Str('memberallowcmd_sudocmd?',
            label=_('Sudo Allow Commands'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberdenycmd_sudocmd?',
            label=_('Sudo Deny Commands'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberallowcmd_sudocmdgroup?',
            label=_('Sudo Allow Command Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberdenycmd_sudocmdgroup?',
            label=_('Sudo Deny Command Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('ipasudorunas_user?',
            label=_('RunAs Users'),
            doc=_('Run as a user'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('ipasudorunas_group?',
            label=_('Groups of RunAs Users'),
            doc=_('Run as any user within a specified group'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('ipasudorunasextuser?', validate_runasextuser,
            cli_name='runasexternaluser',
            label=_('RunAs External User'),
            doc=_('External User the commands can run as (sudorule-find only)'),
        ),
        Str('ipasudorunasextusergroup?',
            cli_name='runasexternalusergroup',
            label=_('External Groups of RunAs Users'),
            doc=_('External Groups of users that the command can run as'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('ipasudorunasgroup_group?',
            label=_('RunAs Groups'),
            doc=_('Run with the gid of a specified POSIX group'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('ipasudorunasextgroup?', validate_runasextgroup,
            cli_name='runasexternalgroup',
            label=_('RunAs External Group'),
            doc=_('External Group the commands can run as (sudorule-find only)'),
        ),
        Str('ipasudoopt?',
            label=_('Sudo Option'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
    )

    order_not_unique_msg = _(
        'order must be a unique value (%(order)d already used by %(rule)s)'
    )

    def check_order_uniqueness(self, *keys, **options):
        if options.get('sudoorder') is not None:
            entries = self.methods.find(
                sudoorder=options['sudoorder']
            )['result']

            if len(entries) > 0:
                rule_name = entries[0]['cn'][0]
                raise errors.ValidationError(
                    name='order',
                    error=self.order_not_unique_msg % {
                        'order': options['sudoorder'],
                        'rule': rule_name,
                    }
                )


@register()
class sudorule_add(LDAPCreate):
    __doc__ = _('Create new Sudo Rule.')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.check_order_uniqueness(*keys, **options)
        # Sudo Rules are enabled by default
        entry_attrs['ipaenabledflag'] = 'TRUE'
        return dn

    msg_summary = _('Added Sudo Rule "%(value)s"')


@register()
class sudorule_del(LDAPDelete):
    __doc__ = _('Delete Sudo Rule.')

    msg_summary = _('Deleted Sudo Rule "%(value)s"')


@register()
class sudorule_mod(LDAPUpdate):
    __doc__ = _('Modify Sudo Rule.')

    msg_summary = _('Modified Sudo Rule "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

        if 'sudoorder' in options:
            new_order = options.get('sudoorder')
            old_entry = self.api.Command.sudorule_show(keys[-1])['result']
            if 'sudoorder' in old_entry:
                old_order = int(old_entry['sudoorder'][0])
                if old_order != new_order:
                    self.obj.check_order_uniqueness(*keys, **options)
            else:
                self.obj.check_order_uniqueness(*keys, **options)

        try:
            _entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        error = _("%(type)s category cannot be set to 'all' "
                  "while there are allowed %(objects)s")

        category_info = [(
                'usercategory',
                 ['memberuser', 'externaluser'],
                 error % {'type': _('user'), 'objects': _('users')}
            ),
            (
                'hostcategory',
                ['memberhost', 'externalhost', 'hostmask'],
                error % {'type': _('host'), 'objects': _('hosts')}
            ),
            (
                'cmdcategory',
                ['memberallowcmd'],
                error % {'type': _('command'), 'objects': _('commands')}
            ),
            (
                'ipasudorunasusercategory',
                ['ipasudorunas', 'ipasudorunasextuser',
                 'ipasudorunasextusergroup'],
                error % {'type': _('runAs user'), 'objects': _('runAs users')}
            ),
            (
                'ipasudorunasgroupcategory',
                ['ipasudorunasgroup', 'ipasudorunasextgroup'],
                error % {'type': _('group runAs'), 'objects': _('runAs groups')}
            ),
        ]


        # Enforce the checks for all the categories
        for category, member_attrs, error in category_info:
            any_member_attrs_set = any(attr in _entry_attrs
                                       for attr in member_attrs)

            if is_all(options, category) and any_member_attrs_set:
                raise errors.MutuallyExclusiveError(reason=error)

        return dn


@register()
class sudorule_find(LDAPSearch):
    __doc__ = _('Search for Sudo Rule.')

    msg_summary = ngettext(
        '%(count)d Sudo Rule matched', '%(count)d Sudo Rules matched', 0
    )


@register()
class sudorule_show(LDAPRetrieve):
    __doc__ = _('Display Sudo Rule.')


@register()
class sudorule_enable(LDAPQuery):
    __doc__ = _('Enable a Sudo Rule.')

    def execute(self, cn, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)
        try:
            entry_attrs = ldap.get_entry(dn, ['ipaenabledflag'])
        except errors.NotFound:
            raise self.obj.handle_not_found(cn)

        entry_attrs['ipaenabledflag'] = ['TRUE']

        try:
            ldap.update_entry(entry_attrs)
        except errors.EmptyModlist:
            pass

        return dict(result=True)


@register()
class sudorule_disable(LDAPQuery):
    __doc__ = _('Disable a Sudo Rule.')

    def execute(self, cn, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)
        try:
            entry_attrs = ldap.get_entry(dn, ['ipaenabledflag'])
        except errors.NotFound:
            raise self.obj.handle_not_found(cn)

        entry_attrs['ipaenabledflag'] = ['FALSE']

        try:
            ldap.update_entry(entry_attrs)
        except errors.EmptyModlist:
            pass

        return dict(result=True)


@register()
class sudorule_add_allow_command(LDAPAddMember):
    __doc__ = _('Add commands and sudo command groups affected by Sudo Rule.')

    member_attributes = ['memberallowcmd']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)

        try:
            _entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        if is_all(_entry_attrs, 'cmdcategory'):
            raise errors.MutuallyExclusiveError(
                reason=_("commands cannot be added when command "
                         "category='all'"))

        return dn


@register()
class sudorule_remove_allow_command(LDAPRemoveMember):
    __doc__ = _('Remove commands and sudo command groups affected by Sudo Rule.')

    member_attributes = ['memberallowcmd']
    member_count_out = ('%i object removed.', '%i objects removed.')


@register()
class sudorule_add_deny_command(LDAPAddMember):
    __doc__ = _('Add commands and sudo command groups affected by Sudo Rule.')

    member_attributes = ['memberdenycmd']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        return dn


@register()
class sudorule_remove_deny_command(LDAPRemoveMember):
    __doc__ = _('Remove commands and sudo command groups affected by Sudo Rule.')

    member_attributes = ['memberdenycmd']
    member_count_out = ('%i object removed.', '%i objects removed.')


@register()
class sudorule_add_user(LDAPAddMember):
    __doc__ = _('Add users and groups affected by Sudo Rule.')

    member_attributes = ['memberuser']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)

        try:
            _entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        if is_all(_entry_attrs, 'usercategory'):
            raise errors.MutuallyExclusiveError(
                reason=_("users cannot be added when user category='all'"))

        return add_external_pre_callback('user', ldap, dn, keys, options)

    def post_callback(self, ldap, completed, failed, dn, entry_attrs,
                      *keys, **options):
        assert isinstance(dn, DN)
        return add_external_post_callback(ldap, dn, entry_attrs,
                                          failed=failed,
                                          completed=completed,
                                          memberattr='memberuser',
                                          membertype='user',
                                          externalattr='externaluser')


@register()
class sudorule_remove_user(LDAPRemoveMember):
    __doc__ = _('Remove users and groups affected by Sudo Rule.')

    member_attributes = ['memberuser']
    member_count_out = ('%i object removed.', '%i objects removed.')

    def post_callback(self, ldap, completed, failed, dn, entry_attrs,
                      *keys, **options):
        assert isinstance(dn, DN)
        return remove_external_post_callback(ldap, dn, entry_attrs,
                                             failed=failed,
                                             completed=completed,
                                             memberattr='memberuser',
                                             membertype='user',
                                             externalattr='externaluser')


@register()
class sudorule_add_host(LDAPAddMember):
    __doc__ = _('Add hosts and hostgroups affected by Sudo Rule.')

    member_attributes = ['memberhost']
    member_count_out = ('%i object added.', '%i objects added.')

    def get_options(self):
        for option in super(sudorule_add_host, self).get_options():
            yield option
        yield hostmask_membership_param

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        try:
            _entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        if is_all(_entry_attrs, 'hostcategory'):
            raise errors.MutuallyExclusiveError(
                reason=_("hosts cannot be added when host category='all'"))

        return add_external_pre_callback('host', ldap, dn, keys, options)

    def post_callback(self, ldap, completed, failed, dn, entry_attrs,
                      *keys, **options):
        assert isinstance(dn, DN)
        try:
            _entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        if 'hostmask' in options:
            def norm(x):
                return unicode(netaddr.IPNetwork(x).cidr)

            old_masks = set(norm(m) for m in _entry_attrs.get('hostmask', []))
            new_masks = set(norm(m) for m in options['hostmask'])

            num_added = len(new_masks - old_masks)

            if num_added:
                entry_attrs['hostmask'] = list(old_masks | new_masks)
                try:
                    ldap.update_entry(entry_attrs)
                except errors.EmptyModlist:
                    pass
                completed = completed + num_added

        return add_external_post_callback(ldap, dn, entry_attrs,
                                          failed=failed,
                                          completed=completed,
                                          memberattr='memberhost',
                                          membertype='host',
                                          externalattr='externalhost')


@register()
class sudorule_remove_host(LDAPRemoveMember):
    __doc__ = _('Remove hosts and hostgroups affected by Sudo Rule.')

    member_attributes = ['memberhost']
    member_count_out = ('%i object removed.', '%i objects removed.')

    def get_options(self):
        for option in super(sudorule_remove_host, self).get_options():
            yield option
        yield hostmask_membership_param

    def post_callback(self, ldap, completed, failed, dn, entry_attrs,
                      *keys, **options):
        assert isinstance(dn, DN)

        try:
            _entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        if 'hostmask' in options:
            def norm(x):
                return unicode(netaddr.IPNetwork(x).cidr)

            old_masks = set(norm(m) for m in _entry_attrs.get('hostmask', []))
            removed_masks = set(norm(m) for m in options['hostmask'])

            num_added = len(removed_masks & old_masks)

            if num_added:
                entry_attrs['hostmask'] = list(old_masks - removed_masks)
                try:
                    ldap.update_entry(entry_attrs)
                except errors.EmptyModlist:
                    pass
                completed = completed + num_added

        return remove_external_post_callback(ldap, dn, entry_attrs,
                                             failed=failed,
                                             completed=completed,
                                             memberattr='memberhost',
                                             membertype='host',
                                             externalattr='externalhost')


@register()
class sudorule_add_runasuser(LDAPAddMember):
    __doc__ = _('Add users and groups for Sudo to execute as.')

    member_attributes = ['ipasudorunas']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

        def check_validity(runas):
            v = unicode(runas)
            if v.upper() == u'ALL':
                return False
            return True

        try:
            _entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        if any((is_all(_entry_attrs, 'ipasudorunasusercategory'),
                is_all(_entry_attrs, 'ipasudorunasgroupcategory'))):

            raise errors.MutuallyExclusiveError(
                reason=_("users cannot be added when runAs user or runAs "
                         "group category='all'"))

        if 'user' in options:
            for name in options['user']:
                if not check_validity(name):
                    raise errors.ValidationError(name='runas-user',
                          error=unicode(_("RunAsUser does not accept "
                                          "'%(name)s' as a user name")) %
                                          dict(name=name))

        if 'group' in options:
            for name in options['group']:
                if not check_validity(name):
                    raise errors.ValidationError(name='runas-user',
                          error=unicode(_("RunAsUser does not accept "
                                          "'%(name)s' as a group name")) %
                                          dict(name=name))

        return add_external_pre_callback('user', ldap, dn, keys, options)

    def post_callback(self, ldap, completed, failed, dn, entry_attrs,
                      *keys, **options):
        assert isinstance(dn, DN)

        # Since external_post_callback returns the total number of completed
        # entries yet (that is, any external users it added plus the value of
        # passed variable 'completed', we need to pass 0 as completed,
        # so that the entries added by the framework are not counted twice
        # (once in each call of add_external_post_callback)

        (completed_ex_users, dn) = add_external_post_callback(ldap, dn,
                                        entry_attrs,
                                        failed=failed,
                                        completed=0,
                                        memberattr='ipasudorunas',
                                        membertype='user',
                                        externalattr='ipasudorunasextuser',
                                        )

        (completed_ex_groups, dn) = add_external_post_callback(ldap, dn,
                                        entry_attrs=entry_attrs,
                                        failed=failed,
                                        completed=0,
                                        memberattr='ipasudorunas',
                                        membertype='group',
                                        externalattr='ipasudorunasextusergroup',
                                        )

        return (completed + completed_ex_users + completed_ex_groups, dn)


@register()
class sudorule_remove_runasuser(LDAPRemoveMember):
    __doc__ = _('Remove users and groups for Sudo to execute as.')

    member_attributes = ['ipasudorunas']
    member_count_out = ('%i object removed.', '%i objects removed.')

    def post_callback(self, ldap, completed, failed, dn, entry_attrs,
                      *keys, **options):
        assert isinstance(dn, DN)

        # Since external_post_callback returns the total number of completed
        # entries yet (that is, any external users it added plus the value of
        # passed variable 'completed', we need to pass 0 as completed,
        # so that the entries added by the framework are not counted twice
        # (once in each call of remove_external_post_callback)

        (completed_ex_users, dn) = remove_external_post_callback(ldap, dn,
                                        entry_attrs=entry_attrs,
                                        failed=failed,
                                        completed=0,
                                        memberattr='ipasudorunas',
                                        membertype='user',
                                        externalattr='ipasudorunasextuser',
                                        )

        (completed_ex_groups, dn) = remove_external_post_callback(ldap, dn,
                                        entry_attrs=entry_attrs,
                                        failed=failed,
                                        completed=0,
                                        memberattr='ipasudorunas',
                                        membertype='group',
                                        externalattr='ipasudorunasextusergroup',
                                        )

        return (completed + completed_ex_users + completed_ex_groups, dn)


@register()
class sudorule_add_runasgroup(LDAPAddMember):
    __doc__ = _('Add group for Sudo to execute as.')

    member_attributes = ['ipasudorunasgroup']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

        def check_validity(runas):
            v = unicode(runas)
            if v.upper() == u'ALL':
                return False
            return True

        try:
            _entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)
        if (is_all(_entry_attrs, 'ipasudorunasusercategory') or
                is_all(_entry_attrs, 'ipasudorunasgroupcategory')):
            raise errors.MutuallyExclusiveError(
                reason=_("users cannot be added when runAs user or runAs "
                         "group category='all'"))

        if 'group' in options:
            for name in options['group']:
                if not check_validity(name):
                    raise errors.ValidationError(name='runas-group',
                          error=unicode(_("RunAsGroup does not accept "
                                          "'%(name)s' as a group name")) %
                                          dict(name=name))

        return add_external_pre_callback('group', ldap, dn, keys, options)

    def post_callback(self, ldap, completed, failed, dn, entry_attrs,
                      *keys, **options):
        assert isinstance(dn, DN)
        return add_external_post_callback(ldap, dn, entry_attrs,
                                          failed=failed,
                                          completed=completed,
                                          memberattr='ipasudorunasgroup',
                                          membertype='group',
                                          externalattr='ipasudorunasextgroup',
                                          )


@register()
class sudorule_remove_runasgroup(LDAPRemoveMember):
    __doc__ = _('Remove group for Sudo to execute as.')

    member_attributes = ['ipasudorunasgroup']
    member_count_out = ('%i object removed.', '%i objects removed.')

    def post_callback(self, ldap, completed, failed, dn, entry_attrs,
                      *keys, **options):
        assert isinstance(dn, DN)
        return remove_external_post_callback(ldap, dn, entry_attrs,
                                          failed=failed,
                                          completed=completed,
                                          memberattr='ipasudorunasgroup',
                                          membertype='group',
                                          externalattr='ipasudorunasextgroup',
                                          )


@register()
class sudorule_add_option(LDAPQuery):
    __doc__ = _('Add an option to the Sudo Rule.')

    has_output = output.standard_entry
    takes_options = (
        Str('ipasudoopt',
            cli_name='sudooption',
            label=_('Sudo Option'),
        ),
    )

    def execute(self, cn, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)

        if not options['ipasudoopt'].strip():
            raise errors.EmptyModlist()
        entry_attrs = ldap.get_entry(dn, ['ipasudoopt'])

        try:
            if options['ipasudoopt'] not in entry_attrs['ipasudoopt']:
                entry_attrs.setdefault('ipasudoopt', []).append(
                    options['ipasudoopt'])
            else:
                raise errors.DuplicateEntry
        except KeyError:
            entry_attrs.setdefault('ipasudoopt', []).append(
                options['ipasudoopt'])
        try:
            ldap.update_entry(entry_attrs)
        except errors.EmptyModlist:
            pass
        except errors.NotFound:
            raise self.obj.handle_not_found(cn)

        attrs_list = self.obj.default_attributes
        entry_attrs = ldap.get_entry(dn, attrs_list)

        self.obj.get_indirect_members(entry_attrs, attrs_list)
        self.obj.convert_attribute_members(entry_attrs, [cn], **options)

        entry_attrs = entry_to_dict(entry_attrs, **options)

        return dict(result=entry_attrs, value=pkey_to_value(cn, options))


@register()
class sudorule_remove_option(LDAPQuery):
    __doc__ = _('Remove an option from Sudo Rule.')

    has_output = output.standard_entry
    takes_options = (
        Str('ipasudoopt',
            cli_name='sudooption',
            label=_('Sudo Option'),
        ),
    )

    def execute(self, cn, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)

        if not options['ipasudoopt'].strip():
            raise errors.EmptyModlist()

        entry_attrs = ldap.get_entry(dn, ['ipasudoopt'])

        try:
            if options['ipasudoopt'] in entry_attrs['ipasudoopt']:
                entry_attrs.setdefault('ipasudoopt', []).remove(
                    options['ipasudoopt'])
                ldap.update_entry(entry_attrs)
            else:
                raise errors.AttrValueNotFound(
                    attr='ipasudoopt',
                    value=options['ipasudoopt']
                    )
        except ValueError:
            pass
        except KeyError:
            raise errors.AttrValueNotFound(
                    attr='ipasudoopt',
                    value=options['ipasudoopt']
                    )
        except errors.NotFound:
            raise self.obj.handle_not_found(cn)

        attrs_list = self.obj.default_attributes
        entry_attrs = ldap.get_entry(dn, attrs_list)

        self.obj.get_indirect_members(entry_attrs, attrs_list)
        self.obj.convert_attribute_members(entry_attrs, [cn], **options)

        entry_attrs = entry_to_dict(entry_attrs, **options)

        return dict(result=entry_attrs, value=pkey_to_value(cn, options))
