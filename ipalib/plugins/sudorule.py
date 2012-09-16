# Authors:
#   Jr Aquino <jr.aquino@citrixonline.com>
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

from ipalib import api, errors
from ipalib import Str, StrEnum, Bool
from ipalib.plugins.baseldap import *
from ipalib.plugins.hbacrule import is_all
from ipalib import _, ngettext

__doc__ = _("""
Sudo Rules

Sudo (su "do") allows a system administrator to delegate authority to
give certain users (or groups of users) the ability to run some (or all)
commands as root or another user while providing an audit trail of the
commands and their arguments.

FreeIPA provides a means to configure the various aspects of Sudo:
   Users: The user(s)/group(s) allowed to invoke Sudo.
   Hosts: The host(s)/hostgroup(s) which the user is allowed to to invoke Sudo.
   Allow Command: The specific command(s) permitted to be run via Sudo.
   Deny Command: The specific command(s) prohibited to be run via Sudo.
   RunAsUser: The user(s) or group(s) of users whose rights Sudo will be invoked with.
   RunAsGroup: The group(s) whose gid rights Sudo will be invoked with.
   Options: The various Sudoers Options that can modify Sudo's behavior.

An order can be added to a sudorule to control the order in which they
are evaluated (if the client supports it). This order is an integer and
must be unique.

FreeIPA provides a designated binddn to use with Sudo located at:
uid=sudo,cn=sysaccounts,cn=etc,dc=example,dc=com

To enable the binddn run the following command to set the password:
LDAPTLS_CACERT=/etc/ipa/ca.crt /usr/bin/ldappasswd -S -W \
-h ipa.example.com -ZZ -D "cn=Directory Manager" \
uid=sudo,cn=sysaccounts,cn=etc,dc=example,dc=com

For more information, see the FreeIPA Documentation to Sudo.
""")

topic = ('sudo', _('Commands for controlling sudo configuration'))

def deprecated(attribute):
    raise errors.ValidationError(name=attribute, error=_('this option has been deprecated.'))

def validate_externaluser(ugettext, value):
    deprecated('externaluser')

def validate_runasextuser(ugettext, value):
    deprecated('runasexternaluser')

def validate_runasextgroup(ugettext, value):
    deprecated('runasexternalgroup')

class sudorule(LDAPObject):
    """
    Sudo Rule object.
    """
    container_dn = api.env.container_sudorule
    object_name = _('sudo rule')
    object_name_plural = _('sudo rules')
    object_class = ['ipaassociation', 'ipasudorule']
    default_attributes = [
        'cn', 'ipaenabledflag', 'externaluser',
        'description', 'usercategory', 'hostcategory',
        'cmdcategory', 'memberuser', 'memberhost',
        'memberallowcmd', 'memberdenycmd', 'ipasudoopt',
        'ipasudorunas', 'ipasudorunasgroup',
        'ipasudorunasusercategory', 'ipasudorunasgroupcategory',
        'sudoorder',
    ]
    uuid_attribute = 'ipauniqueid'
    rdn_attribute = 'ipauniqueid'
    attribute_members = {
        'memberuser': ['user', 'group'],
        'memberhost': ['host', 'hostgroup'],
        'memberallowcmd': ['sudocmd', 'sudocmdgroup'],
        'memberdenycmd': ['sudocmd', 'sudocmdgroup'],
        'ipasudorunas': ['user', 'group'],
        'ipasudorunasgroup': ['group'],
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
        Str('memberhost_host?',
            label=_('Hosts'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberhost_hostgroup?',
            label=_('Host Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
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
        Str('externaluser?', validate_externaluser,
            cli_name='externaluser',
            label=_('External User'),
            doc=_('External User the rule applies to (sudorule-find only)'),
        ),
        Str('ipasudorunasextuser?', validate_runasextuser,
            cli_name='runasexternaluser',
            label=_('RunAs External User'),
            doc=_('External User the commands can run as (sudorule-find only)'),
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
        Str('ipasudorunasgroup_group?',
            label=_('RunAs Groups'),
            doc=_('Run with the gid of a specified POSIX group'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        external_host_param,
    )

    order_not_unique_msg = _(
        'order must be a unique value (%(order)d already used by %(rule)s)'
    )

    def check_order_uniqueness(self, *keys, **options):
        if 'sudoorder' in options:
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

api.register(sudorule)


class sudorule_add(LDAPCreate):
    __doc__ = _('Create new Sudo Rule.')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.check_order_uniqueness(*keys, **options)
        # Sudo Rules are enabled by default
        entry_attrs['ipaenabledflag'] = 'TRUE'
        return dn

    msg_summary = _('Added Sudo Rule "%(value)s"')

api.register(sudorule_add)


class sudorule_del(LDAPDelete):
    __doc__ = _('Delete Sudo Rule.')

    msg_summary = _('Deleted Sudo Rule "%(value)s"')

api.register(sudorule_del)


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
            (_dn, _entry_attrs) = ldap.get_entry(dn, self.obj.default_attributes)
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        if is_all(options, 'usercategory') and 'memberuser' in _entry_attrs:
            raise errors.MutuallyExclusiveError(reason=_("user category cannot be set to 'all' while there are allowed users"))
        if is_all(options, 'hostcategory') and 'memberhost' in _entry_attrs:
            raise errors.MutuallyExclusiveError(reason=_("host category cannot be set to 'all' while there are allowed hosts"))
        if is_all(options, 'cmdcategory') and ('memberallowcmd' or
            'memberdenywcmd') in _entry_attrs:
            raise errors.MutuallyExclusiveError(reason=_("command category cannot be set to 'all' while there are allow or deny commands"))
        if is_all(options, 'ipasudorunasusercategory') and 'ipasudorunas' in _entry_attrs:
            raise errors.MutuallyExclusiveError(reason=_("user runAs category cannot be set to 'all' while there are users"))
        if is_all(options, 'ipasudorunasgroupcategory') and 'ipasudorunasgroup' in _entry_attrs:
            raise errors.MutuallyExclusiveError(reason=_("group runAs category cannot be set to 'all' while there are groups"))

        return dn

api.register(sudorule_mod)


class sudorule_find(LDAPSearch):
    __doc__ = _('Search for Sudo Rule.')

    msg_summary = ngettext(
        '%(count)d Sudo Rule matched', '%(count)d Sudo Rules matched', 0
    )

api.register(sudorule_find)


class sudorule_show(LDAPRetrieve):
    __doc__ = _('Display Sudo Rule.')

api.register(sudorule_show)


class sudorule_enable(LDAPQuery):
    __doc__ = _('Enable a Sudo Rule.')

    def execute(self, cn):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)
        entry_attrs = {'ipaenabledflag': 'TRUE'}

        try:
            ldap.update_entry(dn, entry_attrs)
        except errors.EmptyModlist:
            pass
        except errors.NotFound:
            self.obj.handle_not_found(cn)

        return dict(result=True)

    def output_for_cli(self, textui, result, cn):
        textui.print_dashed(_('Enabled Sudo Rule "%s"') % cn)

api.register(sudorule_enable)


class sudorule_disable(LDAPQuery):
    __doc__ = _('Disable a Sudo Rule.')

    def execute(self, cn):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)
        entry_attrs = {'ipaenabledflag': 'FALSE'}

        try:
            ldap.update_entry(dn, entry_attrs)
        except errors.EmptyModlist:
            pass
        except errors.NotFound:
            self.obj.handle_not_found(cn)

        return dict(result=True)

    def output_for_cli(self, textui, result, cn):
        textui.print_dashed(_('Disabled Sudo Rule "%s"') % cn)

api.register(sudorule_disable)


class sudorule_add_allow_command(LDAPAddMember):
    __doc__ = _('Add commands and sudo command groups affected by Sudo Rule.')

    member_attributes = ['memberallowcmd']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        try:
            (_dn, _entry_attrs) = ldap.get_entry(dn, self.obj.default_attributes)
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        if is_all(_entry_attrs, 'cmdcategory'):
            raise errors.MutuallyExclusiveError(reason=_("commands cannot be added when command category='all'"))

        return dn

api.register(sudorule_add_allow_command)


class sudorule_remove_allow_command(LDAPRemoveMember):
    __doc__ = _('Remove commands and sudo command groups affected by Sudo Rule.')

    member_attributes = ['memberallowcmd']
    member_count_out = ('%i object removed.', '%i objects removed.')

api.register(sudorule_remove_allow_command)


class sudorule_add_deny_command(LDAPAddMember):
    __doc__ = _('Add commands and sudo command groups affected by Sudo Rule.')

    member_attributes = ['memberdenycmd']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        try:
            (_dn, _entry_attrs) = ldap.get_entry(dn, self.obj.default_attributes)
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        if is_all(_entry_attrs, 'cmdcategory'):
            raise errors.MutuallyExclusiveError(reason=_("commands cannot be added when command category='all'"))
        return dn

api.register(sudorule_add_deny_command)


class sudorule_remove_deny_command(LDAPRemoveMember):
    __doc__ = _('Remove commands and sudo command groups affected by Sudo Rule.')

    member_attributes = ['memberdenycmd']
    member_count_out = ('%i object removed.', '%i objects removed.')

api.register(sudorule_remove_deny_command)


class sudorule_add_user(LDAPAddMember):
    __doc__ = _('Add users and groups affected by Sudo Rule.')

    member_attributes = ['memberuser']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        try:
            (_dn, _entry_attrs) = ldap.get_entry(dn, self.obj.default_attributes)
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        if is_all(_entry_attrs, 'usercategory'):
            raise errors.MutuallyExclusiveError(reason=_("users cannot be added when user category='all'"))
        return add_external_pre_callback('user', ldap, dn, keys, options)

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return add_external_post_callback('memberuser', 'user', 'externaluser', ldap, completed, failed, dn, entry_attrs, keys, options)

api.register(sudorule_add_user)


class sudorule_remove_user(LDAPRemoveMember):
    __doc__ = _('Remove users and groups affected by Sudo Rule.')

    member_attributes = ['memberuser']
    member_count_out = ('%i object removed.', '%i objects removed.')

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return remove_external_post_callback('memberuser', 'user', 'externaluser', ldap, completed, failed, dn, entry_attrs, keys, options)

api.register(sudorule_remove_user)


class sudorule_add_host(LDAPAddMember):
    __doc__ = _('Add hosts and hostgroups affected by Sudo Rule.')

    member_attributes = ['memberhost']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        try:
            (_dn, _entry_attrs) = ldap.get_entry(dn, self.obj.default_attributes)
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        if is_all(_entry_attrs, 'hostcategory'):
            raise errors.MutuallyExclusiveError(reason=_("hosts cannot be added when host category='all'"))
        return add_external_pre_callback('host', ldap, dn, keys, options)

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return add_external_post_callback('memberhost', 'host', 'externalhost', ldap, completed, failed, dn, entry_attrs, keys, options)

api.register(sudorule_add_host)


class sudorule_remove_host(LDAPRemoveMember):
    __doc__ = _('Remove hosts and hostgroups affected by Sudo Rule.')

    member_attributes = ['memberhost']
    member_count_out = ('%i object removed.', '%i objects removed.')

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return remove_external_post_callback('memberhost', 'host', 'externalhost', ldap, completed, failed, dn, entry_attrs, keys, options)

api.register(sudorule_remove_host)

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
            (_dn, _entry_attrs) = ldap.get_entry(dn, self.obj.default_attributes)
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        if is_all(_entry_attrs, 'ipasudorunasusercategory') or \
          is_all(_entry_attrs, 'ipasudorunasgroupcategory'):
            raise errors.MutuallyExclusiveError(reason=_("users cannot be added when runAs user or runAs group category='all'"))

        if 'user' in options:
            for name in options['user']:
                if not check_validity(name):
                    raise errors.ValidationError(name='runas-user',
                          error=unicode(_("RunAsUser does not accept '%(name)s' as a user name")) %
                          dict(name=name))
        if 'group' in options:
            for name in options['group']:
                if not check_validity(name):
                    raise errors.ValidationError(name='runas-user',
                          error=unicode(_("RunAsUser does not accept '%(name)s' as a group name")) %
                          dict(name=name))

        return add_external_pre_callback('user', ldap, dn, keys, options)

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return add_external_post_callback('ipasudorunas', 'user', 'ipasudorunasextuser', ldap, completed, failed, dn, entry_attrs, keys, options)

api.register(sudorule_add_runasuser)


class sudorule_remove_runasuser(LDAPRemoveMember):
    __doc__ = _('Remove users and groups for Sudo to execute as.')

    member_attributes = ['ipasudorunas']
    member_count_out = ('%i object removed.', '%i objects removed.')

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return remove_external_post_callback('ipasudorunas', 'user', 'ipasudorunasextuser', ldap, completed, failed, dn, entry_attrs, keys, options)

api.register(sudorule_remove_runasuser)


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
            (_dn, _entry_attrs) = ldap.get_entry(dn, self.obj.default_attributes)
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        if is_all(_entry_attrs, 'ipasudorunasusercategory') or \
          is_all(_entry_attrs, 'ipasudorunasgroupcategory'):
            raise errors.MutuallyExclusiveError(reason=_("users cannot be added when runAs user or runAs group category='all'"))

        if 'group' in options:
            for name in options['group']:
                if not check_validity(name):
                    raise errors.ValidationError(name='runas-group',
                          error=unicode(_("RunAsGroup does not accept '%(name)s' as a group name")) %
                          dict(name=name))

        return add_external_pre_callback('group', ldap, dn, keys, options)

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return add_external_post_callback('ipasudorunasgroup', 'group', 'ipasudorunasextgroup', ldap, completed, failed, dn, entry_attrs, keys, options)

api.register(sudorule_add_runasgroup)


class sudorule_remove_runasgroup(LDAPRemoveMember):
    __doc__ = _('Remove group for Sudo to execute as.')

    member_attributes = ['ipasudorunasgroup']
    member_count_out = ('%i object removed.', '%i objects removed.')

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return remove_external_post_callback('ipasudorunasgroup', 'group', 'ipasudorunasextgroup', ldap, completed, failed, dn, entry_attrs, keys, options)

api.register(sudorule_remove_runasgroup)


class sudorule_add_option(LDAPQuery):
    __doc__ = _('Add an option to the Sudo Rule.')

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
        (dn, entry_attrs) = ldap.get_entry(dn, ['ipasudoopt'])

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
            ldap.update_entry(dn, entry_attrs)
        except errors.EmptyModlist:
            pass
        except errors.NotFound:
            self.obj.handle_not_found(cn)

        attrs_list = self.obj.default_attributes
        (dn, entry_attrs) = ldap.get_entry(
            dn, attrs_list, normalize=self.obj.normalize_dn
            )

        return dict(result=entry_attrs)

    def output_for_cli(self, textui, result, cn, **options):
        textui.print_dashed(_('Added option "%(option)s" to Sudo Rule "%(rule)s"') % \
                dict(option=options['ipasudoopt'], rule=cn))
        super(sudorule_add_option, self).output_for_cli(textui, result, cn, options)



api.register(sudorule_add_option)


class sudorule_remove_option(LDAPQuery):
    __doc__ = _('Remove an option from Sudo Rule.')

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
        (dn, entry_attrs) = ldap.get_entry(dn, ['ipasudoopt'])
        try:
            if options['ipasudoopt'] in entry_attrs['ipasudoopt']:
                entry_attrs.setdefault('ipasudoopt', []).remove(
                    options['ipasudoopt'])
                ldap.update_entry(dn, entry_attrs)
            else:
                raise errors.AttrValueNotFound(
                    attr='ipasudoopt',
                    value=options['ipasudoopt']
                    )
        except ValueError, e:
            pass
        except KeyError:
            raise errors.AttrValueNotFound(
                    attr='ipasudoopt',
                    value=options['ipasudoopt']
                    )
        except errors.NotFound:
            self.obj.handle_not_found(cn)

        attrs_list = self.obj.default_attributes
        (dn, entry_attrs) = ldap.get_entry(
            dn, attrs_list, normalize=self.obj.normalize_dn
            )

        return dict(result=entry_attrs)

    def output_for_cli(self, textui, result, cn, **options):
        textui.print_dashed(_('Removed option "%(option)s" from Sudo Rule "%(rule)s"') % \
                dict(option=options['ipasudoopt'], rule=cn))
        super(sudorule_remove_option, self).output_for_cli(textui, result, cn, options)

api.register(sudorule_remove_option)
