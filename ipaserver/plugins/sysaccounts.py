
# Copyright (C) 2025  Red Hat
# see file 'COPYING' for use and warranty information

from ipalib import api, errors
from ipalib import Str, Bool, Password, Flag
from ipalib.plugable import Registry
from ipalib.request import context
from .baseldap import (
    pkey_to_value,
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPUpdate,
    LDAPSearch,
    LDAPRetrieve,
    LDAPQuery)
from .baseuser import validate_nsaccountlock, convert_nsaccountlock
from ipalib import _, ngettext
from ipalib import constants
from ipalib import output
from ipalib.messages import ServerSysacctMgrUpdateRequired, SystemAccountUsage
from ipapython.ipautil import ipa_generate_password, TMP_PWD_ENTROPY_BITS
from ipapython.dn import DN

__doc__ = _("""
System accounts

System accounts designed to allow applications to query LDAP database.
Unlike IPA users, system accounts have no POSIX properties and cannot be
resolved as 'users' in a POSIX environment.

System accounts are stored in cn=sysaccounts,cn=etc LDAP subtree. Some of
system accounts are special to IPA's own operations and cannot be removed.

EXAMPLES:

 Add a new system account, set random password:
   ipa sysaccount-add my-app --random

 Allow the system account to change user passwords without triggering a reset:
   ipa sysaccount-mod my-app --privileged=True

The system account still needs to be permitted to modify user passwords through
a role that includes a corresponding permission ('System: Change User
password'), through the privilege system:
    ipa privilege-add 'my-app password change privilege'
    ipa privilege-add-permission 'my-app password change privilege' \
                      --permission 'System: Change User password'
    ipa role-add 'my-app role'
    ipa role-add-privilege 'my-app role' \
                           --privilege 'my-app password change privilege'
    ipa role-add-member 'my-app role' --sysaccounts my-app

 Delete a system account:
   ipa sysaccount-del my-app

 Find all system accounts:
   ipa sysaccount-find

 Disable the system account:
   ipa sysaccount-disable my-app

 Re-enable the system account:
   ipa sysaccount-enable my-app

 Allow the system account to change user passwords without a reset:
   ipa sysaccount-policy my-app --privileged=true

""")

register = Registry()

required_system_accounts = [
    'passsync',
    'sudo',
]

sysaccount_mgrs_dn = DN('cn=ipa_pwd_extop,cn=plugins,cn=config')
attr_sysacctmgrdns = 'sysacctmanagersdns'

update_without_reset = (
    Bool(
        'privileged?',
        label=_('Privileged'),
        doc=_('Allow password updates without reset'),
    ),
)


def check_userpassword(entry_attrs, **options):
    if 'userpassword' not in entry_attrs and options.get('random'):
        entry_attrs['userpassword'] = ipa_generate_password(
            entropy_bits=TMP_PWD_ENTROPY_BITS)
        # save the password so it can be displayed in post_callback
        setattr(context, 'randompassword', entry_attrs['userpassword'])


def fill_randompassword(entry_attrs, **options):
    if options.get('random', False):
        try:
            entry_attrs['randompassword'] = getattr(context,
                                                    'randompassword')
        except AttributeError:
            # if both randompassword and userpassword options were used
            pass


@register()
class sysaccount(LDAPObject):
    """
    System account object.
    """
    container_dn = api.env.container_sysaccounts
    object_name = _('system account')
    object_name_plural = _('system accounts')
    object_class = [
        'account', 'simplesecurityobject'
    ]
    possible_objectclasses = ['nsmemberof']
    permission_filter_objectclasses = ['simplesecurityobject']
    search_attributes = ['uid', 'description']
    default_attributes = [
        'uid', 'description', 'memberof', 'nsaccountlock']
    uuid_attribute = ''
    attribute_members = {
        'memberof': ['role'],
    }
    password_attributes = [('userpassword', 'has_password')]
    bindable = True
    relationships = {
        'managedby': ('Managed by', 'man_by_', 'not_man_by_'),
    }
    password_attributes = [('userpassword', 'has_password')]
    managed_permissions = {
        'System: Read System Accounts': {
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass',
                'uid', 'memberof', 'nsaccountlock', 'description'
            },
        },
        'System: Check System Accounts passwords': {
            'ipapermright': {'search'},
            'ipapermdefaultattr': {'userpassword'},
            'default_privileges': {'System Accounts Administrators'},
        },
        'System: Add System Accounts': {
            'ipapermright': {'add'},
            'default_privileges': {'System Accounts Administrators'},
        },
        'System: Modify System Accounts': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'userpassword', 'description',
                                   'nsaccountlock'},
            'default_privileges': {'System Accounts Administrators'},
        },
        'System: Remove System Accounts': {
            'ipapermright': {'delete'},
            'default_privileges': {'System Accounts Administrators'},
        },
    }

    label = _('System Accounts')
    label_singular = _('System Account')

    takes_params = (
        Str('uid',
            pattern=constants.PATTERN_GROUPUSER_NAME,
            pattern_errmsg=constants.ERRMSG_GROUPUSER_NAME.format('user'),
            maxlength=255,
            cli_name='login',
            label=_('System account ID'),
            primary_key=True,
            normalizer=lambda value: value.lower()),
        Str('description?',
            cli_name='desc',
            doc=_('A description of system account'),
            label=_('Description')),
        Password('userpassword?',
                 cli_name='password',
                 label=_('Password'),
                 doc=_('Prompt to set the user password'),
                 exclude='webui',
                 flags=('no_search',)),
        Flag('random?',
             doc=_('Generate a random user password'),
             flags=('no_search', 'virtual_attribute'),
             default=False),
        Str('randompassword?',
            label=_('Random password'),
            flags=('no_create', 'no_update', 'no_search', 'virtual_attribute')),
        Bool('nsaccountlock?',
             cli_name=('disabled'),
             default=False,
             label=_('Account disabled')),
    )

    def get_dn(self, *keys, **kwargs):
        key = keys[0]

        parent_dn = DN(self.container_dn, self.api.env.basedn)
        true_rdn = 'uid'

        return self.backend.make_dn_from_attr(
            true_rdn, key, parent_dn
        )

    def get_password_attributes(self, ldap, dn, entry_attrs):
        """
        Search on the entry to determine if it has a password or
        keytab set.
        """
        #  Limit objectclass to simpleSecurityObject
        obj_filter = self.api.Object.permission.make_type_filter(self)
        for (pwattr, attr) in self.password_attributes:
            search_filter = '(&(%s=*)%s)' % (pwattr, obj_filter)
            try:
                ldap.find_entries(
                    search_filter, [pwattr], dn, ldap.SCOPE_BASE
                )
                entry_attrs[attr] = True
            except errors.NotFound:
                entry_attrs[attr] = False

    def handle_reset(self, cmd, next_cmd, ldap, dn, entry_attrs, **options):
        privileged = None
        exc = None
        if 'privileged' in options:
            # TODO: change the code to perform DBUS oddjob operation instead
            # because cn=config changes require cn=Directory Manager permissions
            # and then 389-ds needs a restart
            add_to_passsync_mgrs = options.get('privileged', False)
            try:
                if add_to_passsync_mgrs:
                    ldap.add_entry_to_group(
                        dn, sysaccount_mgrs_dn,
                        attr_sysacctmgrdns)
                    privileged = True
                else:
                    ldap.remove_entry_from_group(
                        dn, sysaccount_mgrs_dn,
                        attr_sysacctmgrdns)
                    privileged = False
                if next_cmd:
                    command_name = next_cmd.name.replace('_','-')
                    cmd.add_message(ServerSysacctMgrUpdateRequired(
                        server=cmd.api.env.server,
                        command=command_name))
            except (errors.EmptyModlist,
                    errors.NotGroupMember,
                    errors.AlreadyGroupMember) as e:
                exc = e
        if entry_attrs is not None:
            if privileged is None:
                privileged = False
                # Retrieve the sysacctmanagersdns and see if the DN is there
                try:
                    entry = ldap.get_entry(
                        sysaccount_mgrs_dn,
                        [attr_sysacctmgrdns]
                    )
                    managers = entry.get(attr_sysacctmgrdns, [])
                    if str(dn) in managers:
                        privileged = True
                except errors.NotFound:
                    pass
            entry_attrs['privileged'] = privileged
        if exc is not None:
            raise exc


@register()
class sysaccount_add(LDAPCreate):
    __doc__ = _('Add a new IPA system account.')
    msg_summary = _('Added system account "%(value)s"')

    takes_options = LDAPCreate.takes_options + update_without_reset
    has_output_params = LDAPCreate.has_output_params + update_without_reset

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        if 'userpassword' not in entry_attrs and 'random' not in options:
            raise errors.ValidationError(
                name='password',
                error=_('Either --password or --random is required')
            )
        check_userpassword(entry_attrs, **options)
        validate_nsaccountlock(entry_attrs)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        fill_randompassword(entry_attrs, **options)
        try:
            self.obj.handle_reset(self, self.api.Command.sysaccount_policy,
                                  ldap, dn, entry_attrs, **options)
        except errors.NotGroupMember:
            pass
        self.add_message(SystemAccountUsage(uid=keys[0], dn=dn))
        convert_nsaccountlock(entry_attrs)
        return dn


@register()
class sysaccount_del(LDAPDelete):
    __doc__ = _('Delete an IPA system account.')
    msg_summary = _('Deleted system account "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)

        sysaccount = keys[-1]
        if sysaccount.lower() in required_system_accounts:
            raise errors.ValidationError(
                name='system account',
                error=_('{} is required by the IPA master').format(sysaccount)
            )

        # Make sure to remove the sysaccount entry from passsync_mgrs_dn
        # don't error out if access is denied
        try:
            options['privileged'] = False
            self.obj.handle_reset(self, None,
                                  ldap, dn, None, **options)
        except (errors.ACIError, errors.NotGroupMember):
            pass

        return dn


@register()
class sysaccount_mod(LDAPUpdate):
    __doc__ = _('Modify an existing IPA system account.')

    takes_options = LDAPUpdate.takes_options + update_without_reset
    has_output_params = LDAPUpdate.has_output_params + update_without_reset
    allow_empty_update = True

    msg_summary = _('Modified service "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        check_userpassword(entry_attrs, **options)
        try:
            self.obj.handle_reset(self, self.api.Command.sysaccount_policy,
                                  ldap, dn, entry_attrs, **options)
        except (errors.EmptyModlist,
                errors.NotGroupMember,
                errors.AlreadyGroupMember):
            object.__setattr__(self, 'allow_empty_update', False)

        setattr(context, 'privileged', entry_attrs['privileged'])
        del entry_attrs['privileged']

        if 'privileged' not in options:
            object.__setattr__(self, 'allow_empty_update', False)

        validate_nsaccountlock(entry_attrs)

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        fill_randompassword(entry_attrs, **options)
        entry_attrs['privileged'] = getattr(context, 'privileged')
        convert_nsaccountlock(entry_attrs)
        return dn


@register()
class sysaccount_find(LDAPSearch):
    __doc__ = _('Search for IPA system accounts.')

    msg_summary = ngettext(
        '%(count)d system account matched',
        '%(count)d system accounts matched', 0
    )
    sort_result_entries = False

    takes_options = LDAPSearch.takes_options
    has_output_params = LDAPSearch.has_output_params + update_without_reset

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if options.get('pkey_only', False):
            return truncated
        for entry_attrs in entries:
            self.obj.get_password_attributes(ldap, entry_attrs.dn, entry_attrs)
            self.obj.handle_reset(self, self,
                                  ldap, entry_attrs.dn, entry_attrs, **options)
            convert_nsaccountlock(entry_attrs)

        return truncated


@register()
class sysaccount_show(LDAPRetrieve):
    __doc__ = _('Display information about an IPA system account.')

    member_attributes = ['memberof']
    has_output_params = LDAPRetrieve.has_output_params + update_without_reset

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.get_password_attributes(ldap, dn, entry_attrs)
        self.obj.handle_reset(self, self,
                              ldap, dn, entry_attrs, **options)
        convert_nsaccountlock(entry_attrs)

        return dn


@register()
class sysaccount_policy(LDAPRetrieve):
    __doc__ = _(
        'Manage the system account policy.'
    )

    takes_options = LDAPRetrieve.takes_options + update_without_reset
    has_output_params = LDAPRetrieve.has_output_params + update_without_reset

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.handle_reset(self, self, ldap, dn, entry_attrs, **options)
        convert_nsaccountlock(entry_attrs)
        return dn


@register()
class sysaccount_disable(LDAPQuery):
    __doc__ = _('Disable a system account.')

    has_output = output.standard_value
    msg_summary = _('Disabled system account "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)
        ldap.deactivate_entry(dn)

        return dict(
            result=True,
            value=pkey_to_value(keys[0], options),
        )


@register()
class sysaccount_enable(LDAPQuery):
    __doc__ = _('Enable a system account.')

    has_output = output.standard_value
    has_output_params = LDAPQuery.has_output_params
    msg_summary = _('Enabled system account "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)

        ldap.activate_entry(dn)

        return dict(
            result=True,
            value=pkey_to_value(keys[0], options),
        )
