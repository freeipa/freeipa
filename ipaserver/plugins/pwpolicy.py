# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#   Martin Kosek <mkosek@redhat.com>
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

import logging

from ipalib import api
from ipalib import Int, Str, DNParam
from ipalib import errors
from .baseldap import (
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPUpdate,
    LDAPRetrieve,
    LDAPSearch)
from ipalib import _
from ipalib.plugable import Registry
from ipalib.request import context
from ipapython.dn import DN

import six

if six.PY3:
    unicode = str

__doc__ = _("""
Password policy

A password policy sets limitations on IPA passwords, including maximum
lifetime, minimum lifetime, the number of passwords to save in
history, the number of character classes required (for stronger passwords)
and the minimum password length.

By default there is a single, global policy for all users. You can also
create a password policy to apply to a group. Each user is only subject
to one password policy, either the group policy or the global policy. A
group policy stands alone; it is not a super-set of the global policy plus
custom settings.

Each group password policy requires a unique priority setting. If a user
is in multiple groups that have password policies, this priority determines
which password policy is applied. A lower value indicates a higher priority
policy.

Group password policies are automatically removed when the groups they
are associated with are removed.

EXAMPLES:

 Modify the global policy:
   ipa pwpolicy-mod --minlength=10

 Add a new group password policy:
   ipa pwpolicy-add --maxlife=90 --minlife=1 --history=10 --minclasses=3 --minlength=8 --priority=10 localadmins

 Display the global password policy:
   ipa pwpolicy-show

 Display a group password policy:
   ipa pwpolicy-show localadmins

 Display the policy that would be applied to a given user:
   ipa pwpolicy-show --user=tuser1

 Modify a group password policy:
   ipa pwpolicy-mod --minclasses=2 localadmins
""")

logger = logging.getLogger(__name__)

register = Registry()

@register()
class cosentry(LDAPObject):
    __doc__ = _('Class of Service object used for linking policies with'
                ' groups')
    NO_CLI = True

    container_dn = DN(('cn', 'costemplates'), api.env.container_accounts)
    object_class = ['top', 'costemplate', 'extensibleobject', 'krbcontainer']
    permission_filter_objectclasses = ['costemplate']
    default_attributes = ['cn', 'cospriority', 'krbpwdpolicyreference']
    managed_permissions = {
        'System: Read Group Password Policy costemplate': {
            'replaces_global_anonymous_aci': True,
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'cospriority', 'krbpwdpolicyreference', 'objectclass',
            },
            'default_privileges': {
                'Password Policy Readers',
                'Password Policy Administrator',
            },
        },
        'System: Add Group Password Policy costemplate': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///cn=*,cn=costemplates,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Add Group Password Policy costemplate";allow (add) groupdn = "ldap:///cn=Add Group Password Policy costemplate,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Password Policy Administrator'},
        },
        'System: Delete Group Password Policy costemplate': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///cn=*,cn=costemplates,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Delete Group Password Policy costemplate";allow (delete) groupdn = "ldap:///cn=Delete Group Password Policy costemplate,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Password Policy Administrator'},
        },
        'System: Modify Group Password Policy costemplate': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'cospriority'},
            'replaces': [
                '(targetattr = "cospriority")(target = "ldap:///cn=*,cn=costemplates,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Modify Group Password Policy costemplate";allow (write) groupdn = "ldap:///cn=Modify Group Password Policy costemplate,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Password Policy Administrator'},
        },
    }

    takes_params = (
        Str('cn', primary_key=True),
        DNParam('krbpwdpolicyreference'),
        Int('cospriority', minvalue=0),
    )

    priority_not_unique_msg = _(
        'priority must be a unique value (%(prio)d already used by %(gname)s)'
    )

    def get_dn(self, *keys, **options):
        group_dn = self.api.Object.group.get_dn(keys[-1])
        return self.backend.make_dn_from_attr(
            'cn', group_dn, DN(self.container_dn, api.env.basedn)
        )

    def check_priority_uniqueness(self, *keys, **options):
        if options.get('cospriority') is not None:
            entries = self.methods.find(
                cospriority=options['cospriority']
            )['result']
            if len(entries) > 0:
                group_name = self.api.Object.group.get_primary_key_from_dn(
                    DN(entries[0]['cn'][0]))
                raise errors.ValidationError(
                    name='priority',
                    error=self.priority_not_unique_msg % {
                        'prio': options['cospriority'],
                        'gname': group_name,
                    }
                )


@register()
class cosentry_add(LDAPCreate):
    __doc__ = _('Add Class of Service entry')
    NO_CLI = True

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

        # check for existence of the group
        group_dn = self.api.Object.group.get_dn(keys[-1])
        try:
            result = ldap.get_entry(group_dn, ['objectclass'])
        except errors.NotFound:
            raise self.api.Object.group.handle_not_found(keys[-1])

        oc = [x.lower() for x in result['objectclass']]
        if 'mepmanagedentry' in oc:
            raise errors.ManagedPolicyError()
        self.obj.check_priority_uniqueness(*keys, **options)
        del entry_attrs['cn']
        return dn


@register()
class cosentry_del(LDAPDelete):
    __doc__ = _('Delete Class of Service entry')
    NO_CLI = True


@register()
class cosentry_mod(LDAPUpdate):
    __doc__ = _('Modify Class of Service entry')
    NO_CLI = True

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        new_cospriority = options.get('cospriority')
        if new_cospriority is not None:
            cos_entry = self.api.Command.cosentry_show(keys[-1])['result']
            old_cospriority = int(cos_entry['cospriority'][0])

            # check uniqueness only when the new priority differs
            if old_cospriority != new_cospriority:
                self.obj.check_priority_uniqueness(*keys, **options)
        return dn


@register()
class cosentry_show(LDAPRetrieve):
    __doc__ = _('Display Class of Service entry')
    NO_CLI = True


@register()
class cosentry_find(LDAPSearch):
    __doc__ = _('Search for Class of Service entry')
    NO_CLI = True


global_policy_name = 'global_policy'
global_policy_dn = DN(('cn', global_policy_name), ('cn', api.env.realm), ('cn', 'kerberos'), api.env.basedn)

@register()
class pwpolicy(LDAPObject):
    """
    Password Policy object
    """
    container_dn = DN(('cn', api.env.realm), ('cn', 'kerberos'))
    object_name = _('password policy')
    object_name_plural = _('password policies')
    object_class = ['top', 'nscontainer', 'krbpwdpolicy']
    permission_filter_objectclasses = ['krbpwdpolicy']
    default_attributes = [
        'cn', 'cospriority', 'krbmaxpwdlife', 'krbminpwdlife',
        'krbpwdhistorylength', 'krbpwdmindiffchars', 'krbpwdminlength',
        'krbpwdmaxfailure', 'krbpwdfailurecountinterval',
        'krbpwdlockoutduration',
    ]
    managed_permissions = {
        'System: Read Group Password Policy': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'permission',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'cospriority', 'krbmaxpwdlife', 'krbminpwdlife',
                'krbpwdfailurecountinterval', 'krbpwdhistorylength',
                'krbpwdlockoutduration', 'krbpwdmaxfailure',
                'krbpwdmindiffchars', 'krbpwdminlength', 'objectclass',
            },
            'default_privileges': {
                'Password Policy Readers',
                'Password Policy Administrator',
            },
        },
        'System: Add Group Password Policy': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///cn=*,cn=$REALM,cn=kerberos,$SUFFIX")(version 3.0;acl "permission:Add Group Password Policy";allow (add) groupdn = "ldap:///cn=Add Group Password Policy,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Password Policy Administrator'},
        },
        'System: Delete Group Password Policy': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///cn=*,cn=$REALM,cn=kerberos,$SUFFIX")(version 3.0;acl "permission:Delete Group Password Policy";allow (delete) groupdn = "ldap:///cn=Delete Group Password Policy,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Password Policy Administrator'},
        },
        'System: Modify Group Password Policy': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'krbmaxpwdlife', 'krbminpwdlife', 'krbpwdfailurecountinterval',
                'krbpwdhistorylength', 'krbpwdlockoutduration',
                'krbpwdmaxfailure', 'krbpwdmindiffchars', 'krbpwdminlength'
            },
            'replaces': [
                '(targetattr = "krbmaxpwdlife || krbminpwdlife || krbpwdhistorylength || krbpwdmindiffchars || krbpwdminlength || krbpwdmaxfailure || krbpwdfailurecountinterval || krbpwdlockoutduration")(target = "ldap:///cn=*,cn=$REALM,cn=kerberos,$SUFFIX")(version 3.0;acl "permission:Modify Group Password Policy";allow (write) groupdn = "ldap:///cn=Modify Group Password Policy,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Password Policy Administrator'},
        },
    }

    label = _('Password Policies')
    label_singular = _('Password Policy')

    takes_params = (
        Str('cn?',
            cli_name='group',
            label=_('Group'),
            doc=_('Manage password policy for specific group'),
            primary_key=True,
        ),
        Int('krbmaxpwdlife?',
            cli_name='maxlife',
            label=_('Max lifetime (days)'),
            doc=_('Maximum password lifetime (in days)'),
            minvalue=0,
            maxvalue=20000,  # a little over 54 years
        ),
        Int('krbminpwdlife?',
            cli_name='minlife',
            label=_('Min lifetime (hours)'),
            doc=_('Minimum password lifetime (in hours)'),
            minvalue=0,
        ),
        Int('krbpwdhistorylength?',
            cli_name='history',
            label=_('History size'),
            doc=_('Password history size'),
            minvalue=0,
        ),
        Int('krbpwdmindiffchars?',
            cli_name='minclasses',
            label=_('Character classes'),
            doc=_('Minimum number of character classes'),
            minvalue=0,
            maxvalue=5,
        ),
        Int('krbpwdminlength?',
            cli_name='minlength',
            label=_('Min length'),
            doc=_('Minimum length of password'),
            minvalue=0,
        ),
        Int('cospriority',
            cli_name='priority',
            label=_('Priority'),
            doc=_('Priority of the policy (higher number means lower priority'),
            minvalue=0,
            flags=('virtual_attribute',),
        ),
        Int(
            'krbpwdmaxfailure?',
            cli_name='maxfail',
            label=_('Max failures'),
            doc=_('Consecutive failures before lockout'),
            minvalue=0,
        ),
        Int(
            'krbpwdfailurecountinterval?',
            cli_name='failinterval',
            label=_('Failure reset interval'),
            doc=_('Period after which failure count will be reset (seconds)'),
            minvalue=0,
        ),
        Int(
            'krbpwdlockoutduration?',
            cli_name='lockouttime',
            label=_('Lockout duration'),
            doc=_('Period for which lockout is enforced (seconds)'),
            minvalue=0,
        ),
    )

    def get_dn(self, *keys, **options):
        if keys[-1] is not None:
            return self.backend.make_dn_from_attr(
                self.primary_key.name, keys[-1],
                DN(self.container_dn, api.env.basedn)
            )
        return global_policy_dn

    def convert_time_for_output(self, entry_attrs, **options):
        # Convert seconds to hours and days for displaying to user
        if not options.get('raw', False):
            if 'krbmaxpwdlife' in entry_attrs:
                entry_attrs['krbmaxpwdlife'][0] = unicode(
                    int(entry_attrs['krbmaxpwdlife'][0]) // 86400
                )
            if 'krbminpwdlife' in entry_attrs:
                entry_attrs['krbminpwdlife'][0] = unicode(
                    int(entry_attrs['krbminpwdlife'][0]) // 3600
                )

    def convert_time_on_input(self, entry_attrs):
        # Convert hours and days to seconds for writing to LDAP
        if 'krbmaxpwdlife' in entry_attrs and entry_attrs['krbmaxpwdlife']:
            entry_attrs['krbmaxpwdlife'] = entry_attrs['krbmaxpwdlife'] * 86400
        if 'krbminpwdlife' in entry_attrs and entry_attrs['krbminpwdlife']:
            entry_attrs['krbminpwdlife'] = entry_attrs['krbminpwdlife'] * 3600

    def validate_lifetime(self, entry_attrs, add=False, *keys):
        """
        Ensure that the maximum lifetime is greater than the minimum.
        If there is no minimum lifetime set then don't return an error.
        """
        maxlife=entry_attrs.get('krbmaxpwdlife', None)
        minlife=entry_attrs.get('krbminpwdlife', None)
        existing_entry = {}
        if not add: # then read existing entry
            existing_entry = self.api.Command.pwpolicy_show(keys[-1],
                all=True,
            )['result']
            if minlife is None and 'krbminpwdlife' in existing_entry:
                minlife = int(existing_entry['krbminpwdlife'][0]) * 3600
            if maxlife is None and 'krbmaxpwdlife' in existing_entry:
                maxlife = int(existing_entry['krbmaxpwdlife'][0]) * 86400

        if maxlife not in (None, 0) and minlife is not None:
            if minlife > maxlife:
                raise errors.ValidationError(
                    name='maxlife',
                    error=_('Maximum password life must be greater than minimum.'),
                )

    def add_cospriority(self, entry, pwpolicy_name, rights=True):
        if pwpolicy_name and pwpolicy_name != global_policy_name:
            cos_entry = self.api.Command.cosentry_show(
                pwpolicy_name,
                rights=rights, all=rights
            )['result']
            if cos_entry.get('cospriority') is not None:
                entry['cospriority'] = cos_entry['cospriority']
                if rights:
                    entry['attributelevelrights']['cospriority'] = \
                        cos_entry['attributelevelrights']['cospriority']


@register()
class pwpolicy_add(LDAPCreate):
    __doc__ = _('Add a new group password policy.')

    def get_args(self):
        yield self.obj.primary_key.clone(attribute=True, required=True)

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.convert_time_on_input(entry_attrs)
        self.obj.validate_lifetime(entry_attrs, True)
        self.api.Command.cosentry_add(
            keys[-1], krbpwdpolicyreference=dn,
            cospriority=options.get('cospriority')
        )
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        logger.info('%r', entry_attrs)
        # attribute rights are not allowed for pwpolicy_add
        self.obj.add_cospriority(entry_attrs, keys[-1], rights=False)
        self.obj.convert_time_for_output(entry_attrs, **options)
        return dn


@register()
class pwpolicy_del(LDAPDelete):
    __doc__ = _('Delete a group password policy.')

    def get_args(self):
        yield self.obj.primary_key.clone(
            attribute=True, required=True, multivalue=True
        )

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        if dn == global_policy_dn:
            raise errors.ValidationError(
                name='group',
                error=_('cannot delete global password policy')
            )
        return dn

    def post_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        try:
            self.api.Command.cosentry_del(keys[-1])
        except errors.NotFound:
            pass
        return True


@register()
class pwpolicy_mod(LDAPUpdate):
    __doc__ = _('Modify a group password policy.')

    def execute(self, cn=None, **options):
        return super(pwpolicy_mod, self).execute(cn, **options)

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.convert_time_on_input(entry_attrs)
        self.obj.validate_lifetime(entry_attrs, False, *keys)
        setattr(context, 'cosupdate', False)
        if options.get('cospriority') is not None:
            if keys[-1] is None:
                raise errors.ValidationError(
                    name='priority',
                    error=_('priority cannot be set on global policy')
                )
            try:
                self.api.Command.cosentry_mod(
                    keys[-1], cospriority=options['cospriority']
                    )
            except errors.EmptyModlist as e:
                if len(entry_attrs) == 1:   # cospriority only was passed
                    raise e
            else:
                setattr(context, 'cosupdate', True)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        rights = options.get('all', False) and options.get('rights', False)
        self.obj.add_cospriority(entry_attrs, keys[-1], rights)
        self.obj.convert_time_for_output(entry_attrs, **options)
        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        if call_func.__name__ == 'update_entry':
            if isinstance(exc, errors.EmptyModlist):
                entry_attrs = call_args[0]
                cosupdate = getattr(context, 'cosupdate')
                if not entry_attrs or cosupdate:
                    return
        raise exc


@register()
class pwpolicy_show(LDAPRetrieve):
    __doc__ = _('Display information about password policy.')

    takes_options = LDAPRetrieve.takes_options + (
        Str('user?',
            label=_('User'),
            doc=_('Display effective policy for a specific user'),
        ),
    )

    def execute(self, cn=None, **options):
        return super(pwpolicy_show, self).execute(cn, **options)

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        if options.get('user') is not None:
            user_entry = self.api.Command.user_show(
                options['user'], all=True
            )['result']
            if 'krbpwdpolicyreference' in user_entry:
                return user_entry.get('krbpwdpolicyreference', [dn])[0]
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        rights = options.get('all', False) and options.get('rights', False)
        self.obj.add_cospriority(entry_attrs, keys[-1], rights)
        self.obj.convert_time_for_output(entry_attrs, **options)
        return dn


@register()
class pwpolicy_find(LDAPSearch):
    __doc__ = _('Search for group password policies.')

    # this command does custom sorting in post_callback
    sort_result_entries = False

    def priority_sort_key(self, entry):
        """Key for sorting password policies

        returns a pair: (is_global, priority)
        """
        # global policy will be always last in the output
        if entry['cn'][0] == global_policy_name:
            return True, 0
        else:
            # policies with higher priority (lower number) will be at the
            # beginning of the list
            try:
                cospriority = int(entry['cospriority'][0])
            except KeyError:
                # if cospriority is not present in the entry, rather return 0
                # than crash
                cospriority = 0
            return False, cospriority

    def post_callback(self, ldap, entries, truncated, *args, **options):
        for e in entries:
            # When pkey_only flag is on, entries should contain only a cn.
            # Add a cospriority attribute that will be used for sorting.
            # Attribute rights are not allowed for pwpolicy_find.
            self.obj.add_cospriority(e, e['cn'][0], rights=False)

            self.obj.convert_time_for_output(e, **options)

        # do custom entry sorting by its cospriority
        entries.sort(key=self.priority_sort_key)

        if options.get('pkey_only', False):
            # remove cospriority that was used for sorting
            for e in entries:
                try:
                    del e['cospriority']
                except KeyError:
                    pass

        return truncated
