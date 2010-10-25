# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2010  Red Hat
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
"""

from ipalib import api
from ipalib import Int, Str
from ipalib.plugins.baseldap import *
from ipalib import _
from ipapython.ipautil import run

class cosentry(LDAPObject):
    """
    Class of Service object used for linking policies with groups
    """
    INTERNAL = True

    container_dn = 'cn=costemplates,%s' % api.env.container_accounts
    object_class = ['top', 'costemplate', 'extensibleobject', 'krbcontainer']
    default_attributes = ['cn', 'cospriority', 'krbpwdpolicyreference']

    takes_params = (
        Str('cn', primary_key=True),
        Str('krbpwdpolicyreference'),
        Int('cospriority', minvalue=0),
    )

    priority_not_unique_msg = _(
        'priority must be a unique value (%(prio)d already used by %(gname)s)'
    )

    def get_dn(self, *keys, **options):
        group_dn = self.api.Object.group.get_dn(keys[-1])
        return self.backend.make_dn_from_attr(
            'cn', group_dn, self.container_dn
        )

    def check_priority_uniqueness(self, *keys, **options):
        if options.get('cospriority') is not None:
            entries = self.methods.find(
                cospriority=options['cospriority']
            )['result']
            if len(entries) > 0:
                group_name = self.api.Object.group.get_primary_key_from_dn(
                    entries[0]['cn'][0]
                )
                raise errors.ValidationError(
                    name='priority',
                    error=self.priority_not_unique_msg % {
                        'prio': options['cospriority'],
                        'gname': group_name,
                    }
                )

api.register(cosentry)


class cosentry_add(LDAPCreate):
    INTERNAL = True

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        # check for existence of the group
        result = self.api.Command.group_show(keys[-1], all=True)['result']
        oc = map(lambda x:x.lower(),result['objectclass'])
        if 'mepmanagedentry' in oc:
            raise errors.ManagedPolicyError()
        self.obj.check_priority_uniqueness(*keys, **options)
        del entry_attrs['cn']
        return dn

api.register(cosentry_add)


class cosentry_del(LDAPDelete):
    INTERNAL = True

api.register(cosentry_del)


class cosentry_mod(LDAPUpdate):
    INTERNAL = True

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        self.obj.check_priority_uniqueness(*keys, **options)
        return dn

api.register(cosentry_mod)


class cosentry_show(LDAPRetrieve):
    INTERNAL = True

api.register(cosentry_show)


class cosentry_find(LDAPSearch):
    INTERNAL = True

api.register(cosentry_find)


global_policy_dn = 'cn=global_policy,cn=%s,cn=kerberos,%s' % (api.env.realm, api.env.basedn)

class pwpolicy(LDAPObject):
    """
    Password Policy object
    """
    container_dn = 'cn=%s,cn=kerberos' % api.env.realm
    object_name = 'password policy'
    object_name_plural = 'password policies'
    object_class = ['top', 'nscontainer', 'krbpwdpolicy']
    default_attributes = [
        'cn', 'cospriority', 'krbmaxpwdlife', 'krbminpwdlife',
        'krbpwdhistorylength', 'krbpwdmindiffchars', 'krbpwdminlength',
        'krbpwdmaxfailure', 'krbpwdfailurecountinterval',
        'krbpwdlockoutduration',
    ]
    has_lockout = False
    lockout_params = ()
    (stdout, stderr, rc) = run(['klist', '-V'], raiseonerr=False)
    if rc == 0:
        if stdout.find('version 1.8') > -1:
            has_lockout = True

    if has_lockout:
        lockout_params = (
            Int('krbpwdmaxfailure?',
                cli_name='maxfail',
                label=_('Max failures'),
                doc=_('Consecutive failures before lockout'),
                minvalue=0,
            ),
            Int('krbpwdfailurecountinterval?',
                cli_name='failinterval',
                label=_('Failure reset interval'),
                doc=_('Period after which failure count will be reset (seconds)'),
                minvalue=0,
            ),
            Int('krbpwdlockoutduration?',
                cli_name='lockouttime',
                label=_('Lockout duration'),
                doc=_('Period for which lockout is enforced (seconds)'),
                minvalue=0,
            ),
        )

    label = _('Password Policy')

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
        ),
    ) + lockout_params

    def get_dn(self, *keys, **options):
        if keys[-1] is not None:
            return self.backend.make_dn_from_attr(
                self.primary_key.name, keys[-1], self.container_dn
            )
        return global_policy_dn

    def convert_time_for_output(self, entry_attrs, **options):
        # Convert seconds to hours and days for displaying to user
        if not options.get('raw', False):
            if 'krbmaxpwdlife' in entry_attrs:
                entry_attrs['krbmaxpwdlife'][0] = unicode(
                    int(entry_attrs['krbmaxpwdlife'][0]) / 86400
                )
            if 'krbminpwdlife' in entry_attrs:
                entry_attrs['krbminpwdlife'][0] = unicode(
                    int(entry_attrs['krbminpwdlife'][0]) / 3600
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
                all=True, raw=True,
            )['result']
            if minlife is None and 'krbminpwdlife' in existing_entry:
                minlife = int(existing_entry['krbminpwdlife'][0])
            if maxlife is None and 'krbmaxpwdlife' in existing_entry:
                maxlife = int(existing_entry['krbmaxpwdlife'][0])

        if maxlife is not None and minlife is not None:
            if minlife > maxlife:
                raise errors.ValidationError(
                    name='maxlife',
                    error=_('Maximum password life must be greater than minimum.'),
                )

api.register(pwpolicy)


class pwpolicy_add(LDAPCreate):
    """
    Add a new group password policy.
    """
    def get_args(self):
        yield self.obj.primary_key.clone(attribute=True, required=True)

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        self.obj.convert_time_on_input(entry_attrs)
        self.obj.validate_lifetime(entry_attrs, True)
        self.api.Command.cosentry_add(
            keys[-1], krbpwdpolicyreference=dn,
            cospriority=options.get('cospriority')
        )
        if 'cospriority' in entry_attrs:
            del entry_attrs['cospriority']
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.log.info('%r' % entry_attrs)
        if not options.get('raw', False):
            if options.get('cospriority') is not None:
                entry_attrs['cospriority'] = [unicode(options['cospriority'])]
        self.obj.convert_time_for_output(entry_attrs, **options)
        return dn

api.register(pwpolicy_add)


class pwpolicy_del(LDAPDelete):
    """
    Delete a group password policy.
    """
    def get_args(self):
        yield self.obj.primary_key.clone(
            attribute=True, required=True, multivalue=True
        )

    def post_callback(self, ldap, dn, *keys, **options):
        try:
            self.api.Command.cosentry_del(keys[-1])
        except errors.NotFound:
            pass
        return True

api.register(pwpolicy_del)


class pwpolicy_mod(LDAPUpdate):
    """
    Modify a group password policy.
    """
    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        self.obj.convert_time_on_input(entry_attrs)
        self.obj.validate_lifetime(entry_attrs, False, *keys)
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
            except errors.NotFound:
                self.api.Command.cosentry_add(
                    keys[-1], krbpwdpolicyreference=dn,
                    cospriority=options['cospriority']
                )
            del entry_attrs['cospriority']
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if not options.get('raw', False):
            if options.get('cospriority') is not None:
                entry_attrs['cospriority'] = [unicode(options['cospriority'])]
        self.obj.convert_time_for_output(entry_attrs, **options)
        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        if isinstance(exc, errors.EmptyModlist):
            entry_attrs = call_args[1]
            if not entry_attrs and 'cospriority' in options:
                return
        raise exc

api.register(pwpolicy_mod)


class pwpolicy_show(LDAPRetrieve):
    """
    Display information about password policy.
    """
    takes_options = (
        Str('user?',
            label=_('User'),
            doc=_('Display effective policy for a specific user'),
        ),
    )

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        if options.get('user') is not None:
            user_entry = self.api.Command.user_show(
                options['user'], all=True
            )['result']
            if 'krbpwdpolicyreference' in user_entry:
                return user_entry.get('krbpwdpolicyreference', [dn])[0]
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if not options.get('raw', False):
            if keys[-1] is not None:
                try:
                    cos_entry = self.api.Command.cosentry_show(
                        keys[-1]
                    )['result']
                    if cos_entry.get('cospriority') is not None:
                        entry_attrs['cospriority'] = cos_entry['cospriority']
                except errors.NotFound:
                    pass
        self.obj.convert_time_for_output(entry_attrs, **options)
        return dn

api.register(pwpolicy_show)


class pwpolicy_find(LDAPSearch):
    """
    Search for group password policies.
    """
    def post_callback(self, ldap, entries, truncated, *args, **options):
        if not options.get('raw', False):
            for e in entries:
                try:
                    cos_entry = self.api.Command.cosentry_show(
                        e[1]['cn'][0]
                    )['result']
                    if cos_entry.get('cospriority') is not None:
                        e[1]['cospriority'] = cos_entry['cospriority']
                except errors.NotFound:
                    pass
                self.obj.convert_time_for_output(e[1], **options)

api.register(pwpolicy_find)

