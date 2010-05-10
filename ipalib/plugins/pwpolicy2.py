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
"""

from ipalib import api
from ipalib import Int, Str
from ipalib.plugins.baseldap import *
from ipalib import _


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
        self.api.Command.group_show(keys[-1])
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


GLOBAL_POLICY_NAME = u'GLOBAL'


class pwpolicy2(LDAPObject):
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
    ]

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
    )

    def get_dn(self, *keys, **options):
        if keys[-1] is not None:
            return self.backend.make_dn_from_attr(
                self.primary_key.name, keys[-1], self.container_dn
            )
        return self.api.env.container_accounts

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

api.register(pwpolicy2)


class pwpolicy2_add(LDAPCreate):
    """
    Create new group password policy.
    """
    def get_args(self):
        yield self.obj.primary_key.clone(attribute=True, required=True)

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        self.api.Command.cosentry_add(
            keys[-1], krbpwdpolicyreference=dn,
            cospriority=options.get('cospriority')
        )
        if 'cospriority' in entry_attrs:
            del entry_attrs['cospriority']
        self.obj.convert_time_on_input(entry_attrs)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.log.info('%r' % entry_attrs)
        if not options.get('raw', False):
            if options.get('cospriority') is not None:
                entry_attrs['cospriority'] = [unicode(options['cospriority'])]
        self.obj.convert_time_for_output(entry_attrs, **options)
        return dn

api.register(pwpolicy2_add)


class pwpolicy2_del(LDAPDelete):
    """
    Delete group password policy.
    """
    def get_args(self):
        yield self.obj.primary_key.clone(attribute=True, required=True)

    def post_callback(self, ldap, dn, *keys, **options):
        try:
            self.api.Command.cosentry_del(keys[-1])
        except errors.NotFound:
            pass
        return True

api.register(pwpolicy2_del)


class pwpolicy2_mod(LDAPUpdate):
    """
    Modify group password policy.
    """
    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
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
        self.obj.convert_time_on_input(entry_attrs)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if not options.get('raw', False):
            if options.get('cospriority') is not None:
                entry_attrs['cospriority'] = [unicode(options['cospriority'])]
            if keys[-1] is None:
                entry_attrs['cn'] = GLOBAL_POLICY_NAME
        self.obj.convert_time_for_output(entry_attrs, **options)
        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        if isinstance(exc, errors.EmptyModlist):
            entry_attrs = call_args[1]
            if not entry_attrs and 'cospriority' in options:
                return
        raise exc

api.register(pwpolicy2_mod)


class pwpolicy2_show(LDAPRetrieve):
    """
    Display group password policy.
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
            else:
                entry_attrs['cn'] = GLOBAL_POLICY_NAME
        self.obj.convert_time_for_output(entry_attrs, **options)
        return dn

api.register(pwpolicy2_show)


class pwpolicy2_find(LDAPSearch):
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
        if not args[-1]:
            global_entry = self.api.Command.pwpolicy2_show(
                all=options.get('all', False), raw=options.get('raw', False)
            )['result']
            dn = global_entry['dn']
            del global_entry['dn']
            entries.insert(0, (dn, global_entry))

api.register(pwpolicy2_find)

