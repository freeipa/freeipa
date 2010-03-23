# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008  Red Hat
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

from ipalib import api, crud, errors
from ipalib import Method, Object
from ipalib import Int, Str
from ipalib import output
from ipalib import _, ngettext
from ldap.functions import explode_dn

_fields = {
    'group': 'Group policy',
    'krbminpwdlife': 'Minimum lifetime (in hours)',
    'krbmaxpwdlife': 'Maximum lifetime (in days)',
    'krbpwdmindiffchars': 'Minimum number of characters classes',
    'krbpwdminlength': 'Minimum length',
    'krbpwdhistorylength': 'History size',
}

_global=u'global'

def _convert_time_for_output(entry_attrs):
    # Convert seconds to hours and days for displaying to user
    if 'krbmaxpwdlife' in entry_attrs:
        entry_attrs['krbmaxpwdlife'][0] = unicode(
            int(entry_attrs['krbmaxpwdlife'][0]) / 86400
        )
    if 'krbminpwdlife' in entry_attrs:
        entry_attrs['krbminpwdlife'][0] = unicode(
            int(entry_attrs['krbminpwdlife'][0]) / 3600
        )

def _convert_time_on_input(entry_attrs):
    # Convert hours and days to seconds for writing to LDAP
    if 'krbmaxpwdlife' in entry_attrs and entry_attrs['krbmaxpwdlife']:
        entry_attrs['krbmaxpwdlife'] = entry_attrs['krbmaxpwdlife'] * 86400
    if 'krbminpwdlife' in entry_attrs and entry_attrs['krbminpwdlife']:
        entry_attrs['krbminpwdlife'] = entry_attrs['krbminpwdlife'] * 3600

def find_group_dn(group):
    """
    Given a group name find the DN of that group
    """
    try:
        entry = api.Command['group_show'](group)['result']
    except errors.NotFound:
        raise errors.NotFound(reason="group '%s' does not exist" % group)
    return entry['dn']

def make_cos_entry(group, cospriority=None):
    """
    Make the CoS dn and entry for this group.

    Returns (cos_dn, cos_entry) where:
     cos_dn = DN of the new CoS entry
     cos_entry = entry representing this new object
    """

    groupdn = find_group_dn(group)

    cos_entry = {}
    if cospriority:
        cos_entry['cospriority'] = cospriority
    cos_entry['objectclass'] = ['top', 'costemplate', 'extensibleobject', 'krbcontainer']
    cos_dn = 'cn=\"%s\", cn=cosTemplates, cn=accounts, %s' % (groupdn, api.env.basedn)

    return (cos_dn, cos_entry)


def make_policy_entry(group_cn, policy_entry):
    """
    Make the krbpwdpolicy dn and entry for this group.

    Returns (policy_dn, policy_entry) where:
     policy_dn = DN of the new password policy entry
     policy_entry = entry representing this new object
    """
    ldap = api.Backend.ldap2

    # This DN must *NOT* have spaces between elements
    policy_dn = ldap.make_dn_from_attr(
        'cn', api.env.realm, 'cn=kerberos,%s' % api.env.basedn
    )
    policy_dn = ldap.make_dn_from_attr('cn', group_cn, policy_dn)

    # Create the krb password policy entry. This MUST be located
    # in the same container as the REALM or the kldap plugin won't
    # recognize it. The usual CoS trick of putting the whole DN into
    # the dn won't work either because the kldap plugin doesn't like
    # quotes in the DN.
    policy_entry['objectclass'] = ['top', 'nscontainer', 'krbpwdpolicy']
    policy_entry['cn'] = group_cn

    return (policy_dn, policy_entry)

def find_group_policy(ldap):
    """
    Return all group policy entries.
    """
    attrs = ('cn','krbminpwdlife', 'krbmaxpwdlife', 'krbpwdmindiffchars', 'krbpwdminlength', 'krbpwdhistorylength',)

    attr_filter = ldap.make_filter({'objectclass':'krbpwdpolicy'}, rules=ldap.MATCH_ALL)

    try:
        (entries, truncated) = ldap.find_entries(
            attr_filter, attrs, 'cn=%s,cn=kerberos,%s' % (api.env.realm, api.env.basedn), scope=ldap.SCOPE_ONELEVEL
        )
    except errors.NotFound:
        (entries, truncated) = (tuple(), False)

    return (entries, truncated)

def unique_priority(ldap, priority):
    """
    Return True if the given priority is unique, False otherwise

    Having two cosPriority with the same value is undefined in the DS.

    This isn't done as a validation on the attribute since we want it done
    only on the server side.
    """
    attrs = ('cospriority',)

    attr_filter = ldap.make_filter({'objectclass':'krbcontainer', 'cospriority':

    try:
        (entries, truncated) = ldap.find_entries(
            attr_filter, attrs, 'cn=cosTemplates,%s' % (api.env.container_accoun
        )
        return False
    except errors.NotFound:
        return True

    return True

class pwpolicy(Object):
    """
    Password Policy object.
    """

    takes_params = (
        Str('cn?',
            label=_('Group'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Int('krbmaxpwdlife?',
            cli_name='maxlife',
            label=_('Max lifetime (days)'),
            doc=_('Maximum password lifetime (in days)'),
            minvalue=0,
            attribute=True,
        ),
        Int('krbminpwdlife?',
            cli_name='minlife',
            label=_('Min lifetime (hours)'),
            doc=_('Minimum password lifetime (in hours)'),
            minvalue=0,
            attribute=True,
        ),
        Int('krbpwdhistorylength?',
            cli_name='history',
            label=_('History size'),
            doc=_('Password history size'),
            minvalue=0,
            attribute=True,
        ),
        Int('krbpwdmindiffchars?',
            cli_name='minclasses',
            label=_('Character classes'),
            doc=_('Minimum number of character classes'),
            minvalue=0,
            attribute=True,
        ),
        Int('krbpwdminlength?',
            cli_name='minlength',
            label=_('Min length'),
            doc=_('Minimum length of password'),
            minvalue=0,
            attribute=True,
        ),
    )

api.register(pwpolicy)


class pwpolicy_add(crud.Create):
    """
    Create a new password policy associated with a group.
    """

    msg_summary = _('Added policy for group "%(value)s"')

    takes_options = (
        Str('group',
            label=_('Group'),
            doc=_('Group to set policy for'),
            attribute=False,
        ),
        Int('cospriority',
            cli_name='priority',
            label=_('Priority'),
            doc=_('Priority of the policy (higher number equals lower priority)'),
            minvalue=0,
            attribute=True,
        ),
    )

    def execute(self, *args, **options):
        ldap = self.api.Backend.ldap2

        group_cn = options['group']

        if 'cospriority' in options:
            if not unique_priority(ldap, options['cospriority']):
                raise errors.ValidationError(name='priority', error=_('Priority must be a unique value.'))

        # Create the CoS template
        (cos_dn, cos_entry) = make_cos_entry(group_cn, options.get('cospriority', None))
        if 'cospriority' in options:
            del options['cospriority']

        # Create the new password policy
        policy_entry = self.args_options_2_entry(*args, **options)
        (policy_dn, policy_entry) = make_policy_entry(group_cn, policy_entry)
        _convert_time_on_input(policy_entry)

        # Link the two entries together
        cos_entry['krbpwdpolicyreference'] = policy_dn

        ldap.add_entry(policy_dn, policy_entry, normalize=False)
        ldap.add_entry(cos_dn, cos_entry, normalize=False)

        # The policy is what is interesting, return that
        (dn, entry_attrs) = ldap.get_entry(policy_dn, policy_entry.keys())

        _convert_time_for_output(entry_attrs)

        entry_attrs['dn'] = dn
        return dict(result=entry_attrs, value=group_cn)

api.register(pwpolicy_add)


class pwpolicy_mod(crud.Update):
    """
    Modify password policy.
    """
    msg_summary = _('Modified policy for group "%(value)s"')
    takes_options = (
        Str('group?',
            label=_('Group'),
            doc=_('Group to set policy for'),
            attribute=False,
        ),
        Int('cospriority?',
            cli_name='priority',
            label=_('Priority'),
            doc=_('Priority of the policy (higher number equals lower priority)'),
            minvalue=0,
            attribute=True,
        ),
    )

    def execute(self, *args, **options):
        assert 'dn' not in options
        ldap = self.api.Backend.ldap2
        cospriority = None

        if 'group' in options:
            group_cn = options['group']
            del options['group']
        else:
            group_cn = None
        if len(options) == 2: # 'all' and 'raw' are always sent
            raise errors.EmptyModlist()

        if not group_cn:
            group_cn = _global
            if 'cospriority' in options:
                raise errors.ValidationError(name='priority', error=_('priority cannot be set on global policy'))
            dn = self.api.env.container_accounts
            entry_attrs = self.args_options_2_entry(*args, **options)
        else:
            if 'cospriority' in options:
                if options['cospriority'] is None:
                    raise errors.RequirementError(name='priority')
                if not unique_priority(ldap, options['cospriority']):
                    raise errors.ValidationError(name='priority', error=_('Priority must be a unique value.'))
                groupdn = find_group_dn(group_cn)
                cos_dn = 'cn="%s", cn=cosTemplates, cn=accounts, %s' % (groupdn, api.env.basedn)
                self.log.debug('%s' % cos_dn)
                ldap.update_entry(cos_dn, dict(cospriority = options['cospriority']), normalize=False)
                cospriority = options['cospriority']
                del options['cospriority']
            entry_attrs = self.args_options_2_entry(*args, **options)
            (dn, entry_attrs) = make_policy_entry(group_cn, entry_attrs)
        _convert_time_on_input(entry_attrs)
        try:
            ldap.update_entry(dn, entry_attrs)
        except errors.EmptyModlist:
            pass

        (dn, entry_attrs) = ldap.get_entry(dn, entry_attrs.keys())

        if cospriority:
            entry_attrs['cospriority'] = cospriority

        _convert_time_for_output(entry_attrs)

        return dict(result=entry_attrs, value=group_cn)

api.register(pwpolicy_mod)


class pwpolicy_del(crud.Delete):
    """
    Delete a group password policy.
    """

    msg_summary = _('Deleted policy for group "%(value)s"')
    takes_options = (
        Str('group',
            doc=_('Group to remove policy from'),
        ),
    )

    def execute(self, *args, **options):
        assert 'dn' not in options
        ldap = self.api.Backend.ldap2

        group_cn = options['group']

        # Get the DN of the CoS template to delete
        try:
            (cos_dn, cos_entry) = make_cos_entry(group_cn, None)
        except errors.NotFound:
            # Ok, perhaps the group was deleted, try to make the group DN
            rdn = ldap.make_rdn_from_attr('cn', group_cn)
            group_dn = ldap.make_dn_from_rdn(rdn, api.env.container_group)
            cos_dn = 'cn=\"%s\", cn=cosTemplates, cn=accounts, %s' % (group_dn, api.env.basedn)
        policy_entry = self.args_options_2_entry(*args, **options)
        (policy_dn, policy_entry) = make_policy_entry(group_cn, policy_entry)

        ldap.delete_entry(policy_dn, normalize=False)
        ldap.delete_entry(cos_dn, normalize=False)
        return dict(
            result=True,
            value=group_cn,
        )

api.register(pwpolicy_del)


class pwpolicy_show(Method):
    """
    Display password policy.
    """

    has_output = (
        output.Entry('result'),
    )
    takes_options = (
        Str('group?',
            label=_('Group'),
            doc=_('Group to display policy'),
        ),
        Str('user?',
            label=_('User'),
            doc=_('Display policy applied to a given user'),
        ),
        Int('cospriority?',
            cli_name='priority',
            label=_('Priority'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
    )

    def execute(self, *args, **options):
        ldap = self.api.Backend.ldap2

        dn = None
        group = None

        if 'user' in options:
            rdn = ldap.make_rdn_from_attr('uid', options['user'])
            user_dn = ldap.make_dn_from_rdn(rdn, api.env.container_user)
            try:
                (user_dn, user_attrs) = ldap.get_entry(user_dn, ['krbpwdpolicyreference'])
                if 'krbpwdpolicyreference' in user_attrs:
                    dn = user_attrs['krbpwdpolicyreference'][0]
                    rdn = explode_dn(dn)
                    group = rdn[0].replace('cn=','')
            except errors.NotFound:
                 raise errors.NotFound(reason="user '%s' not found" % options['user'])

        if dn is None:
            if not 'group' in options:
                dn = self.api.env.container_accounts
            else:
                policy_entry = self.args_options_2_entry(*args, **options)
                (dn, policy_entry) = make_policy_entry(options['group'], policy_entry)
        (dn, entry_attrs) = ldap.get_entry(dn)

        if 'group' in options:
            groupdn = find_group_dn(options['group'])
            cos_dn = 'cn="%s", cn=cosTemplates, cn=accounts, %s' % (groupdn, api.env.basedn)
            (dn, cos_attrs) = ldap.get_entry(cos_dn, normalize=False)
            entry_attrs['cospriority'] = cos_attrs['cospriority']
        else:
            entry_attrs['cn'] = _global

        if 'user' in options:
            if group:
                entry_attrs['cn'] = unicode(group)
        _convert_time_for_output(entry_attrs)

        return dict(result=entry_attrs)

api.register(pwpolicy_show)

class pwpolicy_find(Method):
    """
    Display all groups with a password policy.
    """

    has_output = output.standard_list_of_entries

    takes_options = (
        Int('cospriority?',
            cli_name='priority',
            label=_('Priority'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
    )

    def execute(self, *args, **options):
        ldap = self.api.Backend.ldap2

        (entries, truncated) = find_group_policy(ldap)
        for e in entries:
            _convert_time_for_output(e[1])
            e[1]['dn'] = e[0]
            groupdn = find_group_dn(e[1]['cn'][0])
            cos_dn = 'cn="%s", cn=cosTemplates, cn=accounts, %s' % (groupdn, api.env.basedn)
            (dn, cos_attrs) = ldap.get_entry(cos_dn, normalize=False)
            e[1]['cospriority'] = cos_attrs['cospriority']
        entries = tuple(e for (dn, e) in entries)

        return dict(result=entries,
                    count=len(entries),
                    truncated=truncated,
        )

api.register(pwpolicy_find)
