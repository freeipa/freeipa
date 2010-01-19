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
from ipalib import Command, Object
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

def _convert_time_for_output(entry_attrs):
    # Convert seconds to hours and days for displaying to user
    if 'krbmaxpwdlife' in entry_attrs:
        entry_attrs['krbmaxpwdlife'][0] = str(
            int(entry_attrs['krbmaxpwdlife'][0]) / 86400
        )
    if 'krbminpwdlife' in entry_attrs:
        entry_attrs['krbminpwdlife'][0] = str(
            int(entry_attrs['krbminpwdlife'][0]) / 3600
        )

def _convert_time_on_input(entry_attrs):
    # Convert hours and days to seconds for writing to LDAP
    if 'krbmaxpwdlife' in entry_attrs:
        entry_attrs['krbmaxpwdlife'] = entry_attrs['krbmaxpwdlife'] * 86400
    if 'krbminpwdlife' in entry_attrs:
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

    # This DN must *NOT* have spaces between elements
    policy_dn = "cn=%s,cn=%s,cn=kerberos,%s" % (group_cn, api.env.realm, api.env.basedn)

    # Create the krb password policy entry. This MUST be located
    # in the same container as the REALM or the kldap plugin won't
    # recognize it. The usual CoS trick of putting the whole DN into
    # the dn won't work either because the kldap plugin doesn't like
    # quotes in the DN.
    policy_entry['objectclass'] = ['top', 'nscontainer', 'krbpwdpolicy']
    policy_entry['cn'] = group_cn

    return (policy_dn, policy_entry)


class pwpolicy(Object):
    """
    Password Policy object.
    """

    takes_params = (
        Int('krbmaxpwdlife?',
            cli_name='maxlife',
            doc='Max. Password Lifetime (days)',
            minvalue=0,
            attribute=True,
        ),
        Int('krbminpwdlife?',
            cli_name='minlife',
            doc='Min. Password Lifetime (hours)',
            minvalue=0,
            attribute=True,
        ),
        Int('krbpwdhistorylength?',
            cli_name='history',
            doc='Password History Size',
            minvalue=0,
            attribute=True,
        ),
        Int('krbpwdmindiffchars?',
            cli_name='minclasses',
            doc='Min. Number of Character Classes',
            minvalue=0,
            attribute=True,
        ),
        Int('krbpwdminlength?',
            cli_name='minlength',
            doc='Min. Length of Password',
            minvalue=0,
            attribute=True,
        ),
    )

api.register(pwpolicy)


class pwpolicy_add(crud.Create):
    """
    Create a new password policy associated with a group.
    """

    takes_options = (
        Str('group',
            doc='Group to set policy for',
            attribute=False,
        ),
        Int('cospriority',
            cli_name='priority',
            label='Priority',
            doc='Priority of the policy. Higher number equals lower priority',
            minvalue=0,
            attribute=True,
        ),
    )

    def execute(self, *args, **options):
        ldap = self.api.Backend.ldap2

        group_cn = options['group']

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
    takes_options = (
        Str('group?',
            doc='Group to set policy for',
            attribute=False,
        ),
        Int('cospriority?',
            cli_name='priority',
            doc='Priority of the policy. Higher number equals lower priority',
            minvalue=0,
            attribute=True,
        ),
    )

    has_output = (
        output.Entry('result'),
    )

    def execute(self, *args, **options):
        assert 'dn' not in options
        ldap = self.api.Backend.ldap2

        if not 'group' in options:
            if 'cospriority' in options:
                raise errors.ValidationError(name='priority', error=_('priority cannot be set on global policy'))
            dn = self.api.env.container_accounts
            entry_attrs = self.args_options_2_entry(*args, **options)
        else:
            if 'cospriority' in options:
                groupdn = find_group_dn(options['group'])
                cos_dn = 'cn="%s", cn=cosTemplates, cn=accounts, %s' % (groupdn, api.env.basedn)
                self.log.debug('%s' % cos_dn)
                ldap.update_entry(cos_dn, dict(cospriority = options['cospriority']), normalize=False)
                del options['cospriority']
            entry_attrs = self.args_options_2_entry(*args, **options)
            (dn, entry_attrs) = make_policy_entry(options['group'], entry_attrs)
        _convert_time_on_input(entry_attrs)
        try:
            ldap.update_entry(dn, entry_attrs)
        except errors.EmptyModlist:
            pass

        (dn, entry_attrs) = ldap.get_entry(dn, entry_attrs.keys())

        _convert_time_for_output(entry_attrs)

        return dict(result=entry_attrs)

api.register(pwpolicy_mod)


class pwpolicy_del(crud.Delete):
    """
    Delete a group password policy.
    """

    takes_options = (
        Str('group',
            doc='Group to remove policy from',
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


class pwpolicy_show(Command):
    """
    Display password policy.
    """

    takes_options = (
        Str('group?',
            doc='Group to display policy',
        ),
        Str('user?',
            doc='Display policy applied to a given user',
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
            entry_attrs['priority'] = cos_attrs['cospriority']

        if 'user' in options:
            if group:
                entry_attrs['group'] = group
            else:
                entry_attrs['group'] = 'global'
        _convert_time_for_output(entry_attrs)

        return dict(result=entry_attrs)

api.register(pwpolicy_show)
