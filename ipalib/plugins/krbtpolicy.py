# Authors:
#   Pavel Zuna <pzuna@redhat.com>
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

from ipalib import api
from ipalib import Int, Str
from ipalib.plugins.baseldap import *
from ipalib import _

__doc__ = _("""
Kerberos ticket policy

There is a single Kerberos ticket policy. This policy defines the
maximum ticket lifetime and the maximum renewal age, the period during
which the ticket is renewable.

You can also create a per-user ticket policy by specifying the user login.

For changes to the global policy to take effect, restarting the KDC service
is required, which can be achieved using:

service krb5kdc restart

Changes to per-user policies take effect immediately for newly requested
tickets (e.g. when the user next runs kinit).

EXAMPLES:

 Display the current Kerberos ticket policy:
  ipa krbtpolicy-show

 Reset the policy to the default:
  ipa krbtpolicy-reset

 Modify the policy to 8 hours max life, 1-day max renewal:
  ipa krbtpolicy-mod --maxlife=28800 --maxrenew=86400

 Display effective Kerberos ticket policy for user 'admin':
  ipa krbtpolicy-show admin

 Reset per-user policy for user 'admin':
  ipa krbtpolicy-reset admin

 Modify per-user policy for user 'admin':
  ipa krbtpolicy-mod admin --maxlife=3600
""")

# FIXME: load this from a config file?
_default_values = {
    'krbmaxticketlife': 86400,
    'krbmaxrenewableage': 604800,
}


class krbtpolicy(LDAPObject):
    """
    Kerberos Ticket Policy object
    """
    container_dn = DN(('cn', api.env.realm), ('cn', 'kerberos'))
    object_name = _('kerberos ticket policy settings')
    default_attributes = ['krbmaxticketlife', 'krbmaxrenewableage']
    limit_object_classes = ['krbticketpolicyaux']

    label=_('Kerberos Ticket Policy')
    label_singular = _('Kerberos Ticket Policy')

    takes_params = (
        Str('uid?',
            cli_name='user',
            label=_('User name'),
            doc=_('Manage ticket policy for specific user'),
            primary_key=True,
        ),
        Int('krbmaxticketlife?',
            cli_name='maxlife',
            label=_('Max life'),
            doc=_('Maximum ticket life (seconds)'),
            minvalue=1,
        ),
        Int('krbmaxrenewableage?',
            cli_name='maxrenew',
            label=_('Max renew'),
            doc=_('Maximum renewable age (seconds)'),
            minvalue=1,
        ),
    )

    def get_dn(self, *keys, **kwargs):
        if keys[-1] is not None:
            return self.api.Object.user.get_dn(*keys, **kwargs)
        return self.container_dn

api.register(krbtpolicy)


class krbtpolicy_mod(LDAPUpdate):
    __doc__ = _('Modify Kerberos ticket policy.')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        # disable all flag
        #  ticket policies are attached to objects with unrelated attributes
        if options.get('all'):
            options['all'] = False
        return dn

api.register(krbtpolicy_mod)


class krbtpolicy_show(LDAPRetrieve):
    __doc__ = _('Display the current Kerberos ticket policy.')

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        # disable all flag
        #  ticket policies are attached to objects with unrelated attributes
        if options.get('all'):
            options['all'] = False
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        if keys[-1] is not None:
            # if policy for a specific user isn't set, display global values
            if 'krbmaxticketlife' not in entry_attrs or \
                'krbmaxrenewableage' not in entry_attrs:
                res = self.api.Command.krbtpolicy_show()
                for a in self.obj.default_attributes:
                    entry_attrs.setdefault(a, res['result'][a])
        return dn

api.register(krbtpolicy_show)


class krbtpolicy_reset(LDAPQuery):
    __doc__ = _('Reset Kerberos ticket policy to the default values.')

    has_output = output.standard_entry

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)

        def_values = {}
        # if reseting policy for a user - just his values
        if keys[-1] is not None:
            for a in self.obj.default_attributes:
                def_values[a] = None
        # if reseting global policy - set values to default
        else:
            def_values = _default_values

        try:
            ldap.update_entry(dn, def_values)
        except errors.EmptyModlist:
            pass

        if keys[-1] is not None:
            # policy for user was deleted, retrieve global policy
            dn = self.obj.get_dn(None)
        (dn, entry_attrs) = ldap.get_entry(dn, self.obj.default_attributes)

        if keys[-1] is not None:
            return dict(result=entry_attrs, value=keys[-1])
        return dict(result=entry_attrs, value=u'')

api.register(krbtpolicy_reset)
