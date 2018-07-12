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

from ipalib import api, errors, output, _
from ipalib import Int, Str
from . import baseldap
from .baseldap import entry_to_dict, pkey_to_value
from ipalib.plugable import Registry
from ipapython.dn import DN

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

register = Registry()

# FIXME: load this from a config file?
_default_values = {
    'krbmaxticketlife': 86400,
    'krbmaxrenewableage': 604800,
}


@register()
class krbtpolicy(baseldap.LDAPObject):
    """
    Kerberos Ticket Policy object
    """
    container_dn = DN(('cn', api.env.realm), ('cn', 'kerberos'))
    object_name = _('kerberos ticket policy settings')
    default_attributes = ['krbmaxticketlife', 'krbmaxrenewableage']
    limit_object_classes = ['krbticketpolicyaux']
    # permission_filter_objectclasses is deliberately missing,
    # so it is not possible to create a permission of `--type krbtpolicy`.
    # This is because we need two permissions to cover both global and per-user
    # policies.
    managed_permissions = {
        'System: Read Default Kerberos Ticket Policy': {
            'non_object': True,
            'replaces_global_anonymous_aci': True,
            'ipapermtargetfilter': ['(objectclass=krbticketpolicyaux)'],
            'ipapermlocation': DN(container_dn, api.env.basedn),
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'krbdefaultencsalttypes', 'krbmaxrenewableage',
                'krbmaxticketlife', 'krbsupportedencsalttypes',
                'objectclass',
            },
            'default_privileges': {
                'Kerberos Ticket Policy Readers',
            },
        },
        'System: Read User Kerberos Ticket Policy': {
            'non_object': True,
            'replaces_global_anonymous_aci': True,
            'ipapermlocation': DN(api.env.container_user, api.env.basedn),
            'ipapermtargetfilter': ['(objectclass=krbticketpolicyaux)'],
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'krbmaxrenewableage', 'krbmaxticketlife',
            },
            'default_privileges': {
                'Kerberos Ticket Policy Readers',
            },
        },
    }

    label = _('Kerberos Ticket Policy')
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
        return DN(self.container_dn, api.env.basedn)


@register()
class krbtpolicy_mod(baseldap.LDAPUpdate):
    __doc__ = _('Modify Kerberos ticket policy.')

    def execute(self, uid=None, **options):
        return super(krbtpolicy_mod, self).execute(uid, **options)

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        # disable all flag
        #  ticket policies are attached to objects with unrelated attributes
        if options.get('all'):
            options['all'] = False
        return dn


@register()
class krbtpolicy_show(baseldap.LDAPRetrieve):
    __doc__ = _('Display the current Kerberos ticket policy.')

    def execute(self, uid=None, **options):
        return super(krbtpolicy_show, self).execute(uid, **options)

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        # disable all flag
        #  ticket policies are attached to objects with unrelated attributes
        if options.get('all'):
            options['all'] = False
        return dn

    def post_callback(self, ldap, dn, entry, *keys, **options):
        default_entry = None
        rights = None
        for attrname in self.obj.default_attributes:
            if attrname not in entry:
                if keys[-1] is not None:
                    # User entry doesn't override the attribute.
                    # Check if this is caused by insufficient read rights
                    if rights is None:
                        rights = baseldap.get_effective_rights(
                            ldap, dn, self.obj.default_attributes)
                    if 'r' not in rights.get(attrname.lower(), ''):
                        raise errors.ACIError(
                            info=_('Ticket policy for %s could not be read') %
                                keys[-1])
                    # Fallback to the default
                    if default_entry is None:
                        try:
                            default_dn = self.obj.get_dn(None)
                            default_entry = ldap.get_entry(default_dn)
                        except errors.NotFound:
                            default_entry = {}
                    if attrname in default_entry:
                        entry[attrname] = default_entry[attrname]
            if attrname not in entry:
                raise errors.ACIError(
                    info=_('Default ticket policy could not be read'))
        return dn


@register()
class krbtpolicy_reset(baseldap.LDAPQuery):
    __doc__ = _('Reset Kerberos ticket policy to the default values.')

    has_output = output.standard_entry

    def execute(self, uid=None, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(uid, **options)

        def_values = {}
        # if reseting policy for a user - just his values
        if uid is not None:
            for a in self.obj.default_attributes:
                def_values[a] = None
        # if reseting global policy - set values to default
        else:
            def_values = _default_values

        entry = ldap.get_entry(dn, list(def_values))
        entry.update(def_values)
        try:
            ldap.update_entry(entry)
        except errors.EmptyModlist:
            pass

        if uid is not None:
            # policy for user was deleted, retrieve global policy
            dn = self.obj.get_dn(None)
        entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)

        entry_attrs = entry_to_dict(entry_attrs, **options)

        return dict(result=entry_attrs, value=pkey_to_value(uid, options))
