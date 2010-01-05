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
Kerberos ticket policy
"""

from ipalib import api
from ipalib import Int, Str
from ipalib.plugins.baseldap import *


# FIXME: load this from a config file?
_default_values = {
    'krbmaxticketlife': 86400,
    'krbmaxrenewableage': 604800,
}


class krbtpolicy(LDAPObject):
    """
    Kerberos Ticket Policy object
    """
    container_dn = 'cn=%s,cn=kerberos' % api.env.realm
    object_name = 'kerberos ticket policy settings'
    default_attributes = ['krbmaxticketlife', 'krbmaxrenewableage']
    attribute_names = {
        'krbmaxticketlife': 'maximum life',
        'krbmaxrenewableage': 'maximum renewable age',
    }

    takes_params = (
        Str('uid?',
            cli_name='user',
            doc='manage ticket policy for specific user',
            primary_key=True,
        ),
        Int('krbmaxticketlife?',
            cli_name='maxlife',
            doc='maximum ticket life',
        ),
        Int('krbmaxrenewableage?',
            cli_name='maxrenew',
            doc='maximum renewable age',
        ),
    )

    def get_dn(self, *keys, **kwargs):
        if keys[-1] is not None:
            return self.api.Object.user.get_dn(*keys, **kwargs)
        return self.container_dn

api.register(krbtpolicy)


class krbtpolicy_mod(LDAPUpdate):
    """
    Modify kerberos ticket policy.
    """
    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        # disable all flag
        #  ticket policies are attached to objects with unrelated attributes
        if options.get('all'):
            options['all'] = False
        return dn

api.register(krbtpolicy_mod)


class krbtpolicy_show(LDAPRetrieve):
    """
    Display kerberos ticket policy.
    """
    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        # disable all flag
        #  ticket policies are attached to objects with unrelated attributes
        if options.get('all'):
            options['all'] = False
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
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
    """
    Reset kerberos ticket policy to default.
    """
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

