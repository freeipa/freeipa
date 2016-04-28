# Authors:
#   Nathaniel McCallum <npmccallum@redhat.com>
#
# Copyright (C) 2014  Red Hat
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

from ipalib import _, api, Int
from ipalib.plugable import Registry
from .baseldap import DN, LDAPObject, LDAPUpdate, LDAPRetrieve

__doc__ = _("""
OTP configuration

Manage the default values that IPA uses for OTP tokens.

EXAMPLES:

 Show basic OTP configuration:
   ipa otpconfig-show

 Show all OTP configuration options:
   ipa otpconfig-show --all

 Change maximum TOTP authentication window to 10 minutes:
   ipa otpconfig-mod --totp-auth-window=600

 Change maximum TOTP synchronization window to 12 hours:
   ipa otpconfig-mod --totp-sync-window=43200

 Change maximum HOTP authentication window to 5:
   ipa hotpconfig-mod --hotp-auth-window=5

 Change maximum HOTP synchronization window to 50:
   ipa hotpconfig-mod --hotp-sync-window=50
""")

register = Registry()

topic = 'otp'


@register()
class otpconfig(LDAPObject):
    object_name = _('OTP configuration options')
    default_attributes = [
        'ipatokentotpauthwindow',
        'ipatokentotpsyncwindow',
        'ipatokenhotpauthwindow',
        'ipatokenhotpsyncwindow',
    ]

    container_dn = DN(('cn', 'otp'), ('cn', 'etc'))
    permission_filter_objectclasses = ['ipatokenotpconfig']
    managed_permissions = {
        'System: Read OTP Configuration': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'ipatokentotpauthwindow', 'ipatokentotpsyncwindow',
                'ipatokenhotpauthwindow', 'ipatokenhotpsyncwindow',
                'cn',
            },
        },
    }

    label = _('OTP Configuration')
    label_singular = _('OTP Configuration')

    takes_params = (
        Int('ipatokentotpauthwindow',
            cli_name='totp_auth_window',
            label=_('TOTP authentication Window'),
            doc=_('TOTP authentication time variance (seconds)'),
            minvalue=5,
        ),
        Int('ipatokentotpsyncwindow',
            cli_name='totp_sync_window',
            label=_('TOTP Synchronization Window'),
            doc=_('TOTP synchronization time variance (seconds)'),
            minvalue=5,
        ),
        Int('ipatokenhotpauthwindow',
            cli_name='hotp_auth_window',
            label=_('HOTP Authentication Window'),
            doc=_('HOTP authentication skip-ahead'),
            minvalue=1,
        ),
        Int('ipatokenhotpsyncwindow',
            cli_name='hotp_sync_window',
            label=_('HOTP Synchronization Window'),
            doc=_('HOTP synchronization skip-ahead'),
            minvalue=1,
        ),
    )

    def get_dn(self, *keys, **kwargs):
        return self.container_dn + api.env.basedn


@register()
class otpconfig_mod(LDAPUpdate):
    __doc__ = _('Modify OTP configuration options.')


@register()
class otpconfig_show(LDAPRetrieve):
    __doc__ = _('Show the current OTP configuration.')
