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

from ipalib import _, Str, IntEnum
from ipalib.errors import NotFound
from ipalib.plugable import Registry
from ipalib.frontend import Command
from ipalib.plugins.otptoken import otptoken

import os

import usb.core
import yubico

__doc__ = _("""
YubiKey Tokens
""") + _("""
Manage YubiKey tokens.
""") + _("""
This code is an extension to the otptoken plugin and provides support for
reading/writing YubiKey tokens directly.
""") + _("""
EXAMPLES:
""") + _("""
 Add a new token:
   ipa otptoken-add-yubikey --owner=jdoe --desc="My YubiKey"
""")

register = Registry()

topic = ('otp', _('One time password commands'))


@register()
class otptoken_add_yubikey(Command):
    __doc__ = _('Add a new YubiKey OTP token.')

    takes_args = (
        Str('ipatokenuniqueid?',
            cli_name='id',
            label=_('Unique ID'),
            primary_key=True,
        ),
    )

    takes_options = Command.takes_options + (
        IntEnum('slot?',
            cli_name='slot',
            label=_('YubiKey slot'),
            values=(1, 2),
        ),
    ) + tuple(x for x in otptoken.takes_params if x.name in (
        'description',
        'ipatokenowner',
        'ipatokendisabled',
        'ipatokennotbefore',
        'ipatokennotafter',
        'ipatokenotpdigits'
    ))

    has_output_params = Command.has_output_params + \
        tuple(x for x in otptoken.takes_params if x.name in (
            'ipatokenvendor',
            'ipatokenmodel',
            'ipatokenserial',
        ))

    def forward(self, *args, **kwargs):
        # Open the YubiKey
        try:
            yk = yubico.find_yubikey()
        except usb.core.USBError as e:
            raise NotFound(reason="No YubiKey found: %s" % e.strerror)
        except yubico.yubikey.YubiKeyError as e:
            raise NotFound(reason=e.reason)

        assert yk.version_num() >= (2, 1)

        # If no slot is specified, find the first free slot.
        if kwargs.get('slot', None) is None:
            try:
                used = yk.status().valid_configs()
                kwargs['slot'] = sorted({1, 2}.difference(used))[0]
            except IndexError:
                raise NotFound(reason=_('No free YubiKey slot!'))

        # Create the key (NOTE: the length is fixed).
        key = os.urandom(20)

        # Write the config.
        cfg = yk.init_config()
        cfg.mode_oath_hotp(key, kwargs['ipatokenotpdigits'])
        cfg.extended_flag('SERIAL_API_VISIBLE', True)
        yk.write_config(cfg, slot=kwargs['slot'])

        # Filter the options we want to pass.
        options = {k: v for k, v in kwargs.items() if k in (
            'version',
            'description',
            'ipatokenowner',
            'ipatokendisabled',
            'ipatokennotbefore',
            'ipatokennotafter',
            'ipatokenotpdigits',
        )}

        # Run the command.
        answer = self.Backend.rpcclient.forward('otptoken_add',
                                                *args,
                                                type=u'hotp',
                                                ipatokenvendor=u'YubiCo',
                                                ipatokenmodel=unicode(yk.model),
                                                ipatokenserial=unicode(yk.serial()),
                                                ipatokenotpalgorithm=u'sha1',
                                                ipatokenhotpcounter=0,
                                                ipatokenotpkey=key,
                                                no_qrcode=True,
                                                **options)

        # Suppress values we don't want to return.
        for k in (u'uri', u'ipatokenotpkey'):
            if k in answer.get('result', {}):
                del answer['result'][k]

        # Return which slot was used for writing.
        answer.get('result', {})['slot'] = kwargs['slot']

        del answer['value']    # Why does this cause an error if omitted?
        del answer['summary']  # Why does this cause an error if omitted?
        return answer
