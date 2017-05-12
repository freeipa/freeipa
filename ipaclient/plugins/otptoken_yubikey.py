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

import os

import six
import usb.core
import yubico

from ipalib import _, api, IntEnum
from ipalib.errors import NotFound
from ipalib.frontend import Command, Method, Object
from ipalib.plugable import Registry
from ipalib.util import classproperty

if six.PY3:
    unicode = str

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

topic = 'otp'


@register(no_fail=True)
class _fake_otptoken(Object):
    name = 'otptoken'


@register(no_fail=True)
class _fake_otptoken_add(Method):
    name = 'otptoken_add'
    NO_CLI = True


@register()
class otptoken_add_yubikey(Command):
    __doc__ = _('Add a new YubiKey OTP token.')

    takes_options = (
        IntEnum('slot?',
            cli_name='slot',
            label=_('YubiKey slot'),
            values=(1, 2),
        ),
    )
    has_output_params = takes_options

    @classmethod
    def __NO_CLI_getter(cls):
        return api.Command.get_plugin('otptoken_add') is _fake_otptoken_add

    NO_CLI = classproperty(__NO_CLI_getter)

    @property
    def api_version(self):
        return self.api.Command.otptoken_add.api_version

    def get_args(self):
        for arg in self.api.Command.otptoken_add.args():
            yield arg
        for arg in super(otptoken_add_yubikey, self).get_args():
            yield arg

    def get_options(self):
        for option in self.api.Command.otptoken_add.options():
            if option.name not in ('type',
                                   'ipatokenvendor',
                                   'ipatokenmodel',
                                   'ipatokenserial',
                                   'ipatokenotpalgorithm',
                                   'ipatokenhotpcounter',
                                   'ipatokenotpkey',
                                   'ipatokentotpclockoffset',
                                   'ipatokentotptimestep',
                                   'no_qrcode',
                                   'qrcode',
                                   'version'):
                yield option
        for option in super(otptoken_add_yubikey, self).get_options():
            yield option

    def get_output_params(self):
        for param in self.api.Command.otptoken_add.output_params():
            yield param
        for param in super(otptoken_add_yubikey, self).get_output_params():
            yield param

    def _iter_output(self):
        return self.api.Command.otptoken_add.output()

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
        cfg.mode_oath_hotp(key, kwargs.get(
            'ipatokenotpdigits',
            self.get_default_of('ipatokenotpdigits')
        ))
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

        return answer
