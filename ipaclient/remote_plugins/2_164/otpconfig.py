#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

# pylint: disable=unused-import

from . import Command, Method, Object
from ipalib import api, parameters, output
from ipalib.parameters import DefaultFrom
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

unicode = str

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


@register()
class otpconfig(Object):
    takes_params = (
        parameters.Int(
            'ipatokentotpauthwindow',
            label=_('TOTP authentication Window'),
            doc=_('TOTP authentication time variance (seconds)'),
        ),
        parameters.Int(
            'ipatokentotpsyncwindow',
            label=_('TOTP Synchronization Window'),
            doc=_('TOTP synchronization time variance (seconds)'),
        ),
        parameters.Int(
            'ipatokenhotpauthwindow',
            label=_('HOTP Authentication Window'),
            doc=_('HOTP authentication skip-ahead'),
        ),
        parameters.Int(
            'ipatokenhotpsyncwindow',
            label=_('HOTP Synchronization Window'),
            doc=_('HOTP synchronization skip-ahead'),
        ),
    )


@register()
class otpconfig_mod(Method):
    __doc__ = _("Modify OTP configuration options.")

    takes_options = (
        parameters.Int(
            'ipatokentotpauthwindow',
            required=False,
            cli_name='totp_auth_window',
            label=_('TOTP authentication Window'),
            doc=_('TOTP authentication time variance (seconds)'),
        ),
        parameters.Int(
            'ipatokentotpsyncwindow',
            required=False,
            cli_name='totp_sync_window',
            label=_('TOTP Synchronization Window'),
            doc=_('TOTP synchronization time variance (seconds)'),
        ),
        parameters.Int(
            'ipatokenhotpauthwindow',
            required=False,
            cli_name='hotp_auth_window',
            label=_('HOTP Authentication Window'),
            doc=_('HOTP authentication skip-ahead'),
        ),
        parameters.Int(
            'ipatokenhotpsyncwindow',
            required=False,
            cli_name='hotp_sync_window',
            label=_('HOTP Synchronization Window'),
            doc=_('HOTP synchronization skip-ahead'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_('Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_('Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'delattr',
            required=False,
            multivalue=True,
            doc=_('Delete an attribute/value pair. The option will be evaluated\nlast, after all sets and adds.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class otpconfig_show(Method):
    __doc__ = _("Show the current OTP configuration.")

    takes_options = (
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )
