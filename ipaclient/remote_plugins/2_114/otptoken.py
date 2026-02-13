#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#


from . import Command, Method, Object
from ipalib import api, parameters, output
from ipalib.parameters import DefaultFrom
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

__doc__ = _("""
OTP Tokens

Manage OTP tokens.

IPA supports the use of OTP tokens for multi-factor authentication. This
code enables the management of OTP tokens.

EXAMPLES:

 Add a new token:
   ipa otptoken-add --type=totp --owner=jdoe --desc="My soft token"

 Examine the token:
   ipa otptoken-show a93db710-a31a-4639-8647-f15b2c70b78a

 Change the vendor:
   ipa otptoken-mod a93db710-a31a-4639-8647-f15b2c70b78a --vendor="Red Hat"

 Delete a token:
   ipa otptoken-del a93db710-a31a-4639-8647-f15b2c70b78a
""")

register = Registry()


@register()
class otptoken(Object):
    takes_params = (
        parameters.Str(
            'ipatokenuniqueid',
            primary_key=True,
            label=_('Unique ID'),
        ),
        parameters.Str(
            'type',
            required=False,
            label=_('Type'),
            doc=_('Type of the token'),
        ),
        parameters.Str(
            'description',
            required=False,
            label=_('Description'),
            doc=_('Token description (informational only)'),
        ),
        parameters.Str(
            'ipatokenowner',
            required=False,
            label=_('Owner'),
            doc=_('Assigned user of the token (default: self)'),
        ),
        parameters.Str(
            'managedby_user',
            required=False,
            label=_('Manager'),
            doc=_('Assigned manager of the token (default: self)'),
        ),
        parameters.Bool(
            'ipatokendisabled',
            required=False,
            label=_('Disabled'),
            doc=_('Mark the token as disabled (default: false)'),
        ),
        parameters.DateTime(
            'ipatokennotbefore',
            required=False,
            label=_('Validity start'),
            doc=_('First date/time the token can be used'),
        ),
        parameters.DateTime(
            'ipatokennotafter',
            required=False,
            label=_('Validity end'),
            doc=_('Last date/time the token can be used'),
        ),
        parameters.Str(
            'ipatokenvendor',
            required=False,
            label=_('Vendor'),
            doc=_('Token vendor name (informational only)'),
        ),
        parameters.Str(
            'ipatokenmodel',
            required=False,
            label=_('Model'),
            doc=_('Token model (informational only)'),
        ),
        parameters.Str(
            'ipatokenserial',
            required=False,
            label=_('Serial'),
            doc=_('Token serial (informational only)'),
        ),
        parameters.Bytes(
            'ipatokenotpkey',
            required=False,
            label=_('Key'),
            doc=_('Token secret (Base32; default: random)'),
        ),
        parameters.Str(
            'ipatokenotpalgorithm',
            required=False,
            label=_('Algorithm'),
            doc=_('Token hash algorithm'),
        ),
        parameters.Int(
            'ipatokenotpdigits',
            required=False,
            label=_('Digits'),
            doc=_('Number of digits each token code will have'),
        ),
        parameters.Int(
            'ipatokentotpclockoffset',
            required=False,
            label=_('Clock offset'),
            doc=_('TOTP token / IPA server time difference'),
        ),
        parameters.Int(
            'ipatokentotptimestep',
            required=False,
            label=_('Clock interval'),
            doc=_('Length of TOTP token code validity'),
        ),
        parameters.Int(
            'ipatokenhotpcounter',
            required=False,
            label=_('Counter'),
            doc=_('Initial counter for the HOTP token'),
        ),
    )


@register()
class otptoken_add(Method):
    __doc__ = _("Add a new OTP token.")

    takes_args = (
        parameters.Str(
            'ipatokenuniqueid',
            required=False,
            cli_name='id',
            label=_('Unique ID'),
        ),
    )
    takes_options = (
        parameters.Str(
            'type',
            required=False,
            cli_metavar="['totp', 'hotp', 'TOTP', 'HOTP']",
            label=_('Type'),
            doc=_('Type of the token'),
            default='totp',
            autofill=True,
        ),
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
            doc=_('Token description (informational only)'),
        ),
        parameters.Str(
            'ipatokenowner',
            required=False,
            cli_name='owner',
            label=_('Owner'),
            doc=_('Assigned user of the token (default: self)'),
        ),
        parameters.Bool(
            'ipatokendisabled',
            required=False,
            cli_name='disabled',
            label=_('Disabled'),
            doc=_('Mark the token as disabled (default: false)'),
        ),
        parameters.DateTime(
            'ipatokennotbefore',
            required=False,
            cli_name='not_before',
            label=_('Validity start'),
            doc=_('First date/time the token can be used'),
        ),
        parameters.DateTime(
            'ipatokennotafter',
            required=False,
            cli_name='not_after',
            label=_('Validity end'),
            doc=_('Last date/time the token can be used'),
        ),
        parameters.Str(
            'ipatokenvendor',
            required=False,
            cli_name='vendor',
            label=_('Vendor'),
            doc=_('Token vendor name (informational only)'),
        ),
        parameters.Str(
            'ipatokenmodel',
            required=False,
            cli_name='model',
            label=_('Model'),
            doc=_('Token model (informational only)'),
        ),
        parameters.Str(
            'ipatokenserial',
            required=False,
            cli_name='serial',
            label=_('Serial'),
            doc=_('Token serial (informational only)'),
        ),
        parameters.Bytes(
            'ipatokenotpkey',
            required=False,
            cli_name='key',
            label=_('Key'),
            doc=_('Token secret (Base32; default: random)'),
            default_from=DefaultFrom(lambda : None),
            # FIXME:
            # lambda: os.urandom(KEY_LENGTH)
            autofill=True,
        ),
        parameters.Str(
            'ipatokenotpalgorithm',
            required=False,
            cli_name='algo',
            cli_metavar="['sha1', 'sha256', 'sha384', 'sha512']",
            label=_('Algorithm'),
            doc=_('Token hash algorithm'),
            default='sha1',
            autofill=True,
        ),
        parameters.Int(
            'ipatokenotpdigits',
            required=False,
            cli_name='digits',
            cli_metavar="['6', '8']",
            label=_('Digits'),
            doc=_('Number of digits each token code will have'),
            default=6,
            autofill=True,
        ),
        parameters.Int(
            'ipatokentotpclockoffset',
            required=False,
            cli_name='offset',
            label=_('Clock offset'),
            doc=_('TOTP token / IPA server time difference'),
            default=0,
            autofill=True,
        ),
        parameters.Int(
            'ipatokentotptimestep',
            required=False,
            cli_name='interval',
            label=_('Clock interval'),
            doc=_('Length of TOTP token code validity'),
            default=30,
            autofill=True,
        ),
        parameters.Int(
            'ipatokenhotpcounter',
            required=False,
            cli_name='counter',
            label=_('Counter'),
            doc=_('Initial counter for the HOTP token'),
            default=0,
            autofill=True,
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_(
                'Set an attribute to a name/value pair. '
                'Format is attr=value.\nFor multi-valued attributes, '
                'the command replaces the values already present.'
            ),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_(
                'Add an attribute/value pair. Format is attr=value. '
                'The attribute\nmust be part of the schema.'
            ),
            exclude=('webui',),
        ),
        parameters.Flag(
            'qrcode',
            required=False,
            label=_('(deprecated)'),
            exclude=('cli', 'webui'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_qrcode',
            label=_('Do not display QR code'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(
                'Retrieve and print all attributes from the server. '
                'Affects command output.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(
                'Print entries as stored on the server. '
                'Only affects output format.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
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
class otptoken_add_managedby(Method):
    __doc__ = _("Add users that can manage this token.")

    takes_args = (
        parameters.Str(
            'ipatokenuniqueid',
            cli_name='id',
            label=_('Unique ID'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'all',
            doc=_(
                'Retrieve and print all attributes from the server. '
                'Affects command output.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(
                'Print entries as stored on the server. '
                'Only affects output format.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'user',
            required=False,
            multivalue=True,
            cli_name='users',
            label=_('member user'),
            doc=_('users to add'),
            alwaysask=True,
        ),
    )
    has_output = (
        output.Entry(
            'result',
        ),
        output.Output(
            'failed',
            dict,
            doc=_('Members that could not be added'),
        ),
        output.Output(
            'completed',
            int,
            doc=_('Number of members added'),
        ),
    )


@register()
class otptoken_del(Method):
    __doc__ = _("Delete an OTP token.")

    takes_args = (
        parameters.Str(
            'ipatokenuniqueid',
            multivalue=True,
            cli_name='id',
            label=_('Unique ID'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_("Continuous mode: Don't stop on errors."),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            dict,
            doc=_('List of deletions that failed'),
        ),
        output.ListOfPrimaryKeys(
            'value',
        ),
    )


@register()
class otptoken_find(Method):
    __doc__ = _("Search for OTP token.")

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_('A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'ipatokenuniqueid',
            required=False,
            cli_name='id',
            label=_('Unique ID'),
        ),
        parameters.Str(
            'type',
            required=False,
            cli_metavar="['totp', 'hotp', 'TOTP', 'HOTP']",
            label=_('Type'),
            doc=_('Type of the token'),
            default='totp',
        ),
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
            doc=_('Token description (informational only)'),
        ),
        parameters.Str(
            'ipatokenowner',
            required=False,
            cli_name='owner',
            label=_('Owner'),
            doc=_('Assigned user of the token (default: self)'),
        ),
        parameters.Bool(
            'ipatokendisabled',
            required=False,
            cli_name='disabled',
            label=_('Disabled'),
            doc=_('Mark the token as disabled (default: false)'),
        ),
        parameters.DateTime(
            'ipatokennotbefore',
            required=False,
            cli_name='not_before',
            label=_('Validity start'),
            doc=_('First date/time the token can be used'),
        ),
        parameters.DateTime(
            'ipatokennotafter',
            required=False,
            cli_name='not_after',
            label=_('Validity end'),
            doc=_('Last date/time the token can be used'),
        ),
        parameters.Str(
            'ipatokenvendor',
            required=False,
            cli_name='vendor',
            label=_('Vendor'),
            doc=_('Token vendor name (informational only)'),
        ),
        parameters.Str(
            'ipatokenmodel',
            required=False,
            cli_name='model',
            label=_('Model'),
            doc=_('Token model (informational only)'),
        ),
        parameters.Str(
            'ipatokenserial',
            required=False,
            cli_name='serial',
            label=_('Serial'),
            doc=_('Token serial (informational only)'),
        ),
        parameters.Str(
            'ipatokenotpalgorithm',
            required=False,
            cli_name='algo',
            cli_metavar="['sha1', 'sha256', 'sha384', 'sha512']",
            label=_('Algorithm'),
            doc=_('Token hash algorithm'),
            default='sha1',
        ),
        parameters.Int(
            'ipatokenotpdigits',
            required=False,
            cli_name='digits',
            cli_metavar="['6', '8']",
            label=_('Digits'),
            doc=_('Number of digits each token code will have'),
            default=6,
        ),
        parameters.Int(
            'ipatokentotpclockoffset',
            required=False,
            cli_name='offset',
            label=_('Clock offset'),
            doc=_('TOTP token / IPA server time difference'),
            default=0,
        ),
        parameters.Int(
            'ipatokentotptimestep',
            required=False,
            cli_name='interval',
            label=_('Clock interval'),
            doc=_('Length of TOTP token code validity'),
            default=30,
        ),
        parameters.Int(
            'ipatokenhotpcounter',
            required=False,
            cli_name='counter',
            label=_('Counter'),
            doc=_('Initial counter for the HOTP token'),
            default=0,
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_('Time Limit'),
            doc=_('Time limit of search in seconds'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_('Size Limit'),
            doc=_('Maximum number of entries returned'),
        ),
        parameters.Flag(
            'all',
            doc=_(
                'Retrieve and print all attributes from the server. '
                'Affects command output.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(
                'Print entries as stored on the server. '
                'Only affects output format.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_('Primary key only'),
            doc=_('Results should contain primary key attribute only ("id")'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.ListOfEntries(
            'result',
        ),
        output.Output(
            'count',
            int,
            doc=_('Number of entries returned'),
        ),
        output.Output(
            'truncated',
            bool,
            doc=_('True if not all results were returned'),
        ),
    )


@register()
class otptoken_mod(Method):
    __doc__ = _("Modify a OTP token.")

    takes_args = (
        parameters.Str(
            'ipatokenuniqueid',
            cli_name='id',
            label=_('Unique ID'),
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
            doc=_('Token description (informational only)'),
        ),
        parameters.Str(
            'ipatokenowner',
            required=False,
            cli_name='owner',
            label=_('Owner'),
            doc=_('Assigned user of the token (default: self)'),
        ),
        parameters.Bool(
            'ipatokendisabled',
            required=False,
            cli_name='disabled',
            label=_('Disabled'),
            doc=_('Mark the token as disabled (default: false)'),
        ),
        parameters.DateTime(
            'ipatokennotbefore',
            required=False,
            cli_name='not_before',
            label=_('Validity start'),
            doc=_('First date/time the token can be used'),
        ),
        parameters.DateTime(
            'ipatokennotafter',
            required=False,
            cli_name='not_after',
            label=_('Validity end'),
            doc=_('Last date/time the token can be used'),
        ),
        parameters.Str(
            'ipatokenvendor',
            required=False,
            cli_name='vendor',
            label=_('Vendor'),
            doc=_('Token vendor name (informational only)'),
        ),
        parameters.Str(
            'ipatokenmodel',
            required=False,
            cli_name='model',
            label=_('Model'),
            doc=_('Token model (informational only)'),
        ),
        parameters.Str(
            'ipatokenserial',
            required=False,
            cli_name='serial',
            label=_('Serial'),
            doc=_('Token serial (informational only)'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_(
                'Set an attribute to a name/value pair. '
                'Format is attr=value.\nFor multi-valued attributes, '
                'the command replaces the values already present.'
            ),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_(
                'Add an attribute/value pair. Format is attr=value. '
                'The attribute\nmust be part of the schema.'
            ),
            exclude=('webui',),
        ),
        parameters.Str(
            'delattr',
            required=False,
            multivalue=True,
            doc=_(
                'Delete an attribute/value pair. '
                'The option will be evaluated\nlast, after all sets and adds.'
            ),
            exclude=('webui',),
        ),
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_(
                'Display the access rights of this entry (requires --all). '
                'See ipa man page for details.'
            ),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(
                'Retrieve and print all attributes from the server. '
                'Affects command output.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(
                'Print entries as stored on the server. '
                'Only affects output format.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'rename',
            required=False,
            label=_('Rename'),
            doc=_('Rename the OTP token object'),
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
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
class otptoken_remove_managedby(Method):
    __doc__ = _("Remove hosts that can manage this host.")

    takes_args = (
        parameters.Str(
            'ipatokenuniqueid',
            cli_name='id',
            label=_('Unique ID'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'all',
            doc=_(
                'Retrieve and print all attributes from the server. '
                'Affects command output.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(
                'Print entries as stored on the server. '
                'Only affects output format.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'user',
            required=False,
            multivalue=True,
            cli_name='users',
            label=_('member user'),
            doc=_('users to remove'),
            alwaysask=True,
        ),
    )
    has_output = (
        output.Entry(
            'result',
        ),
        output.Output(
            'failed',
            dict,
            doc=_('Members that could not be removed'),
        ),
        output.Output(
            'completed',
            int,
            doc=_('Number of members removed'),
        ),
    )


@register()
class otptoken_show(Method):
    __doc__ = _("Display information about an OTP token.")

    takes_args = (
        parameters.Str(
            'ipatokenuniqueid',
            cli_name='id',
            label=_('Unique ID'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_(
                'Display the access rights of this entry (requires --all). '
                'See ipa man page for details.'
            ),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(
                'Retrieve and print all attributes from the server. '
                'Affects command output.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(
                'Print entries as stored on the server. '
                'Only affects output format.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
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
