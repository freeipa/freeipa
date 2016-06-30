#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

# pylint: disable=unused-import
import six

from . import Command, Method, Object
from ipalib import api, parameters, output
from ipalib.parameters import DefaultFrom
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

if six.PY3:
    unicode = str

__doc__ = _("""
Set a user's password

If someone other than a user changes that user's password (e.g., Helpdesk
resets it) then the password will need to be changed the first time it
is used. This is so the end-user is the only one who knows the password.

The IPA password policy controls how often a password may be changed,
what strength requirements exist, and the length of the password history.

EXAMPLES:

 To reset your own password:
   ipa passwd

 To change another user's password:
   ipa passwd tuser1
""")

register = Registry()


@register()
class passwd(Command):
    __doc__ = _("Set a user's password.")

    takes_args = (
        parameters.Str(
            'principal',
            cli_name='user',
            label=_(u'User name'),
            default_from=DefaultFrom(lambda : None),
            # FIXME:
            # lambda: krb_utils.get_principal()
            autofill=True,
            no_convert=True,
        ),
        parameters.Password(
            'password',
            label=_(u'New Password'),
            confirm=True,
        ),
        parameters.Password(
            'current_password',
            label=_(u'Current Password'),
            default_from=DefaultFrom(lambda principal: None, 'principal'),
            # FIXME:
            # lambda principal: get_current_password(principal)
            autofill=True,
        ),
    )
    takes_options = (
        parameters.Password(
            'otp',
            required=False,
            label=_(u'OTP'),
            doc=_(u'One Time Password'),
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_(u'True means the operation was successful'),
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )
