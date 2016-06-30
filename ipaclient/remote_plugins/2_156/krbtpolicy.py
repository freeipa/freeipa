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


@register()
class krbtpolicy(Object):
    takes_params = (
        parameters.Str(
            'uid',
            required=False,
            primary_key=True,
            label=_(u'User name'),
            doc=_(u'Manage ticket policy for specific user'),
        ),
        parameters.Int(
            'krbmaxticketlife',
            required=False,
            label=_(u'Max life'),
            doc=_(u'Maximum ticket life (seconds)'),
        ),
        parameters.Int(
            'krbmaxrenewableage',
            required=False,
            label=_(u'Max renew'),
            doc=_(u'Maximum renewable age (seconds)'),
        ),
    )


@register()
class krbtpolicy_mod(Method):
    __doc__ = _("Modify Kerberos ticket policy.")

    takes_args = (
        parameters.Str(
            'uid',
            required=False,
            cli_name='user',
            label=_(u'User name'),
            doc=_(u'Manage ticket policy for specific user'),
        ),
    )
    takes_options = (
        parameters.Int(
            'krbmaxticketlife',
            required=False,
            cli_name='maxlife',
            label=_(u'Max life'),
            doc=_(u'Maximum ticket life (seconds)'),
        ),
        parameters.Int(
            'krbmaxrenewableage',
            required=False,
            cli_name='maxrenew',
            label=_(u'Max renew'),
            doc=_(u'Maximum renewable age (seconds)'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_(u'Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_(u'Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'delattr',
            required=False,
            multivalue=True,
            doc=_(u'Delete an attribute/value pair. The option will be evaluated\nlast, after all sets and adds.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'rights',
            label=_(u'Rights'),
            doc=_(u'Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class krbtpolicy_reset(Method):
    __doc__ = _("Reset Kerberos ticket policy to the default values.")

    takes_args = (
        parameters.Str(
            'uid',
            required=False,
            cli_name='user',
            label=_(u'User name'),
            doc=_(u'Manage ticket policy for specific user'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class krbtpolicy_show(Method):
    __doc__ = _("Display the current Kerberos ticket policy.")

    takes_args = (
        parameters.Str(
            'uid',
            required=False,
            cli_name='user',
            label=_(u'User name'),
            doc=_(u'Manage ticket policy for specific user'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'rights',
            label=_(u'Rights'),
            doc=_(u'Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )
