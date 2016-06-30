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
Entitlements

Manage entitlements for client machines

Entitlements can be managed either by registering with an entitlement
server with a username and password or by manually importing entitlement
certificates. An entitlement certificate contains embedded information
such as the product being entitled, the quantity and the validity dates.

An entitlement server manages the number of client entitlements available.
To mark these entitlements as used by the IPA server you provide a quantity
and they are marked as consumed on the entitlement server.

 Register with an entitlement server:
   ipa entitle-register consumer

 Import an entitlement certificate:
   ipa entitle-import /home/user/ipaclient.pem

 Display current entitlements:
   ipa entitle-status

 Retrieve details on entitlement certificates:
   ipa entitle-get

 Consume some entitlements from the entitlement server:
   ipa entitle-consume 50

The registration ID is a Unique Identifier (UUID). This ID will be
IMPORTED if you have used entitle-import.

Changes to /etc/rhsm/rhsm.conf require a restart of the httpd service.
""")

register = Registry()


@register()
class entitle(Object):
    takes_params = (
    )


@register()
class entitle_consume(Method):
    __doc__ = _("Consume an entitlement.")

    takes_args = (
        parameters.Int(
            'quantity',
            label=_(u'Quantity'),
        ),
    )
    takes_options = (
        parameters.Int(
            'hidden',
            label=_(u'Quantity'),
            exclude=('cli', 'webui'),
            default=1,
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
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class entitle_find(Method):
    __doc__ = _("Search for entitlement accounts.")

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_(u'A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Int(
            'timelimit',
            required=False,
            label=_(u'Time Limit'),
            doc=_(u'Time limit of search in seconds'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_(u'Size Limit'),
            doc=_(u'Maximum number of entries returned'),
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
        output.ListOfEntries(
            'result',
        ),
        output.Output(
            'count',
            int,
            doc=_(u'Number of entries returned'),
        ),
        output.Output(
            'truncated',
            bool,
            doc=_(u'True if not all results were returned'),
        ),
    )


@register()
class entitle_get(Command):
    __doc__ = _("Retrieve the entitlement certs.")

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
        output.ListOfEntries(
            'result',
        ),
        output.Output(
            'count',
            int,
            doc=_(u'Number of entries returned'),
        ),
        output.Output(
            'truncated',
            bool,
            doc=_(u'True if not all results were returned'),
        ),
    )


@register()
class entitle_import(Method):
    __doc__ = _("Import an entitlement certificate.")

    takes_args = (
        parameters.Str(
            'usercertificate',
            required=False,
            multivalue=True,
            cli_name='certificate_file',
        ),
    )
    takes_options = (
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
            'uuid',
            required=False,
            label=_(u'UUID'),
            doc=_(u'Enrollment UUID'),
            default=u'IMPORTED',
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'result',
            dict,
            doc=_(u'Dictionary mapping variable name to value'),
        ),
    )


@register()
class entitle_register(Method):
    __doc__ = _("Register to the entitlement system.")

    takes_args = (
        parameters.Str(
            'username',
            label=_(u'Username'),
        ),
    )
    takes_options = (
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
            'ipaentitlementid',
            required=False,
            label=_(u'UUID'),
            doc=_(u'Enrollment UUID (not implemented)'),
        ),
        parameters.Password(
            'password',
            label=_(u'Password'),
            doc=_(u'Registration password'),
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
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class entitle_status(Command):
    __doc__ = _("Display current entitlements.")

    has_output = (
        output.Output(
            'result',
            dict,
            doc=_(u'Dictionary mapping variable name to value'),
        ),
    )


@register()
class entitle_sync(Method):
    __doc__ = _("Re-sync the local entitlement cache with the entitlement server.")

    takes_options = (
        parameters.Int(
            'hidden',
            label=_(u'Quantity'),
            exclude=('cli', 'webui'),
            default=1,
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
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )
