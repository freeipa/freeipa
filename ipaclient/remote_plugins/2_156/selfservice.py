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
Self-service Permissions

A permission enables fine-grained delegation of permissions. Access Control
Rules, or instructions (ACIs), grant permission to permissions to perform
given tasks such as adding a user, modifying a group, etc.

A Self-service permission defines what an object can change in its own entry.


EXAMPLES:

 Add a self-service rule to allow users to manage their address (using Bash
 brace expansion):
   ipa selfservice-add --permissions=write --attrs={street,postalCode,l,c,st} "Users manage their own address"

 When managing the list of attributes you need to include all attributes
 in the list, including existing ones.
 Add telephoneNumber to the list (using Bash brace expansion):
   ipa selfservice-mod --attrs={street,postalCode,l,c,st,telephoneNumber} "Users manage their own address"

 Display our updated rule:
   ipa selfservice-show "Users manage their own address"

 Delete a rule:
   ipa selfservice-del "Users manage their own address"
""")

register = Registry()


@register()
class selfservice(Object):
    takes_params = (
        parameters.Str(
            'aciname',
            primary_key=True,
            label=_(u'Self-service name'),
        ),
        parameters.Str(
            'permissions',
            required=False,
            multivalue=True,
            label=_(u'Permissions'),
            doc=_(u'Permissions to grant (read, write). Default is write.'),
        ),
        parameters.Str(
            'attrs',
            multivalue=True,
            label=_(u'Attributes'),
            doc=_(u'Attributes to which the permission applies.'),
        ),
    )


@register()
class selfservice_add(Method):
    __doc__ = _("Add a new self-service permission.")

    takes_args = (
        parameters.Str(
            'aciname',
            cli_name='name',
            label=_(u'Self-service name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'permissions',
            required=False,
            multivalue=True,
            label=_(u'Permissions'),
            doc=_(u'Permissions to grant (read, write). Default is write.'),
        ),
        parameters.Str(
            'attrs',
            multivalue=True,
            label=_(u'Attributes'),
            doc=_(u'Attributes to which the permission applies.'),
            no_convert=True,
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
class selfservice_del(Method):
    __doc__ = _("Delete a self-service permission.")

    takes_args = (
        parameters.Str(
            'aciname',
            cli_name='name',
            label=_(u'Self-service name'),
        ),
    )
    takes_options = (
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


@register()
class selfservice_find(Method):
    __doc__ = _("Search for a self-service permission.")

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_(u'A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'aciname',
            required=False,
            cli_name='name',
            label=_(u'Self-service name'),
        ),
        parameters.Str(
            'permissions',
            required=False,
            multivalue=True,
            label=_(u'Permissions'),
            doc=_(u'Permissions to grant (read, write). Default is write.'),
        ),
        parameters.Str(
            'attrs',
            required=False,
            multivalue=True,
            label=_(u'Attributes'),
            doc=_(u'Attributes to which the permission applies.'),
            no_convert=True,
        ),
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_(u'Primary key only'),
            doc=_(u'Results should contain primary key attribute only ("name")'),
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
class selfservice_mod(Method):
    __doc__ = _("Modify a self-service permission.")

    takes_args = (
        parameters.Str(
            'aciname',
            cli_name='name',
            label=_(u'Self-service name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'permissions',
            required=False,
            multivalue=True,
            label=_(u'Permissions'),
            doc=_(u'Permissions to grant (read, write). Default is write.'),
        ),
        parameters.Str(
            'attrs',
            required=False,
            multivalue=True,
            label=_(u'Attributes'),
            doc=_(u'Attributes to which the permission applies.'),
            no_convert=True,
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
class selfservice_show(Method):
    __doc__ = _("Display information about a self-service permission.")

    takes_args = (
        parameters.Str(
            'aciname',
            cli_name='name',
            label=_(u'Self-service name'),
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
