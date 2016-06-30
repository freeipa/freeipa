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
Group to Group Delegation

A permission enables fine-grained delegation of permissions. Access Control
Rules, or instructions (ACIs), grant permission to permissions to perform
given tasks such as adding a user, modifying a group, etc.

Group to Group Delegations grants the members of one group to update a set
of attributes of members of another group.

EXAMPLES:

 Add a delegation rule to allow managers to edit employee's addresses:
   ipa delegation-add --attrs=street --group=managers --membergroup=employees "managers edit employees' street"

 When managing the list of attributes you need to include all attributes
 in the list, including existing ones. Add postalCode to the list:
   ipa delegation-mod --attrs=street --attrs=postalCode --group=managers --membergroup=employees "managers edit employees' street"

 Display our updated rule:
   ipa delegation-show "managers edit employees' street"

 Delete a rule:
   ipa delegation-del "managers edit employees' street"
""")

register = Registry()


@register()
class delegation(Object):
    takes_params = (
        parameters.Str(
            'aciname',
            primary_key=True,
            label=_(u'Delegation name'),
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
            doc=_(u'Attributes to which the delegation applies'),
        ),
        parameters.Str(
            'memberof',
            label=_(u'Member user group'),
            doc=_(u'User group to apply delegation to'),
        ),
        parameters.Str(
            'group',
            label=_(u'User group'),
            doc=_(u'User group ACI grants access to'),
        ),
    )


@register()
class delegation_add(Method):
    __doc__ = _("Add a new delegation.")

    takes_args = (
        parameters.Str(
            'aciname',
            cli_name='name',
            label=_(u'Delegation name'),
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
            doc=_(u'Attributes to which the delegation applies'),
            no_convert=True,
        ),
        parameters.Str(
            'memberof',
            cli_name='membergroup',
            label=_(u'Member user group'),
            doc=_(u'User group to apply delegation to'),
        ),
        parameters.Str(
            'group',
            label=_(u'User group'),
            doc=_(u'User group ACI grants access to'),
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
class delegation_del(Method):
    __doc__ = _("Delete a delegation.")

    takes_args = (
        parameters.Str(
            'aciname',
            cli_name='name',
            label=_(u'Delegation name'),
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
class delegation_find(Method):
    __doc__ = _("Search for delegations.")

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
            label=_(u'Delegation name'),
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
            doc=_(u'Attributes to which the delegation applies'),
            no_convert=True,
        ),
        parameters.Str(
            'memberof',
            required=False,
            cli_name='membergroup',
            label=_(u'Member user group'),
            doc=_(u'User group to apply delegation to'),
        ),
        parameters.Str(
            'group',
            required=False,
            label=_(u'User group'),
            doc=_(u'User group ACI grants access to'),
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
class delegation_mod(Method):
    __doc__ = _("Modify a delegation.")

    takes_args = (
        parameters.Str(
            'aciname',
            cli_name='name',
            label=_(u'Delegation name'),
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
            doc=_(u'Attributes to which the delegation applies'),
            no_convert=True,
        ),
        parameters.Str(
            'memberof',
            required=False,
            cli_name='membergroup',
            label=_(u'Member user group'),
            doc=_(u'User group to apply delegation to'),
        ),
        parameters.Str(
            'group',
            required=False,
            label=_(u'User group'),
            doc=_(u'User group ACI grants access to'),
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
class delegation_show(Method):
    __doc__ = _("Display information about a delegation.")

    takes_args = (
        parameters.Str(
            'aciname',
            cli_name='name',
            label=_(u'Delegation name'),
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
