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

__doc__ = _("""
ID Views

Manage ID Views

IPA allows to override certain properties of users and groups per each host.
This functionality is primarily used to allow migration from older systems or
other Identity Management solutions.
""")

register = Registry()


@register()
class idoverridegroup(Object):
    takes_params = (
        parameters.Str(
            'ipaanchoruuid',
            primary_key=True,
            label=_('Anchor to override'),
        ),
        parameters.Str(
            'description',
            required=False,
            label=_('Description'),
        ),
        parameters.Str(
            'cn',
            required=False,
            label=_('Group name'),
        ),
        parameters.Int(
            'gidnumber',
            required=False,
            label=_('GID'),
            doc=_('Group ID Number'),
        ),
    )


@register()
class idoverrideuser(Object):
    takes_params = (
        parameters.Str(
            'ipaanchoruuid',
            primary_key=True,
            label=_('Anchor to override'),
        ),
        parameters.Str(
            'description',
            required=False,
            label=_('Description'),
        ),
        parameters.Str(
            'uid',
            required=False,
            label=_('User login'),
        ),
        parameters.Int(
            'uidnumber',
            required=False,
            label=_('UID'),
            doc=_('User ID Number'),
        ),
        parameters.Str(
            'gecos',
            required=False,
            label=_('GECOS'),
        ),
        parameters.Int(
            'gidnumber',
            required=False,
            label=_('GID'),
            doc=_('Group ID Number'),
        ),
        parameters.Str(
            'homedirectory',
            required=False,
            label=_('Home directory'),
        ),
        parameters.Str(
            'loginshell',
            required=False,
            label=_('Login shell'),
        ),
        parameters.Str(
            'ipaoriginaluid',
            required=False,
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ipasshpubkey',
            required=False,
            multivalue=True,
            label=_('SSH public key'),
        ),
    )


@register()
class idview(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_('ID View Name'),
        ),
        parameters.Str(
            'description',
            required=False,
            label=_('Description'),
        ),
    )


@register()
class idoverridegroup_add(Method):
    __doc__ = _("Add a new Group ID override.")

    takes_args = (
        parameters.Str(
            'idviewcn',
            cli_name='idview',
            label=_('ID View Name'),
        ),
        parameters.Str(
            'ipaanchoruuid',
            cli_name='anchor',
            label=_('Anchor to override'),
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
        ),
        parameters.Str(
            'cn',
            required=False,
            cli_name='group_name',
            label=_('Group name'),
            no_convert=True,
        ),
        parameters.Int(
            'gidnumber',
            required=False,
            cli_name='gid',
            label=_('GID'),
            doc=_('Group ID Number'),
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
        parameters.Flag(
            'fallback_to_ldap',
            required=False,
            label=_('Fallback to AD DC LDAP'),
            doc=_('Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.'),
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
class idoverridegroup_del(Method):
    __doc__ = _("Delete an Group ID override.")

    takes_args = (
        parameters.Str(
            'idviewcn',
            cli_name='idview',
            label=_('ID View Name'),
        ),
        parameters.Str(
            'ipaanchoruuid',
            multivalue=True,
            cli_name='anchor',
            label=_('Anchor to override'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_("Continuous mode: Don't stop on errors."),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'fallback_to_ldap',
            required=False,
            label=_('Fallback to AD DC LDAP'),
            doc=_('Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.'),
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
class idoverridegroup_find(Method):
    __doc__ = _("Search for an Group ID override.")

    takes_args = (
        parameters.Str(
            'idviewcn',
            cli_name='idview',
            label=_('ID View Name'),
        ),
        parameters.Str(
            'criteria',
            required=False,
            doc=_('A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'ipaanchoruuid',
            required=False,
            cli_name='anchor',
            label=_('Anchor to override'),
        ),
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
        ),
        parameters.Str(
            'cn',
            required=False,
            cli_name='group_name',
            label=_('Group name'),
            no_convert=True,
        ),
        parameters.Int(
            'gidnumber',
            required=False,
            cli_name='gid',
            label=_('GID'),
            doc=_('Group ID Number'),
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_('Time Limit'),
            doc=_('Time limit of search in seconds (0 is unlimited)'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_('Size Limit'),
            doc=_('Maximum number of entries returned (0 is unlimited)'),
        ),
        parameters.Flag(
            'fallback_to_ldap',
            required=False,
            label=_('Fallback to AD DC LDAP'),
            doc=_('Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.'),
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
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_('Primary key only'),
            doc=_('Results should contain primary key attribute only ("anchor")'),
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
class idoverridegroup_mod(Method):
    __doc__ = _("Modify an Group ID override.")

    takes_args = (
        parameters.Str(
            'idviewcn',
            cli_name='idview',
            label=_('ID View Name'),
        ),
        parameters.Str(
            'ipaanchoruuid',
            cli_name='anchor',
            label=_('Anchor to override'),
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
        ),
        parameters.Str(
            'cn',
            required=False,
            cli_name='group_name',
            label=_('Group name'),
            no_convert=True,
        ),
        parameters.Int(
            'gidnumber',
            required=False,
            cli_name='gid',
            label=_('GID'),
            doc=_('Group ID Number'),
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
            'fallback_to_ldap',
            required=False,
            label=_('Fallback to AD DC LDAP'),
            doc=_('Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.'),
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
        parameters.Str(
            'rename',
            required=False,
            label=_('Rename'),
            doc=_('Rename the Group ID override object'),
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
class idoverridegroup_show(Method):
    __doc__ = _("Display information about an Group ID override.")

    takes_args = (
        parameters.Str(
            'idviewcn',
            cli_name='idview',
            label=_('ID View Name'),
        ),
        parameters.Str(
            'ipaanchoruuid',
            cli_name='anchor',
            label=_('Anchor to override'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'fallback_to_ldap',
            required=False,
            label=_('Fallback to AD DC LDAP'),
            doc=_('Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.'),
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
class idoverrideuser_add(Method):
    __doc__ = _("Add a new User ID override.")

    takes_args = (
        parameters.Str(
            'idviewcn',
            cli_name='idview',
            label=_('ID View Name'),
        ),
        parameters.Str(
            'ipaanchoruuid',
            cli_name='anchor',
            label=_('Anchor to override'),
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
        ),
        parameters.Str(
            'uid',
            required=False,
            cli_name='login',
            label=_('User login'),
            no_convert=True,
        ),
        parameters.Int(
            'uidnumber',
            required=False,
            cli_name='uid',
            label=_('UID'),
            doc=_('User ID Number'),
        ),
        parameters.Str(
            'gecos',
            required=False,
            label=_('GECOS'),
        ),
        parameters.Int(
            'gidnumber',
            required=False,
            label=_('GID'),
            doc=_('Group ID Number'),
        ),
        parameters.Str(
            'homedirectory',
            required=False,
            cli_name='homedir',
            label=_('Home directory'),
        ),
        parameters.Str(
            'loginshell',
            required=False,
            cli_name='shell',
            label=_('Login shell'),
        ),
        parameters.Str(
            'ipaoriginaluid',
            required=False,
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ipasshpubkey',
            required=False,
            multivalue=True,
            cli_name='sshpubkey',
            label=_('SSH public key'),
            no_convert=True,
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
        parameters.Flag(
            'fallback_to_ldap',
            required=False,
            label=_('Fallback to AD DC LDAP'),
            doc=_('Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.'),
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
class idoverrideuser_del(Method):
    __doc__ = _("Delete an User ID override.")

    takes_args = (
        parameters.Str(
            'idviewcn',
            cli_name='idview',
            label=_('ID View Name'),
        ),
        parameters.Str(
            'ipaanchoruuid',
            multivalue=True,
            cli_name='anchor',
            label=_('Anchor to override'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_("Continuous mode: Don't stop on errors."),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'fallback_to_ldap',
            required=False,
            label=_('Fallback to AD DC LDAP'),
            doc=_('Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.'),
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
class idoverrideuser_find(Method):
    __doc__ = _("Search for an User ID override.")

    takes_args = (
        parameters.Str(
            'idviewcn',
            cli_name='idview',
            label=_('ID View Name'),
        ),
        parameters.Str(
            'criteria',
            required=False,
            doc=_('A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'ipaanchoruuid',
            required=False,
            cli_name='anchor',
            label=_('Anchor to override'),
        ),
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
        ),
        parameters.Str(
            'uid',
            required=False,
            cli_name='login',
            label=_('User login'),
            no_convert=True,
        ),
        parameters.Int(
            'uidnumber',
            required=False,
            cli_name='uid',
            label=_('UID'),
            doc=_('User ID Number'),
        ),
        parameters.Str(
            'gecos',
            required=False,
            label=_('GECOS'),
        ),
        parameters.Int(
            'gidnumber',
            required=False,
            label=_('GID'),
            doc=_('Group ID Number'),
        ),
        parameters.Str(
            'homedirectory',
            required=False,
            cli_name='homedir',
            label=_('Home directory'),
        ),
        parameters.Str(
            'loginshell',
            required=False,
            cli_name='shell',
            label=_('Login shell'),
        ),
        parameters.Str(
            'ipaoriginaluid',
            required=False,
            exclude=('cli', 'webui'),
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_('Time Limit'),
            doc=_('Time limit of search in seconds (0 is unlimited)'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_('Size Limit'),
            doc=_('Maximum number of entries returned (0 is unlimited)'),
        ),
        parameters.Flag(
            'fallback_to_ldap',
            required=False,
            label=_('Fallback to AD DC LDAP'),
            doc=_('Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.'),
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
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_('Primary key only'),
            doc=_('Results should contain primary key attribute only ("anchor")'),
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
class idoverrideuser_mod(Method):
    __doc__ = _("Modify an User ID override.")

    takes_args = (
        parameters.Str(
            'idviewcn',
            cli_name='idview',
            label=_('ID View Name'),
        ),
        parameters.Str(
            'ipaanchoruuid',
            cli_name='anchor',
            label=_('Anchor to override'),
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
        ),
        parameters.Str(
            'uid',
            required=False,
            cli_name='login',
            label=_('User login'),
            no_convert=True,
        ),
        parameters.Int(
            'uidnumber',
            required=False,
            cli_name='uid',
            label=_('UID'),
            doc=_('User ID Number'),
        ),
        parameters.Str(
            'gecos',
            required=False,
            label=_('GECOS'),
        ),
        parameters.Int(
            'gidnumber',
            required=False,
            label=_('GID'),
            doc=_('Group ID Number'),
        ),
        parameters.Str(
            'homedirectory',
            required=False,
            cli_name='homedir',
            label=_('Home directory'),
        ),
        parameters.Str(
            'loginshell',
            required=False,
            cli_name='shell',
            label=_('Login shell'),
        ),
        parameters.Str(
            'ipaoriginaluid',
            required=False,
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ipasshpubkey',
            required=False,
            multivalue=True,
            cli_name='sshpubkey',
            label=_('SSH public key'),
            no_convert=True,
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
            'fallback_to_ldap',
            required=False,
            label=_('Fallback to AD DC LDAP'),
            doc=_('Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.'),
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
        parameters.Str(
            'rename',
            required=False,
            label=_('Rename'),
            doc=_('Rename the User ID override object'),
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
class idoverrideuser_show(Method):
    __doc__ = _("Display information about an User ID override.")

    takes_args = (
        parameters.Str(
            'idviewcn',
            cli_name='idview',
            label=_('ID View Name'),
        ),
        parameters.Str(
            'ipaanchoruuid',
            cli_name='anchor',
            label=_('Anchor to override'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'fallback_to_ldap',
            required=False,
            label=_('Fallback to AD DC LDAP'),
            doc=_('Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.'),
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
class idview_add(Method):
    __doc__ = _("Add a new ID View.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_('ID View Name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
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
class idview_apply(Method):
    __doc__ = _("Applies ID View to specified hosts or current members of specified hostgroups. If any other ID View is applied to the host, it is overridden.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_('ID View Name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_('hosts'),
            doc=_('Hosts to apply the ID View to'),
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_('hostgroups'),
            doc=_('Hostgroups to whose hosts apply the ID View to. Please note that view is not applied automatically to any hosts added to the hostgroup after running the idview-apply command.'),
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'succeeded',
            dict,
            doc=_('Hosts that this ID View was applied to.'),
        ),
        output.Output(
            'failed',
            dict,
            doc=_('Hosts or hostgroups that this ID View could not be applied to.'),
        ),
        output.Output(
            'completed',
            int,
            doc=_('Number of hosts the ID View was applied to:'),
        ),
    )


@register()
class idview_del(Method):
    __doc__ = _("Delete an ID View.")

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='name',
            label=_('ID View Name'),
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
class idview_find(Method):
    __doc__ = _("Search for an ID View.")

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_('A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'cn',
            required=False,
            cli_name='name',
            label=_('ID View Name'),
        ),
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_('Time Limit'),
            doc=_('Time limit of search in seconds (0 is unlimited)'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_('Size Limit'),
            doc=_('Maximum number of entries returned (0 is unlimited)'),
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
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_('Primary key only'),
            doc=_('Results should contain primary key attribute only ("name")'),
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
class idview_mod(Method):
    __doc__ = _("Modify an ID View.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_('ID View Name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
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
        parameters.Str(
            'rename',
            required=False,
            label=_('Rename'),
            doc=_('Rename the ID View object'),
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
class idview_show(Method):
    __doc__ = _("Display information about an ID View.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_('ID View Name'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'show_hosts',
            required=False,
            doc=_('Enumerate all the hosts the view applies to.'),
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
class idview_unapply(Method):
    __doc__ = _("Clears ID View from specified hosts or current members of specified hostgroups.")

    takes_options = (
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_('hosts'),
            doc=_('Hosts to clear (any) ID View from.'),
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_('hostgroups'),
            doc=_('Hostgroups whose hosts should have ID Views cleared. Note that view is not cleared automatically from any host added to the hostgroup after running idview-unapply command.'),
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'succeeded',
            dict,
            doc=_('Hosts that ID View was cleared from.'),
        ),
        output.Output(
            'failed',
            dict,
            doc=_('Hosts or hostgroups that ID View could not be cleared from.'),
        ),
        output.Output(
            'completed',
            int,
            doc=_('Number of hosts that had a ID View was unset:'),
        ),
    )
