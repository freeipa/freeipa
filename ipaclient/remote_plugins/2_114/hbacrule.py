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
Host-based access control

Control who can access what services on what hosts. You
can use HBAC to control which users or groups can
access a service, or group of services, on a target host.

You can also specify a category of users and target hosts.
This is currently limited to "all", but might be expanded in the
future.

Target hosts in HBAC rules must be hosts managed by IPA.

The available services and groups of services are controlled by the
hbacsvc and hbacsvcgroup plug-ins respectively.

EXAMPLES:

 Create a rule, "test1", that grants all users access to the host "server" from
 anywhere:
   ipa hbacrule-add --usercat=all test1
   ipa hbacrule-add-host --hosts=server.example.com test1

 Display the properties of a named HBAC rule:
   ipa hbacrule-show test1

 Create a rule for a specific service. This lets the user john access
 the sshd service on any machine from any machine:
   ipa hbacrule-add --hostcat=all john_sshd
   ipa hbacrule-add-user --users=john john_sshd
   ipa hbacrule-add-service --hbacsvcs=sshd john_sshd

 Create a rule for a new service group. This lets the user john access
 the FTP service on any machine from any machine:
   ipa hbacsvcgroup-add ftpers
   ipa hbacsvc-add sftp
   ipa hbacsvcgroup-add-member --hbacsvcs=ftp --hbacsvcs=sftp ftpers
   ipa hbacrule-add --hostcat=all john_ftp
   ipa hbacrule-add-user --users=john john_ftp
   ipa hbacrule-add-service --hbacsvcgroups=ftpers john_ftp

 Disable a named HBAC rule:
   ipa hbacrule-disable test1

 Remove a named HBAC rule:
   ipa hbacrule-del allow_server
""")

register = Registry()


@register()
class hbacrule(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_(u'Rule name'),
        ),
        parameters.Str(
            'accessruletype',
            label=_(u'Rule type'),
            doc=_(u'Rule type (allow)'),
            exclude=('webui', 'cli'),
        ),
        parameters.Str(
            'usercategory',
            required=False,
            label=_(u'User category'),
            doc=_(u'User category the rule applies to'),
        ),
        parameters.Str(
            'hostcategory',
            required=False,
            label=_(u'Host category'),
            doc=_(u'Host category the rule applies to'),
        ),
        parameters.Str(
            'sourcehostcategory',
            required=False,
        ),
        parameters.Str(
            'servicecategory',
            required=False,
            label=_(u'Service category'),
            doc=_(u'Service category the rule applies to'),
        ),
        parameters.Str(
            'description',
            required=False,
            label=_(u'Description'),
        ),
        parameters.Bool(
            'ipaenabledflag',
            required=False,
            label=_(u'Enabled'),
        ),
        parameters.Str(
            'memberuser_user',
            required=False,
            label=_(u'Users'),
        ),
        parameters.Str(
            'memberuser_group',
            required=False,
            label=_(u'User Groups'),
        ),
        parameters.Str(
            'memberhost_host',
            required=False,
            label=_(u'Hosts'),
        ),
        parameters.Str(
            'memberhost_hostgroup',
            required=False,
            label=_(u'Host Groups'),
        ),
        parameters.Str(
            'sourcehost_host',
            required=False,
        ),
        parameters.Str(
            'sourcehost_hostgroup',
            required=False,
        ),
        parameters.Str(
            'memberservice_hbacsvc',
            required=False,
            label=_(u'Services'),
        ),
        parameters.Str(
            'memberservice_hbacsvcgroup',
            required=False,
            label=_(u'Service Groups'),
        ),
        parameters.Str(
            'externalhost',
            required=False,
            multivalue=True,
            label=_(u'External host'),
        ),
    )


@register()
class hbacrule_add(Method):
    __doc__ = _("Create a new HBAC rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Rule name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'accessruletype',
            cli_name='type',
            cli_metavar="['allow', 'deny']",
            label=_(u'Rule type'),
            doc=_(u'Rule type (allow)'),
            exclude=('webui', 'cli'),
            default=u'allow',
            autofill=True,
        ),
        parameters.Str(
            'usercategory',
            required=False,
            cli_name='usercat',
            cli_metavar="['all']",
            label=_(u'User category'),
            doc=_(u'User category the rule applies to'),
        ),
        parameters.Str(
            'hostcategory',
            required=False,
            cli_name='hostcat',
            cli_metavar="['all']",
            label=_(u'Host category'),
            doc=_(u'Host category the rule applies to'),
        ),
        parameters.Str(
            'sourcehostcategory',
            required=False,
            deprecated=True,
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'servicecategory',
            required=False,
            cli_name='servicecat',
            cli_metavar="['all']",
            label=_(u'Service category'),
            doc=_(u'Service category the rule applies to'),
        ),
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
        ),
        parameters.Bool(
            'ipaenabledflag',
            required=False,
            label=_(u'Enabled'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'sourcehost_host',
            required=False,
            deprecated=True,
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'sourcehost_hostgroup',
            required=False,
            deprecated=True,
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'externalhost',
            required=False,
            multivalue=True,
            label=_(u'External host'),
            exclude=('cli', 'webui'),
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
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
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
class hbacrule_add_host(Method):
    __doc__ = _("Add target hosts and hostgroups to an HBAC rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Rule name'),
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
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_(u'member host'),
            doc=_(u'hosts to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_(u'member host group'),
            doc=_(u'host groups to add'),
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
            doc=_(u'Members that could not be added'),
        ),
        output.Output(
            'completed',
            int,
            doc=_(u'Number of members added'),
        ),
    )


@register()
class hbacrule_add_service(Method):
    __doc__ = _("Add services to an HBAC rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Rule name'),
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
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'hbacsvc',
            required=False,
            multivalue=True,
            cli_name='hbacsvcs',
            label=_(u'member HBAC service'),
            doc=_(u'HBAC services to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'hbacsvcgroup',
            required=False,
            multivalue=True,
            cli_name='hbacsvcgroups',
            label=_(u'member HBAC service group'),
            doc=_(u'HBAC service groups to add'),
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
            doc=_(u'Members that could not be added'),
        ),
        output.Output(
            'completed',
            int,
            doc=_(u'Number of members added'),
        ),
    )


@register()
class hbacrule_add_sourcehost(Method):
    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Rule name'),
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
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_(u'member host'),
            doc=_(u'hosts to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_(u'member host group'),
            doc=_(u'host groups to add'),
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
            doc=_(u'Members that could not be added'),
        ),
        output.Output(
            'completed',
            int,
            doc=_(u'Number of members added'),
        ),
    )


@register()
class hbacrule_add_user(Method):
    __doc__ = _("Add users and groups to an HBAC rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Rule name'),
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
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'user',
            required=False,
            multivalue=True,
            cli_name='users',
            label=_(u'member user'),
            doc=_(u'users to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'group',
            required=False,
            multivalue=True,
            cli_name='groups',
            label=_(u'member group'),
            doc=_(u'groups to add'),
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
            doc=_(u'Members that could not be added'),
        ),
        output.Output(
            'completed',
            int,
            doc=_(u'Number of members added'),
        ),
    )


@register()
class hbacrule_del(Method):
    __doc__ = _("Delete an HBAC rule.")

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='name',
            label=_(u'Rule name'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_(u"Continuous mode: Don't stop on errors."),
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
        output.Output(
            'result',
            dict,
            doc=_(u'List of deletions that failed'),
        ),
        output.ListOfPrimaryKeys(
            'value',
        ),
    )


@register()
class hbacrule_disable(Method):
    __doc__ = _("Disable an HBAC rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Rule name'),
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
class hbacrule_enable(Method):
    __doc__ = _("Enable an HBAC rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Rule name'),
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
class hbacrule_find(Method):
    __doc__ = _("Search for HBAC rules.")

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_(u'A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'cn',
            required=False,
            cli_name='name',
            label=_(u'Rule name'),
        ),
        parameters.Str(
            'accessruletype',
            required=False,
            cli_name='type',
            cli_metavar="['allow', 'deny']",
            label=_(u'Rule type'),
            doc=_(u'Rule type (allow)'),
            exclude=('webui', 'cli'),
            default=u'allow',
        ),
        parameters.Str(
            'usercategory',
            required=False,
            cli_name='usercat',
            cli_metavar="['all']",
            label=_(u'User category'),
            doc=_(u'User category the rule applies to'),
        ),
        parameters.Str(
            'hostcategory',
            required=False,
            cli_name='hostcat',
            cli_metavar="['all']",
            label=_(u'Host category'),
            doc=_(u'Host category the rule applies to'),
        ),
        parameters.Str(
            'sourcehostcategory',
            required=False,
            deprecated=True,
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'servicecategory',
            required=False,
            cli_name='servicecat',
            cli_metavar="['all']",
            label=_(u'Service category'),
            doc=_(u'Service category the rule applies to'),
        ),
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
        ),
        parameters.Bool(
            'ipaenabledflag',
            required=False,
            label=_(u'Enabled'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'sourcehost_host',
            required=False,
            deprecated=True,
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'sourcehost_hostgroup',
            required=False,
            deprecated=True,
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'externalhost',
            required=False,
            multivalue=True,
            label=_(u'External host'),
            exclude=('cli', 'webui'),
        ),
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
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_(u'Primary key only'),
            doc=_(u'Results should contain primary key attribute only ("name")'),
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
class hbacrule_mod(Method):
    __doc__ = _("Modify an HBAC rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Rule name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'accessruletype',
            required=False,
            cli_name='type',
            cli_metavar="['allow', 'deny']",
            label=_(u'Rule type'),
            doc=_(u'Rule type (allow)'),
            exclude=('webui', 'cli'),
            default=u'allow',
        ),
        parameters.Str(
            'usercategory',
            required=False,
            cli_name='usercat',
            cli_metavar="['all']",
            label=_(u'User category'),
            doc=_(u'User category the rule applies to'),
        ),
        parameters.Str(
            'hostcategory',
            required=False,
            cli_name='hostcat',
            cli_metavar="['all']",
            label=_(u'Host category'),
            doc=_(u'Host category the rule applies to'),
        ),
        parameters.Str(
            'sourcehostcategory',
            required=False,
            deprecated=True,
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'servicecategory',
            required=False,
            cli_name='servicecat',
            cli_metavar="['all']",
            label=_(u'Service category'),
            doc=_(u'Service category the rule applies to'),
        ),
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
        ),
        parameters.Bool(
            'ipaenabledflag',
            required=False,
            label=_(u'Enabled'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'sourcehost_host',
            required=False,
            deprecated=True,
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'sourcehost_hostgroup',
            required=False,
            deprecated=True,
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'externalhost',
            required=False,
            multivalue=True,
            label=_(u'External host'),
            exclude=('cli', 'webui'),
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
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
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
class hbacrule_remove_host(Method):
    __doc__ = _("Remove target hosts and hostgroups from an HBAC rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Rule name'),
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
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_(u'member host'),
            doc=_(u'hosts to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_(u'member host group'),
            doc=_(u'host groups to remove'),
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
            doc=_(u'Members that could not be removed'),
        ),
        output.Output(
            'completed',
            int,
            doc=_(u'Number of members removed'),
        ),
    )


@register()
class hbacrule_remove_service(Method):
    __doc__ = _("Remove service and service groups from an HBAC rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Rule name'),
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
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'hbacsvc',
            required=False,
            multivalue=True,
            cli_name='hbacsvcs',
            label=_(u'member HBAC service'),
            doc=_(u'HBAC services to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'hbacsvcgroup',
            required=False,
            multivalue=True,
            cli_name='hbacsvcgroups',
            label=_(u'member HBAC service group'),
            doc=_(u'HBAC service groups to remove'),
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
            doc=_(u'Members that could not be removed'),
        ),
        output.Output(
            'completed',
            int,
            doc=_(u'Number of members removed'),
        ),
    )


@register()
class hbacrule_remove_sourcehost(Method):
    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Rule name'),
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
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_(u'member host'),
            doc=_(u'hosts to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_(u'member host group'),
            doc=_(u'host groups to remove'),
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
            doc=_(u'Members that could not be removed'),
        ),
        output.Output(
            'completed',
            int,
            doc=_(u'Number of members removed'),
        ),
    )


@register()
class hbacrule_remove_user(Method):
    __doc__ = _("Remove users and groups from an HBAC rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Rule name'),
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
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'user',
            required=False,
            multivalue=True,
            cli_name='users',
            label=_(u'member user'),
            doc=_(u'users to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'group',
            required=False,
            multivalue=True,
            cli_name='groups',
            label=_(u'member group'),
            doc=_(u'groups to remove'),
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
            doc=_(u'Members that could not be removed'),
        ),
        output.Output(
            'completed',
            int,
            doc=_(u'Number of members removed'),
        ),
    )


@register()
class hbacrule_show(Method):
    __doc__ = _("Display the properties of an HBAC rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Rule name'),
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
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
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
