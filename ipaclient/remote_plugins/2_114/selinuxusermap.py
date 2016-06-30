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
SELinux User Mapping

Map IPA users to SELinux users by host.

Hosts, hostgroups, users and groups can be either defined within
the rule or it may point to an existing HBAC rule. When using
--hbacrule option to selinuxusermap-find an exact match is made on the
HBAC rule name, so only one or zero entries will be returned.

EXAMPLES:

 Create a rule, "test1", that sets all users to xguest_u:s0 on the host "server":
   ipa selinuxusermap-add --usercat=all --selinuxuser=xguest_u:s0 test1
   ipa selinuxusermap-add-host --hosts=server.example.com test1

 Create a rule, "test2", that sets all users to guest_u:s0 and uses an existing HBAC rule for users and hosts:
   ipa selinuxusermap-add --usercat=all --hbacrule=webserver --selinuxuser=guest_u:s0 test2

 Display the properties of a rule:
   ipa selinuxusermap-show test2

 Create a rule for a specific user. This sets the SELinux context for
 user john to unconfined_u:s0-s0:c0.c1023 on any machine:
   ipa selinuxusermap-add --hostcat=all --selinuxuser=unconfined_u:s0-s0:c0.c1023 john_unconfined
   ipa selinuxusermap-add-user --users=john john_unconfined

 Disable a rule:
   ipa selinuxusermap-disable test1

 Enable a rule:
   ipa selinuxusermap-enable test1

 Find a rule referencing a specific HBAC rule:
   ipa selinuxusermap-find --hbacrule=allow_some

 Remove a rule:
   ipa selinuxusermap-del john_unconfined

SEEALSO:

 The list controlling the order in which the SELinux user map is applied
 and the default SELinux user are available in the config-show command.
""")

register = Registry()


@register()
class selinuxusermap(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_(u'Rule name'),
        ),
        parameters.Str(
            'ipaselinuxuser',
            label=_(u'SELinux User'),
        ),
        parameters.Str(
            'seealso',
            required=False,
            label=_(u'HBAC Rule'),
            doc=_(u'HBAC Rule that defines the users, groups and hostgroups'),
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
    )


@register()
class selinuxusermap_add(Method):
    __doc__ = _("Create a new SELinux User Map.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Rule name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'ipaselinuxuser',
            cli_name='selinuxuser',
            label=_(u'SELinux User'),
        ),
        parameters.Str(
            'seealso',
            required=False,
            cli_name='hbacrule',
            label=_(u'HBAC Rule'),
            doc=_(u'HBAC Rule that defines the users, groups and hostgroups'),
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
class selinuxusermap_add_host(Method):
    __doc__ = _("Add target hosts and hostgroups to an SELinux User Map rule.")

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
class selinuxusermap_add_user(Method):
    __doc__ = _("Add users and groups to an SELinux User Map rule.")

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
class selinuxusermap_del(Method):
    __doc__ = _("Delete a SELinux User Map.")

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
class selinuxusermap_disable(Method):
    __doc__ = _("Disable an SELinux User Map rule.")

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
class selinuxusermap_enable(Method):
    __doc__ = _("Enable an SELinux User Map rule.")

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
class selinuxusermap_find(Method):
    __doc__ = _("Search for SELinux User Maps.")

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
            'ipaselinuxuser',
            required=False,
            cli_name='selinuxuser',
            label=_(u'SELinux User'),
        ),
        parameters.Str(
            'seealso',
            required=False,
            cli_name='hbacrule',
            label=_(u'HBAC Rule'),
            doc=_(u'HBAC Rule that defines the users, groups and hostgroups'),
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
class selinuxusermap_mod(Method):
    __doc__ = _("Modify a SELinux User Map.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Rule name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'ipaselinuxuser',
            required=False,
            cli_name='selinuxuser',
            label=_(u'SELinux User'),
        ),
        parameters.Str(
            'seealso',
            required=False,
            cli_name='hbacrule',
            label=_(u'HBAC Rule'),
            doc=_(u'HBAC Rule that defines the users, groups and hostgroups'),
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
class selinuxusermap_remove_host(Method):
    __doc__ = _("Remove target hosts and hostgroups from an SELinux User Map rule.")

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
class selinuxusermap_remove_user(Method):
    __doc__ = _("Remove users and groups from an SELinux User Map rule.")

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
class selinuxusermap_show(Method):
    __doc__ = _("Display the properties of a SELinux User Map rule.")

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
