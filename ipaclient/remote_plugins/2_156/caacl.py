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
Manage CA ACL rules.

This plugin is used to define rules governing which principals are
permitted to have certificates issued using a given certificate
profile.

PROFILE ID SYNTAX:

A Profile ID is a string without spaces or punctuation starting with a letter
and followed by a sequence of letters, digits or underscore ("_").

EXAMPLES:

  Create a CA ACL "test" that grants all users access to the
  "UserCert" profile:
    ipa caacl-add test --usercat=all
    ipa caacl-add-profile test --certprofiles UserCert

  Display the properties of a named CA ACL:
    ipa caacl-show test

  Create a CA ACL to let user "alice" use the "DNP3" profile:
    ipa caacl-add-profile alice_dnp3 --certprofiles DNP3
    ipa caacl-add-user alice_dnp3 --user=alice

  Disable a CA ACL:
    ipa caacl-disable test

  Remove a CA ACL:
    ipa caacl-del test
""")

register = Registry()


@register()
class caacl(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_(u'ACL name'),
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
            'ipacertprofilecategory',
            required=False,
            label=_(u'Profile category'),
            doc=_(u'Profile category the ACL applies to'),
        ),
        parameters.Str(
            'usercategory',
            required=False,
            label=_(u'User category'),
            doc=_(u'User category the ACL applies to'),
        ),
        parameters.Str(
            'hostcategory',
            required=False,
            label=_(u'Host category'),
            doc=_(u'Host category the ACL applies to'),
        ),
        parameters.Str(
            'servicecategory',
            required=False,
            label=_(u'Service category'),
            doc=_(u'Service category the ACL applies to'),
        ),
        parameters.Str(
            'ipamembercertprofile_certprofile',
            required=False,
            label=_(u'Profiles'),
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
            'memberservice_service',
            required=False,
            label=_(u'Services'),
        ),
    )


@register()
class caacl_add(Method):
    __doc__ = _("Create a new CA ACL.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'ACL name'),
        ),
    )
    takes_options = (
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
            'ipacertprofilecategory',
            required=False,
            cli_name='profilecat',
            cli_metavar="['all']",
            label=_(u'Profile category'),
            doc=_(u'Profile category the ACL applies to'),
        ),
        parameters.Str(
            'usercategory',
            required=False,
            cli_name='usercat',
            cli_metavar="['all']",
            label=_(u'User category'),
            doc=_(u'User category the ACL applies to'),
        ),
        parameters.Str(
            'hostcategory',
            required=False,
            cli_name='hostcat',
            cli_metavar="['all']",
            label=_(u'Host category'),
            doc=_(u'Host category the ACL applies to'),
        ),
        parameters.Str(
            'servicecategory',
            required=False,
            cli_name='servicecat',
            cli_metavar="['all']",
            label=_(u'Service category'),
            doc=_(u'Service category the ACL applies to'),
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
class caacl_add_host(Method):
    __doc__ = _("Add target hosts and hostgroups to a CA ACL.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'ACL name'),
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
class caacl_add_profile(Method):
    __doc__ = _("Add profiles to a CA ACL.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'ACL name'),
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
            'certprofile',
            required=False,
            multivalue=True,
            cli_name='certprofiles',
            label=_(u'member Certificate Profile'),
            doc=_(u'Certificate Profiles to add'),
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
class caacl_add_service(Method):
    __doc__ = _("Add services to a CA ACL.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'ACL name'),
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
            'service',
            required=False,
            multivalue=True,
            cli_name='services',
            label=_(u'member service'),
            doc=_(u'services to add'),
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
class caacl_add_user(Method):
    __doc__ = _("Add users and groups to a CA ACL.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'ACL name'),
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
class caacl_del(Method):
    __doc__ = _("Delete a CA ACL.")

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='name',
            label=_(u'ACL name'),
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
class caacl_disable(Method):
    __doc__ = _("Disable a CA ACL.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'ACL name'),
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
class caacl_enable(Method):
    __doc__ = _("Enable a CA ACL.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'ACL name'),
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
class caacl_find(Method):
    __doc__ = _("Search for CA ACLs.")

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
            label=_(u'ACL name'),
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
            'ipacertprofilecategory',
            required=False,
            cli_name='profilecat',
            cli_metavar="['all']",
            label=_(u'Profile category'),
            doc=_(u'Profile category the ACL applies to'),
        ),
        parameters.Str(
            'usercategory',
            required=False,
            cli_name='usercat',
            cli_metavar="['all']",
            label=_(u'User category'),
            doc=_(u'User category the ACL applies to'),
        ),
        parameters.Str(
            'hostcategory',
            required=False,
            cli_name='hostcat',
            cli_metavar="['all']",
            label=_(u'Host category'),
            doc=_(u'Host category the ACL applies to'),
        ),
        parameters.Str(
            'servicecategory',
            required=False,
            cli_name='servicecat',
            cli_metavar="['all']",
            label=_(u'Service category'),
            doc=_(u'Service category the ACL applies to'),
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_(u'Time Limit'),
            doc=_(u'Time limit of search in seconds (0 is unlimited)'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_(u'Size Limit'),
            doc=_(u'Maximum number of entries returned (0 is unlimited)'),
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
class caacl_mod(Method):
    __doc__ = _("Modify a CA ACL.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'ACL name'),
        ),
    )
    takes_options = (
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
            'ipacertprofilecategory',
            required=False,
            cli_name='profilecat',
            cli_metavar="['all']",
            label=_(u'Profile category'),
            doc=_(u'Profile category the ACL applies to'),
        ),
        parameters.Str(
            'usercategory',
            required=False,
            cli_name='usercat',
            cli_metavar="['all']",
            label=_(u'User category'),
            doc=_(u'User category the ACL applies to'),
        ),
        parameters.Str(
            'hostcategory',
            required=False,
            cli_name='hostcat',
            cli_metavar="['all']",
            label=_(u'Host category'),
            doc=_(u'Host category the ACL applies to'),
        ),
        parameters.Str(
            'servicecategory',
            required=False,
            cli_name='servicecat',
            cli_metavar="['all']",
            label=_(u'Service category'),
            doc=_(u'Service category the ACL applies to'),
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
class caacl_remove_host(Method):
    __doc__ = _("Remove target hosts and hostgroups from a CA ACL.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'ACL name'),
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
class caacl_remove_profile(Method):
    __doc__ = _("Remove profiles from a CA ACL.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'ACL name'),
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
            'certprofile',
            required=False,
            multivalue=True,
            cli_name='certprofiles',
            label=_(u'member Certificate Profile'),
            doc=_(u'Certificate Profiles to remove'),
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
class caacl_remove_service(Method):
    __doc__ = _("Remove services from a CA ACL.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'ACL name'),
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
            'service',
            required=False,
            multivalue=True,
            cli_name='services',
            label=_(u'member service'),
            doc=_(u'services to remove'),
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
class caacl_remove_user(Method):
    __doc__ = _("Remove users and groups from a CA ACL.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'ACL name'),
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
class caacl_show(Method):
    __doc__ = _("Display the properties of a CA ACL.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'ACL name'),
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
