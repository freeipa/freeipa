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
Sudo Rules

Sudo (su "do") allows a system administrator to delegate authority to
give certain users (or groups of users) the ability to run some (or all)
commands as root or another user while providing an audit trail of the
commands and their arguments.

FreeIPA provides a means to configure the various aspects of Sudo:
   Users: The user(s)/group(s) allowed to invoke Sudo.
   Hosts: The host(s)/hostgroup(s) which the user is allowed to to invoke Sudo.
   Allow Command: The specific command(s) permitted to be run via Sudo.
   Deny Command: The specific command(s) prohibited to be run via Sudo.
   RunAsUser: The user(s) or group(s) of users whose rights Sudo will be invoked with.
   RunAsGroup: The group(s) whose gid rights Sudo will be invoked with.
   Options: The various Sudoers Options that can modify Sudo's behavior.

An order can be added to a sudorule to control the order in which they
are evaluated (if the client supports it). This order is an integer and
must be unique.

FreeIPA provides a designated binddn to use with Sudo located at:
uid=sudo,cn=sysaccounts,cn=etc,dc=example,dc=com

To enable the binddn run the following command to set the password:
LDAPTLS_CACERT=/etc/ipa/ca.crt /usr/bin/ldappasswd -S -W -h ipa.example.com -ZZ -D "cn=Directory Manager" uid=sudo,cn=sysaccounts,cn=etc,dc=example,dc=com

EXAMPLES:

 Create a new rule:
   ipa sudorule-add readfiles

 Add sudo command object and add it as allowed command in the rule:
   ipa sudocmd-add /usr/bin/less
   ipa sudorule-add-allow-command readfiles --sudocmds /usr/bin/less

 Add a host to the rule:
   ipa sudorule-add-host readfiles --hosts server.example.com

 Add a user to the rule:
   ipa sudorule-add-user readfiles --users jsmith

 Add a special Sudo rule for default Sudo server configuration:
   ipa sudorule-add defaults

 Set a default Sudo option:
   ipa sudorule-add-option defaults --sudooption '!authenticate'
""")

register = Registry()


@register()
class sudorule(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_(u'Rule name'),
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
            'cmdcategory',
            required=False,
            label=_(u'Command category'),
            doc=_(u'Command category the rule applies to'),
        ),
        parameters.Str(
            'ipasudorunasusercategory',
            required=False,
            label=_(u'RunAs User category'),
            doc=_(u'RunAs User category the rule applies to'),
        ),
        parameters.Str(
            'ipasudorunasgroupcategory',
            required=False,
            label=_(u'RunAs Group category'),
            doc=_(u'RunAs Group category the rule applies to'),
        ),
        parameters.Int(
            'sudoorder',
            required=False,
            label=_(u'Sudo order'),
            doc=_(u'integer to order the Sudo rules'),
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
            'externaluser',
            required=False,
            label=_(u'External User'),
            doc=_(u'External User the rule applies to (sudorule-find only)'),
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
            'hostmask',
            multivalue=True,
            label=_(u'Host Masks'),
        ),
        parameters.Str(
            'externalhost',
            required=False,
            multivalue=True,
            label=_(u'External host'),
        ),
        parameters.Str(
            'memberallowcmd_sudocmd',
            required=False,
            label=_(u'Sudo Allow Commands'),
        ),
        parameters.Str(
            'memberdenycmd_sudocmd',
            required=False,
            label=_(u'Sudo Deny Commands'),
        ),
        parameters.Str(
            'memberallowcmd_sudocmdgroup',
            required=False,
            label=_(u'Sudo Allow Command Groups'),
        ),
        parameters.Str(
            'memberdenycmd_sudocmdgroup',
            required=False,
            label=_(u'Sudo Deny Command Groups'),
        ),
        parameters.Str(
            'ipasudorunas_user',
            required=False,
            label=_(u'RunAs Users'),
            doc=_(u'Run as a user'),
        ),
        parameters.Str(
            'ipasudorunas_group',
            required=False,
            label=_(u'Groups of RunAs Users'),
            doc=_(u'Run as any user within a specified group'),
        ),
        parameters.Str(
            'ipasudorunasextuser',
            required=False,
            label=_(u'RunAs External User'),
            doc=_(u'External User the commands can run as (sudorule-find only)'),
        ),
        parameters.Str(
            'ipasudorunasextusergroup',
            required=False,
            label=_(u'External Groups of RunAs Users'),
            doc=_(u'External Groups of users that the command can run as'),
        ),
        parameters.Str(
            'ipasudorunasgroup_group',
            required=False,
            label=_(u'RunAs Groups'),
            doc=_(u'Run with the gid of a specified POSIX group'),
        ),
        parameters.Str(
            'ipasudorunasextgroup',
            required=False,
            label=_(u'RunAs External Group'),
            doc=_(u'External Group the commands can run as (sudorule-find only)'),
        ),
        parameters.Str(
            'ipasudoopt',
            required=False,
            label=_(u'Sudo Option'),
        ),
    )


@register()
class sudorule_add(Method):
    __doc__ = _("Create new Sudo Rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
            label=_(u'Rule name'),
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
            'cmdcategory',
            required=False,
            cli_name='cmdcat',
            cli_metavar="['all']",
            label=_(u'Command category'),
            doc=_(u'Command category the rule applies to'),
        ),
        parameters.Str(
            'ipasudorunasusercategory',
            required=False,
            cli_name='runasusercat',
            cli_metavar="['all']",
            label=_(u'RunAs User category'),
            doc=_(u'RunAs User category the rule applies to'),
        ),
        parameters.Str(
            'ipasudorunasgroupcategory',
            required=False,
            cli_name='runasgroupcat',
            cli_metavar="['all']",
            label=_(u'RunAs Group category'),
            doc=_(u'RunAs Group category the rule applies to'),
        ),
        parameters.Int(
            'sudoorder',
            required=False,
            cli_name='order',
            label=_(u'Sudo order'),
            doc=_(u'integer to order the Sudo rules'),
            default=0,
        ),
        parameters.Str(
            'externaluser',
            required=False,
            label=_(u'External User'),
            doc=_(u'External User the rule applies to (sudorule-find only)'),
        ),
        parameters.Str(
            'externalhost',
            required=False,
            multivalue=True,
            label=_(u'External host'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ipasudorunasextuser',
            required=False,
            cli_name='runasexternaluser',
            label=_(u'RunAs External User'),
            doc=_(u'External User the commands can run as (sudorule-find only)'),
        ),
        parameters.Str(
            'ipasudorunasextgroup',
            required=False,
            cli_name='runasexternalgroup',
            label=_(u'RunAs External Group'),
            doc=_(u'External Group the commands can run as (sudorule-find only)'),
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
class sudorule_add_allow_command(Method):
    __doc__ = _("Add commands and sudo command groups affected by Sudo Rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
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
            'sudocmd',
            required=False,
            multivalue=True,
            cli_name='sudocmds',
            label=_(u'member sudo command'),
            doc=_(u'sudo commands to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'sudocmdgroup',
            required=False,
            multivalue=True,
            cli_name='sudocmdgroups',
            label=_(u'member sudo command group'),
            doc=_(u'sudo command groups to add'),
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
class sudorule_add_deny_command(Method):
    __doc__ = _("Add commands and sudo command groups affected by Sudo Rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
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
            'sudocmd',
            required=False,
            multivalue=True,
            cli_name='sudocmds',
            label=_(u'member sudo command'),
            doc=_(u'sudo commands to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'sudocmdgroup',
            required=False,
            multivalue=True,
            cli_name='sudocmdgroups',
            label=_(u'member sudo command group'),
            doc=_(u'sudo command groups to add'),
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
class sudorule_add_host(Method):
    __doc__ = _("Add hosts and hostgroups affected by Sudo Rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
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
        parameters.Str(
            'hostmask',
            required=False,
            multivalue=True,
            label=_(u'host masks of allowed hosts'),
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
class sudorule_add_option(Method):
    __doc__ = _("Add an option to the Sudo Rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
            label=_(u'Rule name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'ipasudoopt',
            cli_name='sudooption',
            label=_(u'Sudo Option'),
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
class sudorule_add_runasgroup(Method):
    __doc__ = _("Add group for Sudo to execute as.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
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
class sudorule_add_runasuser(Method):
    __doc__ = _("Add users and groups for Sudo to execute as.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
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
class sudorule_add_user(Method):
    __doc__ = _("Add users and groups affected by Sudo Rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
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
class sudorule_del(Method):
    __doc__ = _("Delete Sudo Rule.")

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='sudorule_name',
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
class sudorule_disable(Method):
    __doc__ = _("Disable a Sudo Rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
            label=_(u'Rule name'),
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'result',
        ),
    )


@register()
class sudorule_enable(Method):
    __doc__ = _("Enable a Sudo Rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
            label=_(u'Rule name'),
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'result',
        ),
    )


@register()
class sudorule_find(Method):
    __doc__ = _("Search for Sudo Rule.")

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
            cli_name='sudorule_name',
            label=_(u'Rule name'),
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
            'cmdcategory',
            required=False,
            cli_name='cmdcat',
            cli_metavar="['all']",
            label=_(u'Command category'),
            doc=_(u'Command category the rule applies to'),
        ),
        parameters.Str(
            'ipasudorunasusercategory',
            required=False,
            cli_name='runasusercat',
            cli_metavar="['all']",
            label=_(u'RunAs User category'),
            doc=_(u'RunAs User category the rule applies to'),
        ),
        parameters.Str(
            'ipasudorunasgroupcategory',
            required=False,
            cli_name='runasgroupcat',
            cli_metavar="['all']",
            label=_(u'RunAs Group category'),
            doc=_(u'RunAs Group category the rule applies to'),
        ),
        parameters.Int(
            'sudoorder',
            required=False,
            cli_name='order',
            label=_(u'Sudo order'),
            doc=_(u'integer to order the Sudo rules'),
            default=0,
        ),
        parameters.Str(
            'externaluser',
            required=False,
            label=_(u'External User'),
            doc=_(u'External User the rule applies to (sudorule-find only)'),
        ),
        parameters.Str(
            'externalhost',
            required=False,
            multivalue=True,
            label=_(u'External host'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ipasudorunasextuser',
            required=False,
            cli_name='runasexternaluser',
            label=_(u'RunAs External User'),
            doc=_(u'External User the commands can run as (sudorule-find only)'),
        ),
        parameters.Str(
            'ipasudorunasextgroup',
            required=False,
            cli_name='runasexternalgroup',
            label=_(u'RunAs External Group'),
            doc=_(u'External Group the commands can run as (sudorule-find only)'),
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
            doc=_(u'Results should contain primary key attribute only ("sudorule-name")'),
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
class sudorule_mod(Method):
    __doc__ = _("Modify Sudo Rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
            label=_(u'Rule name'),
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
            'cmdcategory',
            required=False,
            cli_name='cmdcat',
            cli_metavar="['all']",
            label=_(u'Command category'),
            doc=_(u'Command category the rule applies to'),
        ),
        parameters.Str(
            'ipasudorunasusercategory',
            required=False,
            cli_name='runasusercat',
            cli_metavar="['all']",
            label=_(u'RunAs User category'),
            doc=_(u'RunAs User category the rule applies to'),
        ),
        parameters.Str(
            'ipasudorunasgroupcategory',
            required=False,
            cli_name='runasgroupcat',
            cli_metavar="['all']",
            label=_(u'RunAs Group category'),
            doc=_(u'RunAs Group category the rule applies to'),
        ),
        parameters.Int(
            'sudoorder',
            required=False,
            cli_name='order',
            label=_(u'Sudo order'),
            doc=_(u'integer to order the Sudo rules'),
            default=0,
        ),
        parameters.Str(
            'externaluser',
            required=False,
            label=_(u'External User'),
            doc=_(u'External User the rule applies to (sudorule-find only)'),
        ),
        parameters.Str(
            'externalhost',
            required=False,
            multivalue=True,
            label=_(u'External host'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ipasudorunasextuser',
            required=False,
            cli_name='runasexternaluser',
            label=_(u'RunAs External User'),
            doc=_(u'External User the commands can run as (sudorule-find only)'),
        ),
        parameters.Str(
            'ipasudorunasextgroup',
            required=False,
            cli_name='runasexternalgroup',
            label=_(u'RunAs External Group'),
            doc=_(u'External Group the commands can run as (sudorule-find only)'),
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
class sudorule_remove_allow_command(Method):
    __doc__ = _("Remove commands and sudo command groups affected by Sudo Rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
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
            'sudocmd',
            required=False,
            multivalue=True,
            cli_name='sudocmds',
            label=_(u'member sudo command'),
            doc=_(u'sudo commands to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'sudocmdgroup',
            required=False,
            multivalue=True,
            cli_name='sudocmdgroups',
            label=_(u'member sudo command group'),
            doc=_(u'sudo command groups to remove'),
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
class sudorule_remove_deny_command(Method):
    __doc__ = _("Remove commands and sudo command groups affected by Sudo Rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
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
            'sudocmd',
            required=False,
            multivalue=True,
            cli_name='sudocmds',
            label=_(u'member sudo command'),
            doc=_(u'sudo commands to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'sudocmdgroup',
            required=False,
            multivalue=True,
            cli_name='sudocmdgroups',
            label=_(u'member sudo command group'),
            doc=_(u'sudo command groups to remove'),
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
class sudorule_remove_host(Method):
    __doc__ = _("Remove hosts and hostgroups affected by Sudo Rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
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
        parameters.Str(
            'hostmask',
            required=False,
            multivalue=True,
            label=_(u'host masks of allowed hosts'),
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
class sudorule_remove_option(Method):
    __doc__ = _("Remove an option from Sudo Rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
            label=_(u'Rule name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'ipasudoopt',
            cli_name='sudooption',
            label=_(u'Sudo Option'),
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
class sudorule_remove_runasgroup(Method):
    __doc__ = _("Remove group for Sudo to execute as.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
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
class sudorule_remove_runasuser(Method):
    __doc__ = _("Remove users and groups for Sudo to execute as.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
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
class sudorule_remove_user(Method):
    __doc__ = _("Remove users and groups affected by Sudo Rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
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
class sudorule_show(Method):
    __doc__ = _("Display Sudo Rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='sudorule_name',
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
