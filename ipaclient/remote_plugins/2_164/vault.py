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
Vaults

Manage vaults.

Vault is a secure place to store a secret.

Based on the ownership there are three vault categories:
* user/private vault
* service vault
* shared vault

User vaults are vaults owned used by a particular user. Private
vaults are vaults owned the current user. Service vaults are
vaults owned by a service. Shared vaults are owned by the admin
but they can be used by other users or services.

Based on the security mechanism there are three types of
vaults:
* standard vault
* symmetric vault
* asymmetric vault

Standard vault uses a secure mechanism to transport and
store the secret. The secret can only be retrieved by users
that have access to the vault.

Symmetric vault is similar to the standard vault, but it
pre-encrypts the secret using a password before transport.
The secret can only be retrieved using the same password.

Asymmetric vault is similar to the standard vault, but it
pre-encrypts the secret using a public key before transport.
The secret can only be retrieved using the private key.

EXAMPLES:

 List vaults:
   ipa vault-find
       [--user <user>|--service <service>|--shared]

 Add a standard vault:
   ipa vault-add <name>
       [--user <user>|--service <service>|--shared]
       --type standard

 Add a symmetric vault:
   ipa vault-add <name>
       [--user <user>|--service <service>|--shared]
       --type symmetric --password-file password.txt

 Add an asymmetric vault:
   ipa vault-add <name>
       [--user <user>|--service <service>|--shared]
       --type asymmetric --public-key-file public.pem

 Show a vault:
   ipa vault-show <name>
       [--user <user>|--service <service>|--shared]

 Modify vault description:
   ipa vault-mod <name>
       [--user <user>|--service <service>|--shared]
       --desc <description>

 Modify vault type:
   ipa vault-mod <name>
       [--user <user>|--service <service>|--shared]
       --type <type>
       [old password/private key]
       [new password/public key]

 Modify symmetric vault password:
   ipa vault-mod <name>
       [--user <user>|--service <service>|--shared]
       --change-password
   ipa vault-mod <name>
       [--user <user>|--service <service>|--shared]
       --old-password <old password>
       --new-password <new password>
   ipa vault-mod <name>
       [--user <user>|--service <service>|--shared]
       --old-password-file <old password file>
       --new-password-file <new password file>

 Modify asymmetric vault keys:
   ipa vault-mod <name>
       [--user <user>|--service <service>|--shared]
       --private-key-file <old private key file>
       --public-key-file <new public key file>

 Delete a vault:
   ipa vault-del <name>
       [--user <user>|--service <service>|--shared]

 Display vault configuration:
   ipa vaultconfig-show

 Archive data into standard vault:
   ipa vault-archive <name>
       [--user <user>|--service <service>|--shared]
       --in <input file>

 Archive data into symmetric vault:
   ipa vault-archive <name>
       [--user <user>|--service <service>|--shared]
       --in <input file>
       --password-file password.txt

 Archive data into asymmetric vault:
   ipa vault-archive <name>
       [--user <user>|--service <service>|--shared]
       --in <input file>

 Retrieve data from standard vault:
   ipa vault-retrieve <name>
       [--user <user>|--service <service>|--shared]
       --out <output file>

 Retrieve data from symmetric vault:
   ipa vault-retrieve <name>
       [--user <user>|--service <service>|--shared]
       --out <output file>
       --password-file password.txt

 Retrieve data from asymmetric vault:
   ipa vault-retrieve <name>
       [--user <user>|--service <service>|--shared]
       --out <output file> --private-key-file private.pem

 Add vault owners:
   ipa vault-add-owner <name>
       [--user <user>|--service <service>|--shared]
       [--users <users>]  [--groups <groups>] [--services <services>]

 Delete vault owners:
   ipa vault-remove-owner <name>
       [--user <user>|--service <service>|--shared]
       [--users <users>] [--groups <groups>] [--services <services>]

 Add vault members:
   ipa vault-add-member <name>
       [--user <user>|--service <service>|--shared]
       [--users <users>] [--groups <groups>] [--services <services>]

 Delete vault members:
   ipa vault-remove-member <name>
       [--user <user>|--service <service>|--shared]
       [--users <users>] [--groups <groups>] [--services <services>]
""")

register = Registry()


@register()
class vault(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_(u'Vault name'),
        ),
        parameters.Str(
            'description',
            required=False,
            label=_(u'Description'),
            doc=_(u'Vault description'),
        ),
        parameters.Str(
            'ipavaulttype',
            required=False,
            label=_(u'Type'),
            doc=_(u'Vault type'),
        ),
        parameters.Bytes(
            'ipavaultsalt',
            required=False,
            label=_(u'Salt'),
            doc=_(u'Vault salt'),
        ),
        parameters.Bytes(
            'ipavaultpublickey',
            required=False,
            label=_(u'Public key'),
            doc=_(u'Vault public key'),
        ),
        parameters.Str(
            'owner_user',
            required=False,
            label=_(u'Owner users'),
        ),
        parameters.Str(
            'owner_group',
            required=False,
            label=_(u'Owner groups'),
        ),
        parameters.Str(
            'owner_service',
            required=False,
            label=_(u'Owner services'),
        ),
        parameters.Str(
            'owner',
            required=False,
            label=_(u'Failed owners'),
        ),
        parameters.Str(
            'service',
            required=False,
            label=_(u'Vault service'),
        ),
        parameters.Flag(
            'shared',
            required=False,
            label=_(u'Shared vault'),
        ),
        parameters.Str(
            'username',
            required=False,
            label=_(u'Vault user'),
        ),
        parameters.Str(
            'member_user',
            required=False,
            label=_(u'Member users'),
        ),
        parameters.Str(
            'member_group',
            required=False,
            label=_(u'Member groups'),
        ),
        parameters.Str(
            'member_service',
            required=False,
            label=_(u'Member services'),
        ),
    )


@register()
class vaultconfig(Object):
    takes_params = (
        parameters.Bytes(
            'transport_cert',
            label=_(u'Transport Certificate'),
        ),
    )


@register()
class vaultcontainer(Object):
    takes_params = (
        parameters.Str(
            'owner_user',
            required=False,
            label=_(u'Owner users'),
        ),
        parameters.Str(
            'owner_group',
            required=False,
            label=_(u'Owner groups'),
        ),
        parameters.Str(
            'owner_service',
            required=False,
            label=_(u'Owner services'),
        ),
        parameters.Str(
            'owner',
            required=False,
            label=_(u'Failed owners'),
        ),
        parameters.Str(
            'service',
            required=False,
            label=_(u'Vault service'),
        ),
        parameters.Flag(
            'shared',
            required=False,
            label=_(u'Shared vault'),
        ),
        parameters.Str(
            'username',
            required=False,
            label=_(u'Vault user'),
        ),
    )


@register()
class kra_is_enabled(Command):
    NO_CLI = True

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
class vault_add_internal(Method):
    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Vault name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'Vault description'),
        ),
        parameters.Str(
            'ipavaulttype',
            required=False,
            cli_name='type',
            cli_metavar="['standard', 'symmetric', 'asymmetric']",
            label=_(u'Type'),
            doc=_(u'Vault type'),
            default=u'symmetric',
            autofill=True,
        ),
        parameters.Bytes(
            'ipavaultsalt',
            required=False,
            cli_name='salt',
            label=_(u'Salt'),
            doc=_(u'Vault salt'),
        ),
        parameters.Bytes(
            'ipavaultpublickey',
            required=False,
            cli_name='public_key',
            label=_(u'Public key'),
            doc=_(u'Vault public key'),
        ),
        parameters.Str(
            'service',
            required=False,
            doc=_(u'Service name of the service vault'),
            no_convert=True,
        ),
        parameters.Flag(
            'shared',
            required=False,
            doc=_(u'Shared vault'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'username',
            required=False,
            cli_name='user',
            doc=_(u'Username of the user vault'),
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
class vault_add_member(Method):
    __doc__ = _("Add members to a vault.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Vault name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'service',
            required=False,
            doc=_(u'Service name of the service vault'),
            no_convert=True,
        ),
        parameters.Flag(
            'shared',
            required=False,
            doc=_(u'Shared vault'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'username',
            required=False,
            cli_name='user',
            doc=_(u'Username of the user vault'),
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
        parameters.Str(
            'services',
            required=False,
            multivalue=True,
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
class vault_add_owner(Method):
    __doc__ = _("Add owners to a vault.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Vault name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'service',
            required=False,
            doc=_(u'Service name of the service vault'),
            no_convert=True,
        ),
        parameters.Flag(
            'shared',
            required=False,
            doc=_(u'Shared vault'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'username',
            required=False,
            cli_name='user',
            doc=_(u'Username of the user vault'),
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
        parameters.Str(
            'user',
            required=False,
            multivalue=True,
            cli_name='users',
            label=_(u'owner user'),
            doc=_(u'users to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'group',
            required=False,
            multivalue=True,
            cli_name='groups',
            label=_(u'owner group'),
            doc=_(u'groups to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'services',
            required=False,
            multivalue=True,
            label=_(u'owner service'),
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
            doc=_(u'Owners that could not be added'),
        ),
        output.Output(
            'completed',
            int,
            doc=_(u'Number of owners added'),
        ),
    )


@register()
class vault_archive_internal(Method):
    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Vault name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'service',
            required=False,
            doc=_(u'Service name of the service vault'),
            no_convert=True,
        ),
        parameters.Flag(
            'shared',
            required=False,
            doc=_(u'Shared vault'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'username',
            required=False,
            cli_name='user',
            doc=_(u'Username of the user vault'),
        ),
        parameters.Bytes(
            'session_key',
            doc=_(u'Session key wrapped with transport certificate'),
        ),
        parameters.Bytes(
            'vault_data',
            doc=_(u'Vault data encrypted with session key'),
        ),
        parameters.Bytes(
            'nonce',
            doc=_(u'Nonce'),
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
class vault_del(Method):
    __doc__ = _("Delete a vault.")

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='name',
            label=_(u'Vault name'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_(u"Continuous mode: Don't stop on errors."),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'service',
            required=False,
            doc=_(u'Service name of the service vault'),
            no_convert=True,
        ),
        parameters.Flag(
            'shared',
            required=False,
            doc=_(u'Shared vault'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'username',
            required=False,
            cli_name='user',
            doc=_(u'Username of the user vault'),
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
class vault_find(Method):
    __doc__ = _("Search for vaults.")

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
            label=_(u'Vault name'),
        ),
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'Vault description'),
        ),
        parameters.Str(
            'ipavaulttype',
            required=False,
            cli_name='type',
            cli_metavar="['standard', 'symmetric', 'asymmetric']",
            label=_(u'Type'),
            doc=_(u'Vault type'),
            default=u'symmetric',
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
        parameters.Str(
            'service',
            required=False,
            doc=_(u'Service name of the service vault'),
            no_convert=True,
        ),
        parameters.Flag(
            'shared',
            required=False,
            doc=_(u'Shared vault'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'username',
            required=False,
            cli_name='user',
            doc=_(u'Username of the user vault'),
        ),
        parameters.Flag(
            'services',
            required=False,
            doc=_(u'List all service vaults'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'users',
            required=False,
            doc=_(u'List all user vaults'),
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
class vault_mod_internal(Method):
    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Vault name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'Vault description'),
        ),
        parameters.Str(
            'ipavaulttype',
            required=False,
            cli_name='type',
            cli_metavar="['standard', 'symmetric', 'asymmetric']",
            label=_(u'Type'),
            doc=_(u'Vault type'),
            default=u'symmetric',
        ),
        parameters.Bytes(
            'ipavaultsalt',
            required=False,
            cli_name='salt',
            label=_(u'Salt'),
            doc=_(u'Vault salt'),
        ),
        parameters.Bytes(
            'ipavaultpublickey',
            required=False,
            cli_name='public_key',
            label=_(u'Public key'),
            doc=_(u'Vault public key'),
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
        parameters.Str(
            'service',
            required=False,
            doc=_(u'Service name of the service vault'),
            no_convert=True,
        ),
        parameters.Flag(
            'shared',
            required=False,
            doc=_(u'Shared vault'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'username',
            required=False,
            cli_name='user',
            doc=_(u'Username of the user vault'),
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
class vault_remove_member(Method):
    __doc__ = _("Remove members from a vault.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Vault name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'service',
            required=False,
            doc=_(u'Service name of the service vault'),
            no_convert=True,
        ),
        parameters.Flag(
            'shared',
            required=False,
            doc=_(u'Shared vault'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'username',
            required=False,
            cli_name='user',
            doc=_(u'Username of the user vault'),
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
        parameters.Str(
            'services',
            required=False,
            multivalue=True,
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
class vault_remove_owner(Method):
    __doc__ = _("Remove owners from a vault.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Vault name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'service',
            required=False,
            doc=_(u'Service name of the service vault'),
            no_convert=True,
        ),
        parameters.Flag(
            'shared',
            required=False,
            doc=_(u'Shared vault'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'username',
            required=False,
            cli_name='user',
            doc=_(u'Username of the user vault'),
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
        parameters.Str(
            'user',
            required=False,
            multivalue=True,
            cli_name='users',
            label=_(u'owner user'),
            doc=_(u'users to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'group',
            required=False,
            multivalue=True,
            cli_name='groups',
            label=_(u'owner group'),
            doc=_(u'groups to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'services',
            required=False,
            multivalue=True,
            label=_(u'owner service'),
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
            doc=_(u'Owners that could not be removed'),
        ),
        output.Output(
            'completed',
            int,
            doc=_(u'Number of owners removed'),
        ),
    )


@register()
class vault_retrieve_internal(Method):
    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Vault name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'service',
            required=False,
            doc=_(u'Service name of the service vault'),
            no_convert=True,
        ),
        parameters.Flag(
            'shared',
            required=False,
            doc=_(u'Shared vault'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'username',
            required=False,
            cli_name='user',
            doc=_(u'Username of the user vault'),
        ),
        parameters.Bytes(
            'session_key',
            doc=_(u'Session key wrapped with transport certificate'),
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
class vault_show(Method):
    __doc__ = _("Display information about a vault.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Vault name'),
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
        parameters.Str(
            'service',
            required=False,
            doc=_(u'Service name of the service vault'),
            no_convert=True,
        ),
        parameters.Flag(
            'shared',
            required=False,
            doc=_(u'Shared vault'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'username',
            required=False,
            cli_name='user',
            doc=_(u'Username of the user vault'),
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
class vaultconfig_show(Method):
    __doc__ = _("Show vault configuration.")

    takes_options = (
        parameters.Str(
            'transport_out',
            required=False,
            doc=_(u'Output file to store the transport certificate'),
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
class vaultcontainer_add_owner(Method):
    __doc__ = _("Add owners to a vault container.")

    takes_options = (
        parameters.Str(
            'service',
            required=False,
            doc=_(u'Service name of the service vault'),
            no_convert=True,
        ),
        parameters.Flag(
            'shared',
            required=False,
            doc=_(u'Shared vault'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'username',
            required=False,
            cli_name='user',
            doc=_(u'Username of the user vault'),
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
        parameters.Str(
            'user',
            required=False,
            multivalue=True,
            cli_name='users',
            label=_(u'owner user'),
            doc=_(u'users to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'group',
            required=False,
            multivalue=True,
            cli_name='groups',
            label=_(u'owner group'),
            doc=_(u'groups to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'services',
            required=False,
            multivalue=True,
            label=_(u'owner service'),
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
            doc=_(u'Owners that could not be added'),
        ),
        output.Output(
            'completed',
            int,
            doc=_(u'Number of owners added'),
        ),
    )


@register()
class vaultcontainer_del(Method):
    __doc__ = _("Delete a vault container.")

    takes_options = (
        parameters.Flag(
            'continue',
            doc=_(u"Continuous mode: Don't stop on errors."),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'service',
            required=False,
            doc=_(u'Service name of the service vault'),
            no_convert=True,
        ),
        parameters.Flag(
            'shared',
            required=False,
            doc=_(u'Shared vault'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'username',
            required=False,
            cli_name='user',
            doc=_(u'Username of the user vault'),
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
class vaultcontainer_remove_owner(Method):
    __doc__ = _("Remove owners from a vault container.")

    takes_options = (
        parameters.Str(
            'service',
            required=False,
            doc=_(u'Service name of the service vault'),
            no_convert=True,
        ),
        parameters.Flag(
            'shared',
            required=False,
            doc=_(u'Shared vault'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'username',
            required=False,
            cli_name='user',
            doc=_(u'Username of the user vault'),
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
        parameters.Str(
            'user',
            required=False,
            multivalue=True,
            cli_name='users',
            label=_(u'owner user'),
            doc=_(u'users to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'group',
            required=False,
            multivalue=True,
            cli_name='groups',
            label=_(u'owner group'),
            doc=_(u'groups to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'services',
            required=False,
            multivalue=True,
            label=_(u'owner service'),
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
            doc=_(u'Owners that could not be removed'),
        ),
        output.Output(
            'completed',
            int,
            doc=_(u'Number of owners removed'),
        ),
    )


@register()
class vaultcontainer_show(Method):
    __doc__ = _("Display information about a vault container.")

    takes_options = (
        parameters.Flag(
            'rights',
            label=_(u'Rights'),
            doc=_(u'Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'service',
            required=False,
            doc=_(u'Service name of the service vault'),
            no_convert=True,
        ),
        parameters.Flag(
            'shared',
            required=False,
            doc=_(u'Shared vault'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'username',
            required=False,
            cli_name='user',
            doc=_(u'Username of the user vault'),
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
