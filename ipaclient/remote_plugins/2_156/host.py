#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#


from . import Command, Method, Object
from ipalib import api, parameters, output
from ipalib.parameters import DefaultFrom
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

__doc__ = _("""
Hosts/Machines

A host represents a machine. It can be used in a number of contexts:
- service entries are associated with a host
- a host stores the host/ service principal
- a host can be used in Host-based Access Control (HBAC) rules
- every enrolled client generates a host entry

ENROLLMENT:

There are three enrollment scenarios when enrolling a new client:

1. You are enrolling as a full administrator. The host entry may exist
   or not. A full administrator is a member of the hostadmin role
   or the admins group.
2. You are enrolling as a limited administrator. The host must already
   exist. A limited administrator is a member a role with the
   Host Enrollment privilege.
3. The host has been created with a one-time password.

RE-ENROLLMENT:

Host that has been enrolled at some point, and lost its configuration (e.g. VM
destroyed) can be re-enrolled.

For more information, consult the manual pages for ipa-client-install.

A host can optionally store information such as where it is located,
the OS that it runs, etc.

EXAMPLES:

 Add a new host:
   ipa host-add --location="3rd floor lab" --locality=Dallas test.example.com

 Delete a host:
   ipa host-del test.example.com

 Add a new host with a one-time password:
   ipa host-add --os='Fedora 12' --password=Secret123 test.example.com

 Add a new host with a random one-time password:
   ipa host-add --os='Fedora 12' --random test.example.com

 Modify information about a host:
   ipa host-mod --os='Fedora 12' test.example.com

 Remove SSH public keys of a host and update DNS to reflect this change:
   ipa host-mod --sshpubkey= --updatedns test.example.com

 Disable the host Kerberos key, SSL certificate and all of its services:
   ipa host-disable test.example.com

 Add a host that can manage this host's keytab and certificate:
   ipa host-add-managedby --hosts=test2 test

 Allow user to create a keytab:
   ipa host-allow-create-keytab test2 --users=tuser1
""")

register = Registry()


@register()
class host(Object):
    takes_params = (
        parameters.Str(
            'fqdn',
            primary_key=True,
            label=_('Host name'),
        ),
        parameters.Str(
            'description',
            required=False,
            label=_('Description'),
            doc=_('A description of this host'),
        ),
        parameters.Str(
            'l',
            required=False,
            label=_('Locality'),
            doc=_('Host locality (e.g. "Baltimore, MD")'),
        ),
        parameters.Str(
            'nshostlocation',
            required=False,
            label=_('Location'),
            doc=_('Host location (e.g. "Lab 2")'),
        ),
        parameters.Str(
            'nshardwareplatform',
            required=False,
            label=_('Platform'),
            doc=_('Host hardware platform (e.g. "Lenovo T61")'),
        ),
        parameters.Str(
            'nsosversion',
            required=False,
            label=_('Operating system'),
            doc=_('Host operating system and version (e.g. "Fedora 9")'),
        ),
        parameters.Str(
            'userpassword',
            required=False,
            label=_('User password'),
            doc=_('Password used in bulk enrollment'),
        ),
        parameters.Flag(
            'random',
            required=False,
            doc=_('Generate a random password to be used in bulk enrollment'),
        ),
        parameters.Str(
            'randompassword',
            required=False,
            label=_('Random password'),
        ),
        parameters.Bytes(
            'usercertificate',
            required=False,
            multivalue=True,
            label=_('Certificate'),
            doc=_('Base-64 encoded server certificate'),
        ),
        parameters.Str(
            'krbprincipalname',
            required=False,
            label=_('Principal name'),
        ),
        parameters.Str(
            'macaddress',
            required=False,
            multivalue=True,
            label=_('MAC address'),
            doc=_('Hardware MAC address(es) on this host'),
        ),
        parameters.Str(
            'ipasshpubkey',
            required=False,
            multivalue=True,
            label=_('SSH public key'),
        ),
        parameters.Str(
            'userclass',
            required=False,
            multivalue=True,
            label=_('Class'),
            doc=_('Host category (semantics placed on this attribute are for local interpretation)'),
        ),
        parameters.Str(
            'ipaassignedidview',
            required=False,
            label=_('Assigned ID View'),
        ),
        parameters.Bool(
            'ipakrbrequirespreauth',
            required=False,
            label=_('Requires pre-authentication'),
            doc=_('Pre-authentication is required for the service'),
        ),
        parameters.Bool(
            'ipakrbokasdelegate',
            required=False,
            label=_('Trusted for delegation'),
            doc=_('Client credentials may be delegated to the service'),
        ),
        parameters.Flag(
            'has_password',
            label=_('Password'),
        ),
        parameters.Str(
            'memberof_hostgroup',
            required=False,
            label=_('Member of host-groups'),
        ),
        parameters.Str(
            'memberof_role',
            required=False,
            label=_('Roles'),
        ),
        parameters.Str(
            'memberof_netgroup',
            required=False,
            label=_('Member of netgroups'),
        ),
        parameters.Str(
            'memberof_sudorule',
            required=False,
            label=_('Member of Sudo rule'),
        ),
        parameters.Str(
            'memberof_hbacrule',
            required=False,
            label=_('Member of HBAC rule'),
        ),
        parameters.Str(
            'memberofindirect_netgroup',
            required=False,
            label=_('Indirect Member of netgroup'),
        ),
        parameters.Str(
            'memberofindirect_hostgroup',
            required=False,
            label=_('Indirect Member of host-group'),
        ),
        parameters.Str(
            'memberofindirect_role',
            required=False,
            label=_('Indirect Member of role'),
        ),
        parameters.Str(
            'memberofindirect_sudorule',
            required=False,
            label=_('Indirect Member of Sudo rule'),
        ),
        parameters.Str(
            'memberofindirect_hbacrule',
            required=False,
            label=_('Indirect Member of HBAC rule'),
        ),
        parameters.Flag(
            'has_keytab',
            label=_('Keytab'),
        ),
        parameters.Str(
            'managedby_host',
            label=_('Managed by'),
        ),
        parameters.Str(
            'managing_host',
            label=_('Managing'),
        ),
        parameters.Str(
            'ipaallowedtoperform_read_keys_user',
            label=_('Users allowed to retrieve keytab'),
        ),
        parameters.Str(
            'ipaallowedtoperform_read_keys_group',
            label=_('Groups allowed to retrieve keytab'),
        ),
        parameters.Str(
            'ipaallowedtoperform_read_keys_host',
            label=_('Hosts allowed to retrieve keytab'),
        ),
        parameters.Str(
            'ipaallowedtoperform_read_keys_hostgroup',
            label=_('Host Groups allowed to retrieve keytab'),
        ),
        parameters.Str(
            'ipaallowedtoperform_write_keys_user',
            label=_('Users allowed to create keytab'),
        ),
        parameters.Str(
            'ipaallowedtoperform_write_keys_group',
            label=_('Groups allowed to create keytab'),
        ),
        parameters.Str(
            'ipaallowedtoperform_write_keys_host',
            label=_('Hosts allowed to create keytab'),
        ),
        parameters.Str(
            'ipaallowedtoperform_write_keys_hostgroup',
            label=_('Host Groups allowed to create keytab'),
        ),
    )


@register()
class host_add(Method):
    __doc__ = _("Add a new host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_('Host name'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
            doc=_('A description of this host'),
        ),
        parameters.Str(
            'l',
            required=False,
            cli_name='locality',
            label=_('Locality'),
            doc=_('Host locality (e.g. "Baltimore, MD")'),
        ),
        parameters.Str(
            'nshostlocation',
            required=False,
            cli_name='location',
            label=_('Location'),
            doc=_('Host location (e.g. "Lab 2")'),
        ),
        parameters.Str(
            'nshardwareplatform',
            required=False,
            cli_name='platform',
            label=_('Platform'),
            doc=_('Host hardware platform (e.g. "Lenovo T61")'),
        ),
        parameters.Str(
            'nsosversion',
            required=False,
            cli_name='os',
            label=_('Operating system'),
            doc=_('Host operating system and version (e.g. "Fedora 9")'),
        ),
        parameters.Str(
            'userpassword',
            required=False,
            cli_name='password',
            label=_('User password'),
            doc=_('Password used in bulk enrollment'),
        ),
        parameters.Flag(
            'random',
            required=False,
            doc=_('Generate a random password to be used in bulk enrollment'),
            default=False,
            autofill=True,
        ),
        parameters.Bytes(
            'usercertificate',
            required=False,
            multivalue=True,
            cli_name='certificate',
            label=_('Certificate'),
            doc=_('Base-64 encoded server certificate'),
        ),
        parameters.Str(
            'macaddress',
            required=False,
            multivalue=True,
            label=_('MAC address'),
            doc=_('Hardware MAC address(es) on this host'),
            no_convert=True,
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
            'userclass',
            required=False,
            multivalue=True,
            cli_name='class',
            label=_('Class'),
            doc=_('Host category (semantics placed on this attribute are for local interpretation)'),
        ),
        parameters.Str(
            'ipaassignedidview',
            required=False,
            label=_('Assigned ID View'),
            exclude=('cli', 'webui'),
        ),
        parameters.Bool(
            'ipakrbrequirespreauth',
            required=False,
            cli_name='requires_pre_auth',
            label=_('Requires pre-authentication'),
            doc=_('Pre-authentication is required for the service'),
        ),
        parameters.Bool(
            'ipakrbokasdelegate',
            required=False,
            cli_name='ok_as_delegate',
            label=_('Trusted for delegation'),
            doc=_('Client credentials may be delegated to the service'),
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
            'force',
            label=_('Force'),
            doc=_('force host name even if not in DNS'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_reverse',
            doc=_('skip reverse DNS detection'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'ip_address',
            required=False,
            label=_('IP Address'),
            doc=_('Add the host to DNS with this IP address'),
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
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
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
class host_add_cert(Method):
    __doc__ = _("Add certificates to host entry")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_('Host name'),
            no_convert=True,
        ),
    )
    takes_options = (
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
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Bytes(
            'usercertificate',
            required=False,
            multivalue=True,
            cli_name='certificate',
            label=_('Certificate'),
            doc=_('Base-64 encoded server certificate'),
            alwaysask=True,
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
class host_add_managedby(Method):
    __doc__ = _("Add hosts that can manage this host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_('Host name'),
            no_convert=True,
        ),
    )
    takes_options = (
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
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_('member host'),
            doc=_('hosts to add'),
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
            doc=_('Members that could not be added'),
        ),
        output.Output(
            'completed',
            int,
            doc=_('Number of members added'),
        ),
    )


@register()
class host_allow_create_keytab(Method):
    __doc__ = _("Allow users, groups, hosts or host groups to create a keytab of this host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_('Host name'),
            no_convert=True,
        ),
    )
    takes_options = (
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
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'user',
            required=False,
            multivalue=True,
            cli_name='users',
            label=_('member user'),
            doc=_('users to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'group',
            required=False,
            multivalue=True,
            cli_name='groups',
            label=_('member group'),
            doc=_('groups to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_('member host'),
            doc=_('hosts to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_('member host group'),
            doc=_('host groups to add'),
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
            doc=_('Members that could not be added'),
        ),
        output.Output(
            'completed',
            int,
            doc=_('Number of members added'),
        ),
    )


@register()
class host_allow_retrieve_keytab(Method):
    __doc__ = _("Allow users, groups, hosts or host groups to retrieve a keytab of this host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_('Host name'),
            no_convert=True,
        ),
    )
    takes_options = (
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
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'user',
            required=False,
            multivalue=True,
            cli_name='users',
            label=_('member user'),
            doc=_('users to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'group',
            required=False,
            multivalue=True,
            cli_name='groups',
            label=_('member group'),
            doc=_('groups to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_('member host'),
            doc=_('hosts to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_('member host group'),
            doc=_('host groups to add'),
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
            doc=_('Members that could not be added'),
        ),
        output.Output(
            'completed',
            int,
            doc=_('Number of members added'),
        ),
    )


@register()
class host_del(Method):
    __doc__ = _("Delete a host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            multivalue=True,
            cli_name='hostname',
            label=_('Host name'),
            no_convert=True,
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
            'updatedns',
            required=False,
            doc=_('Remove entries from DNS'),
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
class host_disable(Method):
    __doc__ = _("Disable the Kerberos key, SSL certificate and all services of a host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_('Host name'),
            no_convert=True,
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_('True means the operation was successful'),
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class host_disallow_create_keytab(Method):
    __doc__ = _("Disallow users, groups, hosts or host groups to create a keytab of this host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_('Host name'),
            no_convert=True,
        ),
    )
    takes_options = (
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
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'user',
            required=False,
            multivalue=True,
            cli_name='users',
            label=_('member user'),
            doc=_('users to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'group',
            required=False,
            multivalue=True,
            cli_name='groups',
            label=_('member group'),
            doc=_('groups to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_('member host'),
            doc=_('hosts to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_('member host group'),
            doc=_('host groups to remove'),
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
            doc=_('Members that could not be removed'),
        ),
        output.Output(
            'completed',
            int,
            doc=_('Number of members removed'),
        ),
    )


@register()
class host_disallow_retrieve_keytab(Method):
    __doc__ = _("Disallow users, groups, hosts or host groups to retrieve a keytab of this host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_('Host name'),
            no_convert=True,
        ),
    )
    takes_options = (
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
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'user',
            required=False,
            multivalue=True,
            cli_name='users',
            label=_('member user'),
            doc=_('users to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'group',
            required=False,
            multivalue=True,
            cli_name='groups',
            label=_('member group'),
            doc=_('groups to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_('member host'),
            doc=_('hosts to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_('member host group'),
            doc=_('host groups to remove'),
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
            doc=_('Members that could not be removed'),
        ),
        output.Output(
            'completed',
            int,
            doc=_('Number of members removed'),
        ),
    )


@register()
class host_find(Method):
    __doc__ = _("Search for hosts.")

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_('A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'fqdn',
            required=False,
            cli_name='hostname',
            label=_('Host name'),
            no_convert=True,
        ),
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
            doc=_('A description of this host'),
        ),
        parameters.Str(
            'l',
            required=False,
            cli_name='locality',
            label=_('Locality'),
            doc=_('Host locality (e.g. "Baltimore, MD")'),
        ),
        parameters.Str(
            'nshostlocation',
            required=False,
            cli_name='location',
            label=_('Location'),
            doc=_('Host location (e.g. "Lab 2")'),
        ),
        parameters.Str(
            'nshardwareplatform',
            required=False,
            cli_name='platform',
            label=_('Platform'),
            doc=_('Host hardware platform (e.g. "Lenovo T61")'),
        ),
        parameters.Str(
            'nsosversion',
            required=False,
            cli_name='os',
            label=_('Operating system'),
            doc=_('Host operating system and version (e.g. "Fedora 9")'),
        ),
        parameters.Str(
            'userpassword',
            required=False,
            cli_name='password',
            label=_('User password'),
            doc=_('Password used in bulk enrollment'),
        ),
        parameters.Bytes(
            'usercertificate',
            required=False,
            multivalue=True,
            cli_name='certificate',
            label=_('Certificate'),
            doc=_('Base-64 encoded server certificate'),
        ),
        parameters.Str(
            'macaddress',
            required=False,
            multivalue=True,
            label=_('MAC address'),
            doc=_('Hardware MAC address(es) on this host'),
            no_convert=True,
        ),
        parameters.Str(
            'userclass',
            required=False,
            multivalue=True,
            cli_name='class',
            label=_('Class'),
            doc=_('Host category (semantics placed on this attribute are for local interpretation)'),
        ),
        parameters.Str(
            'ipaassignedidview',
            required=False,
            label=_('Assigned ID View'),
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
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_('Primary key only'),
            doc=_('Results should contain primary key attribute only ("hostname")'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'in_hostgroup',
            required=False,
            multivalue=True,
            cli_name='in_hostgroups',
            label=_('host group'),
            doc=_('Search for hosts with these member of host groups.'),
        ),
        parameters.Str(
            'not_in_hostgroup',
            required=False,
            multivalue=True,
            cli_name='not_in_hostgroups',
            label=_('host group'),
            doc=_('Search for hosts without these member of host groups.'),
        ),
        parameters.Str(
            'in_netgroup',
            required=False,
            multivalue=True,
            cli_name='in_netgroups',
            label=_('netgroup'),
            doc=_('Search for hosts with these member of netgroups.'),
        ),
        parameters.Str(
            'not_in_netgroup',
            required=False,
            multivalue=True,
            cli_name='not_in_netgroups',
            label=_('netgroup'),
            doc=_('Search for hosts without these member of netgroups.'),
        ),
        parameters.Str(
            'in_role',
            required=False,
            multivalue=True,
            cli_name='in_roles',
            label=_('role'),
            doc=_('Search for hosts with these member of roles.'),
        ),
        parameters.Str(
            'not_in_role',
            required=False,
            multivalue=True,
            cli_name='not_in_roles',
            label=_('role'),
            doc=_('Search for hosts without these member of roles.'),
        ),
        parameters.Str(
            'in_hbacrule',
            required=False,
            multivalue=True,
            cli_name='in_hbacrules',
            label=_('HBAC rule'),
            doc=_('Search for hosts with these member of HBAC rules.'),
        ),
        parameters.Str(
            'not_in_hbacrule',
            required=False,
            multivalue=True,
            cli_name='not_in_hbacrules',
            label=_('HBAC rule'),
            doc=_('Search for hosts without these member of HBAC rules.'),
        ),
        parameters.Str(
            'in_sudorule',
            required=False,
            multivalue=True,
            cli_name='in_sudorules',
            label=_('sudo rule'),
            doc=_('Search for hosts with these member of sudo rules.'),
        ),
        parameters.Str(
            'not_in_sudorule',
            required=False,
            multivalue=True,
            cli_name='not_in_sudorules',
            label=_('sudo rule'),
            doc=_('Search for hosts without these member of sudo rules.'),
        ),
        parameters.Str(
            'enroll_by_user',
            required=False,
            multivalue=True,
            cli_name='enroll_by_users',
            label=_('user'),
            doc=_('Search for hosts with these enrolled by users.'),
        ),
        parameters.Str(
            'not_enroll_by_user',
            required=False,
            multivalue=True,
            cli_name='not_enroll_by_users',
            label=_('user'),
            doc=_('Search for hosts without these enrolled by users.'),
        ),
        parameters.Str(
            'man_by_host',
            required=False,
            multivalue=True,
            cli_name='man_by_hosts',
            label=_('host'),
            doc=_('Search for hosts with these managed by hosts.'),
        ),
        parameters.Str(
            'not_man_by_host',
            required=False,
            multivalue=True,
            cli_name='not_man_by_hosts',
            label=_('host'),
            doc=_('Search for hosts without these managed by hosts.'),
        ),
        parameters.Str(
            'man_host',
            required=False,
            multivalue=True,
            cli_name='man_hosts',
            label=_('host'),
            doc=_('Search for hosts with these managing hosts.'),
        ),
        parameters.Str(
            'not_man_host',
            required=False,
            multivalue=True,
            cli_name='not_man_hosts',
            label=_('host'),
            doc=_('Search for hosts without these managing hosts.'),
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
class host_mod(Method):
    __doc__ = _("Modify information about a host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_('Host name'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
            doc=_('A description of this host'),
        ),
        parameters.Str(
            'l',
            required=False,
            cli_name='locality',
            label=_('Locality'),
            doc=_('Host locality (e.g. "Baltimore, MD")'),
        ),
        parameters.Str(
            'nshostlocation',
            required=False,
            cli_name='location',
            label=_('Location'),
            doc=_('Host location (e.g. "Lab 2")'),
        ),
        parameters.Str(
            'nshardwareplatform',
            required=False,
            cli_name='platform',
            label=_('Platform'),
            doc=_('Host hardware platform (e.g. "Lenovo T61")'),
        ),
        parameters.Str(
            'nsosversion',
            required=False,
            cli_name='os',
            label=_('Operating system'),
            doc=_('Host operating system and version (e.g. "Fedora 9")'),
        ),
        parameters.Str(
            'userpassword',
            required=False,
            cli_name='password',
            label=_('User password'),
            doc=_('Password used in bulk enrollment'),
        ),
        parameters.Flag(
            'random',
            required=False,
            doc=_('Generate a random password to be used in bulk enrollment'),
            default=False,
            autofill=True,
        ),
        parameters.Bytes(
            'usercertificate',
            required=False,
            multivalue=True,
            cli_name='certificate',
            label=_('Certificate'),
            doc=_('Base-64 encoded server certificate'),
        ),
        parameters.Str(
            'macaddress',
            required=False,
            multivalue=True,
            label=_('MAC address'),
            doc=_('Hardware MAC address(es) on this host'),
            no_convert=True,
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
            'userclass',
            required=False,
            multivalue=True,
            cli_name='class',
            label=_('Class'),
            doc=_('Host category (semantics placed on this attribute are for local interpretation)'),
        ),
        parameters.Str(
            'ipaassignedidview',
            required=False,
            label=_('Assigned ID View'),
            exclude=('cli', 'webui'),
        ),
        parameters.Bool(
            'ipakrbrequirespreauth',
            required=False,
            cli_name='requires_pre_auth',
            label=_('Requires pre-authentication'),
            doc=_('Pre-authentication is required for the service'),
        ),
        parameters.Bool(
            'ipakrbokasdelegate',
            required=False,
            cli_name='ok_as_delegate',
            label=_('Trusted for delegation'),
            doc=_('Client credentials may be delegated to the service'),
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
        parameters.Str(
            'krbprincipalname',
            required=False,
            cli_name='principalname',
            label=_('Principal name'),
            doc=_('Kerberos principal name for this host'),
        ),
        parameters.Flag(
            'updatedns',
            required=False,
            doc=_('Update DNS entries'),
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
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
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
class host_remove_cert(Method):
    __doc__ = _("Remove certificates from host entry")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_('Host name'),
            no_convert=True,
        ),
    )
    takes_options = (
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
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Bytes(
            'usercertificate',
            required=False,
            multivalue=True,
            cli_name='certificate',
            label=_('Certificate'),
            doc=_('Base-64 encoded server certificate'),
            alwaysask=True,
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
class host_remove_managedby(Method):
    __doc__ = _("Remove hosts that can manage this host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_('Host name'),
            no_convert=True,
        ),
    )
    takes_options = (
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
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_('member host'),
            doc=_('hosts to remove'),
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
            doc=_('Members that could not be removed'),
        ),
        output.Output(
            'completed',
            int,
            doc=_('Number of members removed'),
        ),
    )


@register()
class host_show(Method):
    __doc__ = _("Display information about a host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_('Host name'),
            no_convert=True,
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
        parameters.Str(
            'out',
            required=False,
            doc=_('file to store certificate in'),
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
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
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
