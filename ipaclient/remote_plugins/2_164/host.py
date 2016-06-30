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
            label=_(u'Host name'),
        ),
        parameters.Str(
            'description',
            required=False,
            label=_(u'Description'),
            doc=_(u'A description of this host'),
        ),
        parameters.Str(
            'l',
            required=False,
            label=_(u'Locality'),
            doc=_(u'Host locality (e.g. "Baltimore, MD")'),
        ),
        parameters.Str(
            'nshostlocation',
            required=False,
            label=_(u'Location'),
            doc=_(u'Host location (e.g. "Lab 2")'),
        ),
        parameters.Str(
            'nshardwareplatform',
            required=False,
            label=_(u'Platform'),
            doc=_(u'Host hardware platform (e.g. "Lenovo T61")'),
        ),
        parameters.Str(
            'nsosversion',
            required=False,
            label=_(u'Operating system'),
            doc=_(u'Host operating system and version (e.g. "Fedora 9")'),
        ),
        parameters.Str(
            'userpassword',
            required=False,
            label=_(u'User password'),
            doc=_(u'Password used in bulk enrollment'),
        ),
        parameters.Flag(
            'random',
            required=False,
            doc=_(u'Generate a random password to be used in bulk enrollment'),
        ),
        parameters.Str(
            'randompassword',
            required=False,
            label=_(u'Random password'),
        ),
        parameters.Bytes(
            'usercertificate',
            required=False,
            multivalue=True,
            label=_(u'Certificate'),
            doc=_(u'Base-64 encoded server certificate'),
        ),
        parameters.Str(
            'krbprincipalname',
            required=False,
            label=_(u'Principal name'),
        ),
        parameters.Str(
            'macaddress',
            required=False,
            multivalue=True,
            label=_(u'MAC address'),
            doc=_(u'Hardware MAC address(es) on this host'),
        ),
        parameters.Str(
            'ipasshpubkey',
            required=False,
            multivalue=True,
            label=_(u'SSH public key'),
        ),
        parameters.Str(
            'userclass',
            required=False,
            multivalue=True,
            label=_(u'Class'),
            doc=_(u'Host category (semantics placed on this attribute are for local interpretation)'),
        ),
        parameters.Str(
            'ipaassignedidview',
            required=False,
            label=_(u'Assigned ID View'),
        ),
        parameters.Bool(
            'ipakrbrequirespreauth',
            required=False,
            label=_(u'Requires pre-authentication'),
            doc=_(u'Pre-authentication is required for the service'),
        ),
        parameters.Bool(
            'ipakrbokasdelegate',
            required=False,
            label=_(u'Trusted for delegation'),
            doc=_(u'Client credentials may be delegated to the service'),
        ),
        parameters.Flag(
            'has_password',
            label=_(u'Password'),
        ),
        parameters.Str(
            'memberof_hostgroup',
            required=False,
            label=_(u'Member of host-groups'),
        ),
        parameters.Str(
            'memberof_role',
            required=False,
            label=_(u'Roles'),
        ),
        parameters.Str(
            'memberof_netgroup',
            required=False,
            label=_(u'Member of netgroups'),
        ),
        parameters.Str(
            'memberof_sudorule',
            required=False,
            label=_(u'Member of Sudo rule'),
        ),
        parameters.Str(
            'memberof_hbacrule',
            required=False,
            label=_(u'Member of HBAC rule'),
        ),
        parameters.Str(
            'memberofindirect_netgroup',
            required=False,
            label=_(u'Indirect Member of netgroup'),
        ),
        parameters.Str(
            'memberofindirect_hostgroup',
            required=False,
            label=_(u'Indirect Member of host-group'),
        ),
        parameters.Str(
            'memberofindirect_role',
            required=False,
            label=_(u'Indirect Member of role'),
        ),
        parameters.Str(
            'memberofindirect_sudorule',
            required=False,
            label=_(u'Indirect Member of Sudo rule'),
        ),
        parameters.Str(
            'memberofindirect_hbacrule',
            required=False,
            label=_(u'Indirect Member of HBAC rule'),
        ),
        parameters.Flag(
            'has_keytab',
            label=_(u'Keytab'),
        ),
        parameters.Str(
            'managedby_host',
            label=_(u'Managed by'),
        ),
        parameters.Str(
            'managing_host',
            label=_(u'Managing'),
        ),
        parameters.Str(
            'ipaallowedtoperform_read_keys_user',
            label=_(u'Users allowed to retrieve keytab'),
        ),
        parameters.Str(
            'ipaallowedtoperform_read_keys_group',
            label=_(u'Groups allowed to retrieve keytab'),
        ),
        parameters.Str(
            'ipaallowedtoperform_read_keys_host',
            label=_(u'Hosts allowed to retrieve keytab'),
        ),
        parameters.Str(
            'ipaallowedtoperform_read_keys_hostgroup',
            label=_(u'Host Groups allowed to retrieve keytab'),
        ),
        parameters.Str(
            'ipaallowedtoperform_write_keys_user',
            label=_(u'Users allowed to create keytab'),
        ),
        parameters.Str(
            'ipaallowedtoperform_write_keys_group',
            label=_(u'Groups allowed to create keytab'),
        ),
        parameters.Str(
            'ipaallowedtoperform_write_keys_host',
            label=_(u'Hosts allowed to create keytab'),
        ),
        parameters.Str(
            'ipaallowedtoperform_write_keys_hostgroup',
            label=_(u'Host Groups allowed to create keytab'),
        ),
    )


@register()
class host_add(Method):
    __doc__ = _("Add a new host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_(u'Host name'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'A description of this host'),
        ),
        parameters.Str(
            'l',
            required=False,
            cli_name='locality',
            label=_(u'Locality'),
            doc=_(u'Host locality (e.g. "Baltimore, MD")'),
        ),
        parameters.Str(
            'nshostlocation',
            required=False,
            cli_name='location',
            label=_(u'Location'),
            doc=_(u'Host location (e.g. "Lab 2")'),
        ),
        parameters.Str(
            'nshardwareplatform',
            required=False,
            cli_name='platform',
            label=_(u'Platform'),
            doc=_(u'Host hardware platform (e.g. "Lenovo T61")'),
        ),
        parameters.Str(
            'nsosversion',
            required=False,
            cli_name='os',
            label=_(u'Operating system'),
            doc=_(u'Host operating system and version (e.g. "Fedora 9")'),
        ),
        parameters.Str(
            'userpassword',
            required=False,
            cli_name='password',
            label=_(u'User password'),
            doc=_(u'Password used in bulk enrollment'),
        ),
        parameters.Flag(
            'random',
            required=False,
            doc=_(u'Generate a random password to be used in bulk enrollment'),
            default=False,
            autofill=True,
        ),
        parameters.Bytes(
            'usercertificate',
            required=False,
            multivalue=True,
            cli_name='certificate',
            label=_(u'Certificate'),
            doc=_(u'Base-64 encoded server certificate'),
        ),
        parameters.Str(
            'macaddress',
            required=False,
            multivalue=True,
            label=_(u'MAC address'),
            doc=_(u'Hardware MAC address(es) on this host'),
            no_convert=True,
        ),
        parameters.Str(
            'ipasshpubkey',
            required=False,
            multivalue=True,
            cli_name='sshpubkey',
            label=_(u'SSH public key'),
            no_convert=True,
        ),
        parameters.Str(
            'userclass',
            required=False,
            multivalue=True,
            cli_name='class',
            label=_(u'Class'),
            doc=_(u'Host category (semantics placed on this attribute are for local interpretation)'),
        ),
        parameters.Str(
            'ipaassignedidview',
            required=False,
            label=_(u'Assigned ID View'),
            exclude=('cli', 'webui'),
        ),
        parameters.Bool(
            'ipakrbrequirespreauth',
            required=False,
            cli_name='requires_pre_auth',
            label=_(u'Requires pre-authentication'),
            doc=_(u'Pre-authentication is required for the service'),
        ),
        parameters.Bool(
            'ipakrbokasdelegate',
            required=False,
            cli_name='ok_as_delegate',
            label=_(u'Trusted for delegation'),
            doc=_(u'Client credentials may be delegated to the service'),
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
            'force',
            label=_(u'Force'),
            doc=_(u'force host name even if not in DNS'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_reverse',
            doc=_(u'skip reverse DNS detection'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'ip_address',
            required=False,
            label=_(u'IP Address'),
            doc=_(u'Add the host to DNS with this IP address'),
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
class host_add_cert(Method):
    __doc__ = _("Add certificates to host entry")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_(u'Host name'),
            no_convert=True,
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
        parameters.Bytes(
            'usercertificate',
            required=False,
            multivalue=True,
            cli_name='certificate',
            label=_(u'Certificate'),
            doc=_(u'Base-64 encoded server certificate'),
            alwaysask=True,
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
class host_add_managedby(Method):
    __doc__ = _("Add hosts that can manage this host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_(u'Host name'),
            no_convert=True,
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
class host_allow_create_keytab(Method):
    __doc__ = _("Allow users, groups, hosts or host groups to create a keytab of this host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_(u'Host name'),
            no_convert=True,
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
class host_allow_retrieve_keytab(Method):
    __doc__ = _("Allow users, groups, hosts or host groups to retrieve a keytab of this host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_(u'Host name'),
            no_convert=True,
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
class host_del(Method):
    __doc__ = _("Delete a host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            multivalue=True,
            cli_name='hostname',
            label=_(u'Host name'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_(u"Continuous mode: Don't stop on errors."),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'updatedns',
            required=False,
            doc=_(u'Remove entries from DNS'),
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
class host_disable(Method):
    __doc__ = _("Disable the Kerberos key, SSL certificate and all services of a host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_(u'Host name'),
            no_convert=True,
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
class host_disallow_create_keytab(Method):
    __doc__ = _("Disallow users, groups, hosts or host groups to create a keytab of this host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_(u'Host name'),
            no_convert=True,
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
class host_disallow_retrieve_keytab(Method):
    __doc__ = _("Disallow users, groups, hosts or host groups to retrieve a keytab of this host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_(u'Host name'),
            no_convert=True,
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
class host_find(Method):
    __doc__ = _("Search for hosts.")

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_(u'A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'fqdn',
            required=False,
            cli_name='hostname',
            label=_(u'Host name'),
            no_convert=True,
        ),
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'A description of this host'),
        ),
        parameters.Str(
            'l',
            required=False,
            cli_name='locality',
            label=_(u'Locality'),
            doc=_(u'Host locality (e.g. "Baltimore, MD")'),
        ),
        parameters.Str(
            'nshostlocation',
            required=False,
            cli_name='location',
            label=_(u'Location'),
            doc=_(u'Host location (e.g. "Lab 2")'),
        ),
        parameters.Str(
            'nshardwareplatform',
            required=False,
            cli_name='platform',
            label=_(u'Platform'),
            doc=_(u'Host hardware platform (e.g. "Lenovo T61")'),
        ),
        parameters.Str(
            'nsosversion',
            required=False,
            cli_name='os',
            label=_(u'Operating system'),
            doc=_(u'Host operating system and version (e.g. "Fedora 9")'),
        ),
        parameters.Str(
            'userpassword',
            required=False,
            cli_name='password',
            label=_(u'User password'),
            doc=_(u'Password used in bulk enrollment'),
        ),
        parameters.Bytes(
            'usercertificate',
            required=False,
            multivalue=True,
            cli_name='certificate',
            label=_(u'Certificate'),
            doc=_(u'Base-64 encoded server certificate'),
        ),
        parameters.Str(
            'macaddress',
            required=False,
            multivalue=True,
            label=_(u'MAC address'),
            doc=_(u'Hardware MAC address(es) on this host'),
            no_convert=True,
        ),
        parameters.Str(
            'userclass',
            required=False,
            multivalue=True,
            cli_name='class',
            label=_(u'Class'),
            doc=_(u'Host category (semantics placed on this attribute are for local interpretation)'),
        ),
        parameters.Str(
            'ipaassignedidview',
            required=False,
            label=_(u'Assigned ID View'),
            exclude=('cli', 'webui'),
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
            doc=_(u'Results should contain primary key attribute only ("hostname")'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'in_hostgroup',
            required=False,
            multivalue=True,
            cli_name='in_hostgroups',
            label=_(u'host group'),
            doc=_(u'Search for hosts with these member of host groups.'),
        ),
        parameters.Str(
            'not_in_hostgroup',
            required=False,
            multivalue=True,
            cli_name='not_in_hostgroups',
            label=_(u'host group'),
            doc=_(u'Search for hosts without these member of host groups.'),
        ),
        parameters.Str(
            'in_netgroup',
            required=False,
            multivalue=True,
            cli_name='in_netgroups',
            label=_(u'netgroup'),
            doc=_(u'Search for hosts with these member of netgroups.'),
        ),
        parameters.Str(
            'not_in_netgroup',
            required=False,
            multivalue=True,
            cli_name='not_in_netgroups',
            label=_(u'netgroup'),
            doc=_(u'Search for hosts without these member of netgroups.'),
        ),
        parameters.Str(
            'in_role',
            required=False,
            multivalue=True,
            cli_name='in_roles',
            label=_(u'role'),
            doc=_(u'Search for hosts with these member of roles.'),
        ),
        parameters.Str(
            'not_in_role',
            required=False,
            multivalue=True,
            cli_name='not_in_roles',
            label=_(u'role'),
            doc=_(u'Search for hosts without these member of roles.'),
        ),
        parameters.Str(
            'in_hbacrule',
            required=False,
            multivalue=True,
            cli_name='in_hbacrules',
            label=_(u'HBAC rule'),
            doc=_(u'Search for hosts with these member of HBAC rules.'),
        ),
        parameters.Str(
            'not_in_hbacrule',
            required=False,
            multivalue=True,
            cli_name='not_in_hbacrules',
            label=_(u'HBAC rule'),
            doc=_(u'Search for hosts without these member of HBAC rules.'),
        ),
        parameters.Str(
            'in_sudorule',
            required=False,
            multivalue=True,
            cli_name='in_sudorules',
            label=_(u'sudo rule'),
            doc=_(u'Search for hosts with these member of sudo rules.'),
        ),
        parameters.Str(
            'not_in_sudorule',
            required=False,
            multivalue=True,
            cli_name='not_in_sudorules',
            label=_(u'sudo rule'),
            doc=_(u'Search for hosts without these member of sudo rules.'),
        ),
        parameters.Str(
            'enroll_by_user',
            required=False,
            multivalue=True,
            cli_name='enroll_by_users',
            label=_(u'user'),
            doc=_(u'Search for hosts with these enrolled by users.'),
        ),
        parameters.Str(
            'not_enroll_by_user',
            required=False,
            multivalue=True,
            cli_name='not_enroll_by_users',
            label=_(u'user'),
            doc=_(u'Search for hosts without these enrolled by users.'),
        ),
        parameters.Str(
            'man_by_host',
            required=False,
            multivalue=True,
            cli_name='man_by_hosts',
            label=_(u'host'),
            doc=_(u'Search for hosts with these managed by hosts.'),
        ),
        parameters.Str(
            'not_man_by_host',
            required=False,
            multivalue=True,
            cli_name='not_man_by_hosts',
            label=_(u'host'),
            doc=_(u'Search for hosts without these managed by hosts.'),
        ),
        parameters.Str(
            'man_host',
            required=False,
            multivalue=True,
            cli_name='man_hosts',
            label=_(u'host'),
            doc=_(u'Search for hosts with these managing hosts.'),
        ),
        parameters.Str(
            'not_man_host',
            required=False,
            multivalue=True,
            cli_name='not_man_hosts',
            label=_(u'host'),
            doc=_(u'Search for hosts without these managing hosts.'),
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
class host_mod(Method):
    __doc__ = _("Modify information about a host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_(u'Host name'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'A description of this host'),
        ),
        parameters.Str(
            'l',
            required=False,
            cli_name='locality',
            label=_(u'Locality'),
            doc=_(u'Host locality (e.g. "Baltimore, MD")'),
        ),
        parameters.Str(
            'nshostlocation',
            required=False,
            cli_name='location',
            label=_(u'Location'),
            doc=_(u'Host location (e.g. "Lab 2")'),
        ),
        parameters.Str(
            'nshardwareplatform',
            required=False,
            cli_name='platform',
            label=_(u'Platform'),
            doc=_(u'Host hardware platform (e.g. "Lenovo T61")'),
        ),
        parameters.Str(
            'nsosversion',
            required=False,
            cli_name='os',
            label=_(u'Operating system'),
            doc=_(u'Host operating system and version (e.g. "Fedora 9")'),
        ),
        parameters.Str(
            'userpassword',
            required=False,
            cli_name='password',
            label=_(u'User password'),
            doc=_(u'Password used in bulk enrollment'),
        ),
        parameters.Flag(
            'random',
            required=False,
            doc=_(u'Generate a random password to be used in bulk enrollment'),
            default=False,
            autofill=True,
        ),
        parameters.Bytes(
            'usercertificate',
            required=False,
            multivalue=True,
            cli_name='certificate',
            label=_(u'Certificate'),
            doc=_(u'Base-64 encoded server certificate'),
        ),
        parameters.Str(
            'macaddress',
            required=False,
            multivalue=True,
            label=_(u'MAC address'),
            doc=_(u'Hardware MAC address(es) on this host'),
            no_convert=True,
        ),
        parameters.Str(
            'ipasshpubkey',
            required=False,
            multivalue=True,
            cli_name='sshpubkey',
            label=_(u'SSH public key'),
            no_convert=True,
        ),
        parameters.Str(
            'userclass',
            required=False,
            multivalue=True,
            cli_name='class',
            label=_(u'Class'),
            doc=_(u'Host category (semantics placed on this attribute are for local interpretation)'),
        ),
        parameters.Str(
            'ipaassignedidview',
            required=False,
            label=_(u'Assigned ID View'),
            exclude=('cli', 'webui'),
        ),
        parameters.Bool(
            'ipakrbrequirespreauth',
            required=False,
            cli_name='requires_pre_auth',
            label=_(u'Requires pre-authentication'),
            doc=_(u'Pre-authentication is required for the service'),
        ),
        parameters.Bool(
            'ipakrbokasdelegate',
            required=False,
            cli_name='ok_as_delegate',
            label=_(u'Trusted for delegation'),
            doc=_(u'Client credentials may be delegated to the service'),
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
            'krbprincipalname',
            required=False,
            cli_name='principalname',
            label=_(u'Principal name'),
            doc=_(u'Kerberos principal name for this host'),
        ),
        parameters.Flag(
            'updatedns',
            required=False,
            doc=_(u'Update DNS entries'),
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
class host_remove_cert(Method):
    __doc__ = _("Remove certificates from host entry")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_(u'Host name'),
            no_convert=True,
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
        parameters.Bytes(
            'usercertificate',
            required=False,
            multivalue=True,
            cli_name='certificate',
            label=_(u'Certificate'),
            doc=_(u'Base-64 encoded server certificate'),
            alwaysask=True,
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
class host_remove_managedby(Method):
    __doc__ = _("Remove hosts that can manage this host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_(u'Host name'),
            no_convert=True,
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
class host_show(Method):
    __doc__ = _("Display information about a host.")

    takes_args = (
        parameters.Str(
            'fqdn',
            cli_name='hostname',
            label=_(u'Host name'),
            no_convert=True,
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
            'out',
            required=False,
            doc=_(u'file to store certificate in'),
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
