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

__doc__ = _(r"""
Cross-realm trusts

Manage trust relationship between IPA and Active Directory domains.

In order to allow users from a remote domain to access resources in IPA
domain, trust relationship needs to be established. Currently IPA supports
only trusts between IPA and Active Directory domains under control of Windows
Server 2008 or later, with functional level 2008 or later.

Please note that DNS on both IPA and Active Directory domain sides should be
configured properly to discover each other. Trust relationship relies on
ability to discover special resources in the other domain via DNS records.

Examples:

1. Establish cross-realm trust with Active Directory using AD administrator
   credentials:

   ipa trust-add --type=ad <ad.domain> --admin <AD domain administrator> --password

2. List all existing trust relationships:

   ipa trust-find

3. Show details of the specific trust relationship:

   ipa trust-show <ad.domain>

4. Delete existing trust relationship:

   ipa trust-del <ad.domain>

Once trust relationship is established, remote users will need to be mapped
to local POSIX groups in order to actually use IPA resources. The mapping should
be done via use of external membership of non-POSIX group and then this group
should be included into one of local POSIX groups.

Example:

1. Create group for the trusted domain admins' mapping and their local POSIX group:

   ipa group-add --desc='<ad.domain> admins external map' ad_admins_external --external
   ipa group-add --desc='<ad.domain> admins' ad_admins

2. Add security identifier of Domain Admins of the <ad.domain> to the ad_admins_external
   group:

   ipa group-add-member ad_admins_external --external 'AD\Domain Admins'

3. Allow members of ad_admins_external group to be associated with ad_admins POSIX group:

   ipa group-add-member ad_admins --groups ad_admins_external

4. List members of external members of ad_admins_external group to see their SIDs:

   ipa group-show ad_admins_external


GLOBAL TRUST CONFIGURATION

When IPA AD trust subpackage is installed and ipa-adtrust-install is run,
a local domain configuration (SID, GUID, NetBIOS name) is generated. These
identifiers are then used when communicating with a trusted domain of the
particular type.

1. Show global trust configuration for Active Directory type of trusts:

   ipa trustconfig-show --type ad

2. Modify global configuration for all trusts of Active Directory type and set
   a different fallback primary group (fallback primary group GID is used as
   a primary user GID if user authenticating to IPA domain does not have any other
   primary GID already set):

   ipa trustconfig-mod --type ad --fallback-primary-group "alternative AD group"

3. Change primary fallback group back to default hidden group (any group with
   posixGroup object class is allowed):

   ipa trustconfig-mod --type ad --fallback-primary-group "Default SMB Group"
""")

register = Registry()


@register()
class trust(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_(u'Realm name'),
        ),
        parameters.Str(
            'ipantflatname',
            label=_(u'Domain NetBIOS name'),
        ),
        parameters.Str(
            'ipanttrusteddomainsid',
            label=_(u'Domain Security Identifier'),
        ),
        parameters.Str(
            'ipantsidblacklistincoming',
            required=False,
            multivalue=True,
            label=_(u'SID blacklist incoming'),
        ),
        parameters.Str(
            'ipantsidblacklistoutgoing',
            required=False,
            multivalue=True,
            label=_(u'SID blacklist outgoing'),
        ),
    )


@register()
class trustconfig(Object):
    takes_params = (
        parameters.Str(
            'cn',
            label=_(u'Domain'),
        ),
        parameters.Str(
            'ipantsecurityidentifier',
            label=_(u'Security Identifier'),
        ),
        parameters.Str(
            'ipantflatname',
            label=_(u'NetBIOS name'),
        ),
        parameters.Str(
            'ipantdomainguid',
            label=_(u'Domain GUID'),
        ),
        parameters.Str(
            'ipantfallbackprimarygroup',
            label=_(u'Fallback primary group'),
        ),
    )


@register()
class trustdomain(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_(u'Domain name'),
        ),
        parameters.Str(
            'ipantflatname',
            required=False,
            label=_(u'Domain NetBIOS name'),
        ),
        parameters.Str(
            'ipanttrusteddomainsid',
            required=False,
            label=_(u'Domain Security Identifier'),
        ),
        parameters.Str(
            'ipanttrustpartner',
            required=False,
            label=_(u'Trusted domain partner'),
        ),
    )


@register()
class adtrust_is_enabled(Command):
    __doc__ = _("Determine whether ipa-adtrust-install has been run on this system")

    NO_CLI = True

    takes_options = (
    )
    has_output = (
        output.Output(
            'result',
        ),
    )


@register()
class compat_is_enabled(Command):
    __doc__ = _("Determine whether Schema Compatibility plugin is configured to serve trusted domain users and groups")

    NO_CLI = True

    takes_options = (
    )
    has_output = (
        output.Output(
            'result',
        ),
    )


@register()
class sidgen_was_run(Command):
    __doc__ = _("Determine whether ipa-adtrust-install has been run with sidgen task")

    NO_CLI = True

    takes_options = (
    )
    has_output = (
        output.Output(
            'result',
        ),
    )


@register()
class trust_add(Method):
    __doc__ = _("""
Add new trust to use.

This command establishes trust relationship to another domain
which becomes 'trusted'. As result, users of the trusted domain
may access resources of this domain.

Only trusts to Active Directory domains are supported right now.

The command can be safely run multiple times against the same domain,
this will cause change to trust relationship credentials on both
sides.
    """)

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='realm',
            label=_(u'Realm name'),
        ),
    )
    takes_options = (
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
            'trust_type',
            cli_name='type',
            cli_metavar="['ad']",
            label=_(u'Trust type (ad for Active Directory, default)'),
            default=u'ad',
            autofill=True,
        ),
        parameters.Str(
            'realm_admin',
            required=False,
            cli_name='admin',
            label=_(u'Active Directory domain administrator'),
        ),
        parameters.Password(
            'realm_passwd',
            required=False,
            cli_name='password',
            label=_(u"Active Directory domain administrator's password"),
        ),
        parameters.Str(
            'realm_server',
            required=False,
            cli_name='server',
            label=_(u'Domain controller for the Active Directory domain (optional)'),
        ),
        parameters.Password(
            'trust_secret',
            required=False,
            label=_(u'Shared secret for the trust'),
        ),
        parameters.Int(
            'base_id',
            required=False,
            label=_(u'First Posix ID of the range reserved for the trusted domain'),
        ),
        parameters.Int(
            'range_size',
            required=False,
            label=_(u'Size of the ID range reserved for the trusted domain'),
        ),
        parameters.Str(
            'range_type',
            required=False,
            cli_metavar="['ipa-ad-trust-posix', 'ipa-ad-trust']",
            label=_(u'Range type'),
            doc=_(u'Type of trusted domain ID range, one of ipa-ad-trust-posix, ipa-ad-trust'),
        ),
        parameters.Bool(
            'bidirectional',
            required=False,
            cli_name='two_way',
            label=_(u'Two-way trust'),
            doc=_(u'Establish bi-directional trust. By default trust is inbound one-way only.'),
            default=False,
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
class trust_del(Method):
    __doc__ = _("Delete a trust.")

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='realm',
            label=_(u'Realm name'),
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
class trust_fetch_domains(Method):
    __doc__ = _("Refresh list of the domains associated with the trust")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='realm',
            label=_(u'Realm name'),
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
            'realm_server',
            required=False,
            cli_name='server',
            label=_(u'Domain controller for the Active Directory domain (optional)'),
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
class trust_find(Method):
    __doc__ = _("Search for trusts.")

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
            cli_name='realm',
            label=_(u'Realm name'),
        ),
        parameters.Str(
            'ipantflatname',
            required=False,
            cli_name='flat_name',
            label=_(u'Domain NetBIOS name'),
        ),
        parameters.Str(
            'ipanttrusteddomainsid',
            required=False,
            cli_name='sid',
            label=_(u'Domain Security Identifier'),
        ),
        parameters.Str(
            'ipantsidblacklistincoming',
            required=False,
            multivalue=True,
            cli_name='sid_blacklist_incoming',
            label=_(u'SID blacklist incoming'),
        ),
        parameters.Str(
            'ipantsidblacklistoutgoing',
            required=False,
            multivalue=True,
            cli_name='sid_blacklist_outgoing',
            label=_(u'SID blacklist outgoing'),
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
            'pkey_only',
            required=False,
            label=_(u'Primary key only'),
            doc=_(u'Results should contain primary key attribute only ("realm")'),
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
class trust_mod(Method):
    __doc__ = _("""
Modify a trust (for future use).

    Currently only the default option to modify the LDAP attributes is
    available. More specific options will be added in coming releases.
    """)

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='realm',
            label=_(u'Realm name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'ipantsidblacklistincoming',
            required=False,
            multivalue=True,
            cli_name='sid_blacklist_incoming',
            label=_(u'SID blacklist incoming'),
        ),
        parameters.Str(
            'ipantsidblacklistoutgoing',
            required=False,
            multivalue=True,
            cli_name='sid_blacklist_outgoing',
            label=_(u'SID blacklist outgoing'),
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
class trust_resolve(Command):
    __doc__ = _("Resolve security identifiers of users and groups in trusted domains")

    NO_CLI = True

    takes_options = (
        parameters.Str(
            'sids',
            multivalue=True,
            label=_(u'Security Identifiers (SIDs)'),
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
        output.ListOfEntries(
            'result',
        ),
    )


@register()
class trust_show(Method):
    __doc__ = _("Display information about a trust.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='realm',
            label=_(u'Realm name'),
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
class trustconfig_mod(Method):
    __doc__ = _("Modify global trust configuration.")

    takes_options = (
        parameters.Str(
            'ipantfallbackprimarygroup',
            required=False,
            cli_name='fallback_primary_group',
            label=_(u'Fallback primary group'),
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
            'trust_type',
            cli_name='type',
            cli_metavar="['ad']",
            label=_(u'Trust type (ad for Active Directory, default)'),
            default=u'ad',
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
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class trustconfig_show(Method):
    __doc__ = _("Show global trust configuration.")

    takes_options = (
        parameters.Flag(
            'rights',
            label=_(u'Rights'),
            doc=_(u'Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'trust_type',
            cli_name='type',
            cli_metavar="['ad']",
            label=_(u'Trust type (ad for Active Directory, default)'),
            default=u'ad',
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
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class trustdomain_add(Method):
    __doc__ = _("Allow access from the trusted domain")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'trustcn',
            cli_name='trust',
            label=_(u'Realm name'),
        ),
        parameters.Str(
            'cn',
            cli_name='domain',
            label=_(u'Domain name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'ipantflatname',
            required=False,
            cli_name='flat_name',
            label=_(u'Domain NetBIOS name'),
        ),
        parameters.Str(
            'ipanttrusteddomainsid',
            required=False,
            cli_name='sid',
            label=_(u'Domain Security Identifier'),
        ),
        parameters.Str(
            'ipanttrustpartner',
            required=False,
            label=_(u'Trusted domain partner'),
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
            'trust_type',
            cli_name='type',
            cli_metavar="['ad']",
            label=_(u'Trust type (ad for Active Directory, default)'),
            default=u'ad',
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
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class trustdomain_del(Method):
    __doc__ = _("Remove information about the domain associated with the trust.")

    takes_args = (
        parameters.Str(
            'trustcn',
            cli_name='trust',
            label=_(u'Realm name'),
        ),
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='domain',
            label=_(u'Domain name'),
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
class trustdomain_disable(Method):
    __doc__ = _("Disable use of IPA resources by the domain of the trust")

    takes_args = (
        parameters.Str(
            'trustcn',
            cli_name='trust',
            label=_(u'Realm name'),
        ),
        parameters.Str(
            'cn',
            cli_name='domain',
            label=_(u'Domain name'),
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
class trustdomain_enable(Method):
    __doc__ = _("Allow use of IPA resources by the domain of the trust")

    takes_args = (
        parameters.Str(
            'trustcn',
            cli_name='trust',
            label=_(u'Realm name'),
        ),
        parameters.Str(
            'cn',
            cli_name='domain',
            label=_(u'Domain name'),
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
class trustdomain_find(Method):
    __doc__ = _("Search domains of the trust")

    takes_args = (
        parameters.Str(
            'trustcn',
            cli_name='trust',
            label=_(u'Realm name'),
        ),
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
            cli_name='domain',
            label=_(u'Domain name'),
        ),
        parameters.Str(
            'ipantflatname',
            required=False,
            cli_name='flat_name',
            label=_(u'Domain NetBIOS name'),
        ),
        parameters.Str(
            'ipanttrusteddomainsid',
            required=False,
            cli_name='sid',
            label=_(u'Domain Security Identifier'),
        ),
        parameters.Str(
            'ipanttrustpartner',
            required=False,
            label=_(u'Trusted domain partner'),
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
            'pkey_only',
            required=False,
            label=_(u'Primary key only'),
            doc=_(u'Results should contain primary key attribute only ("domain")'),
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
class trustdomain_mod(Method):
    __doc__ = _("Modify trustdomain of the trust")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'trustcn',
            cli_name='trust',
            label=_(u'Realm name'),
        ),
        parameters.Str(
            'cn',
            cli_name='domain',
            label=_(u'Domain name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'ipantflatname',
            required=False,
            cli_name='flat_name',
            label=_(u'Domain NetBIOS name'),
        ),
        parameters.Str(
            'ipanttrusteddomainsid',
            required=False,
            cli_name='sid',
            label=_(u'Domain Security Identifier'),
        ),
        parameters.Str(
            'ipanttrustpartner',
            required=False,
            label=_(u'Trusted domain partner'),
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
        parameters.Str(
            'trust_type',
            cli_name='type',
            cli_metavar="['ad']",
            label=_(u'Trust type (ad for Active Directory, default)'),
            default=u'ad',
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
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )
