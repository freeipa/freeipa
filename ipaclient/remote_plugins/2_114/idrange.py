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
ID ranges

Manage ID ranges  used to map Posix IDs to SIDs and back.

There are two type of ID ranges which are both handled by this utility:

 - the ID ranges of the local domain
 - the ID ranges of trusted remote domains

Both types have the following attributes in common:

 - base-id: the first ID of the Posix ID range
 - range-size: the size of the range

With those two attributes a range object can reserve the Posix IDs starting
with base-id up to but not including base-id+range-size exclusively.

Additionally an ID range of the local domain may set
 - rid-base: the first RID(*) of the corresponding RID range
 - secondary-rid-base: first RID of the secondary RID range

and an ID range of a trusted domain must set
 - rid-base: the first RID of the corresponding RID range
 - sid: domain SID of the trusted domain



EXAMPLE: Add a new ID range for a trusted domain

Since there might be more than one trusted domain the domain SID must be given
while creating the ID range.

  ipa idrange-add --base-id=1200000 --range-size=200000 --rid-base=0 \
                  --dom-sid=S-1-5-21-123-456-789 trusted_dom_range

This ID range is then used by the IPA server and the SSSD IPA provider to
assign Posix UIDs to users from the trusted domain.

If e.g. a range for a trusted domain is configured with the following values:
 base-id = 1200000
 range-size = 200000
 rid-base = 0
the RIDs 0 to 199999 are mapped to the Posix ID from 1200000 to 13999999. So
RID 1000 <-> Posix ID 1201000



EXAMPLE: Add a new ID range for the local domain

To create an ID range for the local domain it is not necessary to specify a
domain SID. But since it is possible that a user and a group can have the same
value as Posix ID a second RID interval is needed to handle conflicts.

  ipa idrange-add --base-id=1200000 --range-size=200000 --rid-base=1000 \
                  --secondary-rid-base=1000000 local_range

The data from the ID ranges of the local domain are used by the IPA server
internally to assign SIDs to IPA users and groups. The SID will then be stored
in the user or group objects.

If e.g. the ID range for the local domain is configured with the values from
the example above then a new user with the UID 1200007 will get the RID 1007.
If this RID is already used by a group the RID will be 1000007. This can only
happen if a user or a group object was created with a fixed ID because the
automatic assignment will not assign the same ID twice. Since there are only
users and groups sharing the same ID namespace it is sufficient to have only
one fallback range to handle conflicts.

To find the Posix ID for a given RID from the local domain it has to be
checked first if the RID falls in the primary or secondary RID range and
the rid-base or the secondary-rid-base has to be subtracted, respectively,
and the base-id has to be added to get the Posix ID.

Typically the creation of ID ranges happens behind the scenes and this CLI
must not be used at all. The ID range for the local domain will be created
during installation or upgrade from an older version. The ID range for a
trusted domain will be created together with the trust by 'ipa trust-add ...'.

USE CASES:

  Add an ID range from a transitively trusted domain

    If the trusted domain (A) trusts another domain (B) as well and this trust
    is transitive 'ipa trust-add domain-A' will only create a range for
    domain A.  The ID range for domain B must be added manually.

  Add an additional ID range for the local domain

    If the ID range of the local domain is exhausted, i.e. no new IDs can be
    assigned to Posix users or groups by the DNA plugin, a new range has to be
    created to allow new users and groups to be added. (Currently there is no
    connection between this range CLI and the DNA plugin, but a future version
    might be able to modify the configuration of the DNS plugin as well)

In general it is not necessary to modify or delete ID ranges. If there is no
other way to achieve a certain configuration than to modify or delete an ID
range it should be done with great care. Because UIDs are stored in the file
system and are used for access control it might be possible that users are
allowed to access files of other users if an ID range got deleted and reused
for a different domain.

(*) The RID is typically the last integer of a user or group SID which follows
the domain SID. E.g. if the domain SID is S-1-5-21-123-456-789 and a user from
this domain has the SID S-1-5-21-123-456-789-1010 then 1010 is the RID of the
user. RIDs are unique in a domain, 32bit values and are used for users and
groups.

WARNING:

DNA plugin in 389-ds will allocate IDs based on the ranges configured for the
local domain. Currently the DNA plugin *cannot* be reconfigured itself based
on the local ranges set via this family of commands.

Manual configuration change has to be done in the DNA plugin configuration for
the new local range. Specifically, The dnaNextRange attribute of 'cn=Posix
IDs,cn=Distributed Numeric Assignment Plugin,cn=plugins,cn=config' has to be
modified to match the new range.
""")

register = Registry()


@register()
class idrange(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_(u'Range name'),
        ),
        parameters.Int(
            'ipabaseid',
            label=_(u'First Posix ID of the range'),
        ),
        parameters.Int(
            'ipaidrangesize',
            label=_(u'Number of IDs in the range'),
        ),
        parameters.Int(
            'ipabaserid',
            required=False,
            label=_(u'First RID of the corresponding RID range'),
        ),
        parameters.Int(
            'ipasecondarybaserid',
            required=False,
            label=_(u'First RID of the secondary RID range'),
        ),
        parameters.Str(
            'ipanttrusteddomainsid',
            required=False,
            label=_(u'Domain SID of the trusted domain'),
        ),
        parameters.Str(
            'ipanttrusteddomainname',
            required=False,
            label=_(u'Name of the trusted domain'),
        ),
        parameters.Str(
            'iparangetype',
            required=False,
            label=_(u'Range type'),
            doc=_(u'ID range type, one of ipa-ad-trust-posix, ipa-ad-trust, ipa-local'),
        ),
    )


@register()
class idrange_add(Method):
    __doc__ = _("""
Add new ID range.

    To add a new ID range you always have to specify

        --base-id
        --range-size

    Additionally

        --rid-base
        --secondary-rid-base

    may be given for a new ID range for the local domain while

        --rid-base
        --dom-sid

    must be given to add a new range for a trusted AD domain.

    WARNING:

    DNA plugin in 389-ds will allocate IDs based on the ranges configured for the
    local domain. Currently the DNA plugin *cannot* be reconfigured itself based
    on the local ranges set via this family of commands.

    Manual configuration change has to be done in the DNA plugin configuration for
    the new local range. Specifically, The dnaNextRange attribute of 'cn=Posix
    IDs,cn=Distributed Numeric Assignment Plugin,cn=plugins,cn=config' has to be
    modified to match the new range.
    """)

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Range name'),
        ),
    )
    takes_options = (
        parameters.Int(
            'ipabaseid',
            cli_name='base_id',
            label=_(u'First Posix ID of the range'),
        ),
        parameters.Int(
            'ipaidrangesize',
            cli_name='range_size',
            label=_(u'Number of IDs in the range'),
        ),
        parameters.Int(
            'ipabaserid',
            required=False,
            cli_name='rid_base',
            label=_(u'First RID of the corresponding RID range'),
        ),
        parameters.Int(
            'ipasecondarybaserid',
            required=False,
            cli_name='secondary_rid_base',
            label=_(u'First RID of the secondary RID range'),
        ),
        parameters.Str(
            'ipanttrusteddomainsid',
            required=False,
            cli_name='dom_sid',
            label=_(u'Domain SID of the trusted domain'),
        ),
        parameters.Str(
            'ipanttrusteddomainname',
            required=False,
            cli_name='dom_name',
            label=_(u'Name of the trusted domain'),
        ),
        parameters.Str(
            'iparangetype',
            required=False,
            cli_name='type',
            cli_metavar="['ipa-ad-trust-posix', 'ipa-ad-trust', 'ipa-local']",
            label=_(u'Range type'),
            doc=_(u'ID range type, one of ipa-ad-trust-posix, ipa-ad-trust, ipa-local'),
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
class idrange_del(Method):
    __doc__ = _("Delete an ID range.")

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='name',
            label=_(u'Range name'),
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
class idrange_find(Method):
    __doc__ = _("Search for ranges.")

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
            label=_(u'Range name'),
        ),
        parameters.Int(
            'ipabaseid',
            required=False,
            cli_name='base_id',
            label=_(u'First Posix ID of the range'),
        ),
        parameters.Int(
            'ipaidrangesize',
            required=False,
            cli_name='range_size',
            label=_(u'Number of IDs in the range'),
        ),
        parameters.Int(
            'ipabaserid',
            required=False,
            cli_name='rid_base',
            label=_(u'First RID of the corresponding RID range'),
        ),
        parameters.Int(
            'ipasecondarybaserid',
            required=False,
            cli_name='secondary_rid_base',
            label=_(u'First RID of the secondary RID range'),
        ),
        parameters.Str(
            'ipanttrusteddomainsid',
            required=False,
            cli_name='dom_sid',
            label=_(u'Domain SID of the trusted domain'),
        ),
        parameters.Str(
            'iparangetype',
            required=False,
            cli_name='type',
            cli_metavar="['ipa-ad-trust-posix', 'ipa-ad-trust', 'ipa-local']",
            label=_(u'Range type'),
            doc=_(u'ID range type, one of ipa-ad-trust-posix, ipa-ad-trust, ipa-local'),
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
class idrange_mod(Method):
    __doc__ = _("Modify ID range.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Range name'),
        ),
    )
    takes_options = (
        parameters.Int(
            'ipabaseid',
            required=False,
            cli_name='base_id',
            label=_(u'First Posix ID of the range'),
        ),
        parameters.Int(
            'ipaidrangesize',
            required=False,
            cli_name='range_size',
            label=_(u'Number of IDs in the range'),
        ),
        parameters.Int(
            'ipabaserid',
            required=False,
            cli_name='rid_base',
            label=_(u'First RID of the corresponding RID range'),
        ),
        parameters.Int(
            'ipasecondarybaserid',
            required=False,
            cli_name='secondary_rid_base',
            label=_(u'First RID of the secondary RID range'),
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
            'ipanttrusteddomainsid',
            required=False,
            deprecated=True,
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ipanttrusteddomainname',
            required=False,
            deprecated=True,
            exclude=('cli', 'webui'),
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
class idrange_show(Method):
    __doc__ = _("Display information about a range.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Range name'),
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
