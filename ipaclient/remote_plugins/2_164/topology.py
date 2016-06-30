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
Topology

Management of a replication topology at domain level 1.

IPA server's data is stored in LDAP server in two suffixes:
* domain suffix, e.g., 'dc=example,dc=com', contains all domain related data
* ca suffix, 'o=ipaca', is present only on server with CA installed. It
  contains data for Certificate Server component

Data stored on IPA servers is replicated to other IPA servers. The way it is
replicated is defined by replication agreements. Replication agreements needs
to be set for both suffixes separately. On domain level 0 they are managed
using ipa-replica-manage and ipa-csreplica-manage tools. With domain level 1
they are managed centrally using `ipa topology*` commands.

Agreements are represented by topology segments. By default topology segment
represents 2 replication agreements - one for each direction, e.g., A to B and
B to A. Creation of unidirectional segments is not allowed.

To verify that no server is disconnected in the topology of the given suffix,
use:
  ipa topologysuffix-verify $suffix


Examples:
  Find all IPA servers:
    ipa server-find

  Find all suffixes:
    ipa topologysuffix-find

  Add topology segment to 'domain' suffix:
    ipa topologysegment-add domain --left IPA_SERVER_A --right IPA_SERVER_B

  Add topology segment to 'ca' suffix:
    ipa topologysegment-add ca --left IPA_SERVER_A --right IPA_SERVER_B

  List all topology segments in 'domain' suffix:
    ipa topologysegment-find domain

  List all topology segments in 'ca' suffix:
    ipa topologysegment-find ca

  Delete topology segment in 'domain' suffix:
    ipa topologysegment-del domain segment_name

  Delete topology segment in 'ca' suffix:
    ipa topologysegment-del ca segment_name

  Verify topology of 'domain' suffix:
    ipa topologysuffix-verify domain

  Verify topology of 'ca' suffix:
    ipa topologysuffix-verify ca
""")

register = Registry()


@register()
class topologysegment(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_(u'Segment name'),
            doc=_(u'Arbitrary string identifying the segment'),
        ),
        parameters.Str(
            'iparepltoposegmentleftnode',
            label=_(u'Left node'),
            doc=_(u'Left replication node - an IPA server'),
        ),
        parameters.Str(
            'iparepltoposegmentrightnode',
            label=_(u'Right node'),
            doc=_(u'Right replication node - an IPA server'),
        ),
        parameters.Str(
            'iparepltoposegmentdirection',
            label=_(u'Connectivity'),
            doc=_(u'Direction of replication between left and right replication node'),
        ),
        parameters.Str(
            'nsds5replicastripattrs',
            required=False,
            label=_(u'Attributes to strip'),
            doc=_(u'A space separated list of attributes which are removed from replication updates.'),
        ),
        parameters.Str(
            'nsds5replicatedattributelist',
            required=False,
            label=_(u'Attributes to replicate'),
            doc=_(u'Attributes that are not replicated to a consumer server during a fractional update. E.g., `(objectclass=*) $ EXCLUDE accountlockout memberof'),
        ),
        parameters.Str(
            'nsds5replicatedattributelisttotal',
            required=False,
            label=_(u'Attributes for total update'),
            doc=_(u'Attributes that are not replicated to a consumer server during a total update. E.g. (objectclass=*) $ EXCLUDE accountlockout'),
        ),
        parameters.Int(
            'nsds5replicatimeout',
            required=False,
            label=_(u'Session timeout'),
            doc=_(u'Number of seconds outbound LDAP operations waits for a response from the remote replica before timing out and failing'),
        ),
        parameters.Str(
            'nsds5replicaenabled',
            required=False,
            label=_(u'Replication agreement enabled'),
            doc=_(u'Whether a replication agreement is active, meaning whether replication is occurring per that agreement'),
        ),
    )


@register()
class topologysuffix(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_(u'Suffix name'),
        ),
        parameters.DNParam(
            'iparepltopoconfroot',
            label=_(u'Managed LDAP suffix DN'),
        ),
    )


@register()
class topologysegment_add(Method):
    __doc__ = _("Add a new segment.")

    takes_args = (
        parameters.Str(
            'topologysuffixcn',
            cli_name='topologysuffix',
            label=_(u'Suffix name'),
        ),
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Segment name'),
            doc=_(u'Arbitrary string identifying the segment'),
            default_from=DefaultFrom(lambda iparepltoposegmentleftnode, iparepltoposegmentrightnode: None, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            # FIXME:
            # lambda iparepltoposegmentleftnode, iparepltoposegmentrightnode:
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'iparepltoposegmentleftnode',
            cli_name='leftnode',
            label=_(u'Left node'),
            doc=_(u'Left replication node - an IPA server'),
            no_convert=True,
        ),
        parameters.Str(
            'iparepltoposegmentrightnode',
            cli_name='rightnode',
            label=_(u'Right node'),
            doc=_(u'Right replication node - an IPA server'),
            no_convert=True,
        ),
        parameters.Str(
            'iparepltoposegmentdirection',
            cli_name='direction',
            cli_metavar="['both', 'left-right', 'right-left']",
            label=_(u'Connectivity'),
            doc=_(u'Direction of replication between left and right replication node'),
            exclude=('cli', 'webui'),
            default=u'both',
            autofill=True,
        ),
        parameters.Str(
            'nsds5replicastripattrs',
            required=False,
            cli_name='stripattrs',
            label=_(u'Attributes to strip'),
            doc=_(u'A space separated list of attributes which are removed from replication updates.'),
            no_convert=True,
        ),
        parameters.Str(
            'nsds5replicatedattributelist',
            required=False,
            cli_name='replattrs',
            label=_(u'Attributes to replicate'),
            doc=_(u'Attributes that are not replicated to a consumer server during a fractional update. E.g., `(objectclass=*) $ EXCLUDE accountlockout memberof'),
        ),
        parameters.Str(
            'nsds5replicatedattributelisttotal',
            required=False,
            cli_name='replattrstotal',
            label=_(u'Attributes for total update'),
            doc=_(u'Attributes that are not replicated to a consumer server during a total update. E.g. (objectclass=*) $ EXCLUDE accountlockout'),
        ),
        parameters.Int(
            'nsds5replicatimeout',
            required=False,
            cli_name='timeout',
            label=_(u'Session timeout'),
            doc=_(u'Number of seconds outbound LDAP operations waits for a response from the remote replica before timing out and failing'),
        ),
        parameters.Str(
            'nsds5replicaenabled',
            required=False,
            cli_name='enabled',
            cli_metavar="['on', 'off']",
            label=_(u'Replication agreement enabled'),
            doc=_(u'Whether a replication agreement is active, meaning whether replication is occurring per that agreement'),
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
class topologysegment_del(Method):
    __doc__ = _("Delete a segment.")

    takes_args = (
        parameters.Str(
            'topologysuffixcn',
            cli_name='topologysuffix',
            label=_(u'Suffix name'),
        ),
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='name',
            label=_(u'Segment name'),
            doc=_(u'Arbitrary string identifying the segment'),
            default_from=DefaultFrom(lambda iparepltoposegmentleftnode, iparepltoposegmentrightnode: None, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            # FIXME:
            # lambda iparepltoposegmentleftnode, iparepltoposegmentrightnode:
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
class topologysegment_find(Method):
    __doc__ = _("Search for topology segments.")

    takes_args = (
        parameters.Str(
            'topologysuffixcn',
            cli_name='topologysuffix',
            label=_(u'Suffix name'),
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
            cli_name='name',
            label=_(u'Segment name'),
            doc=_(u'Arbitrary string identifying the segment'),
            default_from=DefaultFrom(lambda iparepltoposegmentleftnode, iparepltoposegmentrightnode: None, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            # FIXME:
            # lambda iparepltoposegmentleftnode, iparepltoposegmentrightnode:
            no_convert=True,
        ),
        parameters.Str(
            'iparepltoposegmentleftnode',
            required=False,
            cli_name='leftnode',
            label=_(u'Left node'),
            doc=_(u'Left replication node - an IPA server'),
            no_convert=True,
        ),
        parameters.Str(
            'iparepltoposegmentrightnode',
            required=False,
            cli_name='rightnode',
            label=_(u'Right node'),
            doc=_(u'Right replication node - an IPA server'),
            no_convert=True,
        ),
        parameters.Str(
            'iparepltoposegmentdirection',
            required=False,
            cli_name='direction',
            cli_metavar="['both', 'left-right', 'right-left']",
            label=_(u'Connectivity'),
            doc=_(u'Direction of replication between left and right replication node'),
            exclude=('cli', 'webui'),
            default=u'both',
        ),
        parameters.Str(
            'nsds5replicastripattrs',
            required=False,
            cli_name='stripattrs',
            label=_(u'Attributes to strip'),
            doc=_(u'A space separated list of attributes which are removed from replication updates.'),
            no_convert=True,
        ),
        parameters.Str(
            'nsds5replicatedattributelist',
            required=False,
            cli_name='replattrs',
            label=_(u'Attributes to replicate'),
            doc=_(u'Attributes that are not replicated to a consumer server during a fractional update. E.g., `(objectclass=*) $ EXCLUDE accountlockout memberof'),
        ),
        parameters.Str(
            'nsds5replicatedattributelisttotal',
            required=False,
            cli_name='replattrstotal',
            label=_(u'Attributes for total update'),
            doc=_(u'Attributes that are not replicated to a consumer server during a total update. E.g. (objectclass=*) $ EXCLUDE accountlockout'),
        ),
        parameters.Int(
            'nsds5replicatimeout',
            required=False,
            cli_name='timeout',
            label=_(u'Session timeout'),
            doc=_(u'Number of seconds outbound LDAP operations waits for a response from the remote replica before timing out and failing'),
        ),
        parameters.Str(
            'nsds5replicaenabled',
            required=False,
            cli_name='enabled',
            cli_metavar="['on', 'off']",
            label=_(u'Replication agreement enabled'),
            doc=_(u'Whether a replication agreement is active, meaning whether replication is occurring per that agreement'),
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
class topologysegment_mod(Method):
    __doc__ = _("Modify a segment.")

    takes_args = (
        parameters.Str(
            'topologysuffixcn',
            cli_name='topologysuffix',
            label=_(u'Suffix name'),
        ),
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Segment name'),
            doc=_(u'Arbitrary string identifying the segment'),
            default_from=DefaultFrom(lambda iparepltoposegmentleftnode, iparepltoposegmentrightnode: None, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            # FIXME:
            # lambda iparepltoposegmentleftnode, iparepltoposegmentrightnode:
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'nsds5replicastripattrs',
            required=False,
            cli_name='stripattrs',
            label=_(u'Attributes to strip'),
            doc=_(u'A space separated list of attributes which are removed from replication updates.'),
            no_convert=True,
        ),
        parameters.Str(
            'nsds5replicatedattributelist',
            required=False,
            cli_name='replattrs',
            label=_(u'Attributes to replicate'),
            doc=_(u'Attributes that are not replicated to a consumer server during a fractional update. E.g., `(objectclass=*) $ EXCLUDE accountlockout memberof'),
        ),
        parameters.Str(
            'nsds5replicatedattributelisttotal',
            required=False,
            cli_name='replattrstotal',
            label=_(u'Attributes for total update'),
            doc=_(u'Attributes that are not replicated to a consumer server during a total update. E.g. (objectclass=*) $ EXCLUDE accountlockout'),
        ),
        parameters.Int(
            'nsds5replicatimeout',
            required=False,
            cli_name='timeout',
            label=_(u'Session timeout'),
            doc=_(u'Number of seconds outbound LDAP operations waits for a response from the remote replica before timing out and failing'),
        ),
        parameters.Str(
            'nsds5replicaenabled',
            required=False,
            cli_name='enabled',
            cli_metavar="['on', 'off']",
            label=_(u'Replication agreement enabled'),
            doc=_(u'Whether a replication agreement is active, meaning whether replication is occurring per that agreement'),
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
class topologysegment_reinitialize(Method):
    __doc__ = _("Request a full re-initialization of the node retrieving data from the other node.")

    takes_args = (
        parameters.Str(
            'topologysuffixcn',
            cli_name='topologysuffix',
            label=_(u'Suffix name'),
        ),
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Segment name'),
            doc=_(u'Arbitrary string identifying the segment'),
            default_from=DefaultFrom(lambda iparepltoposegmentleftnode, iparepltoposegmentrightnode: None, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            # FIXME:
            # lambda iparepltoposegmentleftnode, iparepltoposegmentrightnode:
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'left',
            required=False,
            doc=_(u'Initialize left node'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'right',
            required=False,
            doc=_(u'Initialize right node'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'stop',
            required=False,
            doc=_(u'Stop already started refresh of chosen node(s)'),
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
            bool,
            doc=_(u'True means the operation was successful'),
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class topologysegment_show(Method):
    __doc__ = _("Display a segment.")

    takes_args = (
        parameters.Str(
            'topologysuffixcn',
            cli_name='topologysuffix',
            label=_(u'Suffix name'),
        ),
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Segment name'),
            doc=_(u'Arbitrary string identifying the segment'),
            default_from=DefaultFrom(lambda iparepltoposegmentleftnode, iparepltoposegmentrightnode: None, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            # FIXME:
            # lambda iparepltoposegmentleftnode, iparepltoposegmentrightnode:
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
class topologysuffix_add(Method):
    __doc__ = _("Add a new topology suffix to be managed.")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Suffix name'),
        ),
    )
    takes_options = (
        parameters.DNParam(
            'iparepltopoconfroot',
            cli_name='suffix_dn',
            label=_(u'Managed LDAP suffix DN'),
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
class topologysuffix_del(Method):
    __doc__ = _("Delete a topology suffix.")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='name',
            label=_(u'Suffix name'),
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
class topologysuffix_find(Method):
    __doc__ = _("Search for topology suffixes.")

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
            label=_(u'Suffix name'),
        ),
        parameters.DNParam(
            'iparepltopoconfroot',
            required=False,
            cli_name='suffix_dn',
            label=_(u'Managed LDAP suffix DN'),
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
class topologysuffix_mod(Method):
    __doc__ = _("Modify a topology suffix.")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Suffix name'),
        ),
    )
    takes_options = (
        parameters.DNParam(
            'iparepltopoconfroot',
            required=False,
            cli_name='suffix_dn',
            label=_(u'Managed LDAP suffix DN'),
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
class topologysuffix_show(Method):
    __doc__ = _("Show managed suffix.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Suffix name'),
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
class topologysuffix_verify(Method):
    __doc__ = _("""
Verify replication topology for suffix.

Checks done:
  1. check if a topology is not disconnected. In other words if there are
     replication paths between all servers.
  2. check if servers don't have more than the recommended number of
     replication agreements
    """)

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Suffix name'),
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'result',
        ),
    )
