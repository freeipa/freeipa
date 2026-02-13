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
Manage Certificate Profiles

Certificate Profiles are used by Certificate Authority (CA) in the signing of
certificates to determine if a Certificate Signing Request (CSR) is acceptable,
and if so what features and extensions will be present on the certificate.

The Certificate Profile format is the property-list format understood by the
Dogtag or Red Hat Certificate System CA.

PROFILE ID SYNTAX:

A Profile ID is a string without spaces or punctuation starting with a letter
and followed by a sequence of letters, digits or underscore ("_").

EXAMPLES:

  Import a profile that will not store issued certificates:
    ipa certprofile-import ShortLivedUserCert \
      --file UserCert.profile --desc "User Certificates" \
      --store=false

  Delete a certificate profile:
    ipa certprofile-del ShortLivedUserCert

  Show information about a profile:
    ipa certprofile-show ShortLivedUserCert

  Save profile configuration to a file:
    ipa certprofile-show caIPAserviceCert --out caIPAserviceCert.cfg

  Search for profiles that do not store certificates:
    ipa certprofile-find --store=false

PROFILE CONFIGURATION FORMAT:

The profile configuration format is the raw property-list format
used by Dogtag Certificate System.  The XML format is not supported.

The following restrictions apply to profiles managed by IPA:

- When importing a profile the "profileId" field, if present, must
  match the ID given on the command line.

- The "classId" field must be set to "caEnrollImpl"

- The "auth.instance_id" field must be set to "raCertAuth"

- The "certReqInputImpl" input class and "certOutputImpl" output
  class must be used.
""")

register = Registry()


@register()
class certprofile(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_('Profile ID'),
            doc=_('Profile ID for referring to this profile'),
        ),
        parameters.Str(
            'description',
            label=_('Profile description'),
            doc=_('Brief description of this profile'),
        ),
        parameters.Bool(
            'ipacertprofilestoreissued',
            label=_('Store issued certificates'),
            doc=_('Whether to store certs issued using this profile'),
        ),
    )


@register()
class certprofile_del(Method):
    __doc__ = _("Delete a Certificate Profile.")

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='id',
            label=_('Profile ID'),
            doc=_('Profile ID for referring to this profile'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_("Continuous mode: Don't stop on errors."),
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
class certprofile_find(Method):
    __doc__ = _("Search for Certificate Profiles.")

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_('A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'cn',
            required=False,
            cli_name='id',
            label=_('Profile ID'),
            doc=_('Profile ID for referring to this profile'),
        ),
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Profile description'),
            doc=_('Brief description of this profile'),
        ),
        parameters.Bool(
            'ipacertprofilestoreissued',
            required=False,
            cli_name='store',
            label=_('Store issued certificates'),
            doc=_('Whether to store certs issued using this profile'),
            default=True,
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
            doc=_(
                'Retrieve and print all attributes from the server. '
                'Affects command output.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(
                'Print entries as stored on the server. '
                'Only affects output format.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_('Primary key only'),
            doc=_('Results should contain primary key attribute only ("id")'),
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
class certprofile_import(Method):
    __doc__ = _("Import a Certificate Profile.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='id',
            label=_('Profile ID'),
            doc=_('Profile ID for referring to this profile'),
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            cli_name='desc',
            label=_('Profile description'),
            doc=_('Brief description of this profile'),
        ),
        parameters.Bool(
            'ipacertprofilestoreissued',
            cli_name='store',
            label=_('Store issued certificates'),
            doc=_('Whether to store certs issued using this profile'),
            default=True,
        ),
        parameters.Str(
            'file',
            label=_(
                'Filename of a raw profile. The XML format is not supported.'
            ),
        ),
        parameters.Flag(
            'all',
            doc=_(
                'Retrieve and print all attributes from the server. '
                'Affects command output.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(
                'Print entries as stored on the server. '
                'Only affects output format.'
            ),
            exclude=('webui',),
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
class certprofile_mod(Method):
    __doc__ = _("Modify Certificate Profile configuration.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='id',
            label=_('Profile ID'),
            doc=_('Profile ID for referring to this profile'),
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Profile description'),
            doc=_('Brief description of this profile'),
        ),
        parameters.Bool(
            'ipacertprofilestoreissued',
            required=False,
            cli_name='store',
            label=_('Store issued certificates'),
            doc=_('Whether to store certs issued using this profile'),
            default=True,
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_(
                'Set an attribute to a name/value pair. '
                'Format is attr=value.\nFor multi-valued attributes, '
                'the command replaces the values already present.'
            ),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_(
                'Add an attribute/value pair. Format is attr=value. '
                'The attribute\nmust be part of the schema.'
            ),
            exclude=('webui',),
        ),
        parameters.Str(
            'delattr',
            required=False,
            multivalue=True,
            doc=_(
                'Delete an attribute/value pair. '
                'The option will be evaluated\nlast, after all sets and adds.'
            ),
            exclude=('webui',),
        ),
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_(
                'Display the access rights of this entry (requires --all). '
                'See ipa man page for details.'
            ),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'file',
            required=False,
            label=_('File containing profile configuration'),
        ),
        parameters.Flag(
            'all',
            doc=_(
                'Retrieve and print all attributes from the server. '
                'Affects command output.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(
                'Print entries as stored on the server. '
                'Only affects output format.'
            ),
            exclude=('webui',),
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
class certprofile_show(Method):
    __doc__ = _("Display the properties of a Certificate Profile.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='id',
            label=_('Profile ID'),
            doc=_('Profile ID for referring to this profile'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_(
                'Display the access rights of this entry (requires --all). '
                'See ipa man page for details.'
            ),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'out',
            required=False,
            doc=_('Write profile configuration to file'),
        ),
        parameters.Flag(
            'all',
            doc=_(
                'Retrieve and print all attributes from the server. '
                'Affects command output.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(
                'Print entries as stored on the server. '
                'Only affects output format.'
            ),
            exclude=('webui',),
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
