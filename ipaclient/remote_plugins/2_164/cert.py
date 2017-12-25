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
IPA certificate operations

Implements a set of commands for managing server SSL certificates.

Certificate requests exist in the form of a Certificate Signing Request (CSR)
in PEM format.

The dogtag CA uses just the CN value of the CSR and forces the rest of the
subject to values configured in the server.

A certificate is stored with a service principal and a service principal
needs a host.

In order to request a certificate:

* The host must exist
* The service must exist (or you use the --add option to automatically add it)

SEARCHING:

Certificates may be searched on by certificate subject, serial number,
revocation reason, validity dates and the issued date.

When searching on dates the _from date does a >= search and the _to date
does a <= search. When combined these are done as an AND.

Dates are treated as GMT to match the dates in the certificates.

The date format is YYYY-mm-dd.

EXAMPLES:

 Request a new certificate and add the principal:
   ipa cert-request --add --principal=HTTP/lion.example.com example.csr

 Retrieve an existing certificate:
   ipa cert-show 1032

 Revoke a certificate (see RFC 5280 for reason details):
   ipa cert-revoke --revocation-reason=6 1032

 Remove a certificate from revocation hold status:
   ipa cert-remove-hold 1032

 Check the status of a signing request:
   ipa cert-status 10

 Search for certificates by hostname:
   ipa cert-find --subject=ipaserver.example.com

 Search for revoked certificates by reason:
   ipa cert-find --revocation-reason=5

 Search for certificates based on issuance date
   ipa cert-find --issuedon-from=2013-02-01 --issuedon-to=2013-02-07

IPA currently immediately issues (or declines) all certificate requests so
the status of a request is not normally useful. This is for future use
or the case where a CA does not immediately issue a certificate.

The following revocation reasons are supported:

    * 0 - unspecified
    * 1 - keyCompromise
    * 2 - cACompromise
    * 3 - affiliationChanged
    * 4 - superseded
    * 5 - cessationOfOperation
    * 6 - certificateHold
    * 8 - removeFromCRL
    * 9 - privilegeWithdrawn
    * 10 - aACompromise

Note that reason code 7 is not used.  See RFC 5280 for more details:

http://www.ietf.org/rfc/rfc5280.txt
""")

register = Registry()


@register()
class ca_is_enabled(Command):
    __doc__ = _("Checks if any of the servers has the CA service enabled.")

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
class cert_find(Command):
    __doc__ = _("Search for existing certificates.")

    takes_options = (
        parameters.Str(
            'subject',
            required=False,
            label=_(u'Match cn attribute in subject'),
        ),
        parameters.Int(
            'revocation_reason',
            required=False,
            label=_(u'Reason'),
            doc=_(u'Reason for revoking the certificate (0-10)'),
        ),
        parameters.Int(
            'min_serial_number',
            required=False,
            doc=_(u'minimum serial number'),
        ),
        parameters.Int(
            'max_serial_number',
            required=False,
            doc=_(u'maximum serial number'),
        ),
        parameters.Flag(
            'exactly',
            required=False,
            doc=_(u'match the common name exactly'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'validnotafter_from',
            required=False,
            doc=_(u'Valid not after from this date (YYYY-mm-dd)'),
        ),
        parameters.Str(
            'validnotafter_to',
            required=False,
            doc=_(u'Valid not after to this date (YYYY-mm-dd)'),
        ),
        parameters.Str(
            'validnotbefore_from',
            required=False,
            doc=_(u'Valid not before from this date (YYYY-mm-dd)'),
        ),
        parameters.Str(
            'validnotbefore_to',
            required=False,
            doc=_(u'Valid not before to this date (YYYY-mm-dd)'),
        ),
        parameters.Str(
            'issuedon_from',
            required=False,
            doc=_(u'Issued on from this date (YYYY-mm-dd)'),
        ),
        parameters.Str(
            'issuedon_to',
            required=False,
            doc=_(u'Issued on to this date (YYYY-mm-dd)'),
        ),
        parameters.Str(
            'revokedon_from',
            required=False,
            doc=_(u'Revoked on from this date (YYYY-mm-dd)'),
        ),
        parameters.Str(
            'revokedon_to',
            required=False,
            doc=_(u'Revoked on to this date (YYYY-mm-dd)'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_(u'Size Limit'),
            doc=_(u'Maximum number of certs returned'),
            default=100,
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
class cert_remove_hold(Command):
    __doc__ = _("Take a revoked certificate off hold.")

    takes_args = (
        parameters.Str(
            'serial_number',
            label=_(u'Serial number'),
            doc=_(u'Serial number in decimal or if prefixed with 0x in hexadecimal'),
            no_convert=True,
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
class cert_request(Command):
    __doc__ = _("Submit a certificate signing request.")

    takes_args = (
        parameters.Str(
            'csr',
            cli_name='csr_file',
            label=_(u'CSR'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'principal',
            label=_(u'Principal'),
            doc=_(u'Principal for this certificate (e.g. HTTP/test.example.com)'),
        ),
        parameters.Str(
            'request_type',
            default=u'pkcs10',
            autofill=True,
        ),
        parameters.Flag(
            'add',
            doc=_(u"automatically add the principal if it doesn't exist"),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'profile_id',
            required=False,
            label=_(u'Profile ID'),
            doc=_(u'Certificate Profile to use'),
        ),
    )
    has_output = (
        output.Output(
            'result',
            dict,
            doc=_(u'Dictionary mapping variable name to value'),
        ),
    )


@register()
class cert_revoke(Command):
    __doc__ = _("Revoke a certificate.")

    takes_args = (
        parameters.Str(
            'serial_number',
            label=_(u'Serial number'),
            doc=_(u'Serial number in decimal or if prefixed with 0x in hexadecimal'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Int(
            'revocation_reason',
            label=_(u'Reason'),
            doc=_(u'Reason for revoking the certificate (0-10)'),
            default=0,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'result',
        ),
    )


@register()
class cert_show(Command):
    __doc__ = _("Retrieve an existing certificate.")

    takes_args = (
        parameters.Str(
            'serial_number',
            label=_(u'Serial number'),
            doc=_(u'Serial number in decimal or if prefixed with 0x in hexadecimal'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'out',
            required=False,
            label=_(u'Output filename'),
            doc=_(u'File to store the certificate in.'),
            exclude=('webui',),
        ),
    )
    has_output = (
        output.Output(
            'result',
        ),
    )


@register()
class cert_status(Command):
    __doc__ = _("Check the status of a certificate signing request.")

    takes_args = (
        parameters.Str(
            'request_id',
            label=_(u'Request id'),
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'result',
        ),
    )
