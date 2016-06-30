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

If using the selfsign back end then the subject in the CSR needs to match
the subject configured in the server. The dogtag CA uses just the CN
value of the CSR and forces the rest of the subject.

A certificate is stored with a service principal and a service principal
needs a host.

In order to request a certificate:

* The host must exist
* The service must exist (or you use the --add option to automatically add it)

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
            doc=_(u'Service principal for this certificate (e.g. HTTP/test.example.com)'),
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
    has_output = (
        output.Output(
            'result',
        ),
    )
