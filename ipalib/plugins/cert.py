# Authors:
#   Andrew Wnuk <awnuk@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#   John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from ipalib import api, SkipPluginModule
if api.env.enable_ra is not True:
    # In this case, abort loading this plugin module...
    raise SkipPluginModule(reason='env.enable_ra is not True')
import os
from ipalib import Command, Str, Int, Bytes, Flag, File
from ipalib import errors
from ipalib import pkcs10
from ipalib import x509
from ipalib import util
from ipalib.plugins.virtual import *
from ipalib.plugins.service import split_principal
import base64
import traceback
from ipalib.text import _
from ipalib.request import context
from ipalib.output import Output
from ipalib.plugins.service import validate_principal
import nss.nss as nss
from nss.error import NSPRError

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

def get_csr_hostname(csr):
    """
    Return the value of CN in the subject of the request or None
    """
    try:
        request = pkcs10.load_certificate_request(csr)
        subject = pkcs10.get_subject(request)
        return subject.common_name
    except NSPRError, nsprerr:
        raise errors.CertificateOperationError(error=_('Failure decoding Certificate Signing Request:'))

def get_subjectaltname(csr):
    """
    Return the first value of the subject alt name, if any
    """
    try:
        request = pkcs10.load_certificate_request(csr)
        for extension in request.extensions:
            if extension.oid_tag == nss.SEC_OID_X509_SUBJECT_ALT_NAME:
                return nss.x509_alt_name(extension.value)[0]
        return None
    except NSPRError, nsprerr:
        raise errors.CertificateOperationError(error=_('Failure decoding Certificate Signing Request'))

def validate_csr(ugettext, csr):
    """
    Ensure the CSR is base64-encoded and can be decoded by our PKCS#10
    parser.
    """
    if api.env.context == 'cli':
        # If we are passed in a pointer to a valid file on the client side
        # escape and let the load_files() handle things
        if csr and os.path.exists(csr):
            return
    try:
        request = pkcs10.load_certificate_request(csr)
    except TypeError, e:
        raise errors.Base64DecodeError(reason=str(e))
    except NSPRError:
        raise errors.CertificateOperationError(error=_('Failure decoding Certificate Signing Request'))
    except Exception, e:
        raise errors.CertificateOperationError(error=_('Failure decoding Certificate Signing Request: %s') % str(e))

def normalize_csr(csr):
    """
    Strip any leading and trailing cruft around the BEGIN/END block
    """
    end_len = 37
    s = csr.find('-----BEGIN NEW CERTIFICATE REQUEST-----')
    if s == -1:
        s = csr.find('-----BEGIN CERTIFICATE REQUEST-----')
    e = csr.find('-----END NEW CERTIFICATE REQUEST-----')
    if e == -1:
        e = csr.find('-----END CERTIFICATE REQUEST-----')
        if e != -1:
            end_len = 33

    if s > -1 and e > -1:
        # We're normalizing here, not validating
        csr = csr[s:e+end_len]

    return csr

def _convert_serial_number(num):
    """
    Convert a SN given in decimal or hexadecimal.
    Returns the number or None if conversion fails.
    """
    # plain decimal or hexa with radix prefix
    try:
        num = int(num, 0)
    except ValueError:
        try:
            # hexa without prefix
            num = int(num, 16)
        except ValueError:
            num = None

    return num

def validate_serial_number(ugettext, num):
    if _convert_serial_number(num) == None:
        return u"Decimal or hexadecimal number is required for serial number"
    return None

def normalize_serial_number(num):
    # It's been already validated
    return unicode(_convert_serial_number(num))

def get_host_from_principal(principal):
    """
    Given a principal with or without a realm return the
    host portion.
    """
    validate_principal(None, principal)
    realm = principal.find('@')
    slash = principal.find('/')
    if realm == -1:
        realm = len(principal)
    hostname = principal[slash+1:realm]

    return hostname

class cert_request(VirtualCommand):
    __doc__ = _('Submit a certificate signing request.')

    takes_args = (
        File('csr', validate_csr,
            label=_('CSR'),
            cli_name='csr_file',
            normalizer=normalize_csr,
        ),
    )
    operation="request certificate"

    takes_options = (
        Str('principal',
            label=_('Principal'),
            doc=_('Service principal for this certificate (e.g. HTTP/test.example.com)'),
        ),
        Str('request_type',
            default=u'pkcs10',
            autofill=True,
        ),
        Flag('add',
            doc=_("automatically add the principal if it doesn't exist"),
            default=False,
            autofill=True
        ),
    )

    has_output_params = (
        Str('certificate',
            label=_('Certificate'),
        ),
        Str('subject',
            label=_('Subject'),
        ),
        Str('issuer',
            label=_('Issuer'),
        ),
        Str('valid_not_before',
            label=_('Not Before'),
        ),
        Str('valid_not_after',
            label=_('Not After'),
        ),
        Str('md5_fingerprint',
            label=_('Fingerprint (MD5)'),
        ),
        Str('sha1_fingerprint',
            label=_('Fingerprint (SHA1)'),
        ),
        Str('serial_number',
            label=_('Serial number'),
        ),
        Str('serial_number_hex',
            label=_('Serial number (hex)'),
        ),
    )

    has_output = (
        Output('result',
            type=dict,
            doc=_('Dictionary mapping variable name to value'),
        ),
    )

    def execute(self, csr, **kw):
        ldap = self.api.Backend.ldap2
        principal = kw.get('principal')
        add = kw.get('add')
        del kw['principal']
        del kw['add']
        service = None

        """
        Access control is partially handled by the ACI titled
        'Hosts can modify service userCertificate'. This is for the case
        where a machine binds using a host/ prinicpal. It can only do the
        request if the target hostname is in the managedBy attribute which
        is managed using the add/del member commands.

        Binding with a user principal one needs to be in the request_certs
        taskgroup (directly or indirectly via role membership).
        """

        bind_principal = getattr(context, 'principal')
        # Can this user request certs?
        if not bind_principal.startswith('host/'):
            self.check_access()

        # FIXME: add support for subject alt name

        # Ensure that the hostname in the CSR matches the principal
        subject_host = get_csr_hostname(csr)
        (servicename, hostname, realm) = split_principal(principal)
        if subject_host.lower() != hostname.lower():
            raise errors.ACIError(
                info=_("hostname in subject of request '%(subject_host)s' "
                    "does not match principal hostname '%(hostname)s'") % dict(
                        subject_host=subject_host, hostname=hostname))

        dn = None
        service = None
        # See if the service exists and punt if it doesn't and we aren't
        # going to add it
        try:
            if not principal.startswith('host/'):
                service = api.Command['service_show'](principal, all=True, raw=True)['result']
                dn = service['dn']
            else:
                hostname = get_host_from_principal(principal)
                service = api.Command['host_show'](hostname, all=True, raw=True)['result']
                dn = service['dn']
        except errors.NotFound, e:
            if not add:
                raise errors.NotFound(reason=_("The service principal for "
                    "this request doesn't exist."))
            try:
                service = api.Command['service_add'](principal, **{'force': True})['result']
                dn = service['dn']
            except errors.ACIError:
                raise errors.ACIError(info=_('You need to be a member of '
                    'the serviceadmin role to add services'))

        # We got this far so the service entry exists, can we write it?
        if not ldap.can_write(dn, "usercertificate"):
            raise errors.ACIError(info=_("Insufficient 'write' privilege "
                "to the 'userCertificate' attribute of entry '%s'.") % dn)

        # Validate the subject alt name, if any
        request = pkcs10.load_certificate_request(csr)
        subjectaltname = pkcs10.get_subjectaltname(request)
        if subjectaltname is not None:
            for name in subjectaltname:
                name = unicode(name)
                try:
                    hostentry = api.Command['host_show'](name, all=True, raw=True)['result']
                    hostdn = hostentry['dn']
                except errors.NotFound:
                    # We don't want to issue any certificates referencing
                    # machines we don't know about. Nothing is stored in this
                    # host record related to this certificate.
                    raise errors.NotFound(reason=_('no host record for '
                        'subject alt name %s in certificate request') % name)
                authprincipal = getattr(context, 'principal')
                if authprincipal.startswith("host/"):
                    if not hostdn in service.get('managedby', []):
                        raise errors.ACIError(info=_(
                            "Insufficient privilege to create a certificate "
                            "with subject alt name '%s'.") % name)

        if 'usercertificate' in service:
            serial = x509.get_serial_number(service['usercertificate'][0], datatype=x509.DER)
            # revoke the certificate and remove it from the service
            # entry before proceeding. First we retrieve the certificate to
            # see if it is already revoked, if not then we revoke it.
            try:
                result = api.Command['cert_show'](unicode(serial))['result']
                if 'revocation_reason' not in result:
                    try:
                        api.Command['cert_revoke'](unicode(serial), revocation_reason=4)
                    except errors.NotImplementedError:
                        # some CA's might not implement revoke
                        pass
            except errors.NotImplementedError:
                # some CA's might not implement get
                pass
            if not principal.startswith('host/'):
                api.Command['service_mod'](principal, usercertificate=None)
            else:
                hostname = get_host_from_principal(principal)
                api.Command['host_mod'](hostname, usercertificate=None)

        # Request the certificate
        result = self.Backend.ra.request_certificate(csr, **kw)
        cert = x509.load_certificate(result['certificate'])
        result['issuer'] = unicode(cert.issuer)
        result['valid_not_before'] = unicode(cert.valid_not_before_str)
        result['valid_not_after'] = unicode(cert.valid_not_after_str)
        result['md5_fingerprint'] = unicode(nss.data_to_hex(nss.md5_digest(cert.der_data), 64)[0])
        result['sha1_fingerprint'] = unicode(nss.data_to_hex(nss.sha1_digest(cert.der_data), 64)[0])

        # Success? Then add it to the service entry.
        if 'certificate' in result:
            if not principal.startswith('host/'):
                skw = {"usercertificate": str(result.get('certificate'))}
                api.Command['service_mod'](principal, **skw)
            else:
                hostname = get_host_from_principal(principal)
                skw = {"usercertificate": str(result.get('certificate'))}
                api.Command['host_mod'](hostname, **skw)

        return dict(
            result=result
        )

api.register(cert_request)


class cert_status(VirtualCommand):
    __doc__ = _('Check the status of a certificate signing request.')

    takes_args = (
        Str('request_id',
            label=_('Request id'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
    )
    has_output_params = (
        Str('cert_request_status',
            label=_('Request status'),
        ),
    )
    operation = "certificate status"


    def execute(self, request_id, **kw):
        self.check_access()
        return dict(
            result=self.Backend.ra.check_request_status(request_id)
        )

api.register(cert_status)


_serial_number = Str('serial_number',
    validate_serial_number,
    label=_('Serial number'),
    doc=_('Serial number in decimal or if prefixed with 0x in hexadecimal'),
    normalizer=normalize_serial_number,
)

class cert_show(VirtualCommand):
    __doc__ = _('Retrieve an existing certificate.')

    takes_args = _serial_number

    has_output_params = (
        Str('certificate',
            label=_('Certificate'),
        ),
        Str('subject',
            label=_('Subject'),
        ),
        Str('issuer',
            label=_('Issuer'),
        ),
        Str('valid_not_before',
            label=_('Not Before'),
        ),
        Str('valid_not_after',
            label=_('Not After'),
        ),
        Str('md5_fingerprint',
            label=_('Fingerprint (MD5)'),
        ),
        Str('sha1_fingerprint',
            label=_('Fingerprint (SHA1)'),
        ),
        Str('revocation_reason',
            label=_('Revocation reason'),
        ),
        Str('serial_number_hex',
            label=_('Serial number (hex)'),
        ),
    )

    takes_options = (
        Str('out?',
            label=_('Output filename'),
            doc=_('File to store the certificate in.'),
            exclude='webui',
        ),
    )

    operation="retrieve certificate"

    def execute(self, serial_number, **options):
        hostname = None
        try:
            self.check_access()
        except errors.ACIError, acierr:
            self.debug("Not granted by ACI to retrieve certificate, looking at principal")
            bind_principal = getattr(context, 'principal')
            if not bind_principal.startswith('host/'):
                raise acierr
            hostname = get_host_from_principal(bind_principal)

        result=self.Backend.ra.get_certificate(serial_number)
        cert = x509.load_certificate(result['certificate'])
        result['subject'] = unicode(cert.subject)
        result['issuer'] = unicode(cert.issuer)
        result['valid_not_before'] = unicode(cert.valid_not_before_str)
        result['valid_not_after'] = unicode(cert.valid_not_after_str)
        result['md5_fingerprint'] = unicode(nss.data_to_hex(nss.md5_digest(cert.der_data), 64)[0])
        result['sha1_fingerprint'] = unicode(nss.data_to_hex(nss.sha1_digest(cert.der_data), 64)[0])
        if hostname:
            # If we have a hostname we want to verify that the subject
            # of the certificate matches it, otherwise raise an error
            if hostname != cert.subject.common_name:    #pylint: disable=E1101
                raise acierr

        return dict(result=result)

    def forward(self, *keys, **options):
        if 'out' in options:
            util.check_writable_file(options['out'])
            result = super(cert_show, self).forward(*keys, **options)
            if 'certificate' in result['result']:
                x509.write_certificate(result['result']['certificate'], options['out'])
                return result
            else:
                raise errors.NoCertificateError(entry=keys[-1])
        else:
            return super(cert_show, self).forward(*keys, **options)


api.register(cert_show)


class cert_revoke(VirtualCommand):
    __doc__ = _('Revoke a certificate.')

    takes_args = _serial_number

    has_output_params = (
        Flag('revoked',
            label=_('Revoked'),
        ),
    )
    operation = "revoke certificate"

    # FIXME: The default is 0.  Is this really an Int param?
    takes_options = (
        Int('revocation_reason',
            label=_('Reason'),
            doc=_('Reason for revoking the certificate (0-10)'),
            minvalue=0,
            maxvalue=10,
            default=0,
            autofill=True
        ),
    )

    def execute(self, serial_number, **kw):
        hostname = None
        try:
            self.check_access()
        except errors.ACIError, acierr:
            self.debug("Not granted by ACI to revoke certificate, looking at principal")
            try:
                # Let cert_show() handle verifying that the subject of the
                # cert we're dealing with matches the hostname in the principal
                result = api.Command['cert_show'](unicode(serial_number))['result']
            except errors.NotImplementedError:
                pass
        if kw['revocation_reason'] == 7:
            raise errors.CertificateOperationError(error=_('7 is not a valid revocation reason'))
        return dict(
            result=self.Backend.ra.revoke_certificate(serial_number, **kw)
        )

api.register(cert_revoke)


class cert_remove_hold(VirtualCommand):
    __doc__ = _('Take a revoked certificate off hold.')

    takes_args = _serial_number

    has_output_params = (
        Flag('unrevoked',
            label=_('Unrevoked'),
        ),
        Str('error_string',
            label=_('Error'),
        ),
    )
    operation = "certificate remove hold"

    def execute(self, serial_number, **kw):
        self.check_access()
        return dict(
            result=self.Backend.ra.take_certificate_off_hold(serial_number)
        )

api.register(cert_remove_hold)
