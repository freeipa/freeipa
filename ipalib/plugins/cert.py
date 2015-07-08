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

import os
import time
from ipalib import Command, Str, Int, Bytes, Flag, File
from ipalib import api
from ipalib import errors
from ipalib import pkcs10
from ipalib import x509
from ipalib import util
from ipalib import ngettext
from ipalib.plugable import Registry
from ipalib.plugins.virtual import *
from ipalib.plugins.baseldap import pkey_to_value
from ipalib.plugins.service import split_any_principal
from ipalib.plugins.certprofile import validate_profile_id
import ipalib.plugins.caacl
import base64
import traceback
from ipalib.text import _
from ipalib.request import context
from ipalib import output
from ipalib.plugins.service import validate_principal
import nss.nss as nss
from nss.error import NSPRError
from pyasn1.error import PyAsn1Error

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

USER, HOST, SERVICE = range(3)

register = Registry()

def validate_pkidate(ugettext, value):
    """
    A date in the format of %Y-%m-%d
    """
    try:
        ts = time.strptime(value, '%Y-%m-%d')
    except ValueError, e:
        return str(e)

    return None

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
    except Exception, e:
        raise errors.CertificateOperationError(error=_('Failure decoding Certificate Signing Request: %s') % e)

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

def ca_enabled_check():
    if not api.Command.ca_is_enabled()['result']:
        raise errors.NotFound(reason=_('CA is not configured'))

def caacl_check(principal_type, principal_string, ca, profile_id):
    principal_type_map = {USER: 'user', HOST: 'host', SERVICE: 'service'}
    if not ipalib.plugins.caacl.acl_evaluate(
            principal_type_map[principal_type],
            principal_string, ca, profile_id):
        raise errors.ACIError(info=_(
                "Principal '%(principal)s' "
                "is not permitted to use CA '%(ca)s' "
                "with profile '%(profile_id)s' for certificate issuance."
            ) % dict(
                principal=principal_string,
                ca=ca or '.',
                profile_id=profile_id
            )
        )

@register()
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
            doc=_('Principal for this certificate (e.g. HTTP/test.example.com)'),
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
        Str('profile_id?', validate_profile_id,
            label=_("Profile ID"),
            doc=_("Certificate Profile to use"),
        )
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
        output.Output('result',
            type=dict,
            doc=_('Dictionary mapping variable name to value'),
        ),
    )

    _allowed_extensions = {
        '2.5.29.14': None,      # Subject Key Identifier
        '2.5.29.15': None,      # Key Usage
        '2.5.29.17': 'request certificate with subjectaltname',
        '2.5.29.19': None,      # Basic Constraints
        '2.5.29.37': None,      # Extended Key Usage
    }

    def execute(self, csr, **kw):
        ca_enabled_check()

        ldap = self.api.Backend.ldap2
        add = kw.get('add')
        request_type = kw.get('request_type')
        profile_id = kw.get('profile_id', self.Backend.ra.DEFAULT_PROFILE)
        ca = '.'  # top-level CA hardcoded until subca plugin implemented

        """
        Access control is partially handled by the ACI titled
        'Hosts can modify service userCertificate'. This is for the case
        where a machine binds using a host/ prinicpal. It can only do the
        request if the target hostname is in the managedBy attribute which
        is managed using the add/del member commands.

        Binding with a user principal one needs to be in the request_certs
        taskgroup (directly or indirectly via role membership).
        """

        principal_string = kw.get('principal')
        principal = split_any_principal(principal_string)
        servicename, principal_name, realm = principal
        if servicename is None:
            principal_type = USER
        elif servicename == 'host':
            principal_type = HOST
        else:
            principal_type = SERVICE

        caacl_check(principal_type, principal_string, ca, profile_id)

        bind_principal = split_any_principal(getattr(context, 'principal'))
        bind_service, bind_name, bind_realm = bind_principal

        if bind_service is None:
            bind_principal_type = USER
        elif bind_service == 'host':
            bind_principal_type = HOST
        else:
            bind_principal_type = SERVICE

        if bind_principal != principal and bind_principal_type != HOST:
            # Can the bound principal request certs for another principal?
            self.check_access()

        try:
            subject = pkcs10.get_subject(csr)
            extensions = pkcs10.get_extensions(csr)
            subjectaltname = pkcs10.get_subjectaltname(csr) or ()
        except (NSPRError, PyAsn1Error), e:
            raise errors.CertificateOperationError(
                error=_("Failure decoding Certificate Signing Request: %s") % e)

        # host principals may bypass allowed ext check
        if bind_principal_type != HOST:
            for ext in extensions:
                operation = self._allowed_extensions.get(ext)
                if operation:
                    self.check_access(operation)

        dn = None
        principal_obj = None
        # See if the service exists and punt if it doesn't and we aren't
        # going to add it
        try:
            if principal_type == SERVICE:
                principal_obj = api.Command['service_show'](principal_string, all=True)
            elif principal_type == HOST:
                principal_obj = api.Command['host_show'](principal_name, all=True)
            elif principal_type == USER:
                principal_obj = api.Command['user_show'](principal_name, all=True)
        except errors.NotFound as e:
            if principal_type == SERVICE and add:
                principal_obj = api.Command['service_add'](principal_string, force=True)
            else:
                raise errors.NotFound(
                    reason=_("The principal for this request doesn't exist."))
        principal_obj = principal_obj['result']
        dn = principal_obj['dn']

        # Ensure that the DN in the CSR matches the principal
        cn = subject.common_name  #pylint: disable=E1101
        if not cn:
            raise errors.ValidationError(name='csr',
                error=_("No Common Name was found in subject of request."))

        if principal_type in (SERVICE, HOST):
            if cn.lower() != principal_name.lower():
                raise errors.ACIError(
                    info=_("hostname in subject of request '%(cn)s' "
                        "does not match principal hostname '%(hostname)s'")
                        % dict(cn=cn, hostname=principal_name))
        elif principal_type == USER:
            # check user name
            if cn != principal_name:
                raise errors.ValidationError(
                    name='csr',
                    error=_("DN commonName does not match user's login")
                )

            # check email address
            mail = subject.email_address  #pylint: disable=E1101
            if mail is not None and mail not in principal_obj.get('mail', []):
                raise errors.ValidationError(
                    name='csr',
                    error=_(
                        "DN emailAddress does not match "
                        "any of user's email addresses")
                )

        for ext in extensions:
            if ext not in self._allowed_extensions:
                raise errors.ValidationError(
                    name='csr', error=_("extension %s is forbidden") % ext)

        # We got this far so the principal entry exists, can we write it?
        if not ldap.can_write(dn, "usercertificate"):
            raise errors.ACIError(info=_("Insufficient 'write' privilege "
                "to the 'userCertificate' attribute of entry '%s'.") % dn)

        # Validate the subject alt name, if any
        for name_type, name in subjectaltname:
            if name_type == pkcs10.SAN_DNSNAME:
                name = unicode(name)
                alt_principal_obj = None
                alt_principal_string = None
                try:
                    if principal_type == HOST:
                        alt_principal_string = 'host/%s@%s' % (name, realm)
                        alt_principal_obj = api.Command['host_show'](name, all=True)
                    elif principal_type == SERVICE:
                        alt_principal_string = '%s/%s@%s' % (servicename, name, realm)
                        alt_principal_obj = api.Command['service_show'](
                            alt_principal_string, all=True)
                    elif principal_type == USER:
                        raise errors.ValidationError(
                            name='csr',
                            error=_("subject alt name type %s is forbidden "
                                "for user principals") % name_type
                        )
                except errors.NotFound:
                    # We don't want to issue any certificates referencing
                    # machines we don't know about. Nothing is stored in this
                    # host record related to this certificate.
                    raise errors.NotFound(reason=_('The service principal for '
                        'subject alt name %s in certificate request does not '
                        'exist') % name)
                if alt_principal_obj is not None:
                    altdn = alt_principal_obj['result']['dn']
                    if not ldap.can_write(altdn, "usercertificate"):
                        raise errors.ACIError(info=_(
                            "Insufficient privilege to create a certificate "
                            "with subject alt name '%s'.") % name)
                if alt_principal_string is not None:
                    caacl_check(
                        principal_type, alt_principal_string, ca, profile_id)
            elif name_type in (pkcs10.SAN_OTHERNAME_KRB5PRINCIPALNAME,
                               pkcs10.SAN_OTHERNAME_UPN):
                if name != principal_string:
                    raise errors.ACIError(
                        info=_("Principal '%s' in subject alt name does not "
                               "match requested principal") % name)
            elif name_type == pkcs10.SAN_RFC822NAME:
                if principal_type == USER:
                    if name not in principal_obj.get('mail', []):
                        raise errors.ValidationError(
                            name='csr',
                            error=_(
                                "RFC822Name does not match "
                                "any of user's email addresses")
                        )
                else:
                    raise errors.ValidationError(
                        name='csr',
                        error=_("subject alt name type %s is forbidden "
                            "for non-user principals") % name_type
                    )
            else:
                raise errors.ACIError(
                    info=_("Subject alt name type %s is forbidden") %
                         name_type)

        # Request the certificate
        result = self.Backend.ra.request_certificate(
            csr, profile_id, request_type=request_type)
        cert = x509.load_certificate(result['certificate'])
        result['issuer'] = unicode(cert.issuer)
        result['valid_not_before'] = unicode(cert.valid_not_before_str)
        result['valid_not_after'] = unicode(cert.valid_not_after_str)
        result['md5_fingerprint'] = unicode(nss.data_to_hex(nss.md5_digest(cert.der_data), 64)[0])
        result['sha1_fingerprint'] = unicode(nss.data_to_hex(nss.sha1_digest(cert.der_data), 64)[0])

        # Success? Then add it to the principal's entry
        # (unless the profile tells us not to)
        profile = api.Command['certprofile_show'](profile_id)
        store = profile['result']['ipacertprofilestoreissued'][0] == 'TRUE'
        if store and 'certificate' in result:
            cert = str(result.get('certificate'))
            kwargs = dict(addattr=u'usercertificate={}'.format(cert))
            if principal_type == SERVICE:
                api.Command['service_mod'](principal_string, **kwargs)
            elif principal_type == HOST:
                api.Command['host_mod'](principal_name, **kwargs)
            elif principal_type == USER:
                api.Command['user_mod'](principal_name, **kwargs)

        return dict(
            result=result
        )



@register()
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
        ca_enabled_check()
        self.check_access()
        return dict(
            result=self.Backend.ra.check_request_status(request_id)
        )



_serial_number = Str('serial_number',
    validate_serial_number,
    label=_('Serial number'),
    doc=_('Serial number in decimal or if prefixed with 0x in hexadecimal'),
    normalizer=normalize_serial_number,
)

@register()
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
        ca_enabled_check()
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




@register()
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
        ca_enabled_check()
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
        revocation_reason = kw['revocation_reason']
        if revocation_reason == 7:
            raise errors.CertificateOperationError(error=_('7 is not a valid revocation reason'))
        return dict(
            result=self.Backend.ra.revoke_certificate(
                serial_number, revocation_reason=revocation_reason)
        )



@register()
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
        ca_enabled_check()
        self.check_access()
        return dict(
            result=self.Backend.ra.take_certificate_off_hold(serial_number)
        )



@register()
class cert_find(Command):
    __doc__ = _('Search for existing certificates.')

    takes_options = (
        Str('subject?',
            label=_('Subject'),
            doc=_('Subject'),
            autofill=False,
        ),
        Int('revocation_reason?',
            label=_('Reason'),
            doc=_('Reason for revoking the certificate (0-10)'),
            minvalue=0,
            maxvalue=10,
            autofill=False,
        ),
        Int('min_serial_number?',
            doc=_("minimum serial number"),
            autofill=False,
            minvalue=0,
            maxvalue=2147483647,
        ),
        Int('max_serial_number?',
            doc=_("maximum serial number"),
            autofill=False,
            minvalue=0,
            maxvalue=2147483647,
        ),
        Flag('exactly?',
            doc=_('match the common name exactly'),
            autofill=False,
        ),
        Str('validnotafter_from?', validate_pkidate,
            doc=_('Valid not after from this date (YYYY-mm-dd)'),
            autofill=False,
        ),
        Str('validnotafter_to?', validate_pkidate,
            doc=_('Valid not after to this date (YYYY-mm-dd)'),
            autofill=False,
        ),
        Str('validnotbefore_from?', validate_pkidate,
            doc=_('Valid not before from this date (YYYY-mm-dd)'),
            autofill=False,
        ),
        Str('validnotbefore_to?', validate_pkidate,
            doc=_('Valid not before to this date (YYYY-mm-dd)'),
            autofill=False,
        ),
        Str('issuedon_from?', validate_pkidate,
            doc=_('Issued on from this date (YYYY-mm-dd)'),
            autofill=False,
        ),
        Str('issuedon_to?', validate_pkidate,
            doc=_('Issued on to this date (YYYY-mm-dd)'),
            autofill=False,
        ),
        Str('revokedon_from?', validate_pkidate,
            doc=_('Revoked on from this date (YYYY-mm-dd)'),
            autofill=False,
        ),
        Str('revokedon_to?', validate_pkidate,
            doc=_('Revoked on to this date (YYYY-mm-dd)'),
            autofill=False,
        ),
        Int('sizelimit?',
            label=_('Size Limit'),
            doc=_('Maximum number of certs returned'),
            flags=['no_display'],
            minvalue=0,
            default=100,
        ),
    )

    has_output = output.standard_list_of_entries
    has_output_params = (
        Str('serial_number_hex',
            label=_('Serial number (hex)'),
        ),
        Str('serial_number',
            label=_('Serial number'),
        ),
        Str('status',
            label=_('Status'),
        ),
    )

    msg_summary = ngettext(
        '%(count)d certificate matched', '%(count)d certificates matched', 0
    )

    def execute(self, **options):
        ca_enabled_check()
        ret = dict(
            result=self.Backend.ra.find(options)
        )
        ret['count'] = len(ret['result'])
        ret['truncated'] = False
        return ret


@register()
class ca_is_enabled(Command):
    """
    Checks if any of the servers has the CA service enabled.
    """
    NO_CLI = True
    has_output = output.standard_value

    def execute(self, *args, **options):
        base_dn = DN(('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'),
                     self.api.env.basedn)
        filter = '(&(objectClass=ipaConfigObject)(cn=CA))'
        try:
            self.api.Backend.ldap2.find_entries(
                base_dn=base_dn, filter=filter, attrs_list=[])
        except errors.NotFound:
            result = False
        else:
            result = True
        return dict(result=result, value=pkey_to_value(None, options))
