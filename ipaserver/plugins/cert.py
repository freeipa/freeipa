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

import base64
import binascii
import datetime
import os

from nss import nss
from nss.error import NSPRError
from pyasn1.error import PyAsn1Error
import six

from ipalib import Command, Str, Int, Flag
from ipalib import api
from ipalib import errors
from ipalib import pkcs10
from ipalib import x509
from ipalib import ngettext
from ipalib.constants import IPA_CA_CN
from ipalib.crud import Create, PKQuery, Retrieve, Search
from ipalib.frontend import Method, Object
from ipalib.parameters import Bytes, DateTime, DNParam
from ipalib.plugable import Registry
from .virtual import VirtualCommand
from .baseldap import pkey_to_value
from .service import split_any_principal
from .certprofile import validate_profile_id
from .caacl import acl_evaluate
from ipalib.text import _
from ipalib.request import context
from ipalib import output
from .service import validate_principal
from ipapython.dn import DN

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

 Search for certificates owned by a specific user:
   ipa cert-find --user=user

 Examine a certificate:
   ipa cert-find --file=cert.pem --all

 Verify that a certificate is owner by a specific user:
   ipa cert-find --file=cert.pem --user=user

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

PKIDATE_FORMAT = '%Y-%m-%d'


def normalize_pkidate(value):
    return datetime.datetime.strptime(value, PKIDATE_FORMAT)


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
    except (TypeError, binascii.Error) as e:
        raise errors.Base64DecodeError(reason=str(e))
    except Exception as e:
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


def normalize_serial_number(num):
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
            pass

    return unicode(num)


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
    if not acl_evaluate(
            principal_type_map[principal_type],
            principal_string, ca, profile_id):
        raise errors.ACIError(info=_(
                "Principal '%(principal)s' "
                "is not permitted to use CA '%(ca)s' "
                "with profile '%(profile_id)s' for certificate issuance."
            ) % dict(
                principal=principal_string,
                ca=ca,
                profile_id=profile_id
            )
        )


def validate_certificate(value):
    return x509.validate_certificate(value, x509.DER)


class BaseCertObject(Object):
    takes_params = (
        Bytes(
            'certificate', validate_certificate,
            label=_("Certificate"),
            doc=_("Base-64 encoded certificate."),
            normalizer=x509.normalize_certificate,
            flags={'no_create', 'no_update', 'no_search'},
        ),
        DNParam(
            'subject',
            label=_('Subject'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        DNParam(
            'issuer',
            label=_('Issuer'),
            doc=_('Issuer DN'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        DateTime(
            'valid_not_before',
            label=_('Not Before'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        DateTime(
            'valid_not_after',
            label=_('Not After'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'md5_fingerprint',
            label=_('Fingerprint (MD5)'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'sha1_fingerprint',
            label=_('Fingerprint (SHA1)'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Int(
            'serial_number',
            label=_('Serial number'),
            doc=_('Serial number in decimal or if prefixed with 0x in hexadecimal'),
            normalizer=normalize_serial_number,
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'serial_number_hex',
            label=_('Serial number (hex)'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
    )

    def _parse(self, obj):
        cert = x509.load_certificate(obj['certificate'])
        obj['subject'] = DN(unicode(cert.subject))
        obj['issuer'] = DN(unicode(cert.issuer))
        obj['valid_not_before'] = unicode(cert.valid_not_before_str)
        obj['valid_not_after'] = unicode(cert.valid_not_after_str)
        obj['md5_fingerprint'] = unicode(
            nss.data_to_hex(nss.md5_digest(cert.der_data), 64)[0])
        obj['sha1_fingerprint'] = unicode(
            nss.data_to_hex(nss.sha1_digest(cert.der_data), 64)[0])
        obj['serial_number'] = cert.serial_number
        obj['serial_number_hex'] = u'0x%X' % cert.serial_number


class BaseCertMethod(Method):
    def get_options(self):
        yield Str('cacn?',
            cli_name='ca',
            query=True,
            label=_('Issuing CA'),
            doc=_('Name of issuing CA'),
        )

        for option in super(BaseCertMethod, self).get_options():
            yield option


@register()
class certreq(BaseCertObject):
    takes_params = BaseCertObject.takes_params + (
        Str(
            'request_type',
            default=u'pkcs10',
            autofill=True,
            flags={'no_update', 'no_update', 'no_search'},
        ),
        Str(
            'profile_id?', validate_profile_id,
            label=_("Profile ID"),
            doc=_("Certificate Profile to use"),
            flags={'no_update', 'no_update', 'no_search'},
        ),
        Str(
            'cert_request_status',
            label=_('Request status'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Int(
            'request_id',
            label=_('Request id'),
            primary_key=True,
            flags={'no_create', 'no_update', 'no_search', 'no_output'},
        ),
    )


@register()
class cert_request(Create, BaseCertMethod, VirtualCommand):
    __doc__ = _('Submit a certificate signing request.')

    obj_name = 'certreq'
    attr_name = 'request'

    takes_args = (
        Str(
            'csr', validate_csr,
            label=_('CSR'),
            cli_name='csr_file',
            normalizer=normalize_csr,
            noextrawhitespace=False,
        ),
    )
    operation="request certificate"

    takes_options = (
        Str(
            'principal',
            label=_('Principal'),
            doc=_('Principal for this certificate (e.g. HTTP/test.example.com)'),
        ),
        Flag(
            'add',
            doc=_("automatically add the principal if it doesn't exist"),
        ),
    )

    def get_args(self):
        # FIXME: the 'no_create' flag is ignored for positional arguments
        for arg in super(cert_request, self).get_args():
            if arg.name == 'request_id':
                continue
            yield arg

    def execute(self, csr, all=False, raw=False, **kw):
        ca_enabled_check()

        ldap = self.api.Backend.ldap2
        add = kw.get('add')
        request_type = kw.get('request_type')
        profile_id = kw.get('profile_id', self.Backend.ra.DEFAULT_PROFILE)

        # Check that requested authority exists (done before CA ACL
        # enforcement so that user gets better error message if
        # referencing nonexistant CA) and look up authority ID.
        #
        ca = kw.get('cacn', IPA_CA_CN)
        ca_id = api.Command.ca_show(ca)['result']['ipacaid'][0]

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
            self.check_access("request certificate ignore caacl")
            bypass_caacl = True
        except errors.ACIError:
            bypass_caacl = False

        if not bypass_caacl:
            caacl_check(principal_type, principal_string, ca, profile_id)

        try:
            subject = pkcs10.get_subject(csr)
            extensions = pkcs10.get_extensions(csr)
            subjectaltname = pkcs10.get_subjectaltname(csr) or ()
        except (NSPRError, PyAsn1Error, ValueError) as e:
            raise errors.CertificateOperationError(
                error=_("Failure decoding Certificate Signing Request: %s") % e)

        # self-service and host principals may bypass SAN permission check
        if bind_principal != principal and bind_principal_type != HOST:
            if '2.5.29.17' in extensions:
                self.check_access('request certificate with subjectaltname')

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
                if alt_principal_string is not None and not bypass_caacl:
                    caacl_check(
                        principal_type, alt_principal_string, ca, profile_id)
            elif name_type in (pkcs10.SAN_OTHERNAME_KRB5PRINCIPALNAME,
                               pkcs10.SAN_OTHERNAME_UPN):
                if split_any_principal(name) != principal:
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
            csr, profile_id, ca_id, request_type=request_type)
        if not raw:
            self.obj._parse(result)
            result['request_id'] = int(result['request_id'])

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
            result=result,
            value=pkey_to_value(int(result['request_id']), kw),
        )


@register()
class cert_status(Retrieve, BaseCertMethod, VirtualCommand):
    __doc__ = _('Check the status of a certificate signing request.')

    obj_name = 'certreq'
    attr_name = 'status'

    operation = "certificate status"

    def get_options(self):
        for option in super(cert_status, self).get_options():
            if option.name == 'cacn':
                continue
            yield option

    def execute(self, request_id, **kw):
        ca_enabled_check()
        self.check_access()
        return dict(
            result=self.Backend.ra.check_request_status(str(request_id)),
            value=pkey_to_value(request_id, kw),
        )


@register()
class cert(BaseCertObject):
    takes_params = BaseCertObject.takes_params + (
        Str(
            'status',
            label=_('Status'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Flag(
            'revoked',
            label=_('Revoked'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Int(
            'revocation_reason',
            label=_('Revocation reason'),
            doc=_('Reason for revoking the certificate (0-10)'),
            minvalue=0,
            maxvalue=10,
            flags={'no_create', 'no_update'},
        ),
    )

    def get_params(self):
        for param in super(cert, self).get_params():
            if param.name == 'serial_number':
                param = param.clone(primary_key=True)
            elif param.name in ('certificate', 'issuer'):
                param = param.clone(flags=param.flags - {'no_search'})
            yield param

        for owner in self._owners():
            yield owner.primary_key.clone_rename(
                'owner_{0}'.format(owner.name),
                required=False,
                multivalue=True,
                primary_key=False,
                label=_("Owner %s") % owner.object_name,
                flags={'no_create', 'no_update', 'no_search'},
            )

    def _owners(self):
        for name in ('user', 'host', 'service'):
            yield self.api.Object[name]

    def _fill_owners(self, obj):
        for owner in self._owners():
            container_dn = DN(owner.container_dn, self.api.env.basedn)
            name = 'owner_' + owner.name
            for dn in obj['owner']:
                if dn.endswith(container_dn, 1):
                    value = owner.get_primary_key_from_dn(dn)
                    obj.setdefault(name, []).append(value)


class CertMethod(BaseCertMethod):
    def get_options(self):
        for option in super(CertMethod, self).get_options():
            yield option

        for o in self.has_output:
            if isinstance(o, (output.Entry, output.ListOfEntries)):
                yield Flag(
                    'no_members',
                    doc=_("Suppress processing of membership attributes."),
                    exclude='webui',
                    flags={'no_output'},
                )
                break


@register()
class cert_show(Retrieve, CertMethod, VirtualCommand):
    __doc__ = _('Retrieve an existing certificate.')

    takes_options = (
        Str('out?',
            label=_('Output filename'),
            doc=_('File to store the certificate in.'),
            exclude='webui',
        ),
    )

    operation="retrieve certificate"

    def execute(self, serial_number, all=False, raw=False, no_members=False,
                **options):
        ca_enabled_check()
        hostname = None
        try:
            self.check_access()
        except errors.ACIError as acierr:
            self.debug("Not granted by ACI to retrieve certificate, looking at principal")
            bind_principal = getattr(context, 'principal')
            if not bind_principal.startswith('host/'):
                raise acierr
            hostname = get_host_from_principal(bind_principal)

        issuer_dn = None
        if 'cacn' in options:
            ca_obj = api.Command.ca_show(options['cacn'])['result']
            issuer_dn = ca_obj['ipacasubjectdn'][0]

        # Dogtag lightweight CAs have shared serial number domain, so
        # we don't tell Dogtag the issuer (but we check the cert after).
        #
        result = self.Backend.ra.get_certificate(str(serial_number))
        cert = x509.load_certificate(result['certificate'])

        if issuer_dn is not None and DN(unicode(cert.issuer)) != DN(issuer_dn):
            # DN of cert differs from what we requested
            raise errors.NotFound(
                reason=_("Certificate with serial number %(serial)s "
                    "issued by CA '%(ca)s' not found")
                    % dict(serial=serial_number, ca=options['cacn']))

        if all or not no_members:
            ldap = self.api.Backend.ldap2
            filter = ldap.make_filter_from_attr(
                'usercertificate', base64.b64decode(result['certificate']))
            try:
                entries = ldap.get_entries(base_dn=self.api.env.basedn,
                                           filter=filter,
                                           attrs_list=[''])
            except errors.EmptyResult:
                entries = []
            for entry in entries:
                result.setdefault('owner', []).append(entry.dn)

        if not raw:
            result['certificate'] = result['certificate'].replace('\r\n', '')
            self.obj._parse(result)
            result['revoked'] = ('revocation_reason' in result)
            if 'owner' in result:
                self.obj._fill_owners(result)
                del result['owner']

        if hostname:
            # If we have a hostname we want to verify that the subject
            # of the certificate matches it, otherwise raise an error
            if hostname != cert.subject.common_name:    #pylint: disable=E1101
                raise acierr

        return dict(result=result, value=pkey_to_value(serial_number, options))


@register()
class cert_revoke(PKQuery, CertMethod, VirtualCommand):
    __doc__ = _('Revoke a certificate.')

    operation = "revoke certificate"

    def get_options(self):
        # FIXME: The default is 0.  Is this really an Int param?
        yield self.obj.params['revocation_reason'].clone(
            default=0,
            autofill=True,
        )

        for option in super(cert_revoke, self).get_options():
            if option.name == 'cacn':
                continue
            yield option

    def execute(self, serial_number, **kw):
        ca_enabled_check()
        hostname = None
        try:
            self.check_access()
        except errors.ACIError as acierr:
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
                str(serial_number), revocation_reason=revocation_reason)
        )



@register()
class cert_remove_hold(PKQuery, CertMethod, VirtualCommand):
    __doc__ = _('Take a revoked certificate off hold.')

    has_output_params = (
        Flag('unrevoked',
            label=_('Unrevoked'),
        ),
        Str('error_string',
            label=_('Error'),
        ),
    )
    operation = "certificate remove hold"

    def get_options(self):
        for option in super(cert_remove_hold, self).get_options():
            if option.name == 'cacn':
                continue
            yield option

    def execute(self, serial_number, **kw):
        ca_enabled_check()
        self.check_access()
        return dict(
            result=self.Backend.ra.take_certificate_off_hold(
                str(serial_number))
        )


@register()
class cert_find(Search, CertMethod):
    __doc__ = _('Search for existing certificates.')

    takes_options = (
        Str('subject?',
            label=_('Subject'),
            doc=_('Subject'),
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
        DateTime('validnotafter_from?',
            doc=_('Valid not after from this date (YYYY-mm-dd)'),
            normalizer=normalize_pkidate,
            autofill=False,
        ),
        DateTime('validnotafter_to?',
            doc=_('Valid not after to this date (YYYY-mm-dd)'),
            normalizer=normalize_pkidate,
            autofill=False,
        ),
        DateTime('validnotbefore_from?',
            doc=_('Valid not before from this date (YYYY-mm-dd)'),
            normalizer=normalize_pkidate,
            autofill=False,
        ),
        DateTime('validnotbefore_to?',
            doc=_('Valid not before to this date (YYYY-mm-dd)'),
            normalizer=normalize_pkidate,
            autofill=False,
        ),
        DateTime('issuedon_from?',
            doc=_('Issued on from this date (YYYY-mm-dd)'),
            normalizer=normalize_pkidate,
            autofill=False,
        ),
        DateTime('issuedon_to?',
            doc=_('Issued on to this date (YYYY-mm-dd)'),
            normalizer=normalize_pkidate,
            autofill=False,
        ),
        DateTime('revokedon_from?',
            doc=_('Revoked on from this date (YYYY-mm-dd)'),
            normalizer=normalize_pkidate,
            autofill=False,
        ),
        DateTime('revokedon_to?',
            doc=_('Revoked on to this date (YYYY-mm-dd)'),
            normalizer=normalize_pkidate,
            autofill=False,
        ),
        Flag('pkey_only?',
            label=_("Primary key only"),
            doc=_("Results should contain primary key attribute only "
                  "(\"certificate\")"),
        ),
        Int('timelimit?',
            label=_('Time Limit'),
            doc=_('Time limit of search in seconds (0 is unlimited)'),
            minvalue=0,
        ),
        Int('sizelimit?',
            label=_("Size Limit"),
            doc=_("Maximum number of entries returned (0 is unlimited)"),
            minvalue=0,
        ),
    )

    msg_summary = ngettext(
        '%(count)d certificate matched', '%(count)d certificates matched', 0
    )

    def get_options(self):
        for option in super(cert_find, self).get_options():
            if option.name == 'no_members':
                option = option.clone(default=True,
                                      flags=set(option.flags) | {'no_option'})
            yield option

        for owner in self.obj._owners():
            yield owner.primary_key.clone_rename(
                '{0}'.format(owner.name),
                required=False,
                multivalue=True,
                primary_key=False,
                query=True,
                cli_name='{0}s'.format(owner.name),
                doc=(_("Search for certificates with these owner %s.") %
                     owner.object_name_plural),
                label=owner.object_name,
            )
            yield owner.primary_key.clone_rename(
                'no_{0}'.format(owner.name),
                required=False,
                multivalue=True,
                primary_key=False,
                query=True,
                cli_name='no_{0}s'.format(owner.name),
                doc=(_("Search for certificates without these owner %s.") %
                     owner.object_name_plural),
                label=owner.object_name,
            )

    def execute(self, criteria=None, all=False, raw=False, pkey_only=False,
                no_members=True, timelimit=None, sizelimit=None, **options):
        ca_options = {'cacn',
                      'revocation_reason',
                      'issuer',
                      'subject',
                      'min_serial_number', 'max_serial_number',
                      'exactly',
                      'validnotafter_from', 'validnotafter_to',
                      'validnotbefore_from', 'validnotbefore_to',
                      'issuedon_from', 'issuedon_to',
                      'revokedon_from', 'revokedon_to'}
        ldap_options = {prefix + owner.name
                        for owner in self.obj._owners()
                        for prefix in ('', 'no_')}
        has_ca_options = (
            any(name in options for name in ca_options - {'exactly'}) or
            options['exactly'])
        has_ldap_options = any(name in options for name in ldap_options)
        has_cert_option = 'certificate' in options

        try:
            ca_enabled_check()
        except errors.NotFound:
            if has_ca_options:
                raise
            ca_enabled = False
        else:
            ca_enabled = True

        if 'cacn' in options:
            ca_obj = api.Command.ca_show(options['cacn'])['result']
            ca_sdn = unicode(ca_obj['ipacasubjectdn'][0])
            if 'issuer' in options:
                if DN(ca_sdn) != DN(options['issuer']):
                    # client has provided both 'ca' and 'issuer' but
                    # issuer DNs don't match; result must be empty
                    return dict(result=[], count=0, truncated=False)
            else:
                options['issuer'] = ca_sdn

        if criteria is not None:
            return dict(result=[], count=0, truncated=False)

        obj_seq = []
        obj_dict = {}
        truncated = False

        if has_cert_option:
            cert = options['certificate']
            obj = {'certificate': unicode(base64.b64encode(cert))}
            obj_seq.append(obj)
            obj_dict[cert] = obj

        if ca_enabled:
            ra_options = {}
            for name, value in options.items():
                if name not in ca_options:
                    continue
                if isinstance(value, datetime.datetime):
                    value = value.strftime(PKIDATE_FORMAT)
                elif isinstance(value, DN):
                    value = unicode(value)
                ra_options[name] = value
            if sizelimit is not None:
                if sizelimit != 0:
                    ra_options['sizelimit'] = sizelimit
                sizelimit = 0
                has_ca_options = True

            for ra_obj in self.Backend.ra.find(ra_options):
                obj = {}
                if ((not pkey_only and all) or
                        not no_members or
                        not has_ca_options or
                        has_ldap_options or
                        has_cert_option):
                    ra_obj.update(
                        self.Backend.ra.get_certificate(
                            str(ra_obj['serial_number'])))
                    cert = base64.b64decode(ra_obj['certificate'])
                    try:
                        obj = obj_dict[cert]
                    except KeyError:
                        if has_cert_option:
                            continue
                        obj = {}
                        obj_seq.append(obj)
                        obj_dict[cert] = obj
                else:
                    obj_seq.append(obj)
                obj.update(ra_obj)

        if ((not pkey_only and all) or
                not no_members or
                not has_ca_options or
                has_ldap_options or
                has_cert_option):
            ldap = self.api.Backend.ldap2

            filters = []
            if 'certificate' in options:
                cert_filter = ldap.make_filter_from_attr(
                    'usercertificate', options['certificate'])
            else:
                cert_filter = '(usercertificate=*)'
            filters.append(cert_filter)
            for owner in self.obj._owners():
                oc_filter = ldap.make_filter_from_attr(
                    'objectclass', owner.object_class, ldap.MATCH_ALL)
                for prefix, rule in (('', ldap.MATCH_ALL),
                                     ('no_', ldap.MATCH_NONE)):
                    value = options.get(prefix + owner.name)
                    if value is None:
                        continue
                    pkey_filter = ldap.make_filter_from_attr(
                        owner.primary_key.name, value, rule)
                    filters.append(oc_filter)
                    filters.append(pkey_filter)
            filter = ldap.combine_filters(filters, ldap.MATCH_ALL)

            try:
                entries, truncated = ldap.find_entries(
                    base_dn=self.api.env.basedn,
                    filter=filter,
                    attrs_list=['usercertificate'],
                    time_limit=timelimit,
                    size_limit=sizelimit,
                )
            except errors.EmptyResult:
                entries, truncated = [], False
            for entry in entries:
                seen = set()
                for attr in ('usercertificate', 'usercertificate;binary'):
                    for cert in entry.get(attr, []):
                        if cert in seen:
                            continue
                        seen.add(cert)
                        try:
                            obj = obj_dict[cert]
                        except KeyError:
                            if has_ca_options or has_cert_option:
                                continue
                            obj = {
                                'certificate': unicode(base64.b64encode(cert))}
                            obj_seq.append(obj)
                            obj_dict[cert] = obj
                        obj.setdefault('owner', []).append(entry.dn)

        result = []
        for obj in obj_seq:
            if has_ldap_options and 'owner' not in obj:
                continue
            if not pkey_only:
                if not raw:
                    if 'certificate' in obj:
                        obj['certificate'] = (
                            obj['certificate'].replace('\r\n', ''))
                        self.obj._parse(obj)
                        if not all:
                            del obj['certificate']
                            del obj['valid_not_before']
                            del obj['valid_not_after']
                            del obj['md5_fingerprint']
                            del obj['sha1_fingerprint']
                    if 'subject' in obj:
                        obj['subject'] = DN(obj['subject'])
                    if 'issuer' in obj:
                        obj['issuer'] = DN(obj['issuer'])
                    if 'status' in obj:
                        obj['revoked'] = (
                            obj['status'] in (u'REVOKED', u'REVOKED_EXPIRED'))
                    if 'owner' in obj:
                        if all or not no_members:
                            self.obj._fill_owners(obj)
                        del obj['owner']
                else:
                    if 'certificate' in obj:
                        if not all:
                            del obj['certificate']
                    if 'owner' in obj:
                        if not all and no_members:
                            del obj['owner']
            else:
                if 'serial_number' in obj:
                    serial_number = obj['serial_number']
                    obj.clear()
                    obj['serial_number'] = serial_number
                else:
                    obj.clear()
            result.append(obj)

        ret = dict(
            result=result
        )
        ret['count'] = len(ret['result'])
        ret['truncated'] = bool(truncated)
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
