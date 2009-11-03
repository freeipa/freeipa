# Authors:
#   Andrew Wnuk <awnuk@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
Command plugins for IPA-RA certificate operations.
"""

from ipalib import api, SkipPluginModule
if api.env.enable_ra is not True:
    # In this case, abort loading this plugin module...
    raise SkipPluginModule(reason='env.enable_ra is not True')
from ipalib import Command, Str, Int, Bytes, Flag
from ipalib import errors
from ipalib.plugins.virtual import *
from ipalib.plugins.service import split_principal
import base64
from OpenSSL import crypto
from ipalib.request import context
from ipapython import dnsclient

def get_serial(certificate):
    """
    Given a certificate, return the serial number in that cert

    In theory there should be only one cert per object so even if we get
    passed in a list/tuple only return the first one.
    """
    if type(certificate) in (list, tuple):
        certificate = certificate[0]
    try:
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate)
        serial = str(x509.get_serial_number())
    except crypto.Error:
        raise errors.GenericError(format='Unable to decode certificate in entry')

    return serial

def get_csr_hostname(csr):
    """
    Return the value of CN in the subject of the request
    """
    try:
        der = base64.b64decode(csr)
        request = crypto.load_certificate_request(crypto.FILETYPE_ASN1, der)
        sub = request.get_subject().get_components()
        for s in sub:
            if s[0].lower() == "cn":
                return s[1]
    except crypto.Error, e:
        raise errors.GenericError(format='Unable to decode CSR: %s' % str(e))

    return None

def validate_csr(ugettext, csr):
    """
    For now just verify that it is properly base64-encoded.
    """
    try:
        base64.b64decode(csr)
    except Exception, e:
        raise errors.Base64DecodeError(reason=str(e))


class cert_request(VirtualCommand):
    """
    Submit a certificate signing request.
    """

    takes_args = (Str('csr', validate_csr),)
    operation="request certificate"

    takes_options = (
        Str('principal',
            doc="service principal for this certificate (e.g. HTTP/test.example.com)",
        ),
        Str('request_type',
            default=u'pkcs10',
            autofill=True,
        ),
        Flag('add',
            doc="automatically add the principal if it doesn't exist",
            default=False,
            autofill=True
        ),
    )

    def execute(self, csr, **kw):
        ldap = self.api.Backend.ldap2
        skw = {"all": True}
        principal = kw.get('principal')
        add = kw.get('add')
        del kw['principal']
        del kw['add']
        service = None

        # Can this user request certs?
        self.check_access()

        # FIXME: add support for subject alt name
        # Is this cert for this principal?
        subject_host = get_csr_hostname(csr)

        # Ensure that the hostname in the CSR matches the principal
        (servicename, hostname, realm) = split_principal(principal)
        if subject_host.lower() != hostname.lower():
            raise errors.ACIError(info="hostname in subject of request '%s' does not match principal hostname '%s'" % (subject_host, hostname))

        # See if the service exists and punt if it doesn't and we aren't
        # going to add it
        try:
            (dn, service) = api.Command['service_show'](principal, **skw)
            if 'usercertificate' in service:
                # FIXME, what to do here? Do we revoke the old cert?
                raise errors.GenericError(format='entry already has a certificate, serial number %s' % get_serial(service['usercertificate']))
        except errors.NotFound, e:
            if not add:
                raise errors.NotFound(reason="The service principal for this request doesn't exist.")
            try:
                (dn, service) = api.Command['service_add'](principal, **{})
            except errors.ACIError:
                raise errors.ACIError(info='You need to be a member of the serviceadmin role to add services')

        # We got this far so the service entry exists, can we write it?
        if not ldap.can_write(dn, "usercertificate"):
            raise errors.ACIError(info="Insufficient 'write' privilege to the 'userCertificate' attribute of entry '%s'." % dn)

        # Request the certificate
        result = self.Backend.ra.request_certificate(csr, **kw)

        # Success? Then add it to the service entry.
        if result.get('status') == 0:
            skw = {"usercertificate": str(result.get('certificate'))}
            api.Command['service_mod'](principal, **skw)

        return result

    def output_for_cli(self, textui, result, *args, **kw):
        if isinstance(result, dict) and len(result) > 0:
            textui.print_entry(result, 0)
        else:
            textui.print_plain('Failed to submit a certificate request.')

    def run(self, *args, **options):
        """
        Dispatch to forward() and execute() to do work locally and on the
        server.
        """
        if self.env.in_server:
            return self.execute(*args, **options)

        # Client-side code
        csr = args[0]
        if csr[:7] == "file://":
            file = csr[7:]
            try:
                f = open(file, "r")
                csr = f.readlines()
                f.close()
            except IOError, err:
                raise errors.ValidationError(name='csr', error=err[1])
            csr = "".join(csr)
            # We just want the CSR bits, make sure there is nothing else
            s = csr.find("-----BEGIN NEW CERTIFICATE REQUEST-----")
            e = csr.find("-----END NEW CERTIFICATE REQUEST-----")
            if s >= 0:
                csr = csr[s+40:e]
        csr = csr.decode('UTF-8')
        return self.forward(csr, **options)

api.register(cert_request)


class cert_status(VirtualCommand):
    """
    Check status of a certificate signing request.
    """

    takes_args = ('request_id')
    operation = "certificate status"


    def execute(self, request_id, **kw):
        self.check_access()
        return self.Backend.ra.check_request_status(request_id)

    def output_for_cli(self, textui, result, *args, **kw):
        if isinstance(result, dict) and len(result) > 0:
            textui.print_entry(result, 0)
        else:
            textui.print_plain('Failed to retrieve a request status.')

api.register(cert_status)


class cert_get(VirtualCommand):
    """
    Retrieve an existing certificate.
    """

    takes_args = ('serial_number')
    operation="retrieve certificate"

    def execute(self, serial_number):
        self.check_access()
        return self.Backend.ra.get_certificate(serial_number)

    def output_for_cli(self, textui, result, *args, **kw):
        if isinstance(result, dict) and len(result) > 0:
            textui.print_entry(result, 0)
        else:
            textui.print_plain('Failed to obtain a certificate.')

api.register(cert_get)


class cert_revoke(VirtualCommand):
    """
    Revoke a certificate.
    """

    takes_args = ('serial_number')
    operation = "revoke certificate"

    # FIXME: The default is 0.  Is this really an Int param?
    takes_options = (
        Int('revocation_reason?',
            doc='Reason for revoking the certificate (0-10)',
            minvalue=0,
            maxvalue=10,
            default=0,
        ),
    )


    def execute(self, serial_number, **kw):
        self.check_access()
        return self.Backend.ra.revoke_certificate(serial_number, **kw)

    def output_for_cli(self, textui, result, *args, **kw):
        if isinstance(result, dict) and len(result) > 0:
            textui.print_entry(result, 0)
        else:
            textui.print_plain('Failed to revoke a certificate.')

api.register(cert_revoke)


class cert_remove_hold(VirtualCommand):
    """
    Take a revoked certificate off hold.
    """

    takes_args = ('serial_number')
    operation = "certificate remove hold"

    def execute(self, serial_number, **kw):
        self.check_access()
        return self.Backend.ra.take_certificate_off_hold(serial_number)

    def output_for_cli(self, textui, result, *args, **kw):
        if isinstance(result, dict) and len(result) > 0:
            textui.print_entry(result, 0)
        else:
            textui.print_plain('Failed to take a revoked certificate off hold.')

api.register(cert_remove_hold)
