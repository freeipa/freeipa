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
import base64

def validate_csr(ugettext, csr):
    """
    For now just verify that it is properly base64-encoded.
    """
    try:
        base64.b64decode(csr)
    except Exception, e:
        raise errors.Base64DecodeError(reason=str(e))


class cert_request(Command):
    """
    Submit a certificate singing request.
    """

    takes_args = (Str('csr', validate_csr),)

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
        skw = {"all": True}
        principal = kw.get('principal')
        add = kw.get('add')
        del kw['principal']
        del kw['add']
        service = None

        # See if the service exists and punt if it doesn't and we aren't
        # going to add it
        try:
            service = api.Command['service_show'](principal, **skw)
            if service.get('usercertificate'):
                # FIXME, what to do here? Do we revoke the old cert?
                raise errors.GenericError(format='entry already has a certificate')

        except errors.NotFound, e:
            if not add:
                raise e

        # Request the certificate
        result = self.Backend.ra.request_certificate(csr, **kw)

        # Success? Then add it to the service entry. We know that it
        # either exists or we should add it.
        if result.get('status') == '0':
            if service is None:
                service = api.Command['service_add'](principal, **{})
            skw = {"usercertificate": str(result.get('certificate'))}
            api.Command['service_mod'](principal, **skw)

        return result

    def output_for_cli(self, textui, result, *args, **kw):
        if isinstance(result, dict) and len(result) > 0:
            textui.print_entry(result, 0)
        else:
            textui.print_plain('Failed to submit a certificate request.')

api.register(cert_request)


class cert_status(Command):
    """
    Check status of a certificate signing request.
    """

    takes_args = ['request_id']


    def execute(self, request_id, **kw):
        return self.Backend.ra.check_request_status(request_id)

    def output_for_cli(self, textui, result, *args, **kw):
        if isinstance(result, dict) and len(result) > 0:
            textui.print_entry(result, 0)
        else:
            textui.print_plain('Failed to retrieve a request status.')

api.register(cert_status)


class cert_get(Command):
    """
    Retrieve an existing certificate.
    """

    takes_args = ['serial_number']

    def execute(self, serial_number):
        return self.Backend.ra.get_certificate(serial_number)

    def output_for_cli(self, textui, result, *args, **kw):
        if isinstance(result, dict) and len(result) > 0:
            textui.print_entry(result, 0)
        else:
            textui.print_plain('Failed to obtain a certificate.')

api.register(cert_get)


class cert_revoke(Command):
    """
    Revoke a certificate.
    """

    takes_args = ['serial_number']

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
        return self.Backend.ra.revoke_certificate(serial_number, **kw)

    def output_for_cli(self, textui, result, *args, **kw):
        if isinstance(result, dict) and len(result) > 0:
            textui.print_entry(result, 0)
        else:
            textui.print_plain('Failed to revoke a certificate.')

api.register(cert_revoke)


class cert_remove_hold(Command):
    """
    Take a revoked certificate off hold.
    """

    takes_args = ['serial_number']

    def execute(self, serial_number, **kw):
        return self.Backend.ra.take_certificate_off_hold(serial_number)

    def output_for_cli(self, textui, result, *args, **kw):
        if isinstance(result, dict) and len(result) > 0:
            textui.print_entry(result, 0)
        else:
            textui.print_plain('Failed to take a revoked certificate off hold.')

api.register(cert_remove_hold)
