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

from ipalib import api, Command, Str, Int


class cert_request(Command):
    """
    Submit a certificate singing request.
    """

    takes_args = ('csr',)

    takes_options = (
        Str('request_type?', default=u'pkcs10', autofill=True),
    )

    def execute(self, csr, **options):
        return self.Backend.ra.request_certificate(csr, **options)

    def output_for_cli(self, textui, result, *args, **options):
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


    def execute(self, request_id, **options):
        return self.Backend.ra.check_request_status(request_id)

    def output_for_cli(self, textui, result, *args, **options):
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

    def output_for_cli(self, textui, result, *args, **options):
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
    takes_options = [Int('revocation_reason?', default=0)]


    def execute(self, serial_number, **options):
        return self.Backend.ra.revoke_certificate(serial_number, **options)

    def output_for_cli(self, textui, result, *args, **options):
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

    def execute(self, serial_number, **options):
        return self.Backend.ra.take_certificate_off_hold(serial_number)

    def output_for_cli(self, textui, result, *args, **options):
        if isinstance(result, dict) and len(result) > 0:
            textui.print_entry(result, 0)
        else:
            textui.print_plain('Failed to take a revoked certificate off hold.')

api.register(cert_remove_hold)
