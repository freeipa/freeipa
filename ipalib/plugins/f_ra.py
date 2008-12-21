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
Frontend plugins for IPA-RA PKI operations.
"""

from ipalib import api, Command, Param
from ipalib import cli


class request_certificate(Command):
    """ Submit a certificate request. """

    takes_args = ['csr']

    takes_options = [Param('request_type?', default='pkcs10')]

    def execute(self, csr, **options):
        return self.Backend.ra.request_certificate(csr, **options)

    def output_for_cli(self, textui, result, *args, **options):
        if isinstance(result, dict) and len(result) > 0:
            textui.print_entry(result, 0)
        else:
            textui.print_plain('Failed to submit a certificate request.')

api.register(request_certificate)


class get_certificate(Command):
    """ Retrieve an existing certificate. """

    takes_args = ['serial_number']

    def execute(self, serial_number, **options):
        return self.Backend.ra.get_certificate(serial_number)

    def output_for_cli(self, textui, result, *args, **options):
        if isinstance(result, dict) and len(result) > 0:
            textui.print_entry(result, 0)
        else:
            textui.print_plain('Failed to obtain a certificate.')

api.register(get_certificate)


class check_request_status(Command):
    """  Check a request status. """

    takes_args = ['request_id']


    def execute(self, request_id, **options):
        return self.Backend.ra.check_request_status(request_id)

    def output_for_cli(self, textui, result, *args, **options):
        if isinstance(result, dict) and len(result) > 0:
            textui.print_entry(result, 0)
        else:
            textui.print_plain('Failed to retrieve a request status.')

api.register(check_request_status)


class revoke_certificate(Command):
    """ Revoke a certificate. """

    takes_args = ['serial_number']

    takes_options = [Param('revocation_reason?', default=0)]


    def execute(self, serial_number, **options):
        return self.Backend.ra.revoke_certificate(serial_number, **options)

    def output_for_cli(self, textui, result, *args, **options):
        if isinstance(result, dict) and len(result) > 0:
            textui.print_entry(result, 0)
        else:
            textui.print_plain('Failed to revoke a certificate.')

api.register(revoke_certificate)


class take_certificate_off_hold(Command):
    """ Take a revoked certificate off hold. """

    takes_args = ['serial_number']

    def execute(self, serial_number, **options):
        return self.Backend.ra.take_certificate_off_hold(serial_number)

    def output_for_cli(self, textui, result, *args, **options):
        if isinstance(result, dict) and len(result) > 0:
            textui.print_entry(result, 0)
        else:
            textui.print_plain('Failed to take a revoked certificate off hold.')

api.register(take_certificate_off_hold)


