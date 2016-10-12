# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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

from __future__ import print_function

import sys
import base64
from cryptography.hazmat.backends import default_backend
import cryptography.x509
import six

if six.PY3:
    unicode = str

PEM = 0
DER = 1


def strip_header(csr):
    """
    Remove the header and footer from a CSR.
    """
    headerlen = 40
    s = csr.find("-----BEGIN NEW CERTIFICATE REQUEST-----")
    if s == -1:
        headerlen = 36
        s = csr.find("-----BEGIN CERTIFICATE REQUEST-----")
    if s >= 0:
        e = csr.find("-----END")
        csr = csr[s+headerlen:e]

    return csr


def load_certificate_request(data, datatype=PEM):
    """
    Load a PKCS #10 certificate request.

    :param datatype: PEM for base64-encoded data (with or without header),
                     or DER
    :return: a python-cryptography ``Certificate`` object.
    :raises: ``ValueError`` if unable to load the request

    """
    if (datatype == PEM):
        data = strip_header(data)
        data = base64.b64decode(data)

    return cryptography.x509.load_der_x509_csr(data, default_backend())


if __name__ == '__main__':
    # Read PEM request from stdin and print out its components

    csrlines = sys.stdin.readlines()
    csr = ''.join(csrlines)

    print(load_certificate_request(csr))
