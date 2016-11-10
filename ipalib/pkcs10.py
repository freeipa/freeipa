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

import binascii
from cryptography.hazmat.backends import default_backend
import cryptography.x509


def strip_header(csr):
    """
    Remove the header and footer (and surrounding material) from a CSR.
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


def load_certificate_request(data):
    """
    Load a PEM or base64-encoded PKCS #10 certificate request.

    :return: a python-cryptography ``Certificate`` object.
    :raises: ``ValueError`` if unable to load the request

    """
    data = strip_header(data)
    try:
        data = binascii.a2b_base64(data)
    except binascii.Error as e:
        raise ValueError(e)
    return cryptography.x509.load_der_x509_csr(data, default_backend())
