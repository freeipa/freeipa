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

import os
import sys
import base64
import nss.nss as nss
from ipapython import ipautil
from ipalib import api

PEM = 0
DER = 1

def get_subjectaltname(request):
    """
    Given a CSR return the subjectaltname value, if any.

    The return value is a tuple of strings or None
    """
    for extension in request.extensions:
        if extension.oid_tag  == nss.SEC_OID_X509_SUBJECT_ALT_NAME:
            return nss.x509_alt_name(extension.value)
    return None

def get_subject(request):
    """
    Given a CSR return the subject value.

    This returns an nss.DN object.
    """
    return request.subject

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

def load_certificate_request(csr):
    """
    Given a base64-encoded certificate request, with or without the
    header/footer, return a request object.
    """
    csr = strip_header(csr)

    substrate = base64.b64decode(csr)

    # A fail-safe so we can always read a CSR. python-nss/NSS will segfault
    # otherwise
    if not nss.nss_is_initialized():
        nss.nss_init_nodb()

    return nss.CertificateRequest(substrate)

if __name__ == '__main__':
    nss.nss_init_nodb()

    # Read PEM request from stdin and print out its components

    csrlines = sys.stdin.readlines()
    csr = ''.join(csrlines)

    csr = load_certificate_request(csr)

    print csr

    print get_subject(csr)
    print get_subjectaltname(csr)
