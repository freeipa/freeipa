# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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

import os
import sys
import base64
import nss.nss as nss
from ipapython import ipautil
from ipalib import api

PEM = 0
DER = 1

def strip_header(pem):
    """
    Remove the header and footer from a certificate.
    """
    s = pem.find("-----BEGIN CERTIFICATE-----")
    if s >= 0:
        e = pem.find("-----END CERTIFICATE-----")
        pem = pem[s+27:e]

    return pem

def load_certificate(data, datatype=PEM, dbdir=None):
    """
    Given a base64-encoded certificate, with or without the
    header/footer, return a request object.

    Returns a nss.Certificate type
    """
    if type(data) in (tuple, list):
        data = data[0]

    if (datatype == PEM):
        data = strip_header(data)
        data = base64.b64decode(data)

    if dbdir is None:
        if api.env.in_tree:
            dbdir = api.env.dot_ipa + os.sep + 'alias'
        else:
            dbdir = "/etc/httpd/alias"

    nss.nss_init(dbdir)
    return nss.Certificate(buffer(data))

def get_subject(certificate, datatype=PEM):
    """
    Load an X509.3 certificate and get the subject.
    """

    cert = load_certificate(certificate, datatype)
    return cert.subject

def get_serial_number(certificate, datatype=PEM):
    """
    Return the decimal value of the serial number.
    """
    cert = load_certificate(certificate, datatype)
    return cert.serial_number

if __name__ == '__main__':

    nss.nss_init_nodb()

    # Read PEM certs from stdin and print out its components

    certlines = sys.stdin.readlines()
    cert = ''.join(certlines)

    cert = load_certificate(cert)

    print cert
