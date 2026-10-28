#
# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2011  Red Hat
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

"""
Provide a custom certificate used in the service tests.

The certificate in cached in a global variable so it only has to be created
once per test run.
"""

from __future__ import absolute_import

import os
import tempfile
import shutil
import base64
import re

from ipalib import api, x509
from ipaserver.plugins import rabase
from ipapython import certdb
from ipapython.dn import DN
from ipaplatform.paths import paths

_subject_base = None


def subject_base():
    global _subject_base

    if _subject_base is None:
        config = api.Command['config_show']()['result']
        _subject_base = DN(config['ipacertificatesubjectbase'][0])

    return _subject_base


def strip_cert_header(pem):
    """
    Remove the header and footer from a certificate.
    """
    regexp = (
        r"^-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----"
    )
    s = re.search(regexp, pem, re.MULTILINE | re.DOTALL)
    if s is not None:
        return s.group(1)
    else:
        return pem


def get_testcert(subject, principal):
    """Get the certificate, creating it if it doesn't exist"""
    reqdir = tempfile.mkdtemp(prefix="tmp-")
    try:
        _testcert = makecert(reqdir, subject,
                             principal)
    finally:
        shutil.rmtree(reqdir)
    return strip_cert_header(_testcert.decode('utf-8'))


def makecert(reqdir, subject, principal):
    """
    Generate a certificate that can be used during unit testing.
    """

    ra = rabase.rabase(api)
    if (not os.path.exists(ra.client_certfile) and
            api.env.xmlrpc_uri == 'http://localhost:8888/ipa/xml'):
        raise AssertionError('The self-signed CA is not configured, '
                             'see ipatests/test_xmlrpc/test_cert.py')

    nssdb = certdb.NSSDatabase(nssdir=reqdir)
    with open(nssdb.pwd_file, "w") as f:
        # Create an empty password file
        f.write("\n")
    # create db
    nssdb.create_db()
    # create CSR
    csr_file = os.path.join(reqdir, 'req')
    nssdb.run_certutil([
        "-R", "-s", str(subject),
        "-o", csr_file,
        "-z", paths.GROUP,
        "-a"
    ])
    with open(csr_file, "rb") as f:
        csr = f.read().decode('ascii')

    res = api.Command['cert_request'](csr, principal=principal, add=True)
    cert = x509.load_der_x509_certificate(
        base64.b64decode(res['result']['certificate']))
    return cert.public_bytes(x509.Encoding.PEM)
