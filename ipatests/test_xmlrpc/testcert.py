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

import os
import tempfile
import shutil
import six
import base64
import re

from ipalib import api, x509
from ipaserver.plugins import rabase
from ipapython import ipautil
from ipaplatform.paths import paths

if six.PY3:
    unicode = str


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


def run_certutil(reqdir, args, stdin=None):
    """
    Run an NSS certutil command
    """
    new_args = [paths.CERTUTIL, "-d", reqdir]
    new_args = new_args + args
    return ipautil.run(new_args, stdin)


def generate_csr(reqdir, pwname, subject):
    """
    Create a CSR for the given subject.
    """
    req_path = os.path.join(reqdir, 'req')
    run_certutil(reqdir, ["-R", "-s", subject,
                          "-o", req_path,
                          "-z", paths.GROUP,
                          "-f", pwname,
                          "-a"])
    with open(req_path, "r") as fp:
        return fp.read()


def makecert(reqdir, subject, principal):
    """
    Generate a certificate that can be used during unit testing.
    """

    ra = rabase.rabase(api)
    if (not os.path.exists(ra.client_certfile) and
            api.env.xmlrpc_uri == 'http://localhost:8888/ipa/xml'):
        raise AssertionError('The self-signed CA is not configured, '
                             'see ipatests/test_xmlrpc/test_cert.py')

    pwname = os.path.join(reqdir, "pwd")

    # Create an empty password file
    with open(pwname, "w") as fp:
        fp.write("\n")

    # Generate NSS cert database to store the private key for our CSR
    run_certutil(reqdir, ["-N", "-f", pwname])

    csr = unicode(generate_csr(reqdir, pwname, str(subject)))

    res = api.Command['cert_request'](csr, principal=principal, add=True)
    cert = x509.load_der_x509_certificate(
        base64.b64decode(res['result']['certificate']))
    return cert.public_bytes(x509.Encoding.PEM)
