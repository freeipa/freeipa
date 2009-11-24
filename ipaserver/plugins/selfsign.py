# Authors:
#   Rob Crittenden <rcritten@@redhat.com>
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
Backend plugin for RA activities.

The `ra` plugin provides access to the CA to issue, retrieve, and revoke
certificates via the following methods:

    * `ra.check_request_status()` - check certificate request status.
    * `ra.get_certificate()` - retrieve an existing certificate.
    * `ra.request_certificate()` - request a new certificate.
    * `ra.revoke_certificate()` - revoke a certificate.
    * `ra.take_certificate_off_hold()` - take a certificate off hold.
"""

from ipalib import api, SkipPluginModule
if api.env.ra_plugin != 'selfsign':
    # In this case, abort loading this plugin module...
    raise SkipPluginModule(reason='selfsign is not selected as RA plugin, it is %s' % api.env.ra_plugin)
from ipalib import Backend
from ipalib import errors
from ipalib import x509
import subprocess
import os
from ipaserver.plugins import rabase
from ipaserver.install import certs
import tempfile
from pyasn1 import error

class ra(rabase.rabase):
    """
    Request Authority backend plugin.
    """

    def request_certificate(self, csr, request_type='pkcs10'):
        """
        Submit certificate signing request.

        :param csr: The certificate signing request.
        :param request_type: The request type (defaults to ``'pkcs10'``).
        """
        (csr_fd, csr_name) = tempfile.mkstemp()

        # certutil wants the CSR to have have a header and footer. Add one
        # if it isn't there.
        s = csr.find('-----BEGIN NEW CERTIFICATE REQUEST-----')
        if s == -1:
            s = csr.find('-----BEGIN CERTIFICATE REQUEST-----')
            if s == -1:
                csr = '-----BEGIN NEW CERTIFICATE REQUEST-----\n' + csr + \
                      '-----END NEW CERTIFICATE REQUEST-----\n'
        os.write(csr_fd, csr)
        os.close(csr_fd)
        (cert_fd, cert_name) = tempfile.mkstemp()
        os.close(cert_fd)

        serialno = certs.next_serial(self.serial_file)

        try:
            args = [
                "/usr/bin/certutil",
                "-C",
                "-d", self.sec_dir,
                "-c", "CA certificate",
                "-i", csr_name,
                "-o", cert_name,
                "-m", str(serialno),
                "-v", "60",
                "-1",
                "-5",
                "-6",
                "-a",
                "-f", self.pwd_file]
            self.log.debug("issue cert: %s" % str(args))
            p = subprocess.Popen(args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True)
            p.stdin.write("0\n1\n2\n3\n9\ny\n")
            p.stdin.write("0\n9\nn\n")
            p.stdin.write("1\n9\nn\n")
            (stdout, stderr) = p.communicate()
            self.log.debug("stdout = %s" % stdout)
            self.log.debug("stderr = %s" % stderr)
        finally:
            os.remove(csr_name)

        try:
            cert_fd = open(cert_name)
            cert = cert_fd.read()
            cert_fd.close()
        finally:
            os.remove(cert_name)

        try:
            # Grab the subject, reverse it, combine it and return it
            sub = list(x509.get_subject_components(cert))
            sub.reverse()
            subject = ""
            for s in sub:
                subject = subject + "%s=%s," % (s[0], s[1])
            subject = subject[:-1]

            serial = x509.get_serial_number(cert)
        except error.PyAsn1Error, e:
            raise errors.GenericError(format='Unable to decode certificate in entry: %s' % str(e))

        # To make it look like dogtag return just the base64 data.
        cert = cert.replace('\n','')
        cert = cert.replace('\r','')
        s = cert.find('-----BEGIN CERTIFICATE-----')
        e = cert.find('-----END CERTIFICATE-----')
        s = s + 27
        cert = cert[s:e]

        return {'status':0, 'subject': subject, 'certificate':cert, 'serial_number': "0x%x" % serial}

api.register(ra)
