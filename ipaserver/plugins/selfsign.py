# Authors:
#   Rob Crittenden <rcritten@@redhat.com>
#   John Dennis <jdennis@redhat.com>
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
from ipalib import pkcs10
import subprocess
import os
import re
from ipaserver.plugins import rabase
from ipaserver.install import certs
import tempfile
from pyasn1 import error
from ipalib import  _
from pyasn1.codec.der import encoder
from ipalib.plugins.cert import get_csr_hostname

class ra(rabase.rabase):
    """
    Request Authority backend plugin.
    """

    def request_certificate(self, csr, request_type='pkcs10'):
        """
        :param csr: The certificate signing request.
        :param request_type: The request type (defaults to ``'pkcs10'``).

        Submit certificate signing request.

        The command returns a dict with these possible key/value pairs.
        Some key/value pairs may be absent.

        +---------------+---------------+---------------+
        |result name    |result type    |comments       |
        +===============+===============+===============+
        |serial_number  |unicode [1]_   |               |
        +---------------+---------------+---------------+
        |certificate    |unicode [2]_   |               |
        +---------------+---------------+---------------+
        |request_id     |unicode        |               |
        +---------------+---------------+---------------+
        |subject        |unicode        |               |
        +---------------+---------------+---------------+

        .. [1] Passed through XMLRPC as decimal string. Can convert to
               optimal integer type (int or long) via int(serial_number)

        .. [2] Base64 encoded

        """
        try:
            config = api.Command['config_show']()['result']
            subject_base = config.get('ipacertificatesubjectbase')[0]
            hostname = get_csr_hostname(csr)
            request = pkcs10.load_certificate_request(csr)
            base = re.split(',\s*(?=\w+=)', subject_base)
            base.reverse()
            base.append("CN=%s" % hostname)
            request_subject = request.get_subject().get_components()
            new_request = []
            for r in request_subject:
                new_request.append("%s=%s" % (r[0], r[1]))

            if str(base).lower() != str(new_request).lower():
                subject_base='CN=%s, %s' % (hostname, subject_base)
                new_request.reverse()
                raise errors.CertificateOperationError(error=_('Request subject "%(request_subject)s" does not match the form "%(subject_base)s"') % \
                                                              {'request_subject' : ', '.join(new_request), 'subject_base' : subject_base})
        except errors.CertificateOperationError, e:
            raise e
        except Exception, e:
            raise errors.CertificateOperationError(error=_('unable to decode csr: %s' % e))

        # certutil wants the CSR to have have a header and footer. Add one
        # if it isn't there.
        s = csr.find('-----BEGIN NEW CERTIFICATE REQUEST-----')
        if s == -1:
            s = csr.find('-----BEGIN CERTIFICATE REQUEST-----')
            if s == -1:
                csr = '-----BEGIN NEW CERTIFICATE REQUEST-----\n' + csr + \
                      '\n-----END NEW CERTIFICATE REQUEST-----\n'

        try:
            (csr_fd, csr_name) = tempfile.mkstemp()
            os.write(csr_fd, csr)
            os.close(csr_fd)
        except Exception, e:
            try:
                os.remove(csr_name)
            except:
                pass
            self.log.error('unable to create temporary csr file: %s' % e)
            raise errors.CertificateOperationError(error=_('file operation'))

        try:
            (cert_fd, cert_name) = tempfile.mkstemp()
            os.close(cert_fd)
        except Exception, e:
            try:
                os.remove(csr_name)
            except:
                pass
            try:
                os.remove(cert_name)
            except:
                pass
            self.log.error('unable to create temporary certificate file: %s' % e)
            raise errors.CertificateOperationError(error=_('file operation'))

        try:
            serialno = certs.next_serial(self.serial_file)
        except Exception, e:
            try:
                os.remove(csr_name)
            except:
                pass
            try:
                os.remove(cert_name)
            except:
                pass
            self.log.error('next_serial() failed: %s' % e)
            raise errors.CertificateOperationError(error=_('cannot obtain next serial number'))

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
            status = p.returncode
            self.log.debug("stdout = %s" % stdout)
            self.log.debug("stderr = %s" % stderr)
            if status != 0:
                try:
                    os.remove(cert_name)
                except:
                    pass
                self.log.error('certutil failed: %s' % stderr)
                raise errors.CertificateOperationError(error=_('certutil failure'))
        finally:
            try:
                os.remove(csr_name)
            except:
                pass

        try:
            cert_fd = open(cert_name)
            cert = cert_fd.read()
            cert_fd.close()
        finally:
            try:
                os.remove(cert_name)
            except:
                pass

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
            self.log.error('Unable to decode certificate in entry: %s' % str(e))
            raise errors.CertificateOperationError(error='Unable to decode certificate in entry: %s' % str(e))

        # To make it look like dogtag return just the base64 data.
        cert = cert.replace('\n','')
        cert = cert.replace('\r','')
        s = cert.find('-----BEGIN CERTIFICATE-----')
        e = cert.find('-----END CERTIFICATE-----')
        s = s + 27
        cert = cert[s:e]

        cmd_result = {}
        cmd_result['serial_number'] = unicode(serial) # convert long to decimal unicode string
        cmd_result['certificate']   = unicode(cert)
        cmd_result['subject']       = unicode(subject)

        return cmd_result

api.register(ra)
