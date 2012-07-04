# Authors:
#   Rob Crittenden <rcritten@@redhat.com>
#   John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
from ipapython.dn import DN, EditableDN, RDN
from ipapython.certdb import get_ca_nickname
import subprocess
import os
import re
from ipaserver.plugins import rabase
from ipaserver.install import certs
import tempfile
from ipalib import  _
from ipalib import  api
from ipalib.plugins.cert import get_csr_hostname
from nss.error import NSPRError

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
            subject_base = EditableDN(config.get('ipacertificatesubjectbase')[0])
            hostname = get_csr_hostname(csr)
            subject_base.insert(0, RDN(('CN', hostname)))
            request = pkcs10.load_certificate_request(csr)
            # python-nss normalizes the request subject
            request_subject = DN(str(pkcs10.get_subject(request)))

            if subject_base != request_subject:
                raise errors.CertificateOperationError(error=_('Request subject "%(request_subject)s" does not match the form "%(subject_base)s"') % \
                {'request_subject' : request_subject, 'subject_base' : subject_base})
        except errors.CertificateOperationError, e:
            raise e
        except NSPRError, e:
            raise errors.CertificateOperationError(error=_('unable to decode csr: %s') % e)

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
                "-c", get_ca_nickname(api.env.realm),
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
            subject = x509.get_subject(cert)

            serial = x509.get_serial_number(cert)
        except NSPRError, e:
            self.log.error('Unable to decode certificate in entry: %s' % str(e))
            raise errors.CertificateOperationError(
                error=_('Unable to decode certificate in entry: %s') % str(e))

        # To make it look like dogtag return just the base64 data.
        cert = cert.replace('\n','')
        cert = cert.replace('\r','')
        s = cert.find('-----BEGIN CERTIFICATE-----')
        e = cert.find('-----END CERTIFICATE-----')
        s = s + 27
        cert = cert[s:e]

        cmd_result = {}
        cmd_result['serial_number'] = unicode(serial) # convert long to decimal unicode string
        cmd_result['serial_number_hex'] = u'0x%X' % serial
        cmd_result['certificate']   = unicode(cert)
        cmd_result['subject']       = unicode(subject)

        return cmd_result

api.register(ra)
