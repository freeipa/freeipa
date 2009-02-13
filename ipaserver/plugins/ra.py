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
Backend plugin for IPA-RA.

The `ra` plugin provides access to the CA to issue, retrieve, and revoke
certificates via the following methods:

    * `ra.check_request_status()` - check certificate request status.
    * `ra.get_certificate()` - retrieve an existing certificate.
    * `ra.request_certificate()` - request a new certificate.
    * `ra.revoke_certificate()` - revoke a certificate.
    * `ra.take_certificate_off_hold()` - take a certificate off hold.
"""

from ipalib import api, SkipPluginModule
if api.env.enable_ra is not True:
    # In this case, abort loading this plugin module...
    raise SkipPluginModule(reason='env.enable_ra is not True')
import os, stat, subprocess
import array
import errno
import binascii
from httplib import HTTPConnection
from urllib import urlencode, quote
from socket import gethostname
import socket
from ipalib import Backend
from ipalib.errors2 import NetworkError
from ipaserver import servercore
from ipaserver import ipaldap
from ipalib.constants import TYPE_ERROR


class ra(Backend):
    """
    Request Authority backend plugin.
    """
    def __init__(self):
        self.sec_dir = api.env.dot_ipa + os.sep + 'alias'
        self.pwd_file = self.sec_dir + os.sep + '.pwd'
        self.noise_file = self.sec_dir + os.sep + '.noise'
        self.ipa_key_size = "2048"
        self.ipa_certificate_nickname = "ipaCert"
        self.ca_certificate_nickname = "caCert"
        super(ra, self).__init__()

    def configure(self):
        if not os.path.isdir(self.sec_dir):
            os.mkdir(self.sec_dir)
            self.__create_pwd_file()
            self.__create_nss_db()
            self.__import_ca_chain()
            self.__request_ipa_certificate(self.__generate_ipa_request())

    def _request(self, url, **kw):
        """
        Perform an HTTP request.

        :param url: The URL to post to.
        :param kw: Keyword arguments to encode into POST body.
        """
        uri = 'http://%s:%s%s' % (self.env.ca_host, self.env.ca_port, url)
        post = urlencode(kw)
        self.info('request %r', uri)
        self.debug('request post %r', post)
        conn = HTTPConnection(self.env.ca_host, self.env.ca_port)
        try:
            conn.request('POST', url,
                body=post,
                headers={'Content-type': 'application/x-www-form-urlencoded'},
            )
        except socket.error, e:
            raise NetworkError(uri=uri, error=e.args[1])
        response = conn.getresponse()
        (status, reason) = (response.status, response.reason)
        data = response.read()
        conn.close()
        self.debug('request status %r', status)
        self.debug('request reason %s', reason)
        self.debug('request data %s', data)
        return (status, reason, data)

    def _sslget(self, url, **kw):
        """
        Perform an HTTPS request using the ``sslget`` command.

        :param url: The URL to post to.
        :param kw: Keyword arguments to encode into POST body.
        """
        uri = 'https://%s:%d%s' % (self.env.ca_host, self.env.ca_ssl_port, url)
        post = urlencode(kw)
        self.info('sslget %r', uri)
        self.debug('sslget post %r', post)
        argv = [
            '/usr/bin/sslget',
            '-n', self.ipa_certificate_nickname,  # nickname
            '-w', self.pwd_file,  # pwfile
            '-d', self.sec_dir,  # dbdir
            '-e', post,  # post
            '-r', url,  # url
            '%s:%d' % (self.env.ca_host, self.env.ca_ssl_port),
        ]
        (returncode, stdout, stderr) = self.__run(argv)
        self.debug('sslget returncode %r', returncode)
        self.debug('sslget stderr %s', stderr)
        self.debug('sslget stdout %s', stdout)
        return (returncode, stdout, stderr)

    def check_request_status(self, request_id):
        """
        Check status of a certificate signing request.

        :param request_id: request ID
        """
        self.debug('%s.check_request_status()', self.fullname)
        (s, r, data) = self._request('/ca/ee/ca/checkRequest',
            requestId=request_id,
            xmlOutput='true',
        )
        response = {'status': '2'}
        if data is not None:
            request_status = self.__find_substring(
                data, 'header.status = "', '"'
            )
            if request_status is not None:
                response['status'] = '0'
                response['request_status'] = request_status
                serial_number = self.__find_substring(
                    data, 'record.serialNumber="', '"'
                )
                if serial_number is not None:
                    # This was "0x"+serial_number, but we should return it in
                    # the same form used as arg to get_certificate(), etc.
                    response['serial_number'] = serial_number
            request_id = self.__find_substring(
                data, 'header.requestId = "', '"'
            )
            if request_id is not None:
                response['request_id'] = request_id
            error = self.__find_substring(
                data, 'fixed.unexpectedError = "', '"'
            )
            if error is not None:
                response['error'] = error
        return response

    def get_certificate(self, serial_number=None):
        """
        Retrieve an existing certificate.

        :param serial_number: certificate serial number
        """
        self.debug('%s.get_certificate()', self.fullname)
        issued_certificate = None
        (returncode, stdout, stderr) = self._sslget(
            '/ca/agent/ca/displayBySerial',
            serialNumber=serial_number,
            xmlOutput='true',
        )
        response = {}
        if (returncode == 0):
            issued_certificate = self.__find_substring(
                stdout, 'header.certChainBase64 = "', '"'
            )
            if issued_certificate is not None:
                response['status'] = '0'
                issued_certificate = issued_certificate.replace('\\r', '')
                issued_certificate = issued_certificate.replace('\\n', '')
                self.debug('IPA-RA: issued_certificate: %s', issued_certificate)
                response['certificate'] = issued_certificate
            else:
                response['status'] = '1'
            revocation_reason = self.__find_substring(
                stdout, 'header.revocationReason = ', ';'
            )
            if revocation_reason is not None:
                response['revocation_reason'] = revocation_reason
        else:
            response['status'] = str(-returncode)
        return response

    def request_certificate(self, csr, request_type='pkcs10'):
        """
        Submit certificate signing request.

        :param csr: The certificate signing request.
        :param request_type: The request type (defaults to ``'pkcs10'``).
        """
        self.debug('%s.request_certificate()', self.fullname)
        certificate = None
        (returncode, stdout, stderr) = self._sslget('/ca/ee/ca/profileSubmit',
            profileId='caRAserverCert',
            cert_request_type=request_type,
            cert_request=csr,
            xmlOutput='true',
        )
        response = {}
        if (returncode == 0):
            status = self.__find_substring(stdout, "<Status>", "</Status>")
            if status is not None:
                response["status"] = status
            request_id = self.__find_substring(stdout, "<Id>", "</Id>")
            if request_id is not None:
                response["request_id"] = request_id
            serial_number = self.__find_substring(stdout, "<serialno>", "</serialno>")
            if serial_number is not None:
                response["serial_number"] = ("0x%s" % serial_number)
            subject = self.__find_substring(stdout, "<SubjectDN>", "</SubjectDN>")
            if subject is not None:
                response["subject"] = subject
            certificate = self.__find_substring(stdout, "<b64>", "</b64>")
            if certificate is not None:
                response["certificate"] = certificate
            if response.has_key("status") is False:
                response["status"] = "2"
        else:
            response["status"] = str(-returncode)
        return response

    def revoke_certificate(self, serial_number, revocation_reason=0):
        """
        Revoke a certificate.

        The integer ``revocation_reason`` code must have one of these values:

            * ``0`` - unspecified
            * ``1`` - keyCompromise
            * ``2`` - cACompromise
            * ``3`` - affiliationChanged
            * ``4`` - superseded
            * ``5`` - cessationOfOperation
            * ``6`` - certificateHold
            * ``8`` - removeFromCRL
            * ``9`` - privilegeWithdrawn
            * ``10`` - aACompromise

        Note that reason code ``7`` is not used.  See RFC 5280 for more details:

            http://www.ietf.org/rfc/rfc5280.txt

        :param serial_number: Certificate serial number.
        :param revocation_reason: Integer code of revocation reason.
        """
        self.debug('%s.revoke_certificate()', self.fullname)
        if type(revocation_reason) is not int:
            raise TYPE_ERROR('revocation_reason', int, revocation_reason,
                type(revocation_reason)
            )
        response = {}
        (returncode, stdout, stderr) = self._sslget('/ca/agent/ca/doRevoke',
            op='revoke',
            revocationReason=revocation_reason,
            revokeAll='(certRecordId=%s)' % serial_number,
            totalRecordCount=1,
        )
        if returncode == 0:
            response['status'] = '0'
            if (stdout.find('revoked = "yes"') > -1):
                response['revoked'] = True
            else:
                response['revoked'] = False
        else:
            response['status'] = str(-returncode)
        return response

    def take_certificate_off_hold(self, serial_number):
        """
        Take revoked certificate off hold.

        :param serial_number: Certificate serial number.
        """
        response = {}
        self.debug('%s.take_certificate_off_hold()', self.fullname)
        (returncode, stdout, stderr) = self._sslget('/ca/agent/ca/doUnrevoke',
            serialNumber=serial_number,
        )
        if (returncode == 0):
            if (stdout.find('unrevoked = "yes"') > -1):
                response['taken_off_hold'] = True
            else:
                response['taken_off_hold'] = False
        else:
            response['status'] = str(-returncode)
        return response

    def __find_substring(self, str, str1, str2):
        sub_str = None
        k0 = len(str)
        k1 = str.find(str1)
        k2 = len(str1)
        if (k0 > 0 and k1 > -1 and k2 > 0 and k0 > k1 + k2):
            sub_str = str[k1+k2:]
            k3 = len(sub_str)
            k4 = sub_str.find(str2)
            if (k3 > 0 and k4 > -1 and k3 > k4):
                sub_str = sub_str[:k4]
        return sub_str

    def __generate_ipa_request(self):
        certificate_request = None
        if not os.path.isfile(self.noise_file):
            self.__create_noise_file()
        returncode, stdout, stderr = self.__run_certutil(["-R", "-k", "rsa", "-g", self.ipa_key_size, "-s", "CN=IPA-Subsystem-Certificate,OU=pki-ipa,O=UsersysRedhat-Domain", "-z", self.noise_file, "-a"])
        if os.path.isfile(self.noise_file):
            os.unlink(self.noise_file)
        if (returncode == 0):
            self.info("IPA-RA: IPA certificate request generated")
            certificate_request = self.__find_substring(stdout, "-----BEGIN NEW CERTIFICATE REQUEST-----", "-----END NEW CERTIFICATE REQUEST-----")
            if certificate_request is not None:
                self.debug("certificate_request=%s" % certificate_request)
            else:
                self.warning("IPA-RA: Error parsing certificate request." % returncode)
        else:
            self.warning("IPA-RA: Error (%d) generating IPA certificate request." % returncode)
        return certificate_request

    def __request_ipa_certificate(self, certificate_request=None):
        ipa_certificate = None
        if certificate_request is not None:
            response = self.request('profileSubmit',
                profileId='caServerCert',
                cert_request_type='pkcs10',
                requestor_name='freeIPA',
                cert_request=self.__generate_ipa_request(),
                xmlOutput='true',
            )
            self.debug("IPA-RA: response.status: %d  response.reason: '%s'" % (response.status, response.reason))
            data = response.read()
            self.info("IPA-RA: IPA certificate request submitted to CA: %s" % data)
        return ipa_certificate

    def __get_ca_chain(self):
        response = self.request('getCertChain')
        self.debug('response.status: %r', response.status)
        self.debug('response.reason: %r', response.reason)
        data = response.read()
        certificate_chain = self.__find_substring(data, "<ChainBase64>", "</ChainBase64>")
        if certificate_chain is None:
            self.warning('IPA-RA: Error parsing certificate chain')
        else:
            self.info('IPA-RA: CA chain obtained from CA: %s', certificate_chain)
        return certificate_chain

    def __import_ca_chain(self):
        (returncode, stdout, stderr) = self.__run_certutil(
            [
                '-A',
                '-t',
                'CT,C,C',
                '-n',
                self.ca_certificate_nickname,
                '-a',
            ],
            stdin=self.__get_ca_chain(),
        )
        if (returncode == 0):
            self.info("IPA-RA: CA chain imported to IPA's NSS DB")
        else:
            self.error("IPA-RA: Error (%d) importing CA chain to IPA's NSS DB",
                returncode)

    def __create_noise_file(self):
        noise = array.array('B', os.urandom(128))
        f = open(self.noise_file, "wb")
        noise.tofile(f)
        f.close()

    def __create_pwd_file(self):
        hex_str = binascii.hexlify(os.urandom(10))
        print "urandom: %s" % hex_str
        f = os.open(self.pwd_file, os.O_CREAT | os.O_RDWR)
        os.write(f, hex_str)
        os.close(f)

    def __create_nss_db(self):
        returncode, stdout, stderr = self.__run_certutil(["-N"])
        if (returncode == 0):
            self.info("IPA-RA: NSS DB created")
        else:
            self.warning("IPA-RA: Error (%d) creating NSS DB." % returncode)

    """
    sslget and certutil utilities are used only till Python-NSS completion.
    """


    def __run_certutil(self, args, stdin=None):
        new_args = ["/usr/bin/certutil", "-d", self.sec_dir, "-f", self.pwd_file]
        new_args = new_args + args
        return self.__run(new_args, stdin)

    def __run(self, args, stdin=None):
        if stdin:
            p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            stdout,stderr = p.communicate(stdin)
        else:
            p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            stdout,stderr = p.communicate()

        self.debug("IPA-RA: returncode: %d  args: '%s'" % (p.returncode, ' '.join(args)))
        # self.debug("IPA-RA: stdout: '%s'" % stdout)
        # self.debug("IPA-RA: stderr: '%s'" % stderr)
        return (p.returncode, stdout, stderr)

api.register(ra)
