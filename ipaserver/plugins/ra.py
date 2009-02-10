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

IPA-RA provides an access to CA to issue, retrieve, and revoke certificates.
IPA-RA plugin provides CA interface via the following methods:
    check_request_status       to check certificate request status
    get_certificate            to retrieve an existing certificate
    request_certificate        to request certificate
    revoke_certificate         to revoke certificate
    take_certificate_off_hold  to take certificate off hold
"""

import os, stat, subprocess
import array
import errno
import binascii
from httplib import HTTPConnection
from urllib import urlencode, quote
from socket import gethostname
import socket

from ipalib import api, Backend
from ipalib.errors2 import NetworkError
from ipaserver import servercore
from ipaserver import ipaldap


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

    def _request(self, method, **kw):
        """
        Perform an HTTP request to CA server.
        """
        # FIXME: should '/ca/ee/ca/%s' be hardcoded, or should it be in Env?
        url = '/ca/ee/ca/%s' % method
        self.info('CA request: %s:%s%s',
            self.env.ca_host, self.env.ca_port, url)
        conn = HTTPConnection(self.env.ca_host, self.env.ca_port)
        try:
            conn.request('POST', url,
                body=urlencode(kw),
                headers={'Content-type': 'application/x-www-form-urlencoded'},
            )
        except socket.error, e:
            raise NetworkError(
                uri='http://%s:%d' % (self.env.ca_host, self.env.ca_port),
                error=e.args[1],
            )
        response = conn.getresponse()
        (status, reason) = (response.status, response.reason)
        data = response.read()
        conn.close()
        self.debug('response status: %r', status)
        self.debug('response reason: %r', reason)
        #self.debug('response data: %r', data)
        return (status, reason, data)

    def check_request_status(self, request_id):
        """
        Check status of a certificate signing request.

        :param request_id: request ID
        """
        self.debug('IPA-RA: check_request_status')
        (s, r, data) = self._request('checkRequest',
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
                    # the same form used in get_certificate()
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

    def __run_sslget(self, args, stdin=None):
        new_args = ["/usr/bin/sslget", "-d", self.sec_dir, "-w", self.pwd_file, "-n", self.ipa_certificate_nickname]
        new_args = new_args + args
        return self.__run(new_args, stdin)

    def _sslget(self, url, **kw):
        """
        Perform HTTPS request using ``sslget`` command.

        This is only a stop-gap till it is replaced with python-nss.
        """
        post = urlencode(kw)
        self.debug('sslget %s %s', url, post)
        argv = [
            '/usr/bin/sslget',
            '-n', self.ipa_certificate_nickname,  # nickname
            '-w', self.pwd_file,  # pwfile
            '-d', self.sec_dir,  # dbdir
            '-e', post,  # post
            '-r', url,  # url
            '%s:%d' % (self.env.ca_host, self.env.ca_ssl_port),
        ]
        return self.__run(argv)

    def get_certificate(self, serial_number=None):
        """
        Retrieve an existing certificate.

        :param serial_number: certificate serial number
        """
        self.debug('IPA-RA: get_certificate')
        issued_certificate = None
        (returncode, stdout, stderr) = self._sslget(
            '/ca/agent/ca/displayBySerial',
            serialNumber=serial_number,
        )
        self.debug("IPA-RA: returncode: %d" % returncode)
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

    def request_certificate(self, certificate_request=None, request_type="pkcs10"):
        """
        Submit certificate request
        :param certificate_request: certificate request
        :param request_type: request type
        """
        self.debug("IPA-RA: request_certificate")
        certificate = None
        return_values = {}
        if request_type is None:
            request_type="pkcs10"
        if certificate_request is not None:
            request = quote(certificate_request)
            request_info = "profileId=caRAserverCert&cert_request_type="+request_type+"&cert_request="+request+"&xmlOutput=true"
            (returncode, stdout, stderr) = self.__run_sslget([
                '-e',
                request_info,
                '-r',
                '/ca/ee/ca/profileSubmit',
                '%s:%d' % (self.env.ca_host, self.env.ca_ssl_port),
            ])
            self.debug("IPA-RA: returncode: %d" % returncode)
            if (returncode == 0):
                status = self.__find_substring(stdout, "<Status>", "</Status>")
                if status is not None:
                    self.debug ("status=%s" % status)
                    return_values["status"] = status
                request_id = self.__find_substring(stdout, "<Id>", "</Id>")
                if request_id is not None:
                    self.debug ("request_id=%s" % request_id)
                    return_values["request_id"] = request_id
                serial_number = self.__find_substring(stdout, "<serialno>", "</serialno>")
                if serial_number is not None:
                    self.debug ("serial_number=%s" % serial_number)
                    return_values["serial_number"] = ("0x%s" % serial_number)
                subject = self.__find_substring(stdout, "<SubjectDN>", "</SubjectDN>")
                if subject is not None:
                    self.debug ("subject=%s" % subject)
                    return_values["subject"] = subject
                certificate = self.__find_substring(stdout, "<b64>", "</b64>")
                if certificate is not None:
                    self.debug ("certificate=%s" % certificate)
                    return_values["certificate"] = certificate
                if return_values.has_key("status") is False:
                    return_values["status"] = "2"
            else:
                return_values["status"] = str(-returncode)
        else:
            return_values["status"] = "1"
        return return_values


    def revoke_certificate(self, serial_number=None, revocation_reason=0):
        """
        Revoke a certificate
        :param serial_number: certificate serial number
        :param revocation_reason: revocation reason
        revocationr reasons: 0 - unspecified
                             1 - key compromise
                             2 - ca compromise
                             3 - affiliation changed
                             4 - superseded
                             5 - cessation of operation
                             6 - certificate hold
                             7 - value 7 is not used
                             8 - remove from CRL
                             9 - privilege withdrawn
                            10 - aa compromise
        see RFC 5280 for more details
        """
        return_values = {}
        self.debug("IPA-RA: revoke_certificate")
        if revocation_reason is None:
            revocation_reason = 0
        if serial_number is not None:
            if isinstance(serial_number, int):
                serial_number = str(serial_number)
            if isinstance(revocation_reason, int):
                revocation_reason = str(revocation_reason)
            request_info = "op=revoke&revocationReason="+revocation_reason+"&revokeAll=(certRecordId%3D"+serial_number+")&totalRecordCount=1"
            (returncode, stdout, stderr) = self.__run_sslget([
                '-e',
                request_info,
                '-r',
                '/ca/agent/ca/doRevoke',
                '%s:%d' % (self.env.ca_host, self.env.ca_ssl_port),
            ])
            self.debug("IPA-RA: returncode: %d" % returncode)
            if (returncode == 0):
                return_values["status"] = "0"
                if (stdout.find('revoked = "yes"') > -1):
                    return_values["revoked"] = True
                else:
                    return_values["revoked"] = False
            else:
                return_values["status"] = str(-returncode)
        else:
            return_values["status"] = "1"
        return return_values


    def take_certificate_off_hold(self, serial_number=None):
        """
        Take revoked certificate off hold
        :param serial_number: certificate serial number
        """
        return_values = {}
        self.debug("IPA-RA: revoke_certificate")
        if serial_number is not None:
            if isinstance(serial_number, int):
                serial_number = str(serial_number)
            request_info = "serialNumber="+serial_number
            (returncode, stdout, stderr) = self.__run_sslget([
                '-e',
                request_info,
                '-r',
                '/ca/agent/ca/doUnrevoke',
                '%s:%d' % (self.env.ca_host, self.env.ca_ssl_port),
            ])
            self.debug("IPA-RA: returncode: %d" % returncode)
            if (returncode == 0):
                if (stdout.find('unrevoked = "yes"') > -1):
                    return_values["taken_off_hold"] = True
                else:
                    return_values["taken_off_hold"] = False
            else:
                return_values["status"] = str(-returncode)
        else:
            return_values["status"] = "1"
        return return_values


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
