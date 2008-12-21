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
    check_request_status       to check a certificate request status
    get_certificate            to retrieve an existing certificate
    request_certificate        to request a certificate
    revoke_certificate         to revoke a certificate
    take_certificate_off_hold  to take a certificate off hold
"""

import os, stat, subprocess
import array
import errno
import binascii
import httplib, urllib
from socket import gethostname

from ipalib import api, Backend
from ipalib import errors
from ipa_server import servercore
from ipa_server import ipaldap


class ra(Backend):


    def __init__(self):
        self.sec_dir = api.env.dot_ipa + os.sep + 'alias'
        self.pwd_file = self.sec_dir + os.sep + '.pwd'
        self.noise_file = self.sec_dir + os.sep + '.noise'

        self.ca_host = None
        self.ca_port = None
        self.ca_ssl_port = None

        self.__get_ca_location()

        self.ipa_key_size = "2048"
        self.ipa_certificate_nickname = "ipaCert"
        self.ca_certificate_nickname = "caCert"

        if not os.path.isdir(self.sec_dir):
            os.mkdir(self.sec_dir)
            self.__create_pwd_file()
            self.__create_nss_db()
            self.__import_ca_chain()
            self.__request_ipa_certificate(self.__generate_ipa_request())


    def check_request_status(self, request_id=None):
        """
        Check certificate request status
        :param request_id: request ID
        """
        self.log.debug("IPA-RA: check_request_status")
        return_values = {}
        if request_id is not None:
            params = urllib.urlencode({'requestId':  request_id, 'xmlOutput': 'true'})
            headers = {"Content-type": "application/x-www-form-urlencoded"}
            conn = httplib.HTTPConnection(self.ca_host, self.ca_port)
            conn.request("POST", "/ca/ee/ca/checkRequest", params, headers)
            response = conn.getresponse()
            api.log.debug("IPA-RA:  response.status: %d  response.reason: %s" % (response.status, response.reason))
            data = response.read()
            conn.close()
            self.log.debug(data)
            if data is not None:
                request_status = self.__find_substring(data, 'header.status = "', '"')
                if request_status is not None:
                    return_values["status"] = "0"
                    return_values["request_status"] = request_status
                    self.log.debug("IPA-RA: request_status: '%s'" % request_status)
                    serial_number = self.__find_substring(data, 'record.serialNumber="', '"')
                    if serial_number is not None:
                        return_values["serial_number"] = "0x"+serial_number
                request_id = self.__find_substring(data, 'header.requestId = "', '"')
                if request_id is not None:
                    return_values["request_id"] = request_id
                error = self.__find_substring(data, 'fixed.unexpectedError = "', '"')
                if error is not None:
                    return_values["error"] = error
            if return_values.has_key("status") is False:
                return_values["status"] = "2"
        else:
            return_values["status"] = "1"
        return return_values


    def get_certificate(self, serial_number=None):
        """
        Retrieve an existing certificate
        :param serial_number: certificate serial number
        """
        self.log.debug("IPA-RA: get_certificate")
        issued_certificate = None
        return_values = {}
        if serial_number is not None:
            request_info = ("serialNumber=%s" % serial_number)
            self.log.debug("request_info: '%s'" % request_info)
            returncode, stdout, stderr = self.__run_sslget(["-e", request_info, "-r", "/ca/agent/ca/displayBySerial", self.ca_host+":"+str(self.ca_ssl_port)])
            self.log.debug("IPA-RA: returncode: %d" % returncode)
            if (returncode == 0):
                issued_certificate = self.__find_substring(stdout, 'header.certChainBase64 = "', '"')
                if issued_certificate is not None:
                    return_values["status"] = "0"
                    issued_certificate = issued_certificate.replace("\\r", "")
                    issued_certificate = issued_certificate.replace("\\n", "")
                    self.log.debug("IPA-RA: issued_certificate: '%s'" % issued_certificate)
                    return_values["certificate"] = issued_certificate
                else:
                    return_values["status"] = "1"
            else:
                return_values["status"] = str(-returncode)
        else:
            return_values["status"] = "1"
        return return_values


    def request_certificate(self, certificate_request=None, request_type="pkcs10"):
        """
        Submit certificate request
        :param certificate_request: certificate request
        :param request_type: request type
        """
        self.log.debug("IPA-RA: request_certificate")
        certificate = None
        return_values = {}
        if request_type is None:
            request_type="pkcs10"
        if certificate_request is not None:
            request = urllib.quote(certificate_request)
            request_info = "profileId=caRAserverCert&cert_request_type="+request_type+"&cert_request="+request+"&xmlOutput=true"
            returncode, stdout, stderr = self.__run_sslget(["-e", request_info, "-r", "/ca/ee/ca/profileSubmit", self.ca_host+":"+str(self.ca_ssl_port)])
            self.log.debug("IPA-RA: returncode: %d" % returncode)
            if (returncode == 0):
                status = self.__find_substring(stdout, "<Status>", "</Status>")
                if status is not None:
                    self.log.debug ("status=%s" % status)
                    return_values["status"] = status
                request_id = self.__find_substring(stdout, "<Id>", "</Id>")
                if request_id is not None:
                    self.log.debug ("request_id=%s" % request_id)
                    return_values["request_id"] = request_id
                serial_number = self.__find_substring(stdout, "<serialno>", "</serialno>")
                if serial_number is not None:
                    self.log.debug ("serial_number=%s" % serial_number)
                    return_values["serial_number"] = ("0x%s" % serial_number)
                subject = self.__find_substring(stdout, "<SubjectDN>", "</SubjectDN>")
                if subject is not None:
                    self.log.debug ("subject=%s" % subject)
                    return_values["subject"] = subject
                certificate = self.__find_substring(stdout, "<b64>", "</b64>")
                if certificate is not None:
                    self.log.debug ("certificate=%s" % certificate)
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
        self.log.debug("IPA-RA: revoke_certificate")
        if revocation_reason is None:
            revocation_reason = 0
        if serial_number is not None:
            if isinstance(serial_number, int):
                serial_number = str(serial_number)
            if isinstance(revocation_reason, int):
                revocation_reason = str(revocation_reason)
            request_info = "op=revoke&revocationReason="+revocation_reason+"&revokeAll=(certRecordId%3D"+serial_number+")&totalRecordCount=1"
            returncode, stdout, stderr = self.__run_sslget(["-e", request_info, "-r", "/ca/agent/ca/doRevoke", self.ca_host+":"+str(self.ca_ssl_port)])
            api.log.debug("IPA-RA: returncode: %d" % returncode)
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
        self.log.debug("IPA-RA: revoke_certificate")
        if serial_number is not None:
            if isinstance(serial_number, int):
                serial_number = str(serial_number)
            request_info = "serialNumber="+serial_number
            returncode, stdout, stderr = self.__run_sslget(["-e", request_info, "-r", "/ca/agent/ca/doUnrevoke", self.ca_host+":"+str(self.ca_ssl_port)])
            api.log.debug("IPA-RA: returncode: %d" % returncode)
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


    def __get_ca_location(self):
        if 'ca_host' in api.env:
            api.log.debug("ca_host configuration found")
            if api.env.ca_host is not None:
                self.ca_host = api.env.ca_host
        else:
            api.log.debug("ca_host configuration not found")
        # if CA is not hosted with IPA on the same system and there is no configuration support for 'api.env.ca_host', then set ca_host below
        # self.ca_host = "example.com"
        if self.ca_host is None:
            self.ca_host = gethostname()
        api.log.debug("ca_host: %s" % self.ca_host)

        if 'ca_ssl_port' in api.env:
            api.log.debug("ca_ssl_port configuration found")
            if api.env.ca_ssl_port is not None:
                self.ca_ssl_port = api.env.ca_ssl_port
        else:
            api.log.debug("ca_ssl_port configuration not found")
        if self.ca_ssl_port is None:
            self.ca_ssl_port = 9443
        api.log.debug("ca_ssl_port: %d" % self.ca_ssl_port)

        if 'ca_port' in api.env:
            api.log.debug("ca_port configuration found")
            if api.env.ca_port is not None:
                self.ca_port = api.env.ca_port
        else:
            api.log.debug("ca_port configuration not found")
        if self.ca_port is None:
            self.ca_port = 9080
        api.log.debug("ca_port: %d" % self.ca_port)


    def __generate_ipa_request(self):
        certificate_request = None
        if not os.path.isfile(self.noise_file):
            self.__create_noise_file()
        returncode, stdout, stderr = self.__run_certutil(["-R", "-k", "rsa", "-g", self.ipa_key_size, "-s", "CN=IPA-Subsystem-Certificate,OU=pki-ipa,O=UsersysRedhat-Domain", "-z", self.noise_file, "-a"])
        if os.path.isfile(self.noise_file):
            os.unlink(self.noise_file)
        if (returncode == 0):
            api.log.info("IPA-RA: IPA certificate request generated")
            certificate_request = self.__find_substring(stdout, "-----BEGIN NEW CERTIFICATE REQUEST-----", "-----END NEW CERTIFICATE REQUEST-----")
            if certificate_request is not None:
                api.log.debug("certificate_request=%s" % certificate_request)
            else:
                api.log.warn("IPA-RA: Error parsing certificate request." % returncode)
        else:
            api.log.warn("IPA-RA: Error (%d) generating IPA certificate request." % returncode)
        return certificate_request

    def __request_ipa_certificate(self, certificate_request=None):
        ipa_certificate = None
        if certificate_request is not None:
            params = urllib.urlencode({'profileId': 'caServerCert', 'cert_request_type': 'pkcs10', 'requestor_name': 'freeIPA', 'cert_request': self.__generate_ipa_request(), 'xmlOutput': 'true'})
            headers = {"Content-type": "application/x-www-form-urlencoded"}
            conn = httplib.HTTPConnection(self.ca_host+":"+elf.ca_port)
            conn.request("POST", "/ca/ee/ca/profileSubmit", params, headers)
            response = conn.getresponse()
            api.log.debug("IPA-RA: response.status: %d  response.reason: '%s'" % (response.status, response.reason))
            data = response.read()
            conn.close()
            api.log.info("IPA-RA: IPA certificate request submitted to CA: %s" % data)
        return ipa_certificate

    def __get_ca_chain(self):
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        conn = httplib.HTTPConnection(self.ca_host+":"+elf.ca_port)
        conn.request("POST", "/ca/ee/ca/getCertChain", None, headers)
        response = conn.getresponse()
        api.log.debug("IPA-RA: response.status: %d  response.reason: '%s'" % (response.status, response.reason))
        data = response.read()
        conn.close()
        certificate_chain = self.__find_substring(data, "<ChainBase64>", "</ChainBase64>")
        if certificate_chain is not None:
            api.log.info(("IPA-RA: CA chain obtained from CA: %s" % certificate_chain))
        else:
            api.log.warn("IPA-RA: Error parsing certificate chain.")
        return certificate_chain

    def __import_ca_chain(self):
        returncode, stdout, stderr = self.__run_certutil(["-A", "-t", "CT,C,C", "-n", self.ca_certificate_nickname, "-a"], self.__get_ca_chain())
        if (returncode == 0):
            api.log.info("IPA-RA: CA chain imported to IPA's NSS DB")
        else:
            api.log.warn("IPA-RA: Error (%d) importing CA chain to IPA's NSS DB." % returncode)

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
            api.log.info("IPA-RA: NSS DB created")
        else:
            api.log.warn("IPA-RA: Error (%d) creating NSS DB." % returncode)

    """
    sslget and certutil utilities are used only till Python-NSS completion.
    """
    def __run_sslget(self, args, stdin=None):
        new_args = ["/usr/bin/sslget", "-d", self.sec_dir, "-w", self.pwd_file, "-n", self.ipa_certificate_nickname]
        new_args = new_args + args
        return self.__run(new_args, stdin)

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

        api.log.debug("IPA-RA: returncode: %d  args: '%s'" % (p.returncode, ' '.join(args)))
        # api.log.debug("IPA-RA: stdout: '%s'" % stdout)
        # api.log.debug("IPA-RA: stderr: '%s'" % stderr)
        return (p.returncode, stdout, stderr)

api.register(ra)
