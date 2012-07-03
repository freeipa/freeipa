# Authors: Rob Crittenden <rcritten@redhat.com>
#          John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2009    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import sys
import httplib
import getpass
import socket
from ipapython.ipa_log_manager import *

from nss.error import NSPRError
import nss.io as io
import nss.nss as nss
import nss.ssl as ssl
import nss.error as error

def auth_certificate_callback(sock, check_sig, is_server, certdb):
    cert_is_valid = False

    cert = sock.get_peer_certificate()

    root_logger.debug("auth_certificate_callback: check_sig=%s is_server=%s\n%s",
                              check_sig, is_server, str(cert))

    pin_args = sock.get_pkcs11_pin_arg()
    if pin_args is None:
        pin_args = ()

    # Define how the cert is being used based upon the is_server flag.  This may
    # seem backwards, but isn't. If we're a server we're trying to validate a
    # client cert. If we're a client we're trying to validate a server cert.
    if is_server:
        intended_usage = nss.certificateUsageSSLClient
    else:
        intended_usage = nss.certificateUsageSSLServer

    try:
        # If the cert fails validation it will raise an exception, the errno attribute
        # will be set to the error code matching the reason why the validation failed
        # and the strerror attribute will contain a string describing the reason.
        approved_usage = cert.verify_now(certdb, check_sig, intended_usage, *pin_args)
    except Exception, e:
        root_logger.error('cert validation failed for "%s" (%s)', cert.subject, e.strerror)
        cert_is_valid = False
        return cert_is_valid

    root_logger.debug("approved_usage = %s intended_usage = %s",
                              ', '.join(nss.cert_usage_flags(approved_usage)),
                              ', '.join(nss.cert_usage_flags(intended_usage)))

    # Is the intended usage a proper subset of the approved usage
    if approved_usage & intended_usage:
        cert_is_valid = True
    else:
        cert_is_valid = False

    # If this is a server, we're finished
    if is_server or not cert_is_valid:
        root_logger.debug('cert valid %s for "%s"', cert_is_valid,  cert.subject)
        return cert_is_valid

    # Certificate is OK.  Since this is the client side of an SSL
    # connection, we need to verify that the name field in the cert
    # matches the desired hostname.  This is our defense against
    # man-in-the-middle attacks.

    hostname = sock.get_hostname()
    try:
        # If the cert fails validation it will raise an exception
        cert_is_valid = cert.verify_hostname(hostname)
    except Exception, e:
        root_logger.error('failed verifying socket hostname "%s" matches cert subject "%s" (%s)',
                                  hostname, cert.subject, e.strerror)
        cert_is_valid = False
        return cert_is_valid

    root_logger.debug('cert valid %s for "%s"', cert_is_valid,  cert.subject)
    return cert_is_valid

def client_auth_data_callback(ca_names, chosen_nickname, password, certdb):
    cert = None
    if chosen_nickname:
        try:
            cert = nss.find_cert_from_nickname(chosen_nickname, password)
            priv_key = nss.find_key_by_any_cert(cert, password)
            return cert, priv_key
        except NSPRError:
            return False
    else:
        nicknames = nss.get_cert_nicknames(certdb, nss.SEC_CERT_NICKNAMES_USER)
        for nickname in nicknames:
            try:
                cert = nss.find_cert_from_nickname(nickname, password)
                if cert.check_valid_times():
                    if cert.has_signer_in_ca_names(ca_names):
                        priv_key = nss.find_key_by_any_cert(cert, password)
                        return cert, priv_key
            except NSPRError:
                return False
        return False

_af_dict = {
    socket.AF_INET: io.PR_AF_INET,
    socket.AF_INET6: io.PR_AF_INET6,
    socket.AF_UNSPEC: io.PR_AF_UNSPEC
}

class NSSAddressFamilyFallback(object):
    def __init__(self, family):
        self.sock_family = family
        self.family = self._get_nss_family(self.sock_family)

    def _get_nss_family(self, sock_family):
        """
        Translate a family from python socket module to nss family.
        """
        try:
            return _af_dict[sock_family]
        except KeyError:
            raise ValueError('Uknown socket family %d\n', sock_family)

    def _create_socket(self):
        self.sock = io.Socket(family=self.family)

    def connect_socket(self, host, port):
        try:
            addr_info = io.AddrInfo(host, family=self.family)
        except Exception:
             raise NSPRError(error.PR_ADDRESS_NOT_SUPPORTED_ERROR,
                             "Cannot resolve %s using family %s" % (host,
                                 io.addr_family_name(self.family)))

        for net_addr in addr_info:
            root_logger.debug("Connecting: %s", net_addr)
            net_addr.port = port
            self.family = net_addr.family
            try:
                self._create_socket()
                self.sock.connect(net_addr)
                return
            except Exception, e:
                root_logger.debug("Could not connect socket to %s, error: %s",
                        net_addr, str(e))
                root_logger.debug("Try to continue with next family...")
                continue

        raise NSPRError(error.PR_ADDRESS_NOT_SUPPORTED_ERROR,
                "Could not connect to %s using any address" % host)


class NSSConnection(httplib.HTTPConnection, NSSAddressFamilyFallback):
    default_port = httplib.HTTPSConnection.default_port

    def __init__(self, host, port=None, strict=None,
                 dbdir=None, family=socket.AF_UNSPEC, no_init=False):
        """
        :param host: the server to connect to
        :param port: the port to use (default is set in HTTPConnection)
        :param dbdir: the NSS database directory
        :param family: network family to use (default AF_UNSPEC)
        :param no_init: do not initialize the NSS database. This requires
                        that the database has already been initialized or
                        the request will fail.
        """
        httplib.HTTPConnection.__init__(self, host, port, strict)
        NSSAddressFamilyFallback.__init__(self, family)

        if not dbdir:
            raise RuntimeError("dbdir is required")

        root_logger.debug('%s init %s', self.__class__.__name__, host)
        if not no_init and nss.nss_is_initialized():
            # close any open NSS database and use the new one
            ssl.clear_session_cache()
            try:
                nss.nss_shutdown()
            except NSPRError, e:
                if e.errno != error.SEC_ERROR_NOT_INITIALIZED:
                    raise e
        nss.nss_init(dbdir)
        ssl.set_domestic_policy()
        nss.set_password_callback(self.password_callback)

    def _create_socket(self):
        # TODO: remove the try block once python-nss is guaranteed to contain
        # these values
        try :
                ssl_enable_renegotiation  = SSL_ENABLE_RENEGOTIATION   #pylint: disable=E0602
                ssl_require_safe_negotiation = SSL_REQUIRE_SAFE_NEGOTIATION  #pylint: disable=E0602
                ssl_renegotiate_requires_xtn = SSL_RENEGOTIATE_REQUIRES_XTN #pylint: disable=E0602
        except :
                ssl_enable_renegotiation  = 20
                ssl_require_safe_negotiation = 21
                ssl_renegotiate_requires_xtn = 2

        # Create the socket here so we can do things like let the caller
        # override the NSS callbacks
        self.sock = ssl.SSLSocket(family=self.family)
        self.sock.set_ssl_option(ssl.SSL_SECURITY, True)
        self.sock.set_ssl_option(ssl.SSL_HANDSHAKE_AS_CLIENT, True)
        self.sock.set_ssl_option(ssl_require_safe_negotiation, False)
        self.sock.set_ssl_option(ssl_enable_renegotiation, ssl_renegotiate_requires_xtn)
        # Provide a callback which notifies us when the SSL handshake is complete
        self.sock.set_handshake_callback(self.handshake_callback)

        # Provide a callback to verify the servers certificate
        self.sock.set_auth_certificate_callback(auth_certificate_callback,
                                                nss.get_default_certdb())
        self.sock.set_hostname(self.host)

    def password_callback(self, slot, retry, password):
        if not retry and password: return password
        return getpass.getpass("Enter password for %s: " % slot.token_name);

    def handshake_callback(self, sock):
        """
        Verify callback. If we get here then the certificate is ok.
        """
        root_logger.debug("handshake complete, peer = %s", sock.get_peer_name())
        pass

    def connect(self):
        self.connect_socket(self.host, self.port)

    def endheaders(self, message=None):
        """
        Explicitly close the connection if an error is returned after the
        headers are sent. This will likely mean the initial SSL handshake
        failed. If this isn't done then the connection is never closed and
        subsequent NSS activities will fail with a BUSY error.
        """
        try:
            # FIXME: httplib uses old-style classes so super doesn't work
            # Python 2.7 changed the API for endheaders. This is an attempt
            # to work across versions
            (major, minor, micro, releaselevel, serial) = sys.version_info
            if major == 2 and minor < 7:
                httplib.HTTPConnection.endheaders(self)
            else:
                httplib.HTTPConnection.endheaders(self, message)
        except NSPRError, e:
            self.close()
            raise e

class NSSHTTPS(httplib.HTTP):
    # We would like to use HTTP 1.1 not the older HTTP 1.0 but xmlrpclib
    # and httplib do not play well together. httplib when the protocol
    # is 1.1 will add a host header in the request. But xmlrpclib
    # always adds a host header irregardless of the HTTP protocol
    # version. That means the request ends up with 2 host headers,
    # but Apache freaks out if it sees 2 host headers, a known Apache
    # issue. httplib has a mechanism to skip adding the host header
    # (i.e. skip_host in HTTPConnection.putrequest()) but xmlrpclib
    # doesn't use it. Oh well, back to 1.0  :-(
    #
    #_http_vsn = 11
    #_http_vsn_str = 'HTTP/1.1'

    _connection_class = NSSConnection

    def __init__(self, host='', port=None, strict=None, dbdir=None, no_init=False):
        # provide a default host, pass the X509 cert info

        # urf. compensate for bad input.
        if port == 0:
            port = None
        self._setup(self._connection_class(host, port, strict, dbdir=dbdir, no_init=no_init))

    def getreply(self):
        """
        Override so we can close duplicated file connection on non-200
        responses. This was causing nss_shutdown() to fail with a busy
        error.
        """
        (status, reason, msg) = httplib.HTTP.getreply(self)
        if status != 200:
            self.file.close()
        return (status, reason, msg)

#------------------------------------------------------------------------------

if __name__ == "__main__":
    standard_logging_setup('nsslib.log', debug=True, filemode='a')
    root_logger.info("Start")

    if False:
        conn = NSSConnection("www.verisign.com", 443, dbdir="/etc/pki/nssdb")
        conn.set_debuglevel(1)
        conn.connect()
        conn.request("GET", "/")
        response = conn.getresponse()
        print response.status
        #print response.msg
        print response.getheaders()
        data = response.read()
        #print data
        conn.close()

    if True:
        h = NSSHTTPS("www.verisign.com", 443, dbdir="/etc/pki/nssdb")
        h.connect()
        h.putrequest('GET', '/')
        h.endheaders()
        http_status, http_reason, headers = h.getreply()
        print "status = %s %s" % (http_status, http_reason)
        print "headers:\n%s" % headers
        f = h.getfile()
        data = f.read() # Get the raw HTML
        f.close()
        #print data
