# Authors: Rob Crittenden <rcritten@redhat.com>
#          John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2009    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import httplib
import getpass
import logging

from nss.error import NSPRError
import nss.io as io
import nss.nss as nss
import nss.ssl as ssl

def auth_certificate_callback(sock, check_sig, is_server, certdb):
    cert_is_valid = False

    cert = sock.get_peer_certificate()

    logging.debug("auth_certificate_callback: check_sig=%s is_server=%s\n%s",
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
        logging.error('cert validation failed for "%s" (%s)', cert.subject, e.strerror)
        cert_is_valid = False
        return cert_is_valid

    logging.debug("approved_usage = %s intended_usage = %s",
                  ', '.join(nss.cert_usage_flags(approved_usage)),
                  ', '.join(nss.cert_usage_flags(intended_usage)))

    # Is the intended usage a proper subset of the approved usage
    if approved_usage & intended_usage:
        cert_is_valid = True
    else:
        cert_is_valid = False

    # If this is a server, we're finished
    if is_server or not cert_is_valid:
        logging.debug('cert valid %s for "%s"', cert_is_valid,  cert.subject)
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
        logging.error('failed verifying socket hostname "%s" matches cert subject "%s" (%s)',
                      hostname, cert.subject, e.strerror)
        cert_is_valid = False
        return cert_is_valid

    logging.debug('cert valid %s for "%s"', cert_is_valid,  cert.subject)
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

class NSSConnection(httplib.HTTPConnection):
    default_port = httplib.HTTPSConnection.default_port

    def __init__(self, host, port=None, strict=None, dbdir=None):
        httplib.HTTPConnection.__init__(self, host, port, strict)

        if not dbdir:
            raise RuntimeError("dbdir is required")

        logging.debug('%s init %s', self.__class__.__name__, host)
        nss.nss_init(dbdir)
        ssl.set_domestic_policy()
        nss.set_password_callback(self.password_callback)

        # Create the socket here so we can do things like let the caller
        # override the NSS callbacks
        self.sock = ssl.SSLSocket()
        self.sock.set_ssl_option(ssl.SSL_SECURITY, True)
        self.sock.set_ssl_option(ssl.SSL_HANDSHAKE_AS_CLIENT, True)

        # Provide a callback which notifies us when the SSL handshake is complete
        self.sock.set_handshake_callback(self.handshake_callback)

        # Provide a callback to verify the servers certificate
        self.sock.set_auth_certificate_callback(auth_certificate_callback,
                                           nss.get_default_certdb())

    def password_callback(self, slot, retry, password):
        if not retry and password: return password
        return getpass.getpass("Enter password for %s: " % slot.token_name);

    def handshake_callback(self, sock):
        """
        Verify callback. If we get here then the certificate is ok.
        """
        logging.debug("handshake complete, peer = %s", sock.get_peer_name())
        pass

    def connect(self):
        logging.debug("connect: host=%s port=%s", self.host, self.port)
        self.sock.set_hostname(self.host)
        net_addr = io.NetworkAddress(self.host, self.port)
        logging.debug("connect: %s", net_addr)
        self.sock.connect(net_addr)

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

    def __init__(self, host='', port=None, strict=None, dbdir=None):
        # provide a default host, pass the X509 cert info

        # urf. compensate for bad input.
        if port == 0:
            port = None
        self._setup(self._connection_class(host, port, strict, dbdir=dbdir))

class NSPRConnection(httplib.HTTPConnection):
    default_port = httplib.HTTPConnection.default_port

    def __init__(self, host, port=None, strict=None):
        httplib.HTTPConnection.__init__(self, host, port, strict)

        logging.debug('%s init %s', self.__class__.__name__, host)
        nss.nss_init_nodb()

        self.sock = io.Socket()
    def connect(self):
        logging.debug("connect: host=%s port=%s", self.host, self.port)
        net_addr = io.NetworkAddress(self.host, self.port)
        logging.debug("connect: %s", net_addr)
        self.sock.connect(net_addr)

class NSPRHTTP(httplib.HTTP):
    _http_vsn = 11
    _http_vsn_str = 'HTTP/1.1'

    _connection_class = NSPRConnection

#------------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%m-%d %H:%M',
                        filename='nsslib.log',
                        filemode='a')
    # Create a seperate logger for the console
    console_logger = logging.StreamHandler()
    console_logger.setLevel(logging.DEBUG)
    # set a format which is simpler for console use
    formatter = logging.Formatter('%(levelname)s %(message)s')
    console_logger.setFormatter(formatter)
    # add the handler to the root logger
    logging.getLogger('').addHandler(console_logger)
    logging.info("Start")

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
