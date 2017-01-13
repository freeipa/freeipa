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

from __future__ import print_function

import getpass
import socket
from ipapython.ipa_log_manager import root_logger
from ipapython.ipa_log_manager import log_mgr
from ipalib.constants import TLS_VERSIONS, TLS_VERSION_MINIMAL

from nss.error import NSPRError
import nss.io as io
import nss.nss as nss
import nss.ssl as ssl
import nss.error as error

# Python 3 rename. The package is available in "six.moves.http_client", but
# pylint cannot handle classes from that alias
try:
    import httplib
except ImportError:
    # pylint: disable=import-error
    import http.client as httplib

# get a logger for this module
logger = log_mgr.get_logger(__name__)

# NSS database currently open
current_dbdir = None

def auth_certificate_callback(sock, check_sig, is_server, certdb):
    cert_is_valid = False

    cert = sock.get_peer_certificate()

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
    except Exception as e:
        root_logger.error(
            'cert validation failed for "%s" (%s)', cert.subject,
            e.strerror)  # pylint: disable=no-member
        cert_is_valid = False
        return cert_is_valid

    root_logger.debug("approved_usage = %s intended_usage = %s",
                              ', '.join(nss.cert_usage_flags(approved_usage)),
                              ', '.join(nss.cert_usage_flags(intended_usage)))

    # Is the intended usage a proper subset of the approved usage
    cert_is_valid = bool(approved_usage & intended_usage)

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
    except Exception as e:
        root_logger.error('failed verifying socket hostname "%s" matches cert subject "%s" (%s)',
                          hostname, cert.subject,
                          e.strerror)  # pylint: disable=no-member
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


def get_proper_tls_version_span(tls_version_min, tls_version_max):
    """
    This function checks whether the given TLS versions are known in FreeIPA
    and that these versions fulfill the requirements for minimal TLS version
    (see `ipalib.constants: TLS_VERSIONS, TLS_VERSION_MINIMAL`).

    :param tls_version_min:
        the lower value in the TLS min-max span, raised to the lowest allowed
        value if too low
    :param tls_version_max:
        the higher value in the TLS min-max span, raised to tls_version_min
        if lower than TLS_VERSION_MINIMAL
    :raises: ValueError
    """
    min_allowed_idx = TLS_VERSIONS.index(TLS_VERSION_MINIMAL)

    try:
        min_version_idx = TLS_VERSIONS.index(tls_version_min)
    except ValueError:
        raise ValueError("tls_version_min ('{val}') is not a known "
                         "TLS version.".format(val=tls_version_min))

    try:
        max_version_idx = TLS_VERSIONS.index(tls_version_max)
    except ValueError:
        raise ValueError("tls_version_max ('{val}') is not a known "
                         "TLS version.".format(val=tls_version_max))

    if min_version_idx > max_version_idx:
        raise ValueError("tls_version_min is higher than "
                         "tls_version_max.")

    if min_version_idx < min_allowed_idx:
        min_version_idx = min_allowed_idx
        logger.warning("tls_version_min set too low ('{old}'),"
                       "using '{new}' instead"
                       .format(old=tls_version_min,
                               new=TLS_VERSIONS[min_version_idx]))

    if max_version_idx < min_allowed_idx:
        max_version_idx = min_version_idx
        logger.warning("tls_version_max set too low ('{old}'),"
                       "using '{new}' instead"
                       .format(old=tls_version_max,
                               new=TLS_VERSIONS[max_version_idx]))

    return TLS_VERSIONS[min_version_idx:max_version_idx+1]


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
            raise NSPRError(
                error_code=error.PR_ADDRESS_NOT_SUPPORTED_ERROR,
                error_message="Cannot resolve %s using family %s" % (host,
                    io.addr_family_name(self.family)))

        for net_addr in addr_info:
            root_logger.debug("Connecting: %s", net_addr)
            net_addr.port = port
            self.family = net_addr.family
            try:
                self._create_socket()
                self.sock.connect(net_addr)
                return
            except Exception as e:
                root_logger.debug("Could not connect socket to %s, error: %s",
                        net_addr, str(e))
                root_logger.debug("Try to continue with next family...")
                continue

        raise NSPRError(
            error_code=error.PR_ADDRESS_NOT_SUPPORTED_ERROR,
            error_message="Could not connect to %s using any address" % host)


class NSSConnection(httplib.HTTPConnection, NSSAddressFamilyFallback):
    default_port = httplib.HTTPSConnection.default_port

    def __init__(self, host, port=None, strict=None,
                 dbdir=None, family=socket.AF_UNSPEC, no_init=False,
                 tls_version_min='tls1.1', tls_version_max='tls1.2'):
        """
        :param host: the server to connect to
        :param port: the port to use (default is set in HTTPConnection)
        :param dbdir: the NSS database directory
        :param family: network family to use (default AF_UNSPEC)
        :param no_init: do not initialize the NSS database. This requires
                        that the database has already been initialized or
                        the request will fail.
        :param tls_min_version: mininum version of SSL/TLS supported
        :param tls_max_version: maximum version of SSL/TLS supported.
        """
        httplib.HTTPConnection.__init__(self, host, port, strict)
        NSSAddressFamilyFallback.__init__(self, family)

        root_logger.debug('%s init %s', self.__class__.__name__, host)

        # If initialization is requested, initialize the new database.
        if not no_init:

            if nss.nss_is_initialized():
                ssl.clear_session_cache()
                try:
                    nss.nss_shutdown()
                except NSPRError as e:
                    if e.errno != error.SEC_ERROR_NOT_INITIALIZED:
                        raise e

            if not dbdir:
                raise RuntimeError("dbdir is required")

            nss.nss_init(dbdir)

            global current_dbdir
            current_dbdir = dbdir

        ssl.set_domestic_policy()
        nss.set_password_callback(self.password_callback)
        tls_versions = get_proper_tls_version_span(
            tls_version_min, tls_version_max)
        self.tls_version_min = tls_versions[0]
        self.tls_version_max = tls_versions[-1]

    def _create_socket(self):
        ssl_enable_renegotiation = getattr(
            ssl, 'SSL_ENABLE_RENEGOTIATION', 20)
        ssl_require_safe_negotiation = getattr(
            ssl,'SSL_REQUIRE_SAFE_NEGOTIATION', 21)
        ssl_renegotiate_requires_xtn = getattr(
            ssl, 'SSL_RENEGOTIATE_REQUIRES_XTN', 2)

        # Create the socket here so we can do things like let the caller
        # override the NSS callbacks
        self.sock = ssl.SSLSocket(family=self.family)
        self.sock.set_ssl_option(ssl.SSL_SECURITY, True)
        self.sock.set_ssl_option(ssl.SSL_HANDSHAKE_AS_CLIENT, True)
        try:
            self.sock.set_ssl_version_range(self.tls_version_min, self.tls_version_max)
        except NSPRError:
            root_logger.error('Failed to set TLS range to %s, %s' % (self.tls_version_min, self.tls_version_max))
            raise
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
        return getpass.getpass("Enter password for %s: " % slot.token_name)

    def handshake_callback(self, sock):
        """
        Verify callback. If we get here then the certificate is ok.
        """
        channel = sock.get_ssl_channel_info()
        suite = ssl.get_cipher_suite_info(channel.cipher_suite)
        root_logger.debug("handshake complete, peer = %s", sock.get_peer_name())
        root_logger.debug('Protocol: %s' % channel.protocol_version_str.upper())
        root_logger.debug('Cipher: %s' % suite.cipher_suite_name)

    def connect(self):
        self.connect_socket(self.host, self.port)

    def close(self):
        """Close the connection to the HTTP server."""
        if self.sock:
            self.sock.close()   # close it manually... there may be other refs
            self.sock = None
            ssl.clear_session_cache()

    def endheaders(self, message=None):
        """
        Explicitly close the connection if an error is returned after the
        headers are sent. This will likely mean the initial SSL handshake
        failed. If this isn't done then the connection is never closed and
        subsequent NSS activities will fail with a BUSY error.
        """
        try:
            # FIXME: httplib uses old-style classes so super doesn't work
            httplib.HTTPConnection.endheaders(self, message)
        except NSPRError as e:
            self.close()
            raise e
