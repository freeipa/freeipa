# Authors: Rob Crittenden <rcritten@redhat.com>
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
import socket

from nss.error import NSPRError
import nss.io as io
import nss.nss as nss
import nss.ssl as ssl

try:
    from httplib import SSLFile
    from httplib import FakeSocket
except ImportError:
    from ipapython.ipasslfile import SSLFile
    from ipapython.ipasslfile import FakeSocket

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

class SSLFile(SSLFile):
    """
    Override the _read method so we can use the NSS recv method.
    """
    def _read(self):
        buf = ''
        while True:
            try:
                buf = self._ssl.recv(self._bufsize)
            except NSPRError, e:
                raise e
            else:
                break
        return buf

class NSSFakeSocket(FakeSocket):
    def makefile(self, mode, bufsize=None):
        if mode != 'r' and mode != 'rb':
            raise httplib.UnimplementedFileMode()
        return SSLFile(self._shared, self._ssl, bufsize)

    def send(self, stuff, flags = 0):
        return self._ssl.send(stuff)

    sendall = send

class NSSConnection(httplib.HTTPConnection):
    default_port = httplib.HTTPSConnection.default_port

    def __init__(self, host, port=None, key_file=None, cert_file=None,
                 ca_file='/etc/pki/tls/certs/ca-bundle.crt', strict=None,
                 dbdir=None):
        httplib.HTTPConnection.__init__(self, host, port, strict)
        self.key_file = key_file
        self.cert_file = cert_file
        self.ca_file = ca_file

        if not dbdir:
            raise RuntimeError("dbdir is required")

        ssl.nssinit(dbdir)
        ssl.set_domestic_policy()
        nss.set_password_callback(self.password_callback)

        # Create the socket here so we can do things like let the caller
        # override the NSS callbacks
        self.sslsock = ssl.SSLSocket()
        self.sslsock.set_ssl_option(ssl.SSL_SECURITY, True)
        self.sslsock.set_ssl_option(ssl.SSL_HANDSHAKE_AS_CLIENT, True)
        self.sslsock.set_handshake_callback(self.handshake_callback)

    def password_callback(self, slot, retry, password):
        if not retry and password: return password
        return getpass.getpass("Enter password for %s: " % slot.token_name);

    def handshake_callback(self, sock):
        """
        Verify callback. If we get here then the certificate is ok.
        """
        if self.debuglevel > 0:
            print "handshake complete, peer = %s" % (sock.get_peer_name())
        pass

    def connect(self):
        self.sslsock.set_hostname(self.host)

        net_addr = io.NetworkAddress(self.host, self.port)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sslsock.connect(net_addr)
        self.sock = NSSFakeSocket(sock, self.sslsock)

class NSSHTTPS(httplib.HTTP):
    _connection_class = NSSConnection

    def __init__(self, host='', port=None, key_file=None, cert_file=None,
                 ca_file='/etc/pki/tls/certs/ca-bundle.crt', strict=None):
        # provide a default host, pass the X509 cert info

        # urf. compensate for bad input.
        if port == 0:
            port = None
        self._setup(self._connection_class(host, port, key_file,
                                           cert_file, ca_file, strict))
        # we never actually use these for anything, but we keep them
        # here for compatibility with post-1.5.2 CVS.
        self.key_file = key_file
        self.cert_file = cert_file
        self.ca_file = ca_file

if __name__ == "__main__":
    h = NSSConnection("www.verisign.com", 443, dbdir="/etc/pki/nssdb")
    h.set_debuglevel(1)
    h.request("GET", "/")
    res = h.getresponse()
    print res.status
    data = res.read()
    print data
    h.close()
