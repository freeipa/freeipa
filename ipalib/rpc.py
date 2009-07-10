# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
RPC client and shared RPC client/server functionality.

This module adds some additional functionality on top of the ``xmlrpclib``
module in the Python standard library.  For documentation on the
``xmlrpclib`` module, see:

    http://docs.python.org/library/xmlrpclib.html

Also see the `ipaserver.rpcserver` module.
"""

from types import NoneType
import threading
import socket
import os
import errno
from xmlrpclib import Binary, Fault, dumps, loads, ServerProxy, Transport, ProtocolError
import kerberos
from ipalib.backend import Connectible
from ipalib.errors import public_errors, PublicError, UnknownError, NetworkError
from ipalib import errors
from ipalib.request import context
from ipapython import ipautil
from OpenSSL import SSL
import httplib

try:
    from httplib import SSLFile
    from httplib import FakeSocket
except ImportError:
    from ipapython.ipasslfile import SSLFile
    from ipapython.ipasslfile import FakeSocket

# Some Kerberos error definitions from krb5.h
KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN = (-1765328377L)
KRB5KRB_AP_ERR_TKT_EXPIRED      = (-1765328352L)
KRB5_FCC_PERM                   = (-1765328190L)
KRB5_FCC_NOFILE                 = (-1765328189L)
KRB5_CC_FORMAT                  = (-1765328185L)
KRB5_REALM_CANT_RESOLVE         = (-1765328164L)

def xml_wrap(value):
    """
    Wrap all ``str`` in ``xmlrpclib.Binary``.

    Because ``xmlrpclib.dumps()`` will itself convert all ``unicode`` instances
    into UTF-8 encoded ``str`` instances, we don't do it here.

    So in total, when encoding data for an XML-RPC packet, the following
    transformations occur:

        * All ``str`` instances are treated as binary data and are wrapped in
          an ``xmlrpclib.Binary()`` instance.

        * Only ``unicode`` instances are treated as character data. They get
          converted to UTF-8 encoded ``str`` instances (although as mentioned,
          not by this function).

    Also see `xml_unwrap()`.

    :param value: The simple scalar or simple compound value to wrap.
    """
    if type(value) in (list, tuple):
        return tuple(xml_wrap(v) for v in value)
    if type(value) is dict:
        return dict(
            (k, xml_wrap(v)) for (k, v) in value.iteritems()
        )
    if type(value) is str:
        return Binary(value)
    assert type(value) in (unicode, int, float, bool, NoneType)
    return value


def xml_unwrap(value, encoding='UTF-8'):
    """
    Unwrap all ``xmlrpc.Binary``, decode all ``str`` into ``unicode``.

    When decoding data from an XML-RPC packet, the following transformations
    occur:

        * The binary payloads of all ``xmlrpclib.Binary`` instances are
          returned as ``str`` instances.

        * All ``str`` instances are treated as UTF-8 encoded Unicode strings.
          They are decoded and the resulting ``unicode`` instance is returned.

    Also see `xml_wrap()`.

    :param value: The value to unwrap.
    :param encoding: The Unicode encoding to use (defaults to ``'UTF-8'``).
    """
    if type(value) in (list, tuple):
        return tuple(xml_unwrap(v, encoding) for v in value)
    if type(value) is dict:
        return dict(
            (k, xml_unwrap(v, encoding)) for (k, v) in value.iteritems()
        )
    if type(value) is str:
        return value.decode(encoding)
    if isinstance(value, Binary):
        assert type(value.data) is str
        return value.data
    assert type(value) in (unicode, int, float, bool, NoneType)
    return value


def xml_dumps(params, methodname=None, methodresponse=False, encoding='UTF-8'):
    """
    Encode an XML-RPC data packet, transparently wraping ``params``.

    This function will wrap ``params`` using `xml_wrap()` and will
    then encode the XML-RPC data packet using ``xmlrpclib.dumps()`` (from the
    Python standard library).

    For documentation on the ``xmlrpclib.dumps()`` function, see:

        http://docs.python.org/library/xmlrpclib.html#convenience-functions

    Also see `xml_loads()`.

    :param params: A ``tuple`` or an ``xmlrpclib.Fault`` instance.
    :param methodname: The name of the method to call if this is a request.
    :param methodresponse: Set this to ``True`` if this is a response.
    :param encoding: The Unicode encoding to use (defaults to ``'UTF-8'``).
    """
    if type(params) is tuple:
        params = xml_wrap(params)
    else:
        assert isinstance(params, Fault)
    return dumps(params,
        methodname=methodname,
        methodresponse=methodresponse,
        encoding=encoding,
        allow_none=True,
    )


def decode_fault(e, encoding='UTF-8'):
    assert isinstance(e, Fault)
    if type(e.faultString) is str:
        return Fault(e.faultCode, e.faultString.decode(encoding))
    return e


def xml_loads(data, encoding='UTF-8'):
    """
    Decode the XML-RPC packet in ``data``, transparently unwrapping its params.

    This function will decode the XML-RPC packet in ``data`` using
    ``xmlrpclib.loads()`` (from the Python standard library).  If ``data``
    contains a fault, ``xmlrpclib.loads()`` will itself raise an
    ``xmlrpclib.Fault`` exception.

    Assuming an exception is not raised, this function will then unwrap the
    params in ``data`` using `xml_unwrap()`.  Finally, a
    ``(params, methodname)`` tuple is returned containing the unwrapped params
    and the name of the method being called.  If the packet contains no method
    name, ``methodname`` will be ``None``.

    For documentation on the ``xmlrpclib.loads()`` function, see:

        http://docs.python.org/library/xmlrpclib.html#convenience-functions

    Also see `xml_dumps()`.

    :param data: The XML-RPC packet to decode.
    """
    try:
        (params, method) = loads(data)
        return (xml_unwrap(params), method)
    except Fault, e:
        raise decode_fault(e)


class SSLTransport(Transport):
    """Handles an HTTPS transaction to an XML-RPC server."""

    def make_connection(self, host):
        host, extra_headers, x509 = self.get_host_info(host)
        return SSLSocket(host, None, **(x509 or {}))


class SSLFile(SSLFile):
    """
    Override the _read method so we can handle PyOpenSSL errors
    gracefully.
    """
    def _read(self):
        buf = ''
        while True:
            try:
                buf = self._ssl.read(self._bufsize)
            except SSL.ZeroReturnError:
                # Nothing more to be read
                break
            except SSL.SysCallError, e:
                print "SSL exception", e.args
                break
            except SSL.WantWriteError:
                break
            except SSL.WantReadError:
                break
            except socket.error, err:
                if err[0] == errno.EINTR:
                    continue
                if err[0] == errno.EBADF:
                    # XXX socket was closed?
                    break
                raise
            else:
                break
        return buf


class FakeSocket(FakeSocket):
    """
    Override this class so we can end up using our own SSLFile
    implementation.
    """
    def makefile(self, mode, bufsize=None):
        if mode != 'r' and mode != 'rb':
            raise httplib.UnimplementedFileMode()
        return SSLFile(self._shared, self._ssl, bufsize)


class SSLConnection(httplib.HTTPConnection):
    """
    Use OpenSSL as the SSL provider instead of the built-in python SSL
    support. The built-in SSL client doesn't do CA validation.

    By default we will attempt to load the ca-bundle.crt and our own
    IPA CA for validation purposes. To add an additional CA to verify
    against set the x509['ca_file'] to the path of the CA PEM file in
    KerbTransport.get_host_info
    """
    default_port = httplib.HTTPSConnection.default_port

    def verify_callback(self, conn, cert, errnum, depth, ok):
        """
        Verify callback. If we get here then the certificate is ok.
        """
        return ok

    def __init__(self, host, port=None, key_file=None, cert_file=None,
                 ca_file=None, strict=None):
        httplib.HTTPConnection.__init__(self, host, port, strict)
        self.key_file = key_file
        self.cert_file = cert_file
        self.ca_file = ca_file

    def connect(self):
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_verify(SSL.VERIFY_PEER, self.verify_callback)
        if self.key_file:
            ctx.use_privatekey_file (self.key_file)
        if self.cert_file:
            ctx.use_certificate_file(self.cert_file)
        if os.path.exists("/etc/pki/tls/certs/ca-bundle.crt"):
            ctx.load_verify_locations("/etc/pki/tls/certs/ca-bundle.crt")
        if os.path.exists("/etc/ipa/ca.crt"):
            ctx.load_verify_locations("/etc/ipa/ca.crt")
        if self.ca_file is not None and os.path.exists(self.ca_file):
            ctx.load_verify_locations(self.ca_file)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl = SSL.Connection(ctx, sock)
        ssl.connect((self.host, self.port))
        ssl.do_handshake()
        self.sock = FakeSocket(sock, ssl)


class SSLSocket(httplib.HTTP):
    """
    This is more or less equivalent to the httplib.HTTPS class, we juse
    use our own connection provider.
    """
    _connection_class = SSLConnection

    def __init__(self, host='', port=None, key_file=None, cert_file=None,
                 ca_file=None, strict=None):
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


class KerbTransport(SSLTransport):
    """
    Handles Kerberos Negotiation authentication to an XML-RPC server.
    """

    def _handle_exception(self, e, service=None):
        (major, minor) = ipautil.get_gsserror(e)
        if minor[1] == KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN:
            raise errors.ServiceError(service=service)
        elif minor[1] == KRB5_FCC_NOFILE:
            raise errors.NoCCacheError()
        elif minor[1] == KRB5KRB_AP_ERR_TKT_EXPIRED:
            raise errors.TicketExpired()
        elif minor[1] == KRB5_FCC_PERM:
            raise errors.BadCCachePerms()
        elif minor[1] == KRB5_CC_FORMAT:
            raise errors.BadCCacheFormat()
        elif minor[1] == KRB5_REALM_CANT_RESOLVE:
            raise errors.CannotResolveKDC()
        else:
            raise errors.KerberosError(major=major, minor=minor)

    def get_host_info(self, host):
        (host, extra_headers, x509) = SSLTransport.get_host_info(self, host)

        # Set the remote host principal
        service = "HTTP@" + host.split(':')[0]

        try:
            (rc, vc) = kerberos.authGSSClientInit(service,
                                                kerberos.GSS_C_DELEG_FLAG |
                                                kerberos.GSS_C_MUTUAL_FLAG |
                                                kerberos.GSS_C_SEQUENCE_FLAG)
        except kerberos.GSSError, e:
            self._handle_exception(e)

        try:
            kerberos.authGSSClientStep(vc, "")
        except kerberos.GSSError, e:
            self._handle_exception(e, service=service)

        extra_headers = [
            ('Authorization', 'negotiate %s' % kerberos.authGSSClientResponse(vc))
        ]

        return (host, extra_headers, x509)


class xmlclient(Connectible):
    """
    Forwarding backend plugin for XML-RPC client.

    Also see the `ipaserver.rpcserver.xmlserver` plugin.
    """

    def __init__(self):
        super(xmlclient, self).__init__()
        self.__errors = dict((e.errno, e) for e in public_errors)

    def create_connection(self, ccache=None):
        kw = dict(allow_none=True, encoding='UTF-8')
        if self.env.xmlrpc_uri.startswith('https://'):
            kw['transport'] = KerbTransport()
        return ServerProxy(self.env.xmlrpc_uri, **kw)

    def destroy_connection(self):
        pass

    def forward(self, name, *args, **kw):
        """
        Forward call to command named ``name`` over XML-RPC.

        This method will encode and forward an XML-RPC request, and will then
        decode and return the corresponding XML-RPC response.

        :param command: The name of the command being forwarded.
        :param args: Positional arguments to pass to remote command.
        :param kw: Keyword arguments to pass to remote command.
        """
        if name not in self.Command:
            raise ValueError(
                '%s.forward(): %r not in api.Command' % (self.name, name)
            )
        self.info('Forwarding %r to server %r', name, self.env.xmlrpc_uri)
        command = getattr(self.conn, name)
        params = args + (kw,)
        try:
            response = command(*xml_wrap(params))
            return xml_unwrap(response)
        except Fault, e:
            e = decode_fault(e)
            self.debug('Caught fault %d from server %s: %s', e.faultCode,
                self.env.xmlrpc_uri, e.faultString)
            if e.faultCode in self.__errors:
                error = self.__errors[e.faultCode]
                raise error(message=e.faultString)
            raise UnknownError(
                code=e.faultCode,
                error=e.faultString,
                server=self.env.xmlrpc_uri,
            )
        except socket.error, e:
            raise NetworkError(uri=self.env.xmlrpc_uri, error=e.args[1])
        except ProtocolError, e:
            raise NetworkError(uri=self.env.xmlrpc_uri, error=e.errmsg)
