# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
RPC client and shared RPC client/server functionality.

This module adds some additional functionality on top of the ``xmlrpclib``
module in the Python standard library.  For documentation on the
``xmlrpclib`` module, see:

    http://docs.python.org/library/xmlrpclib.html

Also see the `ipaserver.rpcserver` module.
"""

from types import NoneType
import threading
import sys
import os
import errno
from xmlrpclib import Binary, Fault, dumps, loads, ServerProxy, Transport, ProtocolError
import kerberos
from ipalib.backend import Connectible
from ipalib.errors import public_errors, PublicError, UnknownError, NetworkError, KerberosError
from ipalib import errors
from ipalib.request import context
from ipapython import ipautil, dnsclient
import httplib
import socket
from ipapython.nsslib import NSSHTTPS, NSSConnection
from nss.error import NSPRError
from urllib2 import urlparse

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
        host, self._extra_headers, x509 = self.get_host_info(host)
        host, self._extra_headers, x509 = self.get_host_info(host)
        # Python 2.7 changed the internal class used in xmlrpclib from
        # HTTP to HTTPConnection. We need to use the proper subclass
        (major, minor, micro, releaselevel, serial) = sys.version_info
        if major == 2 and minor < 7:
            conn = NSSHTTPS(host, 443, dbdir="/etc/pki/nssdb")
        else:
            conn = NSSConnection(host, 443, dbdir="/etc/pki/nssdb")
        conn.connect()
        return conn

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

    def reconstruct_url(self):
        """
        The URL directly isn't stored in the ServerProxy. We can't store
        it in the connection object itself but we can reconstruct it
        from the ServerProxy.
        """
        if not hasattr(self.conn, '_ServerProxy__transport'):
            return None
        if isinstance(self.conn._ServerProxy__transport, KerbTransport):
            scheme = "https"
        else:
            scheme = "http"
        server = '%s://%s%s' % (scheme, self.conn._ServerProxy__host, self.conn._ServerProxy__handler)
        return server

    def get_url_list(self):
        """
        Create a list of urls consisting of the available IPA servers.
        """
        # the configured URL defines what we use for the discovered servers
        (scheme, netloc, path, params, query, fragment) = urlparse.urlparse(self.env.xmlrpc_uri)
        servers = []
        name = '_ldap._tcp.%s.' % self.env.domain
        rs = dnsclient.query(name, dnsclient.DNS_C_IN, dnsclient.DNS_T_SRV)
        for r in rs:
            if r.dns_type == dnsclient.DNS_T_SRV:
                rsrv = r.rdata.server.rstrip('.')
                servers.append('https://%s%s' % (rsrv, path))
        servers = list(set(servers))
        # the list/set conversion won't preserve order so stick in the
        # local config file version here.
        servers.insert(0, self.env.xmlrpc_uri)
        return servers

    def create_connection(self, ccache=None, verbose=False, fallback=True):
        servers = self.get_url_list()
        serverproxy = None
        for server in servers:
            kw = dict(allow_none=True, encoding='UTF-8')
            kw['verbose'] = verbose
            if server.startswith('https://'):
                kw['transport'] = KerbTransport()
            self.log.info('trying %s' % server)
            serverproxy = ServerProxy(server, **kw)
            if len(servers) == 1 or not fallback:
                # if we have only 1 server to try then let the main
                # requester handle any errors
                return serverproxy
            try:
                command = getattr(serverproxy, 'ping')
                response = command()
                # We don't care about the response, just that we got one
                break
            except KerberosError, krberr:
                # kerberos error on one server is likely on all
                raise errors.KerberosError(major=str(krberr), minor='')
            except Exception, e:
                if not fallback:
                    raise e
                serverproxy = None

        if serverproxy is None:
            raise NetworkError(uri='any of the configured servers', error=', '.join(servers))
        return serverproxy

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
        server = self.reconstruct_url()
        self.info('Forwarding %r to server %r', name, server)
        command = getattr(self.conn, name)
        params = [args, kw]
        try:
            response = command(*xml_wrap(params))
            return xml_unwrap(response)
        except Fault, e:
            e = decode_fault(e)
            self.debug('Caught fault %d from server %s: %s', e.faultCode,
                server, e.faultString)
            if e.faultCode in self.__errors:
                error = self.__errors[e.faultCode]
                raise error(message=e.faultString)
            raise UnknownError(
                code=e.faultCode,
                error=e.faultString,
                server=server,
            )
        except NSPRError, e:
            raise NetworkError(uri=server, error=str(e))
        except ProtocolError, e:
            raise NetworkError(uri=server, error=e.errmsg)
        except socket.error, e:
            raise NetworkError(uri=server, error=str(e))
