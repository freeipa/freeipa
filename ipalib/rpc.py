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
from xmlrpclib import Binary, Fault, dumps, loads, ServerProxy, SafeTransport
import kerberos
from ipalib.backend import Backend
from ipalib.errors2 import public_errors, PublicError, UnknownError, NetworkError
from ipalib.request import context


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


class KerbTransport(SafeTransport):
    """
    Handles Kerberos Negotiation authentication to an XML-RPC server.
    """

    def get_host_info(self, host):

        (host, extra_headers, x509) = SafeTransport.get_host_info(self, host)

        # Set the remote host principal
        service = "HTTP@" + host.split(':')[0]

        try:
            (rc, vc) = kerberos.authGSSClientInit(service)
        except kerberos.GSSError, e:
            raise e  # FIXME: raise a PublicError

        try:
            kerberos.authGSSClientStep(vc, "")
        except kerberos.GSSError, e:
            raise e  # FIXME: raise a PublicError

        extra_headers += [
            ('Authorization', 'negotiate %s' % kerberos.authGSSClientResponse(vc))
        ]

        return (host, extra_headers, x509)


class xmlclient(Backend):
    """
    Forwarding backend for XML-RPC client.
    """

    connection_name = 'xmlconn'

    def __init__(self):
        super(xmlclient, self).__init__()
        self.__errors = dict((e.errno, e) for e in public_errors)

    def connect(self, ccache=None, user=None, password=None):
        if hasattr(context, self.connection_name):
            raise StandardError(
                '%s.connect(): context.%s already exists in thread %r' % (
                    self.name, self.connection_name, threading.currentThread().getName()
                )
            )
        conn = ServerProxy(self.env.xmlrpc_uri,
            allow_none=True,
            encoding='UTF-8',
        )
        setattr(context, self.connection_name, conn)

    def get_connection(self):
        return getattr(context, self.connection_name)

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
        if not hasattr(context, 'xmlconn'):
            raise StandardError(
                '%s.forward(%r): need context.xmlconn in thread %r' % (
                    self.name, name, threading.currentThread().getName()
                )
            )
        command = getattr(context.xmlconn, name)
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
