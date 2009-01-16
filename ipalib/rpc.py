# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
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
Shared RPC client/server functionality.

This module adds some additional functionality on top of the ``xmlrpclib``
module in the Python standard library.  For documentation on the
``xmlrpclib`` module, see:

    http://docs.python.org/library/xmlrpclib.html
"""

from types import NoneType
from xmlrpclib import Binary, Fault, dumps, loads


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


def xml_loads(data):
    """
    Decode the XML-RPC packet in ``data``, transparently unwrapped its params.

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
    (params, method) = loads(data)
    return (xml_unwrap(params), method)
