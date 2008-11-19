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
Various utility functions.
"""

import os
from os import path
import imp
import optparse
import logging
import time
from types import NoneType
from xmlrpclib import Binary
import krbV



def xmlrpc_marshal(*args, **kw):
    """
    Marshal (args, kw) into ((kw,) + args).
    """
    kw = dict(
        filter(lambda item: item[1] is not None, kw.iteritems())
    )
    args = tuple(
        filter(lambda value: value is not None, args)
    )
    return ((kw,) + args)


def xmlrpc_unmarshal(*params):
    """
    Unmarshal (params) into (args, kw).
    """
    if len(params) > 0:
        kw = params[0]
        if type(kw) is not dict:
            raise TypeError('first xmlrpc argument must be dict')
    else:
        kw = {}
    return (params[1:], kw)


def xmlrpc_wrap(value):
    """
    Wrap all ``str`` in ``xmlrpclib.Binary``.

    Because ``xmlrpclib.dumps()`` will itself convert all ``unicode`` instances
    into UTF-8 encoded ``str`` instances, we don't do it here.

    So in total, when encoding data for an XML-RPC request, the following
    transformations occur:

        * All ``str`` instances are treated as binary data and are wrapped in
          an ``xmlrpclib.Binary()`` instance.

        * Only ``unicode`` instances are treated as character data. They get
          converted to UTF-8 encoded ``str`` instances (although as mentioned,
          not by this function).

    Also see `xmlrpc_unwrap`.
    """
    if type(value) in (list, tuple):
        return tuple(xmlrpc_wrap(v) for v in value)
    if type(value) is dict:
        return dict(
            (k, xmlrpc_wrap(v)) for (k, v) in value.iteritems()
        )
    if type(value) is str:
        return Binary(value)
    assert type(value) in (unicode, int, float, bool, NoneType)
    return value


def xmlrpc_unwrap(value, encoding='UTF-8'):
    """
    Unwrap all ``xmlrpc.Binary``, decode all ``str`` into ``unicode``.

    When decoding data from an XML-RPC request, the following transformations
    occur:

        * The binary payloads of all ``xmlrpclib.Binary`` instances are
          returned as ``str`` instances.

        * All ``str`` instances are treated as UTF-8 encoded character data.
          They are decoded and the resulting ``unicode`` instance is returned.

    Also see `xmlrpc_wrap`.
    """
    if type(value) in (list, tuple):
        return tuple(xmlrpc_unwrap(v, encoding) for v in value)
    if type(value) is dict:
        return dict(
            (k, xmlrpc_unwrap(v, encoding)) for (k, v) in value.iteritems()
        )
    if type(value) is str:
        return value.decode(encoding)
    if isinstance(value, Binary):
        assert type(value.data) is str
        return value.data
    assert type(value) in (int, float, bool, NoneType)
    return value


def get_current_principal():
    try:
        return krbV.default_context().default_ccache().principal().name
    except krbV.Krb5Error:
        #TODO: do a kinit
        print "Unable to get kerberos principal"
        return None


# FIXME: This function has no unit test
def find_modules_in_dir(src_dir):
    """
    Iterate through module names found in ``src_dir``.
    """
    if not (path.abspath(src_dir) == src_dir and path.isdir(src_dir)):
        return
    if path.islink(src_dir):
        return
    suffix = '.py'
    for name in sorted(os.listdir(src_dir)):
        if not name.endswith(suffix):
            continue
        py_file = path.join(src_dir, name)
        if path.islink(py_file) or not path.isfile(py_file):
            continue
        module = name[:-len(suffix)]
        if module == '__init__':
            continue
        yield module


# FIXME: This function has no unit test
def load_plugins_in_dir(src_dir):
    """
    Import each Python module found in ``src_dir``.
    """
    for module in find_modules_in_dir(src_dir):
        imp.load_module(module, *imp.find_module(module, [src_dir]))


# FIXME: This function has no unit test
def import_plugins_subpackage(name):
    """
    Import everythig in ``plugins`` sub-package of package named ``name``.
    """
    try:
        plugins = __import__(name + '.plugins').plugins
    except ImportError:
        return
    src_dir = path.dirname(path.abspath(plugins.__file__))
    for name in find_modules_in_dir(src_dir):
        full_name = '%s.%s' % (plugins.__name__, name)
        __import__(full_name)


def add_global_options(parser=None):
    """
    Add global options to an optparse.OptionParser instance.
    """
    if parser is None:
        parser = optparse.OptionParser()
    parser.add_option('-e', dest='env', metavar='KEY=VAL', action='append',
        help='Set environment variable KEY to VAL',
    )
    parser.add_option('-c', dest='conf', metavar='FILE',
        help='Load configuration from FILE',
    )
    parser.add_option('-d', '--debug', action='store_true',
        help='Produce full debuging output',
    )
    parser.add_option('-v', '--verbose', action='store_true',
        help='Produce more verbose output',
    )
    return parser


class LogFormatter(logging.Formatter):
    """
    Log formatter that uses UTC for all timestamps.
    """
    converter = time.gmtime


def make_repr(name, *args, **kw):
    """
    Construct a standard representation of a class instance.
    """
    args = [repr(a) for a in args]
    kw = ['%s=%r' % (k, kw[k]) for k in sorted(kw)]
    return '%s(%s)' % (name, ', '.join(args + kw))
