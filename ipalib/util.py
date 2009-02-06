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
        parser.disable_interspersed_args()
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

def realm_to_suffix(realm_name):
    s = realm_name.split(".")
    terms = ["dc=" + x.lower() for x in s]
    return ",".join(terms)
