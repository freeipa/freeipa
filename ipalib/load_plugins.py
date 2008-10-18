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
Importing this module causes the plugins to be loaded.

This is not in __init__.py so that importing ipalib or its other sub-modules
does not cause unnecessary side effects.

Eventually this will also load the out-of tree plugins, but for now it just
loads the internal plugins.
"""

import os
from os import path
import imp
import inspect


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


def load_plugins_in_dir(src_dir):
    """
    Import each Python module found in ``src_dir``.
    """
    for module in find_modules_in_dir(src_dir):
        imp.load_module(module, *imp.find_module(module, [src_dir]))


def import_plugins(name):
    """
    Load all plugins found in standard 'plugins' sub-package.
    """
    try:
        plugins = __import__(name + '.plugins').plugins
    except ImportError:
        return
    src_dir = path.dirname(path.abspath(plugins.__file__))
    for name in find_modules_in_dir(src_dir):
        full_name = '%s.%s' % (plugins.__name__, name)
        __import__(full_name)


for name in ['ipalib', 'ipa_server', 'ipa_not_a_package']:
    import_plugins(name)

load_plugins_in_dir(path.expanduser('~/.freeipa'))
