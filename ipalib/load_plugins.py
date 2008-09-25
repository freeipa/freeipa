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


def load_plugins(src_dir):
    """
    Import each Python module found in ``src_dir``.
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
        imp.load_module(module, *imp.find_module(module, [src_dir]))


def load_plugins_subpackage(file_in_package):
    """
    Load all Python modules found in a plugins/ subpackage.
    """
    package_dir = path.dirname(path.abspath(file_in_package))
    plugins_dir = path.join(package_dir, 'plugins')
    load_plugins(plugins_dir)


load_plugins_subpackage(__file__)
try:
    import ipa_server
    load_plugins_subpackage(ipa_server.__file__)
except ImportError:
    pass

load_plugins(path.expanduser('~/.freeipa'))
