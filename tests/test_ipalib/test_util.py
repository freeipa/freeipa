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
Unit tests for `ipalib.util` module.
"""

from tstutil import raises
from ipalib import util


def test_xmlrpc_marshal():
    """
    Test the `util.xmlrpc_marshal` function.
    """
    f = util.xmlrpc_marshal
    assert f() == ({},)
    assert f('one', 'two') == ({}, 'one', 'two')
    assert f(one=1, two=2) == (dict(one=1, two=2),)
    assert f('one', 'two', three=3, four=4) == \
        (dict(three=3, four=4), 'one', 'two')


def test_xmlrpc_unmarshal():
    """
    Test the `util.xmlrpc_unmarshal` function.
    """
    f = util.xmlrpc_unmarshal
    assert f() == (tuple(), {})
    assert f({}, 'one', 'two') == (('one', 'two'), {})
    assert f(dict(one=1, two=2)) == (tuple(), dict(one=1, two=2))
    assert f(dict(three=3, four=4), 'one', 'two') == \
        (('one', 'two'), dict(three=3, four=4))
