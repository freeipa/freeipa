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
Unit tests for `ipalib.errors` module.
"""

from tstutil import raises, getitem, no_set, no_del, read_only, ClassChecker
from ipalib import errors


class test_IPATypeError(ClassChecker):
    """
    Tests the `errors.IPATypeError` exception.
    """
    _cls = errors.IPATypeError

    def test_class(self):
        assert self.cls.__bases__ == (TypeError,)

    def test_init(self):
        """
        Tests the `errors.IPATypeError.__init__` method.
        """
        t = unicode
        v = 'hello'
        e = self.cls(t, v)
        assert e.type is t
        assert e.value is v
        assert str(e) == 'need a %r; got %r' % (t, v)
