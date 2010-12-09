# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
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
Test the `ipalib.util` module.
"""

from tests.util import raises
from ipalib import util


def test_make_repr():
    """
    Test the `ipalib.util.make_repr` function.
    """
    f = util.make_repr
    assert f('my') == 'my()'
    assert f('my', True, u'hello') == "my(True, u'hello')"
    assert f('my', one=1, two='two') == "my(one=1, two='two')"
    assert f('my', None, 3, dog='animal', apple='fruit') == \
        "my(None, 3, apple='fruit', dog='animal')"
