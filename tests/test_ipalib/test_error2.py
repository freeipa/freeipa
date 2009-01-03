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
Test the `ipalib.error2` module.
"""

import re
import inspect
from ipalib import errors2


def test_public_errors():
    """
    Test the `ipalib.errors2.public_errors` module variable.
    """
    for klass in errors2.public_errors:
        assert issubclass(klass, errors2.PublicError)
        assert not issubclass(klass, errors2.PrivateError)
        assert type(klass.code) is int
        assert 900 <= klass.code <= 5999
        doc = inspect.getdoc(klass)
        m = re.match(r'^\*{2}(\d+)\*{2} ', doc)
        assert m is not None, doc
        assert int(m.group(1)) == klass.code, klass.__name__
