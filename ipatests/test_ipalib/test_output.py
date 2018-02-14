# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2009 Red Hat
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
Test the `ipalib.output` module.
"""

from ipatests.util import raises, ClassChecker
from ipalib import output
from ipalib.frontend import Command
from ipapython.version import API_VERSION

import pytest

pytestmark = pytest.mark.tier0

class test_Output(ClassChecker):
    """
    Test the `ipalib.output.Output` class.
    """

    _cls = output.Output

    def test_init(self):
        """
        Test the `ipalib.output.Output.__init__` method.
        """
        o = self.cls('result')
        assert o.name == 'result'
        assert o.type is None
        assert o.doc is None

    def test_repr(self):
        """
        Test the `ipalib.output.Output.__repr__` method.
        """
        o = self.cls('aye')
        assert repr(o) == "Output('aye')"
        o = self.cls('aye', type=int, doc='An A, aye?')
        assert repr(o) == (
            "Output('aye', type=[<type 'int'>], doc='An A, aye?')"
        )

        class Entry(self.cls):
            pass
        o = Entry('aye')
        assert repr(o) == "Entry('aye')"
        o = Entry('aye', type=int, doc='An A, aye?')
        assert repr(o) == (
            "Entry('aye', type=[<type 'int'>], doc='An A, aye?')"
        )


class test_ListOfEntries(ClassChecker):
    """
    Test the `ipalib.output.ListOfEntries` class.
    """

    _cls = output.ListOfEntries

    def test_validate(self):
        """
        Test the `ipalib.output.ListOfEntries.validate` method.
        """
        api = 'the api instance'
        class example(Command):
            pass
        cmd = example(api)
        inst = self.cls('stuff')

        okay = dict(foo='bar')
        nope = ('aye', 'bee')

        e = raises(TypeError, inst.validate,
                   cmd, [okay, okay, nope], API_VERSION)
        assert str(e) == output.emsg % (
            'example', 'ListOfEntries', 'stuff', 2, dict, tuple, nope
        )

        e = raises(TypeError, inst.validate,
                   cmd, [nope, okay, nope], API_VERSION)
        assert str(e) == output.emsg % (
            'example', 'ListOfEntries', 'stuff', 0, dict, tuple, nope
        )
