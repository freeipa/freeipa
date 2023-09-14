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
Test the `ipalib.cli` module.
"""

from ipatests.util import raises, ClassChecker
from ipalib import cli, plugable

import pytest

pytestmark = pytest.mark.tier0

class test_textui(ClassChecker):
    _cls = cli.textui

    def test_max_col_width(self):
        """
        Test the `ipalib.cli.textui.max_col_width` method.
        """
        api = 'the api instance'
        o = self.cls(api)
        e = raises(TypeError, o.max_col_width, 'hello')
        assert str(e) == 'rows: need %r or %r; got %r' % (list, tuple, 'hello')
        rows = [
            'hello',
            'empathetic',
            'nurse',
        ]
        assert o.max_col_width(rows) == len('empathetic')
        rows = (
            ( 'a',  'bbb',  'ccccc'),
            ('aa', 'bbbb', 'cccccc'),
        )
        assert o.max_col_width(rows, col=0) == 2
        assert o.max_col_width(rows, col=1) == 4
        assert o.max_col_width(rows, col=2) == 6


def test_to_cli():
    """
    Test the `ipalib.cli.to_cli` function.
    """
    f = cli.to_cli
    assert f('initialize') == 'initialize'
    assert f('user_add') == 'user-add'


def test_from_cli():
    """
    Test the `ipalib.cli.from_cli` function.
    """
    f = cli.from_cli
    assert f('initialize') == 'initialize'
    assert f('user-add') == 'user_add'


def get_cmd_name(i):
    return 'cmd_%d' % i


class DummyCommand:
    def __init__(self, name):
        self.__name = name

    def __get_name(self):
        return self.__name
    name = property(__get_name)


class DummyAPI:
    def __init__(self, cnt):
        self.__cmd = plugable.APINameSpace(self.__cmd_iter(cnt), DummyCommand)

    def __get_cmd(self):
        return self.__cmd
    Command = property(__get_cmd)

    def __cmd_iter(self, cnt):
        for i in range(cnt):
            yield DummyCommand(get_cmd_name(i))

    def finalize(self):
        pass

    def register(self, *args, **kw):
        pass


config_cli = """
[global]

from_cli_conf = set in cli.conf
"""

config_default = """
[global]

from_default_conf = set in default.conf

# Make sure cli.conf is loaded first:
from_cli_conf = overridden in default.conf
"""
