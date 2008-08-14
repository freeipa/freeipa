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
Unit tests for `ipalib.cli` module.
"""

from tstutil import raises, getitem, no_set, no_del, read_only, ClassChecker
from ipalib import cli, plugable


def test_to_cli():
    """
    Tests the `cli.to_cli` function.
    """
    f = cli.to_cli
    assert f('initialize') == 'initialize'
    assert f('user_add') == 'user-add'


def test_from_cli():
    """
    Tests the `cli.from_cli` function.
    """
    f = cli.from_cli
    assert f('initialize') == 'initialize'
    assert f('user-add') == 'user_add'


def get_cmd_name(i):
    return 'cmd_%d' % i

class DummyCmd(object):
    def __init__(self, name):
        self.__name = name

    def __get_name(self):
        return self.__name
    name = property(__get_name)

class DummyAPI(object):
    def __init__(self, cnt):
        self.__cmd = plugable.NameSpace(self.__cmd_iter(cnt))

    def __get_cmd(self):
        return self.__cmd
    cmd = property(__get_cmd)

    def __cmd_iter(self, cnt):
        for i in xrange(cnt):
            yield DummyCmd(get_cmd_name(i))

    def finalize(self):
        pass

    def register(self, *args, **kw):
        pass




class test_CLI(ClassChecker):
    """
    Tests the `cli.CLI` class.
    """
    _cls = cli.CLI

    def test_class(self):
        assert type(self.cls.api) is property

    def test_api(self):
        """
        Tests the `cli.CLI.api` property.
        """
        api = 'the plugable.API instance'
        o = self.cls(api)
        assert read_only(o, 'api') is api

    def test_parse(self):
        """
        Tests the `cli.CLI.parse` method.
        """
        o = self.cls(None)
        args = ['hello', 'naughty', 'nurse']
        kw = dict(
            first_name='Naughty',
            last_name='Nurse',
        )
        opts = ['--%s=%s' % (k.replace('_', '-'), v) for (k, v) in kw.items()]
        assert o.parse(args + []) == (args, {})
        assert o.parse(opts + []) == ([], kw)
        assert o.parse(args + opts) == (args, kw)
        assert o.parse(opts + args) == (args, kw)

    def test_mcl(self):
        """
        Tests the `cli.CLI.mcl` (Max Command Length) property .
        """
        cnt = 100
        api = DummyAPI(cnt)
        len(api.cmd) == cnt
        o = self.cls(api)
        assert o.mcl is None
        o.finalize()
        assert o.mcl == 6 # len('cmd_99')

    def test_dict(self):
        """
        Tests the `cli.CLI.__contains__` and `cli.CLI.__getitem__` methods.
        """
        cnt = 25
        api = DummyAPI(cnt)
        assert len(api.cmd) == cnt
        o = self.cls(api)
        o.finalize()
        for cmd in api.cmd():
            key = cli.to_cli(cmd.name)
            assert key in o
            assert o[key] is cmd
            assert cmd.name not in o
            raises(KeyError, getitem, o, cmd.name)
