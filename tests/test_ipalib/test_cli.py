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
Test the `ipalib.cli` module.
"""

from tests.util import raises, getitem, no_set, no_del, read_only, ClassChecker
from tests.util import TempHome
from ipalib import cli, plugable, frontend, backend


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


class DummyCommand(object):
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
    Command = property(__get_cmd)

    def __cmd_iter(self, cnt):
        for i in xrange(cnt):
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




class test_CLI(ClassChecker):
    """
    Test the `ipalib.cli.CLI` class.
    """
    _cls = cli.CLI

    def new(self, argv=tuple()):
        home = TempHome()
        api = plugable.API(
            frontend.Command,
            frontend.Object,
            frontend.Method,
            frontend.Property,
            frontend.Application,
            backend.Backend,
        )
        api.env.mode = 'unit_test'
        api.env.in_tree = True
        o = self.cls(api, argv)
        assert o.api is api
        return (o, api, home)

    def check_cascade(self, *names):
        (o, api, home) = self.new()
        method = getattr(o, names[0])
        for name in names:
            assert o.isdone(name) is False
        method()
        for name in names:
            assert o.isdone(name) is True
        e = raises(StandardError, method)
        assert str(e) == 'CLI.%s() already called' % names[0]

    def test_init(self):
        """
        Test the `ipalib.cli.CLI.__init__` method.
        """
        argv = ['-v', 'user-add', '--first=Jonh', '--last=Doe']
        (o, api, home) = self.new(argv)
        assert o.api is api
        assert o.argv == tuple(argv)

    def test_run(self):
        """
        Test the `ipalib.cli.CLI.run` method.
        """
        self.check_cascade(
            'run',
            'finalize',
            'load_plugins',
            'bootstrap',
            'parse_globals'
        )

    def test_finalize(self):
        """
        Test the `ipalib.cli.CLI.finalize` method.
        """
        self.check_cascade(
            'finalize',
            'load_plugins',
            'bootstrap',
            'parse_globals'
        )

        (o, api, home) = self.new()
        assert api.isdone('finalize') is False
        assert 'Command' not in api
        o.finalize()
        assert api.isdone('finalize') is True
        assert list(api.Command) == \
            sorted(k.__name__ for k in cli.cli_application_commands)

    def test_load_plugins(self):
        """
        Test the `ipalib.cli.CLI.load_plugins` method.
        """
        self.check_cascade(
            'load_plugins',
            'bootstrap',
            'parse_globals'
        )
        (o, api, home) = self.new()
        assert api.isdone('load_plugins') is False
        o.load_plugins()
        assert api.isdone('load_plugins') is True

    def test_bootstrap(self):
        """
        Test the `ipalib.cli.CLI.bootstrap` method.
        """
        self.check_cascade(
            'bootstrap',
            'parse_globals'
        )
        # Test with empty argv
        (o, api, home) = self.new()
        keys = tuple(api.env)
        assert api.isdone('bootstrap') is False
        o.bootstrap()
        assert api.isdone('bootstrap') is True
        e = raises(StandardError, o.bootstrap)
        assert str(e) == 'CLI.bootstrap() already called'
        assert api.env.verbose is False
        assert api.env.context == 'cli'
        keys = tuple(api.env)
        added = (
                'my_key',
                'whatever',
                'from_default_conf',
                'from_cli_conf'
        )
        for key in added:
            assert key not in api.env
            assert key not in keys

        # Test with a populated argv
        argv = ['-e', 'my_key=my_val,whatever=Hello']
        (o, api, home) = self.new(argv)
        home.write(config_default, '.ipa', 'default.conf')
        home.write(config_cli, '.ipa', 'cli.conf')
        o.bootstrap()
        assert api.env.my_key == 'my_val'
        assert api.env.whatever == 'Hello'
        assert api.env.from_default_conf == 'set in default.conf'
        assert api.env.from_cli_conf == 'set in cli.conf'
        assert list(api.env) == sorted(keys + added)

    def test_parse_globals(self):
        """
        Test the `ipalib.cli.CLI.parse_globals` method.
        """
        # Test with empty argv
        (o, api, home) = self.new()
        assert not hasattr(o, 'options')
        assert not hasattr(o, 'cmd_argv')
        assert o.isdone('parse_globals') is False
        o.parse_globals()
        assert o.isdone('parse_globals') is True
        assert o.options.interactive is True
        assert o.options.verbose is False
        assert o.options.config_file is None
        assert o.options.environment is None
        assert o.cmd_argv == tuple()
        e = raises(StandardError, o.parse_globals)
        assert str(e) == 'CLI.parse_globals() already called'

        # Test with a populated argv
        argv = ('-a', '-n', '-v', '-c', '/my/config.conf', '-e', 'my_key=my_val')
        cmd_argv = ('user-add', '--first', 'John', '--last', 'Doe')
        (o, api, home) = self.new(argv + cmd_argv)
        assert not hasattr(o, 'options')
        assert not hasattr(o, 'cmd_argv')
        assert o.isdone('parse_globals') is False
        o.parse_globals()
        assert o.isdone('parse_globals') is True
        assert o.options.prompt_all is True
        assert o.options.interactive is False
        assert o.options.verbose is True
        assert o.options.config_file == '/my/config.conf'
        assert o.options.environment == 'my_key=my_val'
        assert o.cmd_argv == cmd_argv
        e = raises(StandardError, o.parse_globals)
        assert str(e) == 'CLI.parse_globals() already called'
