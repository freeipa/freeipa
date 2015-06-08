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
Test the `ipalib.plugable` module.
"""

# FIXME: Pylint errors
# pylint: disable=no-member

import inspect
from ipatests.util import raises, no_set, no_del, read_only
from ipatests.util import getitem, setitem, delitem
from ipatests.util import ClassChecker, create_test_api
from ipalib import plugable, errors, text
from ipaplatform.paths import paths


class test_Plugin(ClassChecker):
    """
    Test the `ipalib.plugable.Plugin` class.
    """
    _cls = plugable.Plugin

    def test_class(self):
        """
        Test the `ipalib.plugable.Plugin` class.
        """
        assert self.cls.__bases__ == (plugable.ReadOnly,)
        assert type(self.cls.api) is property

    def test_init(self):
        """
        Test the `ipalib.plugable.Plugin.__init__` method.
        """
        api = 'the api instance'
        o = self.cls(api)
        assert o.name == 'Plugin'
        assert o.module == 'ipalib.plugable'
        assert o.fullname == 'ipalib.plugable.Plugin'
        assert isinstance(o.doc, text.Gettext)
        class some_subclass(self.cls):
            """
            Do sub-classy things.

            Although it doesn't know how to comport itself and is not for mixed
            company, this class *is* useful as we all need a little sub-class
            now and then.

            One more paragraph.
            """
        o = some_subclass(api)
        assert o.name == 'some_subclass'
        assert o.module == __name__
        assert o.fullname == '%s.some_subclass' % __name__
        assert o.summary == 'Do sub-classy things.'
        assert isinstance(o.doc, text.Gettext)
        class another_subclass(self.cls):
            pass
        o = another_subclass(api)
        assert o.summary == '<%s>' % o.fullname

        # Test that Plugin makes sure the subclass hasn't defined attributes
        # whose names conflict with the logger methods set in Plugin.__init__():
        class check(self.cls):
            info = 'whatever'
        e = raises(StandardError, check, api)
        assert str(e) == \
            "info is already bound to ipatests.test_ipalib.test_plugable.check()"

    def test_finalize(self):
        """
        Test the `ipalib.plugable.Plugin.finalize` method.
        """
        class api(object):
            @staticmethod
            def is_production_mode():
                return False
        o = self.cls(api)
        assert not o.__islocked__()
        o.finalize()
        assert o.__islocked__()


def test_Registrar():
    """
    Test the `ipalib.plugable.Registrar` class
    """
    class Base1(object):
        pass
    class Base2(object):
        pass
    class Base3(object):
        pass
    class plugin1(Base1):
        pass
    class plugin2(Base2):
        pass
    class plugin3(Base3):
        pass

    # Test creation of Registrar:
    r = plugable.Registrar()

    # Check that TypeError is raised trying to register something that isn't
    # a class:
    p = plugin1()
    e = raises(TypeError, r, p)
    assert str(e) == 'plugin must be a class; got %r' % p

    # Check that registration works
    r(plugin1)
    assert len(r) == 1
    assert plugin1 in r
    assert r[plugin1] == dict(override=False)

    # Check that DuplicateError is raised trying to register exact class
    # again:
    e = raises(errors.PluginDuplicateError, r, plugin1)
    assert e.plugin is plugin1

    # Check that overriding works
    orig1 = plugin1
    class base1_extended(Base1):
        pass
    class plugin1(base1_extended):  # pylint: disable=function-redefined
        pass
    r(plugin1, override=True)
    assert len(r) == 2
    assert plugin1 in r
    assert r[plugin1] == dict(override=True)

    # Test that another plugin can be registered:
    r(plugin2)
    assert len(r) == 3
    assert plugin2 in r
    assert r[plugin2] == dict(override=False)

    # Setup to test more registration:
    class plugin1a(Base1):
        pass
    r(plugin1a)

    class plugin1b(Base1):
        pass
    r(plugin1b)

    class plugin2a(Base2):
        pass
    r(plugin2a)

    class plugin2b(Base2):
        pass
    r(plugin2b)


class test_API(ClassChecker):
    """
    Test the `ipalib.plugable.API` class.
    """

    _cls = plugable.API

    def test_API(self):
        """
        Test the `ipalib.plugable.API` class.
        """
        assert issubclass(plugable.API, plugable.ReadOnly)

        # Setup the test bases, create the API:
        class base0(plugable.Plugin):
            def method(self, n):
                return n

        class base1(plugable.Plugin):
            def method(self, n):
                return n + 1

        class API(plugable.API):
            bases = (base0, base1)
            modules = ()

        api = API()
        api.env.mode = 'unit_test'
        api.env.in_tree = True
        r = api.add_plugin

        class base0_plugin0(base0):
            pass
        r(base0_plugin0)

        class base0_plugin1(base0):
            pass
        r(base0_plugin1)

        class base0_plugin2(base0):
            pass
        r(base0_plugin2)

        class base1_plugin0(base1):
            pass
        r(base1_plugin0)

        class base1_plugin1(base1):
            pass
        r(base1_plugin1)

        class base1_plugin2(base1):
            pass
        r(base1_plugin2)

        # Test API instance:
        assert api.isdone('bootstrap') is False
        assert api.isdone('finalize') is False
        api.finalize()
        assert api.isdone('bootstrap') is True
        assert api.isdone('finalize') is True

        def get_base_name(b):
            return 'base%d' % b


        def get_plugin_name(b, p):
            return 'base%d_plugin%d' % (b, p)

        for b in xrange(2):
            base_name = get_base_name(b)
            base = locals()[base_name]
            ns = getattr(api, base_name)
            assert isinstance(ns, plugable.NameSpace)
            assert read_only(api, base_name) is ns
            assert len(ns) == 3
            for p in xrange(3):
                plugin_name = get_plugin_name(b, p)
                plugin = locals()[plugin_name]
                inst = ns[plugin_name]
                assert isinstance(inst, base)
                assert isinstance(inst, plugin)
                assert inst.name == plugin_name
                assert read_only(ns, plugin_name) is inst
                assert inst.method(7) == 7 + b

        # Test that calling finilize again raises AssertionError:
        e = raises(StandardError, api.finalize)
        assert str(e) == 'API.finalize() already called', str(e)

    def test_bootstrap(self):
        """
        Test the `ipalib.plugable.API.bootstrap` method.
        """
        (o, home) = create_test_api()
        assert o.env._isdone('_bootstrap') is False
        assert o.env._isdone('_finalize_core') is False
        assert o.isdone('bootstrap') is False
        o.bootstrap(my_test_override='Hello, world!')
        assert o.isdone('bootstrap') is True
        assert o.env._isdone('_bootstrap') is True
        assert o.env._isdone('_finalize_core') is True
        assert o.env.my_test_override == 'Hello, world!'
        e = raises(StandardError, o.bootstrap)
        assert str(e) == 'API.bootstrap() already called'

    def test_load_plugins(self):
        """
        Test the `ipalib.plugable.API.load_plugins` method.
        """
        (o, home) = create_test_api()
        assert o.isdone('bootstrap') is False
        assert o.isdone('load_plugins') is False
        o.load_plugins()
        assert o.isdone('bootstrap') is True
        assert o.isdone('load_plugins') is True
        e = raises(StandardError, o.load_plugins)
        assert str(e) == 'API.load_plugins() already called'
