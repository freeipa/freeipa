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
Test the `ipalib.backend` module.
"""

import threading
from tests.util import ClassChecker, raises, create_test_api
from tests.data import unicode_str
from ipalib.request import context, Connection
from ipalib.frontend import Command
from ipalib import  backend, plugable, errors2, base



class test_Backend(ClassChecker):
    """
    Test the `ipalib.backend.Backend` class.
    """

    _cls = backend.Backend

    def test_class(self):
        assert self.cls.__bases__ == (plugable.Plugin,)
        assert self.cls.__proxy__ is False


class DummyConnection(Connection):

    def create(self, *args, **kw):
        self.args = args
        self.kw = kw
        self.closed = False
        return 'The connection'

    def close(self):
        assert self.closed is False
        object.__setattr__(self, 'closed', True)


class test_Connectible(ClassChecker):
    """
    Test the `ipalib.backend.Connectible` class.
    """

    _cls = backend.Connectible

    def test_connect(self):
        """
        Test the `ipalib.backend.Connectible.connect` method.
        """
        # Test that TypeError is raised when connection_klass isn't a
        # Connection subclass:
        class bad(self.cls):
            connection_klass = base.ReadOnly
        o = bad()
        m = '%s.connection_klass must be a request.Connection subclass'
        e = raises(ValueError, o.connect)
        assert str(e) == m % 'bad'

        # Test that connection is created:
        class example(self.cls):
            connection_klass = DummyConnection
        o = example()
        args = ('Arg1', 'Arg2', 'Arg3')
        kw = dict(key1='Val1', key2='Val2', key3='Val3')
        assert not hasattr(context, 'example')
        assert o.connect(*args, **kw) is None
        conn = context.example
        assert type(conn) is DummyConnection
        assert conn.args == args
        assert conn.kw == kw
        assert conn.conn == 'The connection'

        # Test that StandardError is raised if already connected:
        m = "connection 'context.%s' already exists in thread %r"
        e = raises(StandardError, o.connect, *args, **kw)
        assert str(e) == m % ('example', threading.currentThread().getName())

        # Double check that it works after deleting context.example:
        del context.example
        assert o.connect(*args, **kw) is None

    def test_isconnected(self):
        """
        Test the `ipalib.backend.Connectible.isconnected` method.
        """
        class example(self.cls):
            pass
        for klass in (self.cls, example):
            o = klass()
            assert o.isconnected() is False
            conn = DummyConnection()
            setattr(context, klass.__name__, conn)
            assert o.isconnected() is True
            delattr(context, klass.__name__)

    def test_conn(self):
        """
        Test the `ipalib.backend.Connectible.conn` property.
        """
        msg = 'no context.%s in thread %r'
        class example(self.cls):
            pass
        for klass in (self.cls, example):
            o = klass()
            e = raises(AttributeError, getattr, o, 'conn')
            assert str(e) == msg % (
                klass.__name__, threading.currentThread().getName()
            )
            conn = DummyConnection()
            setattr(context, klass.__name__, conn)
            assert o.conn is conn.conn
            delattr(context, klass.__name__)


class test_Executioner(ClassChecker):
    """
    Test the `ipalib.backend.Executioner` class.
    """
    _cls = backend.Executioner

    def test_execute(self):
        """
        Test the `ipalib.backend.Executioner.execute` method.
        """
        (api, home) = create_test_api(in_server=True)

        class echo(Command):
            takes_args = ['arg1', 'arg2+']
            takes_options = ['option1?', 'option2?']
            def execute(self, *args, **options):
                assert type(args[1]) is tuple
                return args + (options,)
        api.register(echo)

        class good(Command):
            def execute(self):
                raise errors2.ValidationError(
                    name='nurse',
                    error=u'Not naughty!',
                )
        api.register(good)

        class bad(Command):
            def execute(self):
                raise ValueError('This is private.')
        api.register(bad)

        api.finalize()
        o = self.cls()
        o.set_api(api)
        o.finalize()

        # Test that CommandError is raised:
        conn = DummyConnection()
        context.someconn = conn
        e = raises(errors2.CommandError, o.execute, 'nope')
        assert e.name == 'nope'
        assert conn.closed is True  # Make sure destroy_context() was called
        assert context.__dict__.keys() == []

        # Test with echo command:
        arg1 = unicode_str
        arg2 = (u'Hello', unicode_str, u'world!')
        args = (arg1,) + arg2
        options = dict(option1=u'How are you?', option2=unicode_str)

        conn = DummyConnection()
        context.someconn = conn
        assert o.execute('echo', arg1, arg2, **options) == (arg1, arg2, options)
        assert conn.closed is True  # Make sure destroy_context() was called
        assert context.__dict__.keys() == []

        conn = DummyConnection()
        context.someconn = conn
        assert o.execute('echo', *args, **options) == (arg1, arg2, options)
        assert conn.closed is True  # Make sure destroy_context() was called
        assert context.__dict__.keys() == []

        # Test with good command:
        conn = DummyConnection()
        context.someconn = conn
        e = raises(errors2.ValidationError, o.execute, 'good')
        assert e.name == 'nurse'
        assert e.error == u'Not naughty!'
        assert conn.closed is True  # Make sure destroy_context() was called
        assert context.__dict__.keys() == []

        # Test with bad command:
        conn = DummyConnection()
        context.someconn = conn
        e = raises(errors2.InternalError, o.execute, 'bad')
        assert conn.closed is True  # Make sure destroy_context() was called
        assert context.__dict__.keys() == []


class test_Context(ClassChecker):
    """
    Test the `ipalib.backend.Context` class.
    """

    _cls = backend.Context

    def test_get_value(self):
        """
        Test the `ipalib.backend.Context.get_value` method.
        """
        class Subclass(self.cls):
            pass
        o = Subclass()
        e = raises(NotImplementedError, o.get_value)
        assert str(e) == 'Subclass.get_value()'
