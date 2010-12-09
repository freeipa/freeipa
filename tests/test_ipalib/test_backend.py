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
Test the `ipalib.backend` module.
"""

import threading
from tests.util import ClassChecker, raises, create_test_api
from tests.data import unicode_str
from ipalib.request import context, Connection
from ipalib.frontend import Command
from ipalib import  backend, plugable, errors, base



class test_Backend(ClassChecker):
    """
    Test the `ipalib.backend.Backend` class.
    """

    _cls = backend.Backend

    def test_class(self):
        assert self.cls.__bases__ == (plugable.Plugin,)


class Disconnect(object):
    called = False

    def __init__(self, id=None):
        self.id = id

    def __call__(self):
        assert self.called is False
        self.called = True
        if self.id is not None:
            delattr(context, self.id)


class test_Connectible(ClassChecker):
    """
    Test the `ipalib.backend.Connectible` class.
    """

    _cls = backend.Connectible

    def test_connect(self):
        """
        Test the `ipalib.backend.Connectible.connect` method.
        """
        # Test that connection is created:
        class example(self.cls):
            def create_connection(self, *args, **kw):
                object.__setattr__(self, 'args', args)
                object.__setattr__(self, 'kw', kw)
                return 'The connection.'
        o = example()
        args = ('Arg1', 'Arg2', 'Arg3')
        kw = dict(key1='Val1', key2='Val2', key3='Val3')
        assert not hasattr(context, 'example')
        assert o.connect(*args, **kw) is None
        conn = context.example
        assert type(conn) is Connection
        assert o.args == args
        assert o.kw == kw
        assert conn.conn == 'The connection.'
        assert conn.disconnect == o.disconnect

        # Test that StandardError is raised if already connected:
        m = "connect: 'context.%s' already exists in thread %r"
        e = raises(StandardError, o.connect, *args, **kw)
        assert str(e) == m % ('example', threading.currentThread().getName())

        # Double check that it works after deleting context.example:
        del context.example
        assert o.connect(*args, **kw) is None

    def test_create_connection(self):
        """
        Test the `ipalib.backend.Connectible.create_connection` method.
        """
        class example(self.cls):
            pass
        for klass in (self.cls, example):
            o = klass()
            e = raises(NotImplementedError, o.create_connection)
            assert str(e) == '%s.create_connection()' % klass.__name__

    def test_disconnect(self):
        """
        Test the `ipalib.backend.Connectible.disconnect` method.
        """
        class example(self.cls):
            destroy_connection = Disconnect()
        o = example()

        m = "disconnect: 'context.%s' does not exist in thread %r"
        e = raises(StandardError, o.disconnect)
        assert str(e) == m % ('example', threading.currentThread().getName())

        context.example = 'The connection.'
        assert o.disconnect() is None
        assert example.destroy_connection.called is True

    def test_destroy_connection(self):
        """
        Test the `ipalib.backend.Connectible.destroy_connection` method.
        """
        class example(self.cls):
            pass
        for klass in (self.cls, example):
            o = klass()
            e = raises(NotImplementedError, o.destroy_connection)
            assert str(e) == '%s.destroy_connection()' % klass.__name__

    def test_isconnected(self):
        """
        Test the `ipalib.backend.Connectible.isconnected` method.
        """
        class example(self.cls):
            pass
        for klass in (self.cls, example):
            o = klass()
            assert o.isconnected() is False
            conn = 'whatever'
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
            conn = Connection('The connection.', Disconnect())
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
            takes_args = ('arg1', 'arg2+')
            takes_options = ('option1?', 'option2?')
            def execute(self, *args, **options):
                assert type(args[1]) is tuple
                return dict(result=args + (options,))
        api.register(echo)

        class good(Command):
            def execute(self):
                raise errors.ValidationError(
                    name='nurse',
                    error=u'Not naughty!',
                )
        api.register(good)

        class bad(Command):
            def execute(self):
                raise ValueError('This is private.')
        api.register(bad)

        class with_name(Command):
            """
            Test that a kwarg named 'name' can be used.
            """
            takes_options = 'name'
            def execute(self, **options):
                return dict(result=options['name'].upper())
        api.register(with_name)

        api.finalize()
        o = self.cls()
        o.set_api(api)
        o.finalize()

        # Test that CommandError is raised:
        conn = Connection('The connection.', Disconnect('someconn'))
        context.someconn = conn
        print str(context.__dict__.keys())
        e = raises(errors.CommandError, o.execute, 'nope')
        assert e.name == 'nope'
        assert conn.disconnect.called is True  # Make sure destroy_context() was called
        print str(context.__dict__.keys())
        assert context.__dict__.keys() == []

        # Test with echo command:
        arg1 = unicode_str
        arg2 = (u'Hello', unicode_str, u'world!')
        args = (arg1,) + arg2
        options = dict(option1=u'How are you?', option2=unicode_str)

        conn = Connection('The connection.', Disconnect('someconn'))
        context.someconn = conn
        assert o.execute('echo', arg1, arg2, **options) == dict(
            result=(arg1, arg2, options)
        )
        assert conn.disconnect.called is True  # Make sure destroy_context() was called
        assert context.__dict__.keys() == []

        conn = Connection('The connection.', Disconnect('someconn'))
        context.someconn = conn
        assert o.execute('echo', *args, **options) == dict(
            result=(arg1, arg2, options)
        )
        assert conn.disconnect.called is True  # Make sure destroy_context() was called
        assert context.__dict__.keys() == []

        # Test with good command:
        conn = Connection('The connection.', Disconnect('someconn'))
        context.someconn = conn
        e = raises(errors.ValidationError, o.execute, 'good')
        assert e.name == 'nurse'
        assert e.error == u'Not naughty!'
        assert conn.disconnect.called is True  # Make sure destroy_context() was called
        assert context.__dict__.keys() == []

        # Test with bad command:
        conn = Connection('The connection.', Disconnect('someconn'))
        context.someconn = conn
        e = raises(errors.InternalError, o.execute, 'bad')
        assert conn.disconnect.called is True  # Make sure destroy_context() was called
        assert context.__dict__.keys() == []

        # Test with option 'name':
        conn = Connection('The connection.', Disconnect('someconn'))
        context.someconn = conn
        assert o.execute('with_name', name=u'test') == dict(result=u'TEST')
