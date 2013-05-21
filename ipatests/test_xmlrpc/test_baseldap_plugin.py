# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2012  Red Hat
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
Test the `ipalib.plugins.baseldap` module.
"""

from ipalib import errors
from ipalib.plugins import baseldap


def test_exc_wrapper():
    """Test the CallbackInterface._exc_wrapper helper method"""
    handled_exceptions = []

    class test_callback(baseldap.BaseLDAPCommand):
        """Fake IPA method"""
        def test_fail(self):
            self._exc_wrapper([], {}, self.fail)(1, 2, a=1, b=2)

        def fail(self, *args, **kwargs):
            assert args == (1, 2)
            assert kwargs == dict(a=1, b=2)
            raise errors.ExecutionError('failure')

    instance = test_callback()

    # Test with one callback first

    @test_callback.register_exc_callback
    def handle_exception(self, keys, options, e, call_func, *args, **kwargs):
        assert args == (1, 2)
        assert kwargs == dict(a=1, b=2)
        handled_exceptions.append(type(e))

    instance.test_fail()
    assert handled_exceptions == [errors.ExecutionError]

    # Test with another callback added

    handled_exceptions = []

    def dont_handle(self, keys, options, e, call_func, *args, **kwargs):
        assert args == (1, 2)
        assert kwargs == dict(a=1, b=2)
        handled_exceptions.append(None)
        raise e
    test_callback.register_exc_callback(dont_handle, first=True)

    instance.test_fail()
    assert handled_exceptions == [None, errors.ExecutionError]


def test_callback_registration():
    class callbacktest_base(baseldap.CallbackInterface):
        _callback_registry = dict(test={})

        def test_callback(self, param):
            messages.append(('Base test_callback', param))

    def registered_callback(self, param):
        messages.append(('Base registered callback', param))
    callbacktest_base.register_callback('test', registered_callback)

    class SomeClass(object):
        def registered_callback(self, command, param):
            messages.append(('Registered callback from another class', param))
    callbacktest_base.register_callback('test', SomeClass().registered_callback)

    class callbacktest_subclass(callbacktest_base):
        pass

    def subclass_callback(self, param):
        messages.append(('Subclass registered callback', param))
    callbacktest_subclass.register_callback('test', subclass_callback)


    messages = []
    instance = callbacktest_base()
    for callback in instance.get_callbacks('test'):
        callback(instance, 42)
    assert messages == [
            ('Base test_callback', 42),
            ('Base registered callback', 42),
            ('Registered callback from another class', 42)]

    messages = []
    instance = callbacktest_subclass()
    for callback in instance.get_callbacks('test'):
        callback(instance, 42)
    assert messages == [
            ('Base test_callback', 42),
            ('Subclass registered callback', 42)]


def test_exc_callback_registration():
    messages = []
    class callbacktest_base(baseldap.BaseLDAPCommand):
        """A method superclass with an exception callback"""
        def exc_callback(self, keys, options, exc, call_func, *args, **kwargs):
            """Let the world know we saw the error, but don't handle it"""
            messages.append('Base exc_callback')
            raise exc

        def test_fail(self):
            """Raise a handled exception"""
            try:
                self._exc_wrapper([], {}, self.fail)(1, 2, a=1, b=2)
            except Exception:
                pass

        def fail(self, *args, **kwargs):
            """Raise an error"""
            raise errors.ExecutionError('failure')

    base_instance = callbacktest_base()

    class callbacktest_subclass(callbacktest_base):
        pass

    @callbacktest_subclass.register_exc_callback
    def exc_callback(self, keys, options, exc, call_func, *args, **kwargs):
        """Subclass's private exception callback"""
        messages.append('Subclass registered callback')
        raise exc

    subclass_instance = callbacktest_subclass()

    # Make sure exception in base class is only handled by the base class
    base_instance.test_fail()
    assert messages == ['Base exc_callback']


    @callbacktest_base.register_exc_callback
    def exc_callback(self, keys, options, exc, call_func, *args, **kwargs):
        """Callback on super class; doesn't affect the subclass"""
        messages.append('Superclass registered callback')
        raise exc

    # Make sure exception in subclass is only handled by both
    messages = []
    subclass_instance.test_fail()
    assert messages == ['Base exc_callback', 'Subclass registered callback']
