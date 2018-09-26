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

import ldap

from ipapython.dn import DN
from ipapython import ipaldap
from ipalib import errors
from ipalib.frontend import Command
from ipaserver.plugins import baseldap
from ipatests.util import assert_deepequal
import pytest


@pytest.mark.tier0
def test_exc_wrapper():
    """Test the BaseLDAPCommand._exc_wrapper helper method"""
    handled_exceptions = []

    class test_callback(baseldap.BaseLDAPCommand):
        """Fake IPA method"""
        def test_fail(self):
            self._exc_wrapper([], {}, self.fail)(1, 2, a=1, b=2)

        def fail(self, *args, **kwargs):
            assert args == (1, 2)
            assert kwargs == dict(a=1, b=2)
            raise errors.ExecutionError('failure')

    api = 'the api instance'
    instance = test_callback(api)

    # Test with one callback first

    @test_callback.register_exc_callback
    def handle_exception(  # pylint: disable=unused-variable
            self, keys, options, e, call_func, *args, **kwargs):
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


@pytest.mark.tier0
def test_callback_registration():
    class callbacktest_base(Command):
        callback_types = Command.callback_types + ('test',)

        def test_callback(self, param):
            messages.append(('Base test_callback', param))

    def registered_callback(self, param):
        messages.append(('Base registered callback', param))
    callbacktest_base.register_callback('test', registered_callback)

    class SomeClass:
        def registered_callback(self, command, param):
            messages.append(('Registered callback from another class', param))
    callbacktest_base.register_callback('test', SomeClass().registered_callback)

    class callbacktest_subclass(callbacktest_base):
        pass

    def subclass_callback(self, param):
        messages.append(('Subclass registered callback', param))
    callbacktest_subclass.register_callback('test', subclass_callback)


    api = 'the api instance'

    messages = []
    instance = callbacktest_base(api)
    for callback in instance.get_callbacks('test'):
        callback(instance, 42)
    assert messages == [
            ('Base test_callback', 42),
            ('Base registered callback', 42),
            ('Registered callback from another class', 42)]

    messages = []
    instance = callbacktest_subclass(api)
    for callback in instance.get_callbacks('test'):
        callback(instance, 42)
    assert messages == [
            ('Base test_callback', 42),
            ('Subclass registered callback', 42)]


@pytest.mark.tier0
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

    api = 'the api instance'

    base_instance = callbacktest_base(api)

    class callbacktest_subclass(callbacktest_base):
        pass

    @callbacktest_subclass.register_exc_callback
    def exc_callback(  # pylint: disable=unused-variable
            self, keys, options, exc, call_func, *args, **kwargs):
        """Subclass's private exception callback"""
        messages.append('Subclass registered callback')
        raise exc

    subclass_instance = callbacktest_subclass(api)

    # Make sure exception in base class is only handled by the base class
    base_instance.test_fail()
    assert messages == ['Base exc_callback']


    @callbacktest_base.register_exc_callback
    def exc_callback_2(  # pylint: disable=unused-variable
            self, keys, options, exc, call_func, *args, **kwargs):
        """Callback on super class; doesn't affect the subclass"""
        messages.append('Superclass registered callback')
        raise exc

    # Make sure exception in subclass is only handled by both
    messages = []
    subclass_instance.test_fail()
    assert messages == ['Base exc_callback', 'Subclass registered callback']


@pytest.mark.tier0
def test_entry_to_dict():
    class FakeAttributeType:
        def __init__(self, name, syntax):
            self.names = (name,)
            self.syntax = syntax

    class FakeSchema:
        def get_obj(self, type, name):
            if type != ldap.schema.AttributeType:
                return
            if name == 'binaryattr':
                return FakeAttributeType(name, '1.3.6.1.4.1.1466.115.121.1.40')
            elif name == 'textattr':
                return FakeAttributeType(name, '1.3.6.1.4.1.1466.115.121.1.15')
            elif name == 'dnattr':
                return FakeAttributeType(name, '1.3.6.1.4.1.1466.115.121.1.12')

    class FakeLDAPClient(ipaldap.LDAPClient):
        def __init__(self):
            super(FakeLDAPClient, self).__init__('ldap://test',
                                                 force_schema_updates=False)
            self._has_schema = True
            self._schema = FakeSchema()

    conn = FakeLDAPClient()
    rights = {'nothing': 'is'}

    entry = ipaldap.LDAPEntry(
        conn,
        DN('cn=test'),
        textattr=[u'text'],
        dnattr=[DN('cn=test')],
        binaryattr=[b'\xffabcd'],
        attributelevelrights=rights)
    the_dict = {
        u'dn': u'cn=test',
        u'textattr': [u'text'],
        u'dnattr': [u'cn=test'],
        u'binaryattr': [b'\xffabcd'],
        u'attributelevelrights': rights}
    assert_deepequal(
        baseldap.entry_to_dict(entry, all=True, raw=True),
        the_dict)
