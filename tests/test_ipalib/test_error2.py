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
from tests.util import assert_equal, raises, dummy_ugettext
from ipalib import errors2
from ipalib.constants import TYPE_ERROR


class PrivateExceptionTester(object):
    _klass = None
    __klass = None

    def __get_klass(self):
        if self.__klass is None:
            self.__klass = self._klass
        assert issubclass(self.__klass, StandardError)
        assert issubclass(self.__klass, errors2.PrivateError)
        assert not issubclass(self.__klass, errors2.PublicError)
        return self.__klass
    klass = property(__get_klass)

    def new(self, **kw):
        for (key, value) in kw.iteritems():
            assert not hasattr(self.klass, key), key
        inst = self.klass(**kw)
        assert isinstance(inst, StandardError)
        assert isinstance(inst, errors2.PrivateError)
        assert isinstance(inst, self.klass)
        assert not isinstance(inst, errors2.PublicError)
        for (key, value) in kw.iteritems():
            assert getattr(inst, key) is value
        assert str(inst) == self.klass.format % kw
        assert inst.message == str(inst)
        return inst


class test_PrivateError(PrivateExceptionTester):
    """
    Test the `ipalib.errors2.PrivateError` exception.
    """
    _klass = errors2.PrivateError

    def test_init(self):
        """
        Test the `ipalib.errors2.PrivateError.__init__` method.
        """
        inst = self.klass(key1='Value 1', key2='Value 2')
        assert inst.key1 == 'Value 1'
        assert inst.key2 == 'Value 2'
        assert str(inst) == ''

        # Test subclass and use of format:
        class subclass(self.klass):
            format = '%(true)r %(text)r %(number)r'

        kw = dict(true=True, text='Hello!', number=18)
        inst = subclass(**kw)
        assert inst.true is True
        assert inst.text is kw['text']
        assert inst.number is kw['number']
        assert str(inst) == subclass.format % kw

        # Test via PrivateExceptionTester.new()
        inst = self.new(**kw)
        assert isinstance(inst, self.klass)
        assert inst.true is True
        assert inst.text is kw['text']
        assert inst.number is kw['number']


class test_SubprocessError(PrivateExceptionTester):
    """
    Test the `ipalib.errors2.SubprocessError` exception.
    """

    _klass = errors2.SubprocessError

    def test_init(self):
        """
        Test the `ipalib.errors2.SubprocessError.__init__` method.
        """
        inst = self.new(returncode=1, argv=('/bin/false',))
        assert inst.returncode == 1
        assert inst.argv == ('/bin/false',)
        assert str(inst) == "return code 1 from ('/bin/false',)"
        assert inst.message == str(inst)


class test_PluginSubclassError(PrivateExceptionTester):
    """
    Test the `ipalib.errors2.PluginSubclassError` exception.
    """

    _klass = errors2.PluginSubclassError

    def test_init(self):
        """
        Test the `ipalib.errors2.PluginSubclassError.__init__` method.
        """
        inst = self.new(plugin='bad', bases=('base1', 'base2'))
        assert inst.plugin == 'bad'
        assert inst.bases == ('base1', 'base2')
        assert str(inst) == \
            "'bad' not subclass of any base in ('base1', 'base2')"
        assert inst.message == str(inst)


class test_PluginDuplicateError(PrivateExceptionTester):
    """
    Test the `ipalib.errors2.PluginDuplicateError` exception.
    """

    _klass = errors2.PluginDuplicateError

    def test_init(self):
        """
        Test the `ipalib.errors2.PluginDuplicateError.__init__` method.
        """
        inst = self.new(plugin='my_plugin')
        assert inst.plugin == 'my_plugin'
        assert str(inst) == "'my_plugin' was already registered"
        assert inst.message == str(inst)


class test_PluginOverrideError(PrivateExceptionTester):
    """
    Test the `ipalib.errors2.PluginOverrideError` exception.
    """

    _klass = errors2.PluginOverrideError

    def test_init(self):
        """
        Test the `ipalib.errors2.PluginOverrideError.__init__` method.
        """
        inst = self.new(base='Base', name='cmd', plugin='my_cmd')
        assert inst.base == 'Base'
        assert inst.name == 'cmd'
        assert inst.plugin == 'my_cmd'
        assert str(inst) == "unexpected override of Base.cmd with 'my_cmd'"
        assert inst.message == str(inst)


class test_PluginMissingOverrideError(PrivateExceptionTester):
    """
    Test the `ipalib.errors2.PluginMissingOverrideError` exception.
    """

    _klass = errors2.PluginMissingOverrideError

    def test_init(self):
        """
        Test the `ipalib.errors2.PluginMissingOverrideError.__init__` method.
        """
        inst = self.new(base='Base', name='cmd', plugin='my_cmd')
        assert inst.base == 'Base'
        assert inst.name == 'cmd'
        assert inst.plugin == 'my_cmd'
        assert str(inst) == "Base.cmd not registered, cannot override with 'my_cmd'"
        assert inst.message == str(inst)



##############################################################################
# Unit tests for public errors:

class PublicExceptionTester(object):
    _klass = None
    __klass = None

    def __get_klass(self):
        if self.__klass is None:
            self.__klass = self._klass
        assert issubclass(self.__klass, StandardError)
        assert issubclass(self.__klass, errors2.PublicError)
        assert not issubclass(self.__klass, errors2.PrivateError)
        assert type(self.__klass.errno) is int
        assert 900 <= self.__klass.errno <= 5999
        return self.__klass
    klass = property(__get_klass)

    def new(self, message=None, **kw):
        # Test that TypeError is raised if message isn't unicode:
        e = raises(TypeError, self.klass, 'The message')
        assert str(e) == TYPE_ERROR % ('message', unicode, 'The message', str)

        # Test the instance:
        for (key, value) in kw.iteritems():
            assert not hasattr(self.klass, key), key
        inst = self.klass(message=message, **kw)
        assert isinstance(inst, StandardError)
        assert isinstance(inst, errors2.PublicError)
        assert isinstance(inst, self.klass)
        assert not isinstance(inst, errors2.PrivateError)
        for (key, value) in kw.iteritems():
            assert getattr(inst, key) is value
        assert str(inst) == inst.get_format(lambda m: m) % kw
        assert inst.message == str(inst)
        return inst


class test_PublicError(PublicExceptionTester):
    """
    Test the `ipalib.errors2.PublicError` exception.
    """
    _klass = errors2.PublicError

    def test_init(self):
        """
        Test the `ipalib.errors2.PublicError.__init__` method.
        """
        inst = self.klass(key1='Value 1', key2='Value 2')
        assert inst.key1 == 'Value 1'
        assert inst.key2 == 'Value 2'
        assert str(inst) == ''

        # Test subclass and use of message, get_format():
        class subclass(self.klass):
            def get_format(self, _):
                return _('%(true)r %(text)r %(number)r')

        kw = dict(true=True, text='Hello!', number=18)
        inst = subclass(**kw)
        assert inst.true is True
        assert inst.text is kw['text']
        assert inst.number is kw['number']
        assert_equal(inst.message, u'%(true)r %(text)r %(number)r' % kw)

        # Test via PublicExceptionTester.new()
        inst = self.new(**kw)
        assert isinstance(inst, self.klass)
        assert inst.true is True
        assert inst.text is kw['text']
        assert inst.number is kw['number']


def test_public_errors():
    """
    Test the `ipalib.errors2.public_errors` module variable.
    """
    for klass in errors2.public_errors:
        assert issubclass(klass, StandardError)
        assert issubclass(klass, errors2.PublicError)
        assert not issubclass(klass, errors2.PrivateError)
        assert type(klass.errno) is int
        assert 900 <= klass.errno <= 5999
        doc = inspect.getdoc(klass)
        assert doc is not None, 'need class docstring for %s' % klass.__name__
        m = re.match(r'^\*{2}(\d+)\*{2} ', doc)
        assert m is not None, "need '**ERRNO**' in %s docstring" % klass.__name__
        errno = int(m.group(1))
        assert errno == klass.errno, (
            'docstring=%r but errno=%r in %s' % (errno, klass.errno, klass.__name__)
        )
