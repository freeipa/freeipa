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
Test the `ipalib.errors` module.
"""

import re
import inspect
from tests.util import assert_equal, raises
from ipalib import errors, text
from ipalib.constants import TYPE_ERROR


class PrivateExceptionTester(object):
    _klass = None
    __klass = None

    def __get_klass(self):
        if self.__klass is None:
            self.__klass = self._klass
        assert issubclass(self.__klass, StandardError)
        assert issubclass(self.__klass, errors.PrivateError)
        assert not issubclass(self.__klass, errors.PublicError)
        return self.__klass
    klass = property(__get_klass)

    def new(self, **kw):
        for (key, value) in kw.iteritems():
            assert not hasattr(self.klass, key), key
        inst = self.klass(**kw)
        assert isinstance(inst, StandardError)
        assert isinstance(inst, errors.PrivateError)
        assert isinstance(inst, self.klass)
        assert not isinstance(inst, errors.PublicError)
        for (key, value) in kw.iteritems():
            assert getattr(inst, key) is value
        assert str(inst) == self.klass.format % kw
        assert inst.message == str(inst)
        return inst


class test_PrivateError(PrivateExceptionTester):
    """
    Test the `ipalib.errors.PrivateError` exception.
    """
    _klass = errors.PrivateError

    def test_init(self):
        """
        Test the `ipalib.errors.PrivateError.__init__` method.
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
    Test the `ipalib.errors.SubprocessError` exception.
    """

    _klass = errors.SubprocessError

    def test_init(self):
        """
        Test the `ipalib.errors.SubprocessError.__init__` method.
        """
        inst = self.new(returncode=1, argv=('/bin/false',))
        assert inst.returncode == 1
        assert inst.argv == ('/bin/false',)
        assert str(inst) == "return code 1 from ('/bin/false',)"
        assert inst.message == str(inst)


class test_PluginSubclassError(PrivateExceptionTester):
    """
    Test the `ipalib.errors.PluginSubclassError` exception.
    """

    _klass = errors.PluginSubclassError

    def test_init(self):
        """
        Test the `ipalib.errors.PluginSubclassError.__init__` method.
        """
        inst = self.new(plugin='bad', bases=('base1', 'base2'))
        assert inst.plugin == 'bad'
        assert inst.bases == ('base1', 'base2')
        assert str(inst) == \
            "'bad' not subclass of any base in ('base1', 'base2')"
        assert inst.message == str(inst)


class test_PluginDuplicateError(PrivateExceptionTester):
    """
    Test the `ipalib.errors.PluginDuplicateError` exception.
    """

    _klass = errors.PluginDuplicateError

    def test_init(self):
        """
        Test the `ipalib.errors.PluginDuplicateError.__init__` method.
        """
        inst = self.new(plugin='my_plugin')
        assert inst.plugin == 'my_plugin'
        assert str(inst) == "'my_plugin' was already registered"
        assert inst.message == str(inst)


class test_PluginOverrideError(PrivateExceptionTester):
    """
    Test the `ipalib.errors.PluginOverrideError` exception.
    """

    _klass = errors.PluginOverrideError

    def test_init(self):
        """
        Test the `ipalib.errors.PluginOverrideError.__init__` method.
        """
        inst = self.new(base='Base', name='cmd', plugin='my_cmd')
        assert inst.base == 'Base'
        assert inst.name == 'cmd'
        assert inst.plugin == 'my_cmd'
        assert str(inst) == "unexpected override of Base.cmd with 'my_cmd'"
        assert inst.message == str(inst)


class test_PluginMissingOverrideError(PrivateExceptionTester):
    """
    Test the `ipalib.errors.PluginMissingOverrideError` exception.
    """

    _klass = errors.PluginMissingOverrideError

    def test_init(self):
        """
        Test the `ipalib.errors.PluginMissingOverrideError.__init__` method.
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
        assert issubclass(self.__klass, errors.PublicError)
        assert not issubclass(self.__klass, errors.PrivateError)
        assert type(self.__klass.errno) is int
        assert 900 <= self.__klass.errno <= 5999
        return self.__klass
    klass = property(__get_klass)

    def new(self, format=None, message=None, **kw):
        # Test that TypeError is raised if message isn't unicode:
        e = raises(TypeError, self.klass, message='The message')
        assert str(e) == TYPE_ERROR % ('message', unicode, 'The message', str)

        # Test the instance:
        for (key, value) in kw.iteritems():
            assert not hasattr(self.klass, key), key
        inst = self.klass(format=format, message=message, **kw)
        assert isinstance(inst, StandardError)
        assert isinstance(inst, errors.PublicError)
        assert isinstance(inst, self.klass)
        assert not isinstance(inst, errors.PrivateError)
        for (key, value) in kw.iteritems():
            assert getattr(inst, key) is value
        return inst


class test_PublicError(PublicExceptionTester):
    """
    Test the `ipalib.errors.PublicError` exception.
    """
    _klass = errors.PublicError

    def test_init(self):
        """
        Test the `ipalib.errors.PublicError.__init__` method.
        """
        message = u'The translated, interpolated message'
        format = 'key=%(key1)r and key2=%(key2)r'
        uformat = u'Translated key=%(key1)r and key2=%(key2)r'
        val1 = 'Value 1'
        val2 = 'Value 2'
        kw = dict(key1=val1, key2=val2)

        # Test with format=str, message=None
        inst = self.klass(format, **kw)
        assert inst.format is format
        assert_equal(inst.message, format % kw)
        assert inst.forwarded is False
        assert inst.key1 is val1
        assert inst.key2 is val2

        # Test with format=None, message=unicode
        inst = self.klass(message=message, **kw)
        assert inst.format is None
        assert inst.message is message
        assert inst.strerror is message
        assert inst.forwarded is True
        assert inst.key1 is val1
        assert inst.key2 is val2

        # Test with format=None, message=str
        e = raises(TypeError, self.klass, message='the message', **kw)
        assert str(e) == TYPE_ERROR % ('message', unicode, 'the message', str)

        # Test with format=None, message=None
        e = raises(ValueError, self.klass, **kw)
        assert str(e) == \
            'PublicError.format is None yet format=None, message=None'


        ######################################
        # Test via PublicExceptionTester.new()

        # Test with format=str, message=None
        inst = self.new(format, **kw)
        assert isinstance(inst, self.klass)
        assert inst.format is format
        assert_equal(inst.message, format % kw)
        assert inst.forwarded is False
        assert inst.key1 is val1
        assert inst.key2 is val2

        # Test with format=None, message=unicode
        inst = self.new(message=message, **kw)
        assert isinstance(inst, self.klass)
        assert inst.format is None
        assert inst.message is message
        assert inst.strerror is message
        assert inst.forwarded is True
        assert inst.key1 is val1
        assert inst.key2 is val2


        ##################
        # Test a subclass:
        class subclass(self.klass):
            format = '%(true)r %(text)r %(number)r'

        uformat = u'Translated %(true)r %(text)r %(number)r'
        kw = dict(true=True, text='Hello!', number=18)

        # Test with format=str, message=None
        e = raises(ValueError, subclass, format, **kw)
        assert str(e) == 'non-generic %r needs format=None; got format=%r' % (
            'subclass', format)

        # Test with format=None, message=None:
        inst = subclass(**kw)
        assert inst.format is subclass.format
        assert_equal(inst.message, subclass.format % kw)
        assert inst.forwarded is False
        assert inst.true is True
        assert inst.text is kw['text']
        assert inst.number is kw['number']

        # Test with format=None, message=unicode:
        inst = subclass(message=message, **kw)
        assert inst.format is subclass.format
        assert inst.message is message
        assert inst.strerror is message
        assert inst.forwarded is True
        assert inst.true is True
        assert inst.text is kw['text']
        assert inst.number is kw['number']

        # Test with instructions:
        # first build up "instructions", then get error and search for
        # lines of instructions appended to the end of the strerror
        # despite the parameter 'instructions' not existing in the format
        instructions = u"The quick brown fox jumps over the lazy dog".split()
        # this expression checks if each word of instructions
        # exists in a string as a separate line, with right order
        regexp = re.compile('(?ims).*' +
                            ''.join(map(lambda x: '(%s).*' % (x),
                                        instructions)) +
                            '$')
        inst = subclass(instructions=instructions, **kw)
        assert inst.format is subclass.format
        assert_equal(inst.instructions, instructions)
        inst_match = regexp.match(inst.strerror).groups()
        assert_equal(list(inst_match),list(instructions))


def test_public_errors():
    """
    Test the `ipalib.errors.public_errors` module variable.
    """
    i = 0
    for klass in errors.public_errors:
        assert issubclass(klass, StandardError)
        assert issubclass(klass, errors.PublicError)
        assert not issubclass(klass, errors.PrivateError)
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

        # Test format
        if klass.format is not None:
            assert klass.format is errors.__messages[i]
            i += 1
