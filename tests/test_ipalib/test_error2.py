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
from ipalib import errors2


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
        inst = self.klass(returncode=1, argv=('/bin/false',))
        assert inst.returncode == 1
        assert inst.argv == ('/bin/false',)
        assert str(inst) == "return code 1 from ('/bin/false',)"


def test_public_errors():
    """
    Test the `ipalib.errors2.public_errors` module variable.
    """
    for klass in errors2.public_errors:
        assert issubclass(klass, StandardError)
        assert issubclass(klass, errors2.PublicError)
        assert not issubclass(klass, errors2.PrivateError)
        assert type(klass.code) is int
        assert 900 <= klass.code <= 5999
        doc = inspect.getdoc(klass)
        m = re.match(r'^\*{2}(\d+)\*{2} ', doc)
        assert m is not None, doc
        assert int(m.group(1)) == klass.code, klass.__name__
