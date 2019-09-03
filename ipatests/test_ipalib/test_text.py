# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty contextrmation
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
Test the `ipalib.text` module.
"""
from __future__ import print_function

import os
import shutil
import tempfile
import unittest

import six
import pytest

from ipatests.i18n import create_po, po_file_iterate
from ipalib.request import context
from ipalib import text

if six.PY3:
    unicode = str

pytestmark = pytest.mark.tier0

singular = '%(count)d goose makes a %(dish)s'
plural = '%(count)d geese make a %(dish)s'


def test_create_translation():
    f = text.create_translation
    key = ('foo', None)
    t = f(key)
    assert context.__dict__[key] is t


class test_TestLang:
    lang_env_vars = {'LC_ALL', 'LC_MESSAGES', 'LANGUAGE', 'LANG'}

    def setup_lang(self):
        """
        Set all env variables used by gettext to localize translation files
        to xh_ZA
        """
        self.lang = 'xh_ZA'
        self.saved_locale = {
            k: v for k, v in os.environ.items() if k in self.lang_env_vars}

        os.environ.update(
            {env_var: self.lang for env_var in self.lang_env_vars}
        )

    def teardown_lang(self):
        """
        Revert the locale settings to original values. If the original env
        variable was not set before, it will be popped off os.environ
        """
        for env_var in self.lang_env_vars:
            if env_var not in self.saved_locale:
                os.environ.pop(env_var, None)

        os.environ.update(self.saved_locale)

    def setup(self):
        self.tmp_dir = None
        self.setup_lang()

        self.domain = 'ipa'

        self.pot_basename = '%s.pot' % self.domain
        self.po_basename = '%s.po' % self.lang
        self.mo_basename = '%s.mo' % self.domain

        self.tmp_dir = tempfile.mkdtemp()

        self.locale_dir = os.path.join(self.tmp_dir, 'test_locale')
        self.msg_dir = os.path.join(self.locale_dir, self.lang, 'LC_MESSAGES')

        if not os.path.exists(self.msg_dir):
            os.makedirs(self.msg_dir)

        self.pot_file = os.path.join(
            os.path.dirname(__file__), 'data', self.pot_basename)
        self.mo_file = os.path.join(self.msg_dir, self.mo_basename)
        self.po_file = os.path.join(self.tmp_dir, self.po_basename)

        result = create_po(self.pot_file, self.po_file, self.mo_file)
        if result:
            raise unittest.SkipTest(
                'Unable to create po file "%s" & mo file "%s" from pot '
                'file "%s"' % (self.po_file, self.mo_file, self.pot_file)
            )

        if not os.path.isfile(self.po_file):
            raise unittest.SkipTest(
                'Test po file unavailable: {}'.format(self.po_file))

        if not os.path.isfile(self.mo_file):
            raise unittest.SkipTest(
                'Test mo file unavailable: {}'.format(self.mo_file))

        self.po_file_iterate = po_file_iterate

    def teardown(self):
        self.teardown_lang()

        if self.tmp_dir is not None:
            shutil.rmtree(self.tmp_dir)

    def test_test_lang(self):
        print("test_test_lang")
        # The test installs the test message catalog under the xh_ZA
        # (e.g. Zambia Xhosa) language by default. It would be nice to
        # use a dummy language not associated with any real language,
        # but the setlocale function demands the locale be a valid
        # known locale, Zambia Xhosa is a reasonable choice :)


        # Create a gettext translation object specifying our domain as
        # 'ipa' and the locale_dir as 'test_locale' (i.e. where to
        # look for the message catalog). Then use that translation
        # object to obtain the translation functions.

        def get_msgstr(msg):
            gt = text.GettextFactory(localedir=self.locale_dir)(msg)
            return unicode(gt)

        def get_msgstr_plural(singular, plural, count):
            ng = text.NGettextFactory(localedir=self.locale_dir)(singular, plural, count)
            return ng(count)

        result = self.po_file_iterate(self.po_file, get_msgstr, get_msgstr_plural)
        assert result == 0


class test_LazyText:

    klass = text.LazyText

    def test_init(self):
        inst = self.klass('foo', 'bar')
        assert inst.domain == 'foo'
        assert inst.localedir == 'bar'
        assert inst.key == ('foo', 'bar')


class test_FixMe:
    klass = text.FixMe

    def test_init(self):
        inst = self.klass('user.label')
        assert inst.msg == 'user.label'
        assert inst.domain is None
        assert inst.localedir is None

    def test_repr(self):
        inst = self.klass('user.label')
        assert repr(inst) == "FixMe('user.label')"

    def test_unicode(self):
        inst = self.klass('user.label')
        assert unicode(inst) == u'<user.label>'
        assert type(unicode(inst)) is unicode


class test_Gettext:

    klass = text.Gettext

    def test_init(self):
        inst = self.klass('what up?', 'foo', 'bar')
        assert inst.domain == 'foo'
        assert inst.localedir == 'bar'
        assert inst.msg == 'what up?'
        assert inst.args == ('what up?', 'foo', 'bar')

    def test_repr(self):
        inst = self.klass('foo', 'bar', 'baz')
        assert repr(inst) == "Gettext('foo', domain='bar', localedir='baz')"

    def test_unicode(self):
        inst = self.klass('what up?', 'foo', 'bar')
        assert unicode(inst) == u'what up?'

    def test_mod(self):
        inst = self.klass('hello %(adj)s nurse', 'foo', 'bar')
        assert inst % dict(adj='tall', stuff='junk') == 'hello tall nurse'

    def test_format(self):
        inst = self.klass('{0} {adj} nurse', 'foo', 'bar')
        posargs = ('hello', 'bye')
        knownargs = {'adj': 'caring', 'stuff': 'junk'}
        assert inst.format(*posargs, **knownargs) == 'hello caring nurse'

    def test_eq(self):
        inst1 = self.klass('what up?', 'foo', 'bar')
        inst2 = self.klass('what up?', 'foo', 'bar')
        inst3 = self.klass('Hello world', 'foo', 'bar')
        inst4 = self.klass('what up?', 'foo', 'baz')

        # pylint: disable=comparison-with-itself
        assert (inst1 == inst1) is True
        assert (inst1 == inst2) is True
        assert (inst1 == inst3) is False
        assert (inst1 == inst4) is False

        # Test with args flipped
        assert (inst2 == inst1) is True
        assert (inst3 == inst1) is False
        assert (inst4 == inst1) is False

    def test_ne(self):
        inst1 = self.klass('what up?', 'foo', 'bar')
        inst2 = self.klass('what up?', 'foo', 'bar')
        inst3 = self.klass('Hello world', 'foo', 'bar')
        inst4 = self.klass('what up?', 'foo', 'baz')

        assert (inst1 != inst2) is False
        assert (inst1 != inst2) is False
        assert (inst1 != inst3) is True
        assert (inst1 != inst4) is True

        # Test with args flipped
        assert (inst2 != inst1) is False
        assert (inst3 != inst1) is True
        assert (inst4 != inst1) is True


class test_NGettext:

    klass = text.NGettext

    def test_init(self):
        inst = self.klass(singular, plural, 'foo', 'bar')
        assert inst.singular is singular
        assert inst.plural is plural
        assert inst.domain == 'foo'
        assert inst.localedir == 'bar'
        assert inst.args == (singular, plural, 'foo', 'bar')

    def test_repr(self):
        inst = self.klass('sig', 'plu', 'foo', 'bar')
        assert repr(inst) == \
            "NGettext('sig', 'plu', domain='foo', localedir='bar')"

    def test_call(self):
        inst = self.klass(singular, plural, 'foo', 'bar')
        assert inst(0) == plural
        assert inst(1) == singular
        assert inst(2) == plural
        assert inst(3) == plural

    def test_mod(self):
        inst = self.klass(singular, plural, 'foo', 'bar')
        assert inst % dict(count=0, dish='frown') == '0 geese make a frown'
        assert inst % dict(count=1, dish='stew') == '1 goose makes a stew'
        assert inst % dict(count=2, dish='pie') == '2 geese make a pie'

    def test_format(self):
        singular = '{count} goose makes a {0} {dish}'
        plural = '{count} geese make a {0} {dish}'
        inst = self.klass(singular, plural, 'foo', 'bar')
        posargs = ('tasty', 'disgusting')
        knownargs0 = {'count': 0, 'dish': 'frown', 'stuff': 'junk'}
        knownargs1 = {'count': 1, 'dish': 'stew', 'stuff': 'junk'}
        knownargs2 = {'count': 2, 'dish': 'pie', 'stuff': 'junk'}
        expected_str0 = '0 geese make a tasty frown'
        expected_str1 = '1 goose makes a tasty stew'
        expected_str2 = '2 geese make a tasty pie'
        assert inst.format(*posargs, **knownargs0) == expected_str0
        assert inst.format(*posargs, **knownargs1) == expected_str1
        assert inst.format(*posargs, **knownargs2) == expected_str2

    def test_eq(self):
        inst1 = self.klass(singular, plural, 'foo', 'bar')
        inst2 = self.klass(singular, plural, 'foo', 'bar')
        inst3 = self.klass(singular, '%(count)d thingies', 'foo', 'bar')
        inst4 = self.klass(singular, plural, 'foo', 'baz')

        # pylint: disable=comparison-with-itself
        assert (inst1 == inst1) is True
        assert (inst1 == inst2) is True
        assert (inst1 == inst3) is False
        assert (inst1 == inst4) is False

        # Test with args flipped
        assert (inst2 == inst1) is True
        assert (inst3 == inst1) is False
        assert (inst4 == inst1) is False

    def test_ne(self):
        inst1 = self.klass(singular, plural, 'foo', 'bar')
        inst2 = self.klass(singular, plural, 'foo', 'bar')
        inst3 = self.klass(singular, '%(count)d thingies', 'foo', 'bar')
        inst4 = self.klass(singular, plural, 'foo', 'baz')

        assert (inst1 != inst2) is False
        assert (inst1 != inst2) is False
        assert (inst1 != inst3) is True
        assert (inst1 != inst4) is True

        # Test with args flipped
        assert (inst2 != inst1) is False
        assert (inst3 != inst1) is True
        assert (inst4 != inst1) is True


class test_GettextFactory:

    klass = text.GettextFactory

    def test_init(self):
        # Test with defaults:
        inst = self.klass()
        assert inst.domain == 'ipa'
        assert inst.localedir is None

        # Test with overrides:
        inst = self.klass('foo', 'bar')
        assert inst.domain == 'foo'
        assert inst.localedir == 'bar'

    def test_repr(self):
        # Test with defaults:
        inst = self.klass()
        assert repr(inst) == "GettextFactory(domain='ipa', localedir=None)"

        # Test with overrides:
        inst = self.klass('foo', 'bar')
        assert repr(inst) == "GettextFactory(domain='foo', localedir='bar')"

    def test_call(self):
        inst = self.klass('foo', 'bar')
        g = inst('what up?')
        assert type(g) is text.Gettext
        assert g.msg == 'what up?'
        assert g.domain == 'foo'
        assert g.localedir == 'bar'


class test_NGettextFactory:

    klass = text.NGettextFactory

    def test_init(self):
        # Test with defaults:
        inst = self.klass()
        assert inst.domain == 'ipa'
        assert inst.localedir is None

        # Test with overrides:
        inst = self.klass('foo', 'bar')
        assert inst.domain == 'foo'
        assert inst.localedir == 'bar'

    def test_repr(self):
        # Test with defaults:
        inst = self.klass()
        assert repr(inst) == "NGettextFactory(domain='ipa', localedir=None)"

        # Test with overrides:
        inst = self.klass('foo', 'bar')
        assert repr(inst) == "NGettextFactory(domain='foo', localedir='bar')"

    def test_call(self):
        inst = self.klass('foo', 'bar')
        ng = inst(singular, plural, 7)
        assert type(ng) is text.NGettext
        assert ng.singular is singular
        assert ng.plural is plural
        assert ng.domain == 'foo'
        assert ng.localedir == 'bar'


class test_ConcatenatedText:

    klass = text.ConcatenatedLazyText

    def test_init(self):
        lst = ['a', 'b', 'c', 3]
        inst = self.klass(*lst)
        assert inst.components == lst
        assert unicode(inst) == 'abc3'

    def test_repr(self):
        lazytext = text.Gettext('foo', 'bar', 'baz')
        inst = self.klass(lazytext)
        assert repr(inst) == "ConcatenatedLazyText([%r])" % lazytext

    def test_unicode(self):
        inst = self.klass('[', text.Gettext('green', 'foo', 'bar'), 1, ']')
        assert unicode(inst) == u'[green1]'

    def test_mod(self):
        inst = self.klass('[', text.Gettext('%(color)s', 'foo', 'bar'), ']')
        assert inst % dict(color='red', stuff='junk') == '[red]'

    def test_format(self):
        inst = self.klass('{0}', text.Gettext('{color}', 'foo', 'bar'), ']')
        posargs = ('[', '(')
        knownargs = {'color': 'red', 'stuff': 'junk'}
        assert inst.format(*posargs, **knownargs) == '[red]'

    def test_add(self):
        inst = (text.Gettext('pale ', 'foo', 'bar') +
                text.Gettext('blue', 'foo', 'bar'))
        assert unicode(inst) == 'pale blue'

        inst = (text.Gettext('bright ', 'foo', 'bar') +
                text.Gettext('pale ', 'foo', 'bar') +
                text.Gettext('blue', 'foo', 'bar'))
        assert unicode(inst) == 'bright pale blue'

        inst = text.Gettext('yellow', 'foo', 'bar') + '!'
        assert unicode(inst) == 'yellow!'

        inst = '!' + text.Gettext('yellow', 'foo', 'bar')
        assert unicode(inst) == '!yellow'

        inst = '!' + ('!' + text.Gettext('yellow', 'foo', 'bar'))
        assert unicode(inst) == '!!yellow'

        inst = (text.Gettext('yellow', 'foo', 'bar') + '!') + '!'
        assert unicode(inst) == 'yellow!!'
