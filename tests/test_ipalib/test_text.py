# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty contextrmation
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
Test the `ipalib.text` module.
"""

from tests.util import raises, assert_equal
from ipalib.request import context
from ipalib import text

singular = '%(count)d goose makes a %(dish)s'
plural = '%(count)d geese make a %(dish)s'


def test_create_translation():
    f = text.create_translation
    key = ('foo', None)
    t = f(key)
    assert context.__dict__[key] is t


class test_LazyText(object):

    klass = text.LazyText

    def test_init(self):
        inst = self.klass('foo', 'bar')
        assert inst.domain == 'foo'
        assert inst.localedir == 'bar'
        assert inst.key == ('foo', 'bar')


class test_FixMe(object):
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


class test_Gettext(object):

    klass = text.Gettext

    def test_init(self):
        inst = self.klass('what up?', 'foo', 'bar')
        assert inst.domain == 'foo'
        assert inst.localedir == 'bar'
        assert inst.msg is 'what up?'
        assert inst.args == ('what up?', 'foo', 'bar')

    def test_repr(self):
        inst = self.klass('foo', 'bar', 'baz')
        assert repr(inst) == "Gettext('foo', domain='bar', localedir='baz')"

    def test_unicode(self):
        inst = self.klass('what up?', 'foo', 'bar')
        assert unicode(inst) == u'what up?'

    def test_mod(self):
        inst = self.klass('hello %(adj)s nurse', 'foo', 'bar')
        assert inst % dict(adj='naughty', stuff='junk') == 'hello naughty nurse'

    def test_eq(self):
        inst1 = self.klass('what up?', 'foo', 'bar')
        inst2 = self.klass('what up?', 'foo', 'bar')
        inst3 = self.klass('Hello world', 'foo', 'bar')
        inst4 = self.klass('what up?', 'foo', 'baz')

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


class test_NGettext(object):

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

    def test_eq(self):
        inst1 = self.klass(singular, plural, 'foo', 'bar')
        inst2 = self.klass(singular, plural, 'foo', 'bar')
        inst3 = self.klass(singular, '%(count)d thingies', 'foo', 'bar')
        inst4 = self.klass(singular, plural, 'foo', 'baz')

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


class test_GettextFactory(object):

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
        assert g.msg is 'what up?'
        assert g.domain == 'foo'
        assert g.localedir == 'bar'


class test_NGettextFactory(object):

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
