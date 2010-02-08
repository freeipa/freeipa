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
from tests.data import utf8_bytes, unicode_str
from ipalib import text

singular = '%(count)d goose makes a %(dish)s'
plural = '%(count)d geese make a %(dish)s'


class test_LazyText(object):

    klass = text.LazyText

    def test_init(self):
        inst = self.klass('foo', 'bar')
        assert inst.domain == 'foo'
        assert inst.localedir == 'bar'


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
        inst = self.klass(utf8_bytes, 'foo', 'bar')
        assert inst.domain == 'foo'
        assert inst.localedir == 'bar'
        assert inst.msg is utf8_bytes

    def test_unicode(self):
        inst = self.klass(utf8_bytes, 'foo', 'bar')
        assert unicode(inst) == unicode_str

    def test_mod(self):
        inst = self.klass('hello %(adj)s nurse', 'foo', 'bar')
        assert inst % dict(adj='naughty', stuff='junk') == 'hello naughty nurse'


class test_NGettext(object):

    klass = text.NGettext

    def test_init(self):
        inst = self.klass(singular, plural, 'foo', 'bar')
        assert inst.singular is singular
        assert inst.plural is plural
        assert inst.domain == 'foo'
        assert inst.localedir == 'bar'

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


class test_gettext_factory(object):

    klass = text.gettext_factory

    def test_init(self):
        inst = self.klass('foo', 'bar')
        assert inst.domain == 'foo'
        assert inst.localedir == 'bar'

    def test_call(self):
        inst = self.klass('foo', 'bar')
        g = inst(utf8_bytes)
        assert type(g) is text.Gettext
        assert g.msg is utf8_bytes
        assert g.domain == 'foo'
        assert g.localedir == 'bar'


class test_ngettext_factory(object):

    klass = text.ngettext_factory

    def test_init(self):
        inst = self.klass('foo', 'bar')
        assert inst.domain == 'foo'
        assert inst.localedir == 'bar'

    def test_call(self):
        inst = self.klass('foo', 'bar')
        ng = inst(singular, plural, 7)
        assert type(ng) is text.NGettext
        assert ng.singular is singular
        assert ng.plural is plural
        assert ng.domain == 'foo'
        assert ng.localedir == 'bar'
