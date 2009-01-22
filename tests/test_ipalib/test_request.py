# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
Test the `ipalib.request` module.
"""

import threading
import locale
from tests.util import raises, assert_equal
from tests.util import TempDir, dummy_ugettext, dummy_ungettext
from ipalib.constants import OVERRIDE_ERROR
from ipalib import request


def test_ugettext():
    """
    Test the `ipalib.request.ugettext` function.
    """
    f = request.ugettext
    context = request.context
    message = 'Hello, world!'

    # Test with no context.ugettext:
    assert not hasattr(context, 'ugettext')
    assert_equal(f(message), u'Hello, world!')

    # Test with dummy context.ugettext:
    assert not hasattr(context, 'ugettext')
    dummy = dummy_ugettext()
    context.ugettext = dummy
    assert f(message) is dummy.translation
    assert dummy.message is message

    # Cleanup
    del context.ugettext
    assert not hasattr(context, 'ugettext')


def test_ungettext():
    """
    Test the `ipalib.request.ungettext` function.
    """
    f = request.ungettext
    context = request.context
    singular = 'Goose'
    plural = 'Geese'

    # Test with no context.ungettext:
    assert not hasattr(context, 'ungettext')
    assert_equal(f(singular, plural, 1), u'Goose')
    assert_equal(f(singular, plural, 2), u'Geese')

    # Test singular with dummy context.ungettext
    assert not hasattr(context, 'ungettext')
    dummy = dummy_ungettext()
    context.ungettext = dummy
    assert f(singular, plural, 1) is dummy.translation_singular
    assert dummy.singular is singular
    assert dummy.plural is plural
    assert dummy.n == 1
    del context.ungettext
    assert not hasattr(context, 'ungettext')

    # Test plural with dummy context.ungettext
    assert not hasattr(context, 'ungettext')
    dummy = dummy_ungettext()
    context.ungettext = dummy
    assert f(singular, plural, 2) is dummy.translation_plural
    assert dummy.singular is singular
    assert dummy.plural is plural
    assert dummy.n == 2
    del context.ungettext
    assert not hasattr(context, 'ungettext')


def test_set_languages():
    """
    Test the `ipalib.request.set_languages` function.
    """
    f = request.set_languages
    c = request.context
    langs = ('ru', 'en')

    # Test that StandardError is raised if languages has already been set:
    assert not hasattr(c, 'languages')
    c.languages = None
    e = raises(StandardError, f, *langs)
    assert str(e) == OVERRIDE_ERROR % ('context', 'languages', None, langs)
    del c.languages

    # Test setting the languages:
    assert not hasattr(c, 'languages')
    f(*langs)
    assert c.languages == langs
    del c.languages

    # Test setting language from locale.getdefaultlocale()
    assert not hasattr(c, 'languages')
    f()
    assert c.languages == locale.getdefaultlocale()[:1]
    del c.languages
    assert not hasattr(c, 'languages')


def test_create_translation():
    """
    Test the `ipalib.request.create_translation` function.
    """
    f = request.create_translation
    c = request.context
    t = TempDir()

    # Test that StandardError is raised if ugettext or ungettext:
    assert not (hasattr(c, 'ugettext') or hasattr(c, 'ungettext'))
    for name in ('ugettext', 'ungettext'):
        setattr(c, name, None)
        e = raises(StandardError, f, 'ipa', None)
        assert str(e) == (
            'create_translation() already called in thread %r' %
            threading.currentThread().getName()
        )
        delattr(c, name)

    # Test using default language:
    assert not hasattr(c, 'ugettext')
    assert not hasattr(c, 'ungettext')
    assert not hasattr(c, 'languages')
    f('ipa', t.path)
    assert hasattr(c, 'ugettext')
    assert hasattr(c, 'ungettext')
    assert c.languages == locale.getdefaultlocale()[:1]
    del c.ugettext
    del c.ungettext
    del c.languages

    # Test using explicit languages:
    langs = ('de', 'es')
    f('ipa', t.path, *langs)
    assert hasattr(c, 'ugettext')
    assert hasattr(c, 'ungettext')
    assert c.languages == langs
    del c.ugettext
    del c.ungettext
    del c.languages
