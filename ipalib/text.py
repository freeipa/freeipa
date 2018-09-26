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
Defers gettext translation till request time.

IPA presents some tricky gettext challenges.  On the one hand, most translatable
message are defined as class attributes on the plugins, which means these get
evaluated at module-load time.  But on the other hand, each request to the
server can be in a different locale, so the actual translation must not occur
till request time.

The `text` module provides a mechanism for for deferred gettext translation.  It
was designed to:

    1. Allow translatable strings to be marked with the usual ``_()`` and
       ``ngettext()`` functions so that standard tools like xgettext can still
       be used

    2. Allow programmers to mark strings in a natural way without burdening them
       with details of the deferred translation mechanism

A typical plugin will use the deferred translation like this:

>>> from ipalib import Command, _, ngettext
>>> class my_plugin(Command):
...     my_string = _('Hello, %(name)s.')
...     my_plural = ngettext('%(count)d goose', '%(count)d geese', 0)
...

With normal gettext usage, the *my_string* and *my_plural* message would be
translated at module-load-time when your ``my_plugin`` class is defined.  This
would mean that all message are translated in the locale of the server rather
than the locale of the request.

However, the ``_()`` function above is actually a `GettextFactory` instance,
which when called returns a `Gettext` instance.  A `Gettext` instance stores the
message to be translated, and the gettext domain and localedir, but it doesn't
perform the translation till `Gettext.__unicode__()` is called.  For example:

>>> my_plugin.my_string
Gettext('Hello, %(name)s.', domain='ipa', localedir=None)
>>> unicode(my_plugin.my_string)
u'Hello, %(name)s.'

Translation can also be performed via the `Gettext.__mod__()` convenience
method.  For example, these two are equivalent:

>>> my_plugin.my_string % dict(name='Joe')
u'Hello, Joe.'
>>> unicode(my_plugin.my_string) % dict(name='Joe')  # Long form
u'Hello, Joe.'

Translation can also be performed via the `Gettext.format()` convenience
method.  For example, these two are equivalent:

>>> my_plugin.my_string = _('Hello, {name}.')
>>> my_plugin.my_string.format(name='Joe')
u'Hello, Joe.'

>>> my_plugin.my_string = _('Hello, {0}.')
>>> my_plugin.my_string.format('Joe')
u'Hello, Joe.'

Similar to ``_()``, the ``ngettext()`` function above is actually an
`NGettextFactory` instance, which when called returns an `NGettext` instance.
An `NGettext` instance stores the singular and plural messages, and the gettext
domain and localedir, but it doesn't perform the translation till
`NGettext.__call__()` is called.  For example:

>>> my_plugin.my_plural
NGettext('%(count)d goose', '%(count)d geese', domain='ipa', localedir=None)
>>> my_plugin.my_plural(1)
u'%(count)d goose'
>>> my_plugin.my_plural(2)
u'%(count)d geese'

Translation can also be performed via the `NGettext.__mod__()` convenience
method.  For example, these two are equivalent:

>>> my_plugin.my_plural % dict(count=1)
u'1 goose'
>>> my_plugin.my_plural(1) % dict(count=1)  # Long form
u'1 goose'

Translation can also be performed via the `NGettext.format()` convenience
method.  For example:

>>> my_plugin.my_plural = ngettext('{count} goose', '{count} geese', 0)
>>> my_plugin.my_plural.format(count=1)
u'1 goose'
>>> my_plugin.my_plural.format(count=2)
u'2 geese'

Lastly, 3rd-party plugins can create factories bound to a different gettext
domain.  The default domain is ``'ipa'``, which is also the domain of the
standard ``ipalib._()`` and ``ipalib.ngettext()`` factories.  But 3rd-party
plugins can create their own factories like this:

>>> from ipalib import GettextFactory, NGettextFactory
>>> _ = GettextFactory(domain='ipa_foo')
>>> ngettext = NGettextFactory(domain='ipa_foo')
>>> class foo(Command):
...     msg1 = _('Foo!')
...     msg2 = ngettext('%(count)d bar', '%(count)d bars', 0)
...

Notice that these messages are bound to the ``'ipa_foo'`` domain:

>>> foo.msg1
Gettext('Foo!', domain='ipa_foo', localedir=None)
>>> foo.msg2
NGettext('%(count)d bar', '%(count)d bars', domain='ipa_foo', localedir=None)

For additional details, see `GettextFactory` and `Gettext`, and for plural
forms, see `NGettextFactory` and `NGettext`.
"""

import gettext

import six

from ipalib.request import context

if six.PY3:
    unicode = str


def create_translation(key):
    assert key not in context.__dict__
    (domain, localedir) = key
    translation = gettext.translation(domain,
        localedir=localedir,
        languages=getattr(context, 'languages', None),
        fallback=True,
    )
    context.__dict__[key] = translation
    return translation


class LazyText:
    """
    Base class for deferred translation.

    This class is not used directly.  See the `Gettext` and `NGettext`
    subclasses.

    Concatenating LazyText objects with the + operator gives
    ConcatenatedLazyText objects.
    """

    __slots__ = ('domain', 'localedir', 'key', 'args')
    __hash__ = None

    def __init__(self, domain=None, localedir=None):
        """
        Initialize.

        :param domain: The gettext domain in which this message will be
            translated, e.g. ``'ipa'`` or ``'ipa_3rd_party'``; default is
            ``None``
        :param localedir: The directory containing the gettext translations,
            e.g. ``'/usr/share/locale/'``; default is ``None``, in which case
            gettext will use the default system locale directory.
        """
        self.domain = domain
        self.localedir = localedir
        self.key = (domain, localedir)
        self.args = None

    def __eq__(self, other):
        """
        Return ``True`` if this instances is equal to *other*.

        Note that this method cannot be used on the `LazyText` base class itself
        as subclasses must define an *args* instance attribute.
        """
        if type(other) is not self.__class__:
            return False
        return self.args == other.args

    def __ne__(self, other):
        """
        Return ``True`` if this instances is not equal to *other*.

        Note that this method cannot be used on the `LazyText` base class itself
        as subclasses must define an *args* instance attribute.
        """
        return not self.__eq__(other)

    def __add__(self, other):
        return ConcatenatedLazyText(self) + other

    def __radd__(self, other):
        return other + ConcatenatedLazyText(self)


@six.python_2_unicode_compatible
class Gettext(LazyText):
    """
    Deferred translation using ``gettext.ugettext()``.

    Normally the `Gettext` class isn't used directly and instead is created via
    a `GettextFactory` instance.  However, for illustration, we can create one
    like this:

    >>> msg = Gettext('Hello, %(name)s.')

    When you create a `Gettext` instance, the message is stored on the *msg*
    attribute:

    >>> msg.msg
    'Hello, %(name)s.'

    No translation is performed till `Gettext.__unicode__()` is called.  This
    will translate *msg* using ``gettext.ugettext()``, which will return the
    translated string as a Python ``unicode`` instance.  For example:

    >>> unicode(msg)
    u'Hello, %(name)s.'

    `Gettext.__unicode__()` should be called at request time, which in a
    nutshell means it should be called from within your plugin's
    ``Command.execute()`` method.  `Gettext.__unicode__()` will perform the
    translation based on the locale of the current request.

    `Gettext.__mod__()` is a convenience method for Python "percent" string
    formatting.  It will translate your message using `Gettext.__unicode__()`
    and then perform the string substitution on the translated message.  For
    example, these two are equivalent:

    >>> msg % dict(name='Joe')
    u'Hello, Joe.'
    >>> unicode(msg) % dict(name='Joe')  # Long form
    u'Hello, Joe.'

    `Gettext.format()` is a convenience method for Python string formatting.
    It will translate your message using `Gettext.__unicode__()` and then
    perform the string substitution on the translated message.  For example,
    these two are equivalent:

    >>> msg = Gettext('Hello, {name}.')
    >>> msg.format(name='Joe')
    u'Hello, Joe.'

    >>> msg = Gettext('Hello, {0}.')
    >>> msg.format('Joe')
    u'Hello, Joe.'

    See `GettextFactory` for additional details.  If you need to pick between
    singular and plural form, use `NGettext` instances via the
    `NGettextFactory`.
    """

    __slots__ = ('msg')

    def __init__(self, msg, domain=None, localedir=None):
        super(Gettext, self).__init__(domain, localedir)
        self.msg = msg
        self.args = (msg, domain, localedir)

    def __repr__(self):
        return '%s(%r, domain=%r, localedir=%r)' % (self.__class__.__name__,
            self.msg, self.domain, self.localedir)

    def as_unicode(self):
        """
        Translate this message and return as a ``unicode`` instance.
        """
        if self.key in context.__dict__:
            t = context.__dict__[self.key]
        else:
            t = create_translation(self.key)
        if six.PY2:
            return t.ugettext(self.msg)  # pylint: disable=no-member
        else:
            return t.gettext(self.msg)

    def __str__(self):
        return unicode(self.as_unicode())

    def __json__(self):
        return unicode(self)   #pylint: disable=no-member

    def __mod__(self, kw):
        return unicode(self) % kw  #pylint: disable=no-member

    def format(self, *args, **kwargs):
        return unicode(self).format(*args, **kwargs)


@six.python_2_unicode_compatible
class FixMe(Gettext):
    """
    Non-translated place-holder for UI labels.

    `FixMe` is a subclass of `Gettext` and is used for automatically created
    place-holder labels.  It generally behaves exactly like `Gettext` except no
    translation is ever performed.

    `FixMe` allows programmers to get plugins working without first filling in
    all the labels that will ultimately be required, while at the same time it
    creates conspicuous looking UI labels that remind the programmer to
    "fix-me!".  For example, the typical usage would be something like this:

    >>> class Plugin:
    ...     label = None
    ...     def __init__(self):
    ...         self.name = self.__class__.__name__
    ...         if self.label is None:
    ...             self.label = FixMe(self.name + '.label')
    ...         assert isinstance(self.label, Gettext)
    ...
    >>> class user(Plugin):
    ...     pass # Oops, we didn't set user.label yet
    ...
    >>> u = user()
    >>> u.label
    FixMe('user.label')

    Note that as `FixMe` is a subclass of `Gettext`, is passes the above type
    check using ``isinstance()``.

    Calling `FixMe.__unicode__()` performs no translation, but instead returns
    said conspicuous looking label:

    >>> unicode(u.label)
    u'<user.label>'

    For more examples of how `FixMe` is used, see `ipalib.parameters`.
    """

    __slots__ = tuple()

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.msg)

    def __str__(self):
        return u'<%s>' % self.msg


class NGettext(LazyText):
    """
    Deferred translation for plural forms using ``gettext.ungettext()``.

    Normally the `NGettext` class isn't used directly and instead is created via
    a `NGettextFactory` instance.  However, for illustration, we can create one
    like this:

    >>> msg = NGettext('%(count)d goose', '%(count)d geese')

    When you create an `NGettext` instance, the singular and plural forms of
    your message are stored on the *singular* and *plural* instance attributes:

    >>> msg.singular
    '%(count)d goose'
    >>> msg.plural
    '%(count)d geese'

    The translation and number selection isn't performed till
    `NGettext.__call__()` is called.  This will translate and pick the correct
    number using ``gettext.ungettext()``.  As a callable, an `NGettext` instance
    takes a single argument, an integer specifying the count.  For example:

    >>> msg(0)
    u'%(count)d geese'
    >>> msg(1)
    u'%(count)d goose'
    >>> msg(2)
    u'%(count)d geese'

    `NGettext.__mod__()` is a convenience method for Python "percent" string
    formatting.  It can only be used if your substitution ``dict`` contains the
    count in a ``'count'`` item.  For example:

    >>> msg % dict(count=0)
    u'0 geese'
    >>> msg % dict(count=1)
    u'1 goose'
    >>> msg % dict(count=2)
    u'2 geese'

    Alternatively, these longer forms have the same effect as the three examples
    above:

    >>> msg(0) % dict(count=0)
    u'0 geese'
    >>> msg(1) % dict(count=1)
    u'1 goose'
    >>> msg(2) % dict(count=2)
    u'2 geese'

    A ``KeyError`` is raised if your substitution ``dict`` doesn't have a
    ``'count'`` item.  For example:

    >>> msg2 = NGettext('%(num)d goose', '%(num)d geese')
    >>> msg2 % dict(num=0)
    Traceback (most recent call last):
      ...
    KeyError: 'count'

    However, in this case you can still use the longer, explicit form for string
    substitution:

    >>> msg2(0) % dict(num=0)
    u'0 geese'

    `NGettext.format()` is a convenience method for Python string formatting.
    It can only be used if your substitution ``dict`` contains the count in a
    ``'count'`` item.  For example:

    >>> msg = NGettext('{count} goose', '{count} geese')
    >>> msg.format(count=0)
    u'0 geese'
    >>> msg.format(count=1)
    u'1 goose'
    >>> msg.format(count=2)
    u'2 geese'

    A ``KeyError`` is raised if your substitution ``dict`` doesn't have a
    ``'count'`` item.  For example:

    >>> msg2 = NGettext('{num} goose', '{num} geese')
    >>> msg2.format(num=0)
    Traceback (most recent call last):
      ...
    KeyError: 'count'

    However, in this case you can still use the longer, explicit form for
    string substitution:

    >>> msg2(0).format(num=0)
    u'0 geese'

    See `NGettextFactory` for additional details.
    """

    __slots__ = ('singular', 'plural')

    def __init__(self, singular, plural, domain=None, localedir=None):
        super(NGettext, self).__init__(domain, localedir)
        self.singular = singular
        self.plural = plural
        self.args = (singular, plural, domain, localedir)

    def __repr__(self):
        return '%s(%r, %r, domain=%r, localedir=%r)' % (self.__class__.__name__,
            self.singular, self.plural, self.domain, self.localedir)

    def __mod__(self, kw):
        count = kw['count']
        return self(count) % kw

    def format(self, *args, **kwargs):
        count = kwargs['count']
        return self(count).format(*args, **kwargs)

    def __call__(self, count):
        if self.key in context.__dict__:
            t = context.__dict__[self.key]
        else:
            t = create_translation(self.key)
        if six.PY2:
            # pylint: disable=no-member
            return t.ungettext(self.singular, self.plural, count)
            # pylint: enable=no-member
        else:
            return t.ngettext(self.singular, self.plural, count)


@six.python_2_unicode_compatible
class ConcatenatedLazyText:
    """Concatenation of multiple strings, or any objects convertible to unicode

    Used to concatenate several LazyTexts together.
    This allows large strings like help text to be split, so translators
    do not have to re-translate the whole text when only a small part changes.

    Additional strings may be added to the end with the + or += operators.
    """
    def __init__(self, *components):
        self.components = list(components)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.components)

    def __str__(self):
        return u''.join(unicode(c) for c in self.components)

    def __json__(self):
        return unicode(self)

    def __mod__(self, kw):
        return unicode(self) % kw

    def format(self, *args, **kwargs):
        return unicode(self).format(*args, **kwargs)

    def __add__(self, other):
        if isinstance(other, ConcatenatedLazyText):
            return ConcatenatedLazyText(*self.components + other.components)
        else:
            return ConcatenatedLazyText(*self.components + [other])

    def __radd__(self, other):
        if isinstance(other, ConcatenatedLazyText):
            return ConcatenatedLazyText(*other.components + self.components)
        else:
            return ConcatenatedLazyText(*[other] + self.components)


class GettextFactory:
    """
    Factory for creating ``_()`` functions.

    A `GettextFactory` allows you to mark translatable messages that are
    evaluated at initialization time, but deferred their actual translation till
    request time.

    When you create a `GettextFactory` you can provide a specific gettext
    *domain* and *localedir*.  By default the *domain* will be ``'ipa'`` and
    the *localedir* will be ``None``.  Both are available via instance
    attributes of the same name.  For example:

    >>> _ = GettextFactory()
    >>> _.domain
    'ipa'
    >>> _.localedir is None
    True

    When the *localedir* is ``None``, gettext will use the default system
    localedir (typically ``'/usr/share/locale/'``).  In general, you should
    **not** provide a *localedir*... it is intended only to support in-tree
    testing.

    Third party plugins will most likely want to use a different gettext
    *domain*.  For example:

    >>> _ = GettextFactory(domain='ipa_3rd_party')
    >>> _.domain
    'ipa_3rd_party'

    When you call your `GettextFactory` instance, it will return a `Gettext`
    instance associated with the same *domain* and *localedir*.  For example:

    >>> my_msg = _('Hello world')
    >>> my_msg.domain
    'ipa_3rd_party'
    >>> my_msg.localedir is None
    True

    The message isn't translated till `Gettext.__unicode__()` is called, which
    should be done during each request.  See the `Gettext` class for additional
    details.
    """

    def __init__(self, domain='ipa', localedir=None):
        """
        Initialize.

        :param domain: The gettext domain in which this message will be
            translated, e.g. ``'ipa'`` or ``'ipa_3rd_party'``; default is
            ``'ipa'``
        :param localedir: The directory containing the gettext translations,
            e.g. ``'/usr/share/locale/'``; default is ``None``, in which case
            gettext will use the default system locale directory.
        """
        self.domain = domain
        self.localedir = localedir

    def __repr__(self):
        return '%s(domain=%r, localedir=%r)' % (self.__class__.__name__,
            self.domain, self.localedir)

    def __call__(self, msg):
        return Gettext(msg, self.domain, self.localedir)


class NGettextFactory(GettextFactory):
    """
    Factory for creating ``ngettext()`` functions.

    `NGettextFactory` is similar to `GettextFactory`, except `NGettextFactory`
    is for plural forms.

    So that standard tools like xgettext can find your plural forms, you should
    reference your `NGettextFactory` instance using a variable named
    *ngettext*.  For example:

    >>> ngettext = NGettextFactory()
    >>> ngettext
    NGettextFactory(domain='ipa', localedir=None)

    When you call your `NGettextFactory` instance to create a deferred
    translation, you provide the *singular* message, the *plural* message, and
    a dummy *count*.  An `NGettext` instance will be returned.  For example:

    >>> my_msg = ngettext('%(count)d goose', '%(count)d geese', 0)
    >>> my_msg
    NGettext('%(count)d goose', '%(count)d geese', domain='ipa', localedir=None)

    The *count* is ignored (because the translation is deferred), but you should
    still provide it so parsing tools aren't confused.  For consistency, it is
    recommended to always provide ``0`` for the *count*.

    See `NGettext` for details on how the deferred translation is later
    performed.  See `GettextFactory` for details on setting a different gettext
    *domain* (likely needed for 3rd-party plugins).
    """

    def __call__(self, singular, plural, count):
        return NGettext(singular, plural, self.domain, self.localedir)


# Process wide factories:
_ = GettextFactory()
ngettext = NGettextFactory()
ugettext = _
