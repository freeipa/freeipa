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
Parameter system for command plugins.
"""

from types import NoneType
from plugable import ReadOnly, lock, check_name
from constants import NULLS, TYPE_ERROR, CALLABLE_ERROR


class DefaultFrom(ReadOnly):
    """
    Derive a default value from other supplied values.

    For example, say you wanted to create a default for the user's login from
    the user's first and last names. It could be implemented like this:

    >>> login = DefaultFrom(lambda first, last: first[0] + last)
    >>> login(first='John', last='Doe')
    'JDoe'

    If you do not explicitly provide keys when you create a DefaultFrom
    instance, the keys are implicitly derived from your callback by
    inspecting ``callback.func_code.co_varnames``. The keys are available
    through the ``DefaultFrom.keys`` instance attribute, like this:

    >>> login.keys
    ('first', 'last')

    The callback is available through the ``DefaultFrom.callback`` instance
    attribute, like this:

    >>> login.callback # doctest:+ELLIPSIS
    <function <lambda> at 0x...>
    >>> login.callback.func_code.co_varnames # The keys
    ('first', 'last')

    The keys can be explicitly provided as optional positional arguments after
    the callback. For example, this is equivalent to the ``login`` instance
    above:

    >>> login2 = DefaultFrom(lambda a, b: a[0] + b, 'first', 'last')
    >>> login2.keys
    ('first', 'last')
    >>> login2.callback.func_code.co_varnames # Not the keys
    ('a', 'b')
    >>> login2(first='John', last='Doe')
    'JDoe'

    If any keys are missing when calling your DefaultFrom instance, your
    callback is not called and None is returned. For example:

    >>> login(first='John', lastname='Doe') is None
    True
    >>> login() is None
    True

    Any additional keys are simply ignored, like this:

    >>> login(last='Doe', first='John', middle='Whatever')
    'JDoe'

    As above, because `DefaultFrom.__call__` takes only pure keyword
    arguments, they can be supplied in any order.

    Of course, the callback need not be a lambda expression. This third
    example is equivalent to both the ``login`` and ``login2`` instances
    above:

    >>> def get_login(first, last):
    ...     return first[0] + last
    ...
    >>> login3 = DefaultFrom(get_login)
    >>> login3.keys
    ('first', 'last')
    >>> login3.callback.func_code.co_varnames
    ('first', 'last')
    >>> login3(first='John', last='Doe')
    'JDoe'
    """

    def __init__(self, callback, *keys):
        """
        :param callback: The callable to call when all keys are present.
        :param keys: Optional keys used for source values.
        """
        if not callable(callback):
            raise TypeError('callback must be callable; got %r' % callback)
        self.callback = callback
        if len(keys) == 0:
            fc = callback.func_code
            self.keys = fc.co_varnames[:fc.co_argcount]
        else:
            self.keys = keys
        for key in self.keys:
            if type(key) is not str:
                raise_TypeError(key, str, 'keys')
        lock(self)

    def __call__(self, **kw):
        """
        If all keys are present, calls the callback; otherwise returns None.

        :param kw: The keyword arguments.
        """
        vals = tuple(kw.get(k, None) for k in self.keys)
        if None in vals:
            return
        try:
            return self.callback(*vals)
        except StandardError:
            pass


def parse_param_spec(spec):
    """
    Parse a param spec into to (name, kw).

    The ``spec`` string determines the param name, whether the param is
    required, and whether the param is multivalue according the following
    syntax:

    ======  =====  ========  ==========
    Spec    Name   Required  Multivalue
    ======  =====  ========  ==========
    'var'   'var'  True      False
    'var?'  'var'  False     False
    'var*'  'var'  False     True
    'var+'  'var'  True      True
    ======  =====  ========  ==========

    For example,

    >>> parse_param_spec('login')
    ('login', {'required': True, 'multivalue': False})
    >>> parse_param_spec('gecos?')
    ('gecos', {'required': False, 'multivalue': False})
    >>> parse_param_spec('telephone_numbers*')
    ('telephone_numbers', {'required': False, 'multivalue': True})
    >>> parse_param_spec('group+')
    ('group', {'required': True, 'multivalue': True})

    :param spec: A spec string.
    """
    if type(spec) is not str:
        raise_TypeError(spec, str, 'spec')
    if len(spec) < 2:
        raise ValueError(
            'param spec must be at least 2 characters; got %r' % spec
        )
    _map = {
        '?': dict(required=False, multivalue=False),
        '*': dict(required=False, multivalue=True),
        '+': dict(required=True, multivalue=True),
    }
    end = spec[-1]
    if end in _map:
        return (spec[:-1], _map[end])
    return (spec, dict(required=True, multivalue=False))


class Param(ReadOnly):
    """
    Base class for all parameters.
    """

    # This is a dummy type so that most of the functionality of Param can be
    # unit tested directly without always creating a subclass; however, a real
    # (direct) subclass must *always* override this class attribute:
    type = NoneType  # Ouch, this wont be very useful in the real world!

    kwargs = (
        ('cli_name', str, None),
        ('doc', str, ''),
        ('required', bool, True),
        ('multivalue', bool, False),
        ('primary_key', bool, False),
        ('normalizer', callable, None),
        ('default_from', callable, None),
        ('flags', frozenset, frozenset()),

        # The 'default' kwarg gets appended in Param.__init__():
        # ('default', self.type, None),
    )

    def __init__(self, name, *rules, **kw):
        # We keep these values to use in __repr__():
        self.param_spec = name
        self.__kw = dict(kw)

        # Merge in kw from parse_param_spec():
        if not ('required' in kw or 'multivalue' in kw):
            (name, kw_from_spec) = parse_param_spec(name)
            kw.update(kw_from_spec)
        self.name = check_name(name)
        self.nice = '%s(%r)' % (self.__class__.__name__, self.param_spec)

        # Add 'default' to self.kwargs and makes sure no unknown kw were given:
        assert type(self.type) is type
        self.kwargs += (('default', self.type, None),)
        if not set(t[0] for t in self.kwargs).issuperset(self.__kw):
            extra = set(kw) - set(t[0] for t in self.kwargs)
            raise TypeError(
                '%s: takes no such kwargs: %s' % (self.nice,
                    ', '.join(repr(k) for k in sorted(extra))
                )
            )

        # Merge in default for 'cli_name' if not given:
        if kw.get('cli_name', None) is None:
            kw['cli_name'] = self.name

        # Wrap 'default_from' in a DefaultFrom if not already:
        df = kw.get('default_from', None)
        if callable(df) and not isinstance(df, DefaultFrom):
            kw['default_from'] = DefaultFrom(df)

        # We keep this copy with merged values also to use when cloning:
        self.__clonekw = kw

        # Perform type validation on kw, add in class rules:
        class_rules = []
        for (key, kind, default) in self.kwargs:
            value = kw.get(key, default)
            if value is not None:
                if kind is frozenset:
                    if type(value) in (list, tuple):
                        value = frozenset(value)
                    elif type(value) is str:
                        value = frozenset([value])
                if (
                    type(kind) is type and type(value) is not kind
                    or
                    type(kind) is tuple and not isinstance(value, kind)
                ):
                    raise TypeError(
                        TYPE_ERROR % (key, kind, value, type(value))
                    )
                elif kind is callable and not callable(value):
                    raise TypeError(
                        CALLABLE_ERROR % (key, value, type(value))
                    )
            if hasattr(self, key):
                raise ValueError('kwarg %r conflicts with attribute on %s' % (
                    key, self.__class__.__name__)
                )
            setattr(self, key, value)
            rule_name = '_rule_%s' % key
            if value is not None and hasattr(self, rule_name):
                class_rules.append(getattr(self, rule_name))
        check_name(self.cli_name)

        # Check that all the rules are callable
        self.class_rules = tuple(class_rules)
        self.rules = rules
        self.all_rules = self.class_rules + self.rules
        for rule in self.all_rules:
            if not callable(rule):
                raise TypeError(
                    '%s: rules must be callable; got %r' % (self.nice, rule)
                )

        # And we're done.
        lock(self)

    def normalize(self, value):
        """
        Normalize ``value`` using normalizer callback.

        For example:

        >>> param = Param('telephone',
        ...     normalizer=lambda value: value.replace('.', '-')
        ... )
        >>> param.normalize(u'800.123.4567')
        u'800-123-4567'

        If this `Param` instance was created with a normalizer callback and
        ``value`` is a unicode instance, the normalizer callback is called and
        *its* return value is returned.

        On the other hand, if this `Param` instance was *not* created with a
        normalizer callback, if ``value`` is *not* a unicode instance, or if an
        exception is caught when calling the normalizer callback, ``value`` is
        returned unchanged.

        :param value: A proposed value for this parameter.
        """
        if self.normalizer is None:
            return value
        if self.multivalue:
            if type(value) in (tuple, list):
                return tuple(
                    self._normalize_scalar(v) for v in value
                )
            return (self._normalize_scalar(value),)  # Return a tuple
        return self._normalize_scalar(value)

    def _normalize_scalar(self, value):
        """
        Normalize a scalar value.

        This method is called once for each value in a multivalue.
        """
        if type(value) is not unicode:
            return value
        try:
            return self.normalizer(value)
        except StandardError:
            return value

    def convert(self, value):
        """
        Convert ``value`` to the Python type required by this parameter.

        For example:

        >>> scalar = Str('my_scalar')
        >>> scalar.type
        <type 'unicode'>
        >>> scalar.convert(43.2)
        u'43.2'

        (Note that `Str` is a subclass of `Param`.)

        All values in `constants.NULLS` will be converted to None.  For
        example:

        >>> scalar.convert(u'') is None  # An empty string
        True
        >>> scalar.convert([]) is None  # An empty list
        True

        Likewise, values in `constants.NULLS` will be filtered out of a
        multivalue parameter.  For example:

        >>> multi = Str('my_multi', multivalue=True)
        >>> multi.convert([True, '', 17, None, False])
        (u'True', u'17', u'False')
        >>> multi.convert([None, u'']) is None  # Filters to an empty list
        True

        Lastly, multivalue parameters will always return a tuple (well,
        assuming they don't return None as in the last example above).
        For example:

        >>> multi.convert(42)  # Called with a scalar value
        (u'42',)
        >>> multi.convert([True, False])  # Called with a list value
        (u'True', u'False')

        Note that how values are converted (and from what types they will be
        converted) completely depends upon how a subclass implements its
        `Param._convert_scalar()` method.  For example, see
        `Str._convert_scalar()`.

        :param value: A proposed value for this parameter.
        """
        if value in NULLS:
            return
        if self.multivalue:
            if type(value) not in (tuple, list):
                value = (value,)
            values = tuple(
                self._convert_scalar(v, i) for (i, v) in filter(
                    lambda tup: tup[1] not in NULLS, enumerate(value)
                )
            )
            if len(values) == 0:
                return
            return values
        return self._convert_scalar(value)

    def _convert_scalar(self, value, index=None):
        """
        Implement in subclass.
        """
        raise NotImplementedError(
            '%s.%s()' % (self.__class__.__name__, '_convert_scalar')
        )


class Bool(Param):
    """

    """


class Int(Param):
    """

    """


class Float(Param):
    """

    """


class Bytes(Param):
    """

    """

    type = str

    kwargs = Param.kwargs + (
        ('minlength', int, None),
        ('maxlength', int, None),
        ('length', int, None),
        ('pattern', str, None),

    )

    def __init__(self, name, **kw):
        super(Bytes, self).__init__(name, **kw)

        if not (
            self.length is None or
            (self.minlength is None and self.maxlength is None)
        ):
            raise ValueError(
                '%s: cannot mix length with minlength or maxlength' % self.nice
            )

        if self.minlength is not None and self.minlength < 1:
            raise ValueError(
                '%s: minlength must be >= 1; got %r' % (self.nice, self.minlength)
            )

        if self.maxlength is not None and self.maxlength < 1:
            raise ValueError(
                '%s: maxlength must be >= 1; got %r' % (self.nice, self.maxlength)
            )

        if None not in (self.minlength, self.maxlength):
            if self.minlength > self.maxlength:
                raise ValueError(
                    '%s: minlength > maxlength (minlength=%r, maxlength=%r)' % (
                        self.nice, self.minlength, self.maxlength)
                )
            elif self.minlength == self.maxlength:
                raise ValueError(
                    '%s: minlength == maxlength; use length=%d instead' % (
                        self.nice, self.minlength)
                )

    def _rule_minlength(self, value):
        """
        Check minlength constraint.
        """
        if len(value) < self.minlength:
            return 'Must be at least %(minlength)d bytes long.' % dict(
                minlength=self.minlength,
            )

    def _rule_maxlength(self, value):
        """
        Check maxlength constraint.
        """
        if len(value) > self.maxlength:
            return 'Can be at most %(maxlength)d bytes long.' % dict(
                maxlength=self.maxlength,
            )

    def _rule_length(self, value):
        """
        Check length constraint.
        """
        if len(value) != self.length:
            return 'Must be exactly %(length)d bytes long.' % dict(
                length=self.length,
            )




class Str(Bytes):
    """

    """

    type = unicode

    kwargs = Bytes.kwargs[:-1] + (
        ('pattern', unicode, None),
    )

    def __init__(self, name, **kw):
        super(Str, self).__init__(name, **kw)

    def _convert_scalar(self, value, index=None):
        if type(value) in (self.type, int, float, bool):
            return self.type(value)
        raise TypeError(
            'Can only implicitly convert int, float, or bool; got %r' % value
        )
