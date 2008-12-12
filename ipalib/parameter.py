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

from plugable import ReadOnly, lock, check_name
from constants import NULLS, TYPE_ERROR, CALLABLE_ERROR


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


class Param(ReadOnly):
    """
    Base class for all IPA types.
    """

    __kwargs = dict(
        cli_name=(str, None),
        doc=(str, ''),
        required=(bool, True),
        multivalue=(bool, False),
        primary_key=(bool, False),
        normalizer=(callable, None),
        default=(None, None),
        default_from=(callable, None),
        flags=(frozenset, frozenset()),
    )

    def __init__(self, name, kwargs, **override):
        self.param_spec = name
        self.__override = dict(override)
        if not ('required' in override or 'multivalue' in override):
            (name, kw_from_spec) = parse_param_spec(name)
            override.update(kw_from_spec)
        self.name = check_name(name)
        if 'cli_name' not in override:
            override['cli_name'] = self.name
        df = override.get('default_from', None)
        if callable(df) and not isinstance(df, DefaultFrom):
            override['default_from'] = DefaultFrom(df)
        kwargs = dict(kwargs)
        assert set(self.__kwargs).intersection(kwargs) == set()
        kwargs.update(self.__kwargs)
        for (key, (kind, default)) in kwargs.iteritems():
            value = override.get(key, default)
            if value is None:
                if kind is bool:
                    raise TypeError(
                        TYPE_ERROR % (key, bool, value, type(value))
                    )
            else:
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
        check_name(self.cli_name)
        lock(self)

    def normalize(self, value):
        """
        Normalize ``value`` using normalizer callback.

        For example:

        >>> param = Str('telephone',
        ...     normalizer=lambda value: value.replace('.', '-')
        ... )
        >>> param.normalize(u'800.123.4567')
        u'800-123-4567'

        (Note that `Str` is a subclass of `Param`.)

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
                    self.__normalize_scalar(v) for v in value
                )
            return (self.__normalize_scalar(value),)  # Return a tuple
        return self.__normalize_scalar(value)

    def __normalize_scalar(self, value):
        """
        Normalize a scalar value.

        This method is called once for each value in multivalue.
        """
        if type(value) is not unicode:
            return value
        try:
            return self.normalizer(value)
        except StandardError:
            return value

    def convert(self, value):
        if value in NULLS:
            return
        if self.multivalue:
            if type(value) in (tuple, list):
                values = filter(
                    lambda val: val not in NULLS,
                    (self._convert_scalar(v, i) for (i, v) in enumerate(value))
                )
                if len(values) == 0:
                    return
                return tuple(values)
            return (scalar(value, 0),)  # Return a tuple
        return scalar(value)

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


class Str(Param):
    """

    """

    def __init__(self, name, **overrides):
        self.type = unicode
        super(Str, self).__init__(name, {}, **overrides)

    def _convert_scalar(self, value, index=None):
        if type(value) in (self.type, int, float, bool):
            return self.type(value)
        raise TypeError(
            'Can only implicitly convert int, float, or bool; got %r' % value
        )
