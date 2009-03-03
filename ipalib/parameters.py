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

TODO:

  * Change rule call signature to rule(_, value, **kw) so that rules can also
    validate relative to other parameter values (e.g., login name as it relates
    to first name and last name)

  * Add the _rule_pattern() methods to `Bytes` and `Str`
"""

import re
from types import NoneType
from util import make_repr
from request import ugettext
from plugable import ReadOnly, lock, check_name
from errors2 import ConversionError, RequirementError, ValidationError
from constants import NULLS, TYPE_ERROR, CALLABLE_ERROR


class DefaultFrom(ReadOnly):
    """
    Derive a default value from other supplied values.

    For example, say you wanted to create a default for the user's login from
    the user's first and last names. It could be implemented like this:

    >>> login = DefaultFrom(lambda first, last: first[0] + last)
    >>> login(first='John', last='Doe')
    'JDoe'

    If you do not explicitly provide keys when you create a `DefaultFrom`
    instance, the keys are implicitly derived from your callback by
    inspecting ``callback.func_code.co_varnames``. The keys are available
    through the ``DefaultFrom.keys`` instance attribute, like this:

    >>> login.keys
    ('first', 'last')

    The callback is available through the ``DefaultFrom.callback`` instance
    attribute, like this:

    >>> login.callback  # doctest:+ELLIPSIS
    <function <lambda> at 0x...>
    >>> login.callback.func_code.co_varnames  # The keys
    ('first', 'last')

    The keys can be explicitly provided as optional positional arguments after
    the callback. For example, this is equivalent to the ``login`` instance
    above:

    >>> login2 = DefaultFrom(lambda a, b: a[0] + b, 'first', 'last')
    >>> login2.keys
    ('first', 'last')
    >>> login2.callback.func_code.co_varnames  # Not the keys
    ('a', 'b')
    >>> login2(first='John', last='Doe')
    'JDoe'

    If any keys are missing when calling your `DefaultFrom` instance, your
    callback is not called and ``None`` is returned.  For example:

    >>> login(first='John', lastname='Doe') is None
    True
    >>> login() is None
    True

    Any additional keys are simply ignored, like this:

    >>> login(last='Doe', first='John', middle='Whatever')
    'JDoe'

    As above, because `DefaultFrom.__call__` takes only pure keyword
    arguments, they can be supplied in any order.

    Of course, the callback need not be a ``lambda`` expression. This third
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
            raise TypeError(
                CALLABLE_ERROR % ('callback', callback, type(callback))
            )
        self.callback = callback
        if len(keys) == 0:
            fc = callback.func_code
            self.keys = fc.co_varnames[:fc.co_argcount]
        else:
            self.keys = keys
        for key in self.keys:
            if type(key) is not str:
                raise TypeError(
                    TYPE_ERROR % ('keys', str, key, type(key))
                )
        lock(self)

    def __call__(self, **kw):
        """
        Call the callback if all keys are present.

        If all keys are present, the callback is called and its return value is
        returned.  If any keys are missing, ``None`` is returned.

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
    Parse shorthand ``spec`` into to ``(name, kw)``.

    The ``spec`` string determines the parameter name, whether the parameter is
    required, and whether the parameter is multivalue according the following
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
        raise TypeError(
            TYPE_ERROR % ('spec', str, spec, type(spec))
        )
    if len(spec) < 2:
        raise ValueError(
            'spec must be at least 2 characters; got %r' % spec
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


__messages = set()

def _(message):
    __messages.add(message)
    return message


class Param(ReadOnly):
    """
    Base class for all parameters.
    """

    # This is a dummy type so that most of the functionality of Param can be
    # unit tested directly without always creating a subclass; however, a real
    # (direct) subclass must *always* override this class attribute:
    type = NoneType  # Ouch, this wont be very useful in the real world!

    # Subclasses should override this with something more specific:
    type_error = _('incorrect type')

    kwargs = (
        ('cli_name', str, None),
        ('label', callable, None),
        ('doc', str, ''),
        ('required', bool, True),
        ('multivalue', bool, False),
        ('primary_key', bool, False),
        ('normalizer', callable, None),
        ('default_from', DefaultFrom, None),
        ('create_default', callable, None),
        ('autofill', bool, False),
        ('query', bool, False),
        ('attribute', bool, False),
        ('limit_to', frozenset, None),
        ('flags', frozenset, frozenset()),

        # The 'default' kwarg gets appended in Param.__init__():
        # ('default', self.type, None),
    )

    def __init__(self, name, *rules, **kw):
        # We keep these values to use in __repr__():
        self.param_spec = name
        self.__kw = dict(kw)

        if isinstance(self, Password):
            self.password = True
        else:
            self.password = False

        # Merge in kw from parse_param_spec():
        if not ('required' in kw or 'multivalue' in kw):
            (name, kw_from_spec) = parse_param_spec(name)
            kw.update(kw_from_spec)
        self.name = check_name(name)
        self.nice = '%s(%r)' % (self.__class__.__name__, self.param_spec)

        # Add 'default' to self.kwargs and makes sure no unknown kw were given:
        assert type(self.type) is type
        if kw.get('multivalue', True):
            self.kwargs += (('default', tuple, None),)
        else:
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

        # Check that only default_from or create_default was provided:
        assert not hasattr(self, '_get_default'), self.nice
        if callable(self.default_from):
            if callable(self.create_default):
                raise ValueError(
                    '%s: cannot have both %r and %r' % (
                        self.nice, 'default_from', 'create_default')
                )
            self._get_default = self.default_from
        elif callable(self.create_default):
            self._get_default = self.create_default
        else:
            self._get_default = None

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

    def __repr__(self):
        """
        Return an expresion that could construct this `Param` instance.
        """
        return make_repr(
            self.__class__.__name__,
            self.param_spec,
            **self.__kw
        )

    def __call__(self, value, **kw):
        """
        One stop shopping.
        """
        if value in NULLS:
            value = self.get_default(**kw)
        else:
            value = self.convert(self.normalize(value))
        self.validate(value)
        return value

    def safe_value(self, value):
        """
        Return a value safe for logging.

        This is used so that passwords don't get logged.  If this is a
        `Password` instance and ``value`` is not ``None``, a constant
        ``u'********'`` is returned.  For example:

        >>> p = Password('my_password')
        >>> p.safe_value(u'This is my password')
        u'********'
        >>> p.safe_value(None) is None
        True

        If this is not a `Password` instance, ``value`` is returned unchanged.
        For example:

        >>> s = Str('my_str')
        >>> s.safe_value(u'Some arbitrary value')
        u'Some arbitrary value'
        """
        if self.password and value is not None:
            return u'********'
        return value

    def clone(self, **overrides):
        """
        Return a new `Param` instance similar to this one.
        """
        kw = dict(self.__clonekw)
        kw.update(overrides)
        return self.__class__(self.name, **kw)

    def get_label(self):
        """
        Return translated label using `request.ugettext`.
        """
        if self.label is None:
            return self.cli_name.decode('UTF-8')
        return self.label(ugettext)

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

        All values in `constants.NULLS` will be converted to ``None``.  For
        example:

        >>> scalar.convert(u'') is None  # An empty string
        True
        >>> scalar.convert([]) is None  # An empty list
        True

        Likewise, values in `constants.NULLS` will be filtered out of a
        multivalue parameter.  For example:

        >>> multi = Str('my_multi', multivalue=True)
        >>> multi.convert([1.5, '', 17, None, u'Hello'])
        (u'1.5', u'17', u'Hello')
        >>> multi.convert([None, u'']) is None  # Filters to an empty list
        True

        Lastly, multivalue parameters will always return a ``tuple`` (assuming
        they don't return ``None`` as in the last example above).  For example:

        >>> multi.convert(42)  # Called with a scalar value
        (u'42',)
        >>> multi.convert([0, 1])  # Called with a list value
        (u'0', u'1')

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
                    lambda iv: iv[1] not in NULLS, enumerate(value)
                )
            )
            if len(values) == 0:
                return
            return values
        return self._convert_scalar(value)

    def _convert_scalar(self, value, index=None):
        """
        Convert a single scalar value.
        """
        if type(value) is self.type:
            return value
        raise ConversionError(name=self.name, index=index,
            error=ugettext(self.type_error),
        )

    def validate(self, value):
        """
        Check validity of ``value``.

        :param value: A proposed value for this parameter.
        """
        if value is None:
            if self.required:
                raise RequirementError(name=self.name)
            return
        if self.query:
            return
        if self.multivalue:
            if type(value) is not tuple:
                raise TypeError(
                    TYPE_ERROR % ('value', tuple, value, type(value))
                )
            if len(value) < 1:
                raise ValueError('value: empty tuple must be converted to None')
            for (i, v) in enumerate(value):
                self._validate_scalar(v, i)
        else:
            self._validate_scalar(value)

    def _validate_scalar(self, value, index=None):
        if type(value) is not self.type:
            if index is None:
                name = 'value'
            else:
                name = 'value[%d]' % index
            raise TypeError(
                TYPE_ERROR % (name, self.type, value, type(value))
            )
        if index is not None and type(index) is not int:
            raise TypeError(
                TYPE_ERROR % ('index', int, index, type(index))
            )
        for rule in self.all_rules:
            error = rule(ugettext, value)
            if error is not None:
                raise ValidationError(
                    name=self.name,
                    value=value,
                    index=index,
                    error=error,
                    rule=rule,
                )

    def get_default(self, **kw):
        """
        Return the static default or construct and return a dynamic default.

        (In these examples, we will use the `Str` and `Bytes` classes, which
        both subclass from `Param`.)

        The *default* static default is ``None``.  For example:

        >>> s = Str('my_str')
        >>> s.default is None
        True
        >>> s.get_default() is None
        True

        However, you can provide your own static default via the ``default``
        keyword argument when you create your `Param` instance.  For example:

        >>> s = Str('my_str', default=u'My Static Default')
        >>> s.default
        u'My Static Default'
        >>> s.get_default()
        u'My Static Default'

        If you need to generate a dynamic default from other supplied parameter
        values, provide a callback via the ``default_from`` keyword argument.
        This callback will be automatically wrapped in a `DefaultFrom` instance
        if it isn't one already (see the `DefaultFrom` class for all the gory
        details).  For example:

        >>> login = Str('login', default=u'my-static-login-default',
        ...     default_from=lambda first, last: (first[0] + last).lower(),
        ... )
        >>> isinstance(login.default_from, DefaultFrom)
        True
        >>> login.default_from.keys
        ('first', 'last')

        Then when all the keys needed by the `DefaultFrom` instance are present,
        the dynamic default is constructed and returned.  For example:

        >>> kw = dict(last=u'Doe', first=u'John')
        >>> login.get_default(**kw)
        u'jdoe'

        Or if any keys are missing, your *static* default is returned.
        For example:

        >>> kw = dict(first=u'John', department=u'Engineering')
        >>> login.get_default(**kw)
        u'my-static-login-default'

        The second, less common way to construct a dynamic default is to provide
        a callback via the ``create_default`` keyword argument.  Unlike a
        ``default_from`` callback, your ``create_default`` callback will not get
        wrapped in any dispatcher.  Instead, it will be called directly, which
        means your callback must accept arbitrary keyword arguments, although
        whether your callback utilises these values is up to your
        implementation.  For example:

        >>> def make_csr(**kw):
        ...     print '  make_csr(%r)' % (kw,)  # Note output below
        ...     return 'Certificate Signing Request'
        ...
        >>> csr = Bytes('csr', create_default=make_csr)

        Your ``create_default`` callback will be called with whatever keyword
        arguments are passed to `Param.get_default()`.  For example:

        >>> kw = dict(arbitrary='Keyword', arguments='Here')
        >>> csr.get_default(**kw)
          make_csr({'arguments': 'Here', 'arbitrary': 'Keyword'})
        'Certificate Signing Request'

        And your ``create_default`` callback is called even if
        `Param.get_default()` is called with *zero* keyword arguments.
        For example:

        >>> csr.get_default()
          make_csr({})
        'Certificate Signing Request'

        The ``create_default`` callback will most likely be used as a
        pre-execute hook to perform some special client-side operation.  For
        example, the ``csr`` parameter above might make a call to
        ``/usr/bin/openssl``.  However, often a ``create_default`` callback
        could also be implemented as a ``default_from`` callback.  When this is
        the case, a ``default_from`` callback should be used as they are more
        structured and therefore less error-prone.

        The ``default_from`` and ``create_default`` keyword arguments are
        mutually exclusive.  If you provide both, a ``ValueError`` will be
        raised.  For example:

        >>> homedir = Str('home',
        ...     default_from=lambda login: '/home/%s' % login,
        ...     create_default=lambda **kw: '/lets/use/this',
        ... )
        Traceback (most recent call last):
          ...
        ValueError: Str('home'): cannot have both 'default_from' and 'create_default'
        """
        if self._get_default is not None:
            default = self._get_default(**kw)
            if default is not None:
                try:
                    return self.convert(self.normalize(default))
                except StandardError:
                    pass
        return self.default


class Bool(Param):
    """
    A parameter for boolean values (stored in the ``bool`` type).
    """

    type = bool
    type_error = _('must be True or False')


class Flag(Bool):
    """
    A boolean parameter that always gets filled in with a default value.

    This `Bool` subclass forces ``autofill=True`` in `Flag.__init__()`.  If no
    default is provided, it also fills in a default value of ``False``.
    Lastly, unlike the `Bool` class, the default must be either ``True`` or
    ``False`` and cannot be ``None``.

    For example:

    >>> flag = Flag('my_flag')
    >>> (flag.autofill, flag.default)
    (True, False)

    To have a default value of ``True``, create your `Flag` intance with
    ``default=True``.  For example:

    >>> flag = Flag('my_flag', default=True)
    >>> (flag.autofill, flag.default)
    (True, True)

    Also note that creating a `Flag` instance with ``autofill=False`` will have
    no effect.  For example:

    >>> flag = Flag('my_flag', autofill=False)
    >>> flag.autofill
    True
    """

    def __init__(self, name, *rules, **kw):
        kw['autofill'] = True
        if 'default' not in kw:
            kw['default'] = False
        if type(kw['default']) is not bool:
            default = kw['default']
            raise TypeError(
                TYPE_ERROR % ('default', bool, default, type(default))
            )
        super(Flag, self).__init__(name, *rules, **kw)


class Number(Param):
    """
    Base class for the `Int` and `Float` parameters.
    """

    def _convert_scalar(self, value, index=None):
        """
        Convert a single scalar value.
        """
        if type(value) is self.type:
            return value
        if type(value) in (unicode, int, float):
            try:
                return self.type(value)
            except ValueError:
                pass
        raise ConversionError(name=self.name, index=index,
            error=ugettext(self.type_error),
        )


class Int(Number):
    """
    A parameter for integer values (stored in the ``int`` type).
    """

    type = int
    type_error = _('must be an integer')

    kwargs = Param.kwargs + (
        ('minvalue', int, None),
        ('maxvalue', int, None),
    )

    def __init__(self, name, *rules, **kw):
        super(Number, self).__init__(name, *rules, **kw)

        if (self.minvalue > self.maxvalue) and (self.minvalue is not None and self.maxvalue is not None):
            raise ValueError(
                '%s: minvalue > maxvalue (minvalue=%r, maxvalue=%r)' % (
                    self.nice, self.minvalue, self.maxvalue)
            )

    def _rule_minvalue(self, _, value):
        """
        Check min constraint.
        """
        assert type(value) is int
        if value < self.minvalue:
            return _('must be at least %(minvalue)d') % dict(
                minvalue=self.minvalue,
            )

    def _rule_maxvalue(self, _, value):
        """
        Check max constraint.
        """
        assert type(value) is int
        if value > self.maxvalue:
            return _('can be at most %(maxvalue)d') % dict(
                maxvalue=self.maxvalue,
            )

class Float(Number):
    """
    A parameter for floating-point values (stored in the ``float`` type).
    """

    type = float
    type_error = _('must be a decimal number')

    kwargs = Param.kwargs + (
        ('minvalue', float, None),
        ('maxvalue', float, None),
    )

    def __init__(self, name, *rules, **kw):
        super(Number, self).__init__(name, *rules, **kw)

        if (self.minvalue > self.maxvalue) and (self.minvalue is not None and self.maxvalue is not None):
            raise ValueError(
                '%s: minvalue > maxvalue (minvalue=%r, maxvalue=%r)' % (
                    self.nice, self.minvalue, self.maxvalue)
            )

    def _rule_minvalue(self, _, value):
        """
        Check min constraint.
        """
        assert type(value) is float
        if value < self.minvalue:
            return _('must be at least %(minvalue)f') % dict(
                minvalue=self.minvalue,
            )

    def _rule_maxvalue(self, _, value):
        """
        Check max constraint.
        """
        assert type(value) is float
        if value > self.maxvalue:
            return _('can be at most %(maxvalue)f') % dict(
                maxvalue=self.maxvalue,
            )


class Data(Param):
    """
    Base class for the `Bytes` and `Str` parameters.

    Previously `Str` was as subclass of `Bytes`.  Now the common functionality
    has been split into this base class so that ``isinstance(foo, Bytes)`` wont
    be ``True`` when ``foo`` is actually an `Str` instance (which is confusing).
    """

    kwargs = Param.kwargs + (
        ('minlength', int, None),
        ('maxlength', int, None),
        ('length', int, None),
        ('pattern', (basestring,), None),
    )

    def __init__(self, name, *rules, **kw):
        super(Data, self).__init__(name, *rules, **kw)

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

    def _rule_pattern(self, _, value):
        """
        Check pattern (regex) contraint.
        """
        assert type(value) is self.type
        if self.re.match(value) is None:
            return _('must match pattern "%(pattern)s"') % dict(
                pattern=self.pattern,
            )


class Bytes(Data):
    """
    A parameter for binary data (stored in the ``str`` type).

    This class is named *Bytes* instead of *Str* so it's aligned with the
    Python v3 ``(str, unicode) => (bytes, str)`` clean-up.  See:

        http://docs.python.org/3.0/whatsnew/3.0.html

    Also see the `Str` parameter.
    """

    type = str
    type_error = _('must be binary data')

    def __init__(self, name, *rules, **kw):
        if kw.get('pattern', None) is None:
            self.re = None
        else:
            self.re = re.compile(kw['pattern'])
        super(Bytes, self).__init__(name, *rules, **kw)

    def _rule_minlength(self, _, value):
        """
        Check minlength constraint.
        """
        assert type(value) is str
        if len(value) < self.minlength:
            return _('must be at least %(minlength)d bytes') % dict(
                minlength=self.minlength,
            )

    def _rule_maxlength(self, _, value):
        """
        Check maxlength constraint.
        """
        assert type(value) is str
        if len(value) > self.maxlength:
            return _('can be at most %(maxlength)d bytes') % dict(
                maxlength=self.maxlength,
            )

    def _rule_length(self, _, value):
        """
        Check length constraint.
        """
        assert type(value) is str
        if len(value) != self.length:
            return _('must be exactly %(length)d bytes') % dict(
                length=self.length,
            )


class Str(Data):
    """
    A parameter for Unicode text (stored in the ``unicode`` type).

    This class is named *Str* instead of *Unicode* so it's aligned with the
    Python v3 ``(str, unicode) => (bytes, str)`` clean-up.  See:

        http://docs.python.org/3.0/whatsnew/3.0.html

    Also see the `Bytes` parameter.
    """

    type = unicode
    type_error = _('must be Unicode text')

    def __init__(self, name, *rules, **kw):
        if kw.get('pattern', None) is None:
            self.re = None
        else:
            self.re = re.compile(kw['pattern'], re.UNICODE)
        super(Str, self).__init__(name, *rules, **kw)

    def _convert_scalar(self, value, index=None):
        """
        Convert a single scalar value.
        """
        if type(value) is self.type:
            return value
        if type(value) in (int, float):
            return self.type(value)
        raise ConversionError(name=self.name, index=index,
            error=ugettext(self.type_error),
        )

    def _rule_minlength(self, _, value):
        """
        Check minlength constraint.
        """
        assert type(value) is unicode
        if len(value) < self.minlength:
            return _('must be at least %(minlength)d characters') % dict(
                minlength=self.minlength,
            )

    def _rule_maxlength(self, _, value):
        """
        Check maxlength constraint.
        """
        assert type(value) is unicode
        if len(value) > self.maxlength:
            return _('can be at most %(maxlength)d characters') % dict(
                maxlength=self.maxlength,
            )

    def _rule_length(self, _, value):
        """
        Check length constraint.
        """
        assert type(value) is unicode
        if len(value) != self.length:
            return _('must be exactly %(length)d characters') % dict(
                length=self.length,
            )


class Password(Str):
    """
    A parameter for passwords (stored in the ``unicode`` type).
    """


class Enum(Param):
    """
    Base class for parameters with enumerable values.
    """

    kwargs = Param.kwargs + (
        ('values', tuple, tuple()),
    )

    def __init__(self, name, *rules, **kw):
        super(Enum, self).__init__(name, *rules, **kw)
        for (i, v) in enumerate(self.values):
            if type(v) is not self.type:
                n = '%s values[%d]' % (self.nice, i)
                raise TypeError(
                    TYPE_ERROR % (n, self.type, v, type(v))
                )

    def _rule_values(self, _, value, **kw):
        if value not in self.values:
            return _('must be one of %(values)r') % dict(
                values=self.values,
            )


class BytesEnum(Enum):
    """
    Enumerable for binary data (stored in the ``str`` type).
    """

    type = unicode


class StrEnum(Enum):
    """
    Enumerable for Unicode text (stored in the ``unicode`` type).

    For example:

    >>> enum = StrEnum('my_enum', values=(u'One', u'Two', u'Three'))
    >>> enum.validate(u'Two') is None
    True
    >>> enum.validate(u'Four')
    Traceback (most recent call last):
      ...
    ValidationError: invalid 'my_enum': must be one of (u'One', u'Two', u'Three')
    """

    type = unicode


def create_param(spec):
    """
    Create an `Str` instance from the shorthand ``spec``.

    This function allows you to create `Str` parameters (the most common) from
    a convenient shorthand that defines the parameter name, whether it is
    required, and whether it is multivalue.  (For the definition of the
    shorthand syntax, see the `parse_param_spec()` function.)

    If ``spec`` is an ``str`` instance, it will be used to create a new `Str`
    parameter, which will be returned.  For example:

    >>> s = create_param('hometown?')
    >>> s
    Str('hometown?')
    >>> (s.name, s.required, s.multivalue)
    ('hometown', False, False)

    On the other hand, if ``spec`` is already a `Param` instance, it is
    returned unchanged.  For example:

    >>> b = Bytes('cert')
    >>> create_param(b) is b
    True

    As a plugin author, you will not call this function directly (which would
    be no more convenient than simply creating the `Str` instance).  Instead,
    `frontend.Command` will call it for you when it evaluates the
    ``takes_args`` and ``takes_options`` attributes, and `frontend.Object`
    will call it for you when it evaluates the ``takes_params`` attribute.

    :param spec: A spec string or a `Param` instance.
    """
    if isinstance(spec, Param):
        return spec
    if type(spec) is not str:
        raise TypeError(
            TYPE_ERROR % ('spec', (str, Param), spec, type(spec))
        )
    return Str(spec)
