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

    def __init__(self, name, kwargs, **overrides):
        self.param_spec = name
        self.name = check_name(name)
        kwargs = dict(kwargs)
        assert set(self.__kwargs).intersection(kwargs) == set()
        kwargs.update(self.__kwargs)
        for (key, (kind, default)) in kwargs.iteritems():
            value = overrides.get(key, default)
            if value is None:
                if kind is bool:
                    raise TypeError(
                        TYPE_ERROR % (key, bool, value, type(value))
                    )
            else:
                if (
                    type(kind) is type and type(value) is not kind or
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
        lock(self)

    def normalize(self, value):
        """
        """
        if self.__normalize is None:
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
            return self.__normalize(value)
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
