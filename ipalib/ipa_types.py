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
Type system for coercing and normalizing input values.
"""

import re
from plugable import ReadOnly, lock
import errors


def check_min_max(min_value, max_value, min_name, max_name):
    assert type(min_name) is str, 'min_name must be an str'
    assert type(max_name) is str, 'max_name must be an str'
    for (name, value) in [(min_name, min_value), (max_name, max_value)]:
        if not (value is None or type(value) is int):
            raise TypeError(
                '%s must be an int or None, got: %r' % (name, value)
            )
    if None not in (min_value, max_value) and min_value > max_value:
        d = dict(
            k0=min_name,
            v0=min_value,
            k1=max_name,
            v1=max_value,
        )
        raise ValueError(
            '%(k0)s > %(k1)s: %(k0)s=%(v0)r, %(k1)s=%(v1)r' % d
        )


class Type(ReadOnly):
    """
    Base class for all IPA types.
    """

    type = None # Override in base class

    def convert(self, value):
		return self.type(value)

    def __get_name(self):
        """
        Convenience property to return the class name.
        """
        return self.__class__.__name__
    name = property(__get_name)


class Int(Type):
    type = int

    def __init__(self, min_value=None, max_value=None):
        check_min_max(min_value, max_value, 'min_value', 'max_value')
        self.min_value = min_value
        self.max_value = max_value
        lock(self)

    def validate(self, value):
        if type(value) is not self.type:
            return 'Must be an integer'
        if self.min_value is not None and value < self.min_value:
            return 'Cannot be smaller than %d' % self.min_value
        if self.max_value is not None and value > self.max_value:
            return 'Cannot be larger than %d' % self.max_value


class Unicode(Type):
    type = unicode

    def __init__(self, min_length=None, max_length=None, pattern=None):
        check_min_max(min_length, max_length, 'min_length', 'max_length')
        if min_length is not None and min_length < 0:
            raise ValueError('min_length must be >= 0, got: %r' % min_length)
        if max_length is not None and max_length < 1:
            raise ValueError('max_length must be >= 1, got: %r' % max_length)
        if not (pattern is None or isinstance(pattern, basestring)):
            raise TypeError(
                'pattern must be a basestring or None, got: %r' % pattern
            )
        self.min_length = min_length
        self.max_length = max_length
        self.pattern = pattern
        if pattern is None:
            self.regex = None
        else:
            self.regex = re.compile(pattern)
        lock(self)

    def validate(self, value):
        if type(value) is not self.type:
            return 'Must be a string'

        if self.regex and self.regex.match(value) is None:
            return 'Must match %r' % self.pattern

        if self.min_length is not None and len(value) < self.min_length:
            return 'Must be at least %d characters long' % self.min_length

        if self.max_length is not None and len(value) > self.max_length:
            return 'Can be at most %d characters long' % self.max_length
