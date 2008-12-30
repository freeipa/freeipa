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
Low-level functions and abstract base classes.
"""

import re
from constants import NAME_REGEX, NAME_ERROR
from constants import TYPE_ERROR, SET_ERROR, DEL_ERROR


class ReadOnly(object):
    """
    Base class for classes that can be locked into a read-only state.

    Be forewarned that Python does not offer true read-only attributes for
    user-defined classes.  Do *not* rely upon the read-only-ness of this
    class for security purposes!

    The point of this class is not to make it impossible to set or to delete
    attributes after an instance is locked, but to make it impossible to do so
    *accidentally*.  Rather than constantly reminding our programmers of things
    like, for example, "Don't set any attributes on this ``FooBar`` instance
    because doing so wont be thread-safe", this class offers a real way to
    enforce read-only attribute usage.

    For example, before a `ReadOnly` instance is locked, you can set and delete
    its attributes as normal:

    >>> class Person(ReadOnly):
    ...     pass
    ...
    >>> p = Person()
    >>> p.name = 'John Doe'
    >>> p.phone = '123-456-7890'
    >>> del p.phone

    But after an instance is locked, you cannot set its attributes:

    >>> p.__lock__()  # This will lock the instance
    >>> p.department = 'Engineering'
    Traceback (most recent call last):
      ...
    AttributeError: locked: cannot set Person.department to 'Engineering'

    Nor can you deleted its attributes:

    >>> del p.name
    Traceback (most recent call last):
      ...
    AttributeError: locked: cannot delete Person.name

    However, as noted at the start, there are still obscure ways in which
    attributes can be set or deleted on a locked `ReadOnly` instance.  For
    example:

    >>> object.__setattr__(p, 'department', 'Engineering')
    >>> p.department
    'Engineering'
    >>> object.__delattr__(p, 'name')
    >>> hasattr(p, 'name')
    False

    But again, the point is that a programmer would never employ the above
    techniques accidentally.
    """

    __locked = False

    def __lock__(self):
        """
        Put this instance into a read-only state.

        After the instance has been locked, attempting to set or delete an
        attribute will raise an AttributeError.
        """
        assert self.__locked is False, '__lock__() can only be called once'
        self.__locked = True

    def __islocked__(self):
        """
        Return True if instance is locked, otherwise False.
        """
        return self.__locked

    def __setattr__(self, name, value):
        """
        If unlocked, set attribute named ``name`` to ``value``.

        If this instance is locked, an AttributeError will be raised.

        :param name: Name of attribute to set.
        :param value: Value to assign to attribute.
        """
        if self.__locked:
            raise AttributeError(
                SET_ERROR % (self.__class__.__name__, name, value)
            )
        return object.__setattr__(self, name, value)

    def __delattr__(self, name):
        """
        If unlocked, delete attribute named ``name``.

        If this instance is locked, an AttributeError will be raised.

        :param name: Name of attribute to delete.
        """
        if self.__locked:
            raise AttributeError(
                DEL_ERROR % (self.__class__.__name__, name)
            )
        return object.__delattr__(self, name)


def check_name(name):
    """
    Verify that ``name`` is suitable for a `NameSpace` member name.

    This function will raise a ``ValueError`` if ``name`` does not match the
    `constants.NAME_REGEX` regular expression.  For example:

    >>> check_name('MyName')
    Traceback (most recent call last):
      ...
    ValueError: name must match '^[a-z][_a-z0-9]*[a-z0-9]$'; got 'MyName'

    Also, this function will raise a ``TypeError`` if ``name`` is not an
    ``str`` instance.  For example:

    >>> check_name(u'my_name')
    Traceback (most recent call last):
      ...
    TypeError: name: need a <type 'str'>; got u'my_name' (a <type 'unicode'>)

    So that `check_name()` can be easily used within an assignment, ``name``
    is returned unchanged if it passes the check.  For example:

    >>> n = check_name('my_name')
    >>> n
    'my_name'

    :param name: Identifier to test.
    """
    if type(name) is not str:
        raise TypeError(
            TYPE_ERROR % ('name', str, name, type(name))
        )
    if re.match(NAME_REGEX, name) is None:
        raise ValueError(
            NAME_ERROR % (NAME_REGEX, name)
        )
    return name
