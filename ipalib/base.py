# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
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
Foundational classes and functions.
"""

import re

import six

from ipalib.constants import NAME_REGEX, NAME_ERROR
from ipalib.constants import TYPE_ERROR, SET_ERROR, DEL_ERROR, OVERRIDE_ERROR


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

    >>> p.__islocked__()  # Is this instance locked?
    False
    >>> p.__lock__()  # This will lock the instance
    >>> p.__islocked__()
    True
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
    techniques *accidentally*.

    Lastly, this example aside, you should use the `lock()` function rather
    than the `ReadOnly.__lock__()` method.  And likewise, you should
    use the `islocked()` function rather than the `ReadOnly.__islocked__()`
    method.  For example:

    >>> readonly = ReadOnly()
    >>> islocked(readonly)
    False
    >>> lock(readonly) is readonly  # lock() returns the instance
    True
    >>> islocked(readonly)
    True
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


def lock(instance):
    """
    Lock an instance of the `ReadOnly` class or similar.

    This function can be used to lock instances of any class that implements
    the same locking API as the `ReadOnly` class.  For example, this function
    can lock instances of the `config.Env` class.

    So that this function can be easily used within an assignment, ``instance``
    is returned after it is locked.  For example:

    >>> readonly = ReadOnly()
    >>> readonly is lock(readonly)
    True
    >>> readonly.attr = 'This wont work'
    Traceback (most recent call last):
      ...
    AttributeError: locked: cannot set ReadOnly.attr to 'This wont work'

    Also see the `islocked()` function.

    :param instance: The instance of `ReadOnly` (or similar) to lock.
    """
    assert instance.__islocked__() is False, 'already locked: %r' % instance
    instance.__lock__()
    assert instance.__islocked__() is True, 'failed to lock: %r' % instance
    return instance


def islocked(instance):
    """
    Return ``True`` if ``instance`` is locked.

    This function can be used on an instance of the `ReadOnly` class or an
    instance of any other class implemented the same locking API.

    For example:

    >>> readonly = ReadOnly()
    >>> islocked(readonly)
    False
    >>> readonly.__lock__()
    >>> islocked(readonly)
    True

    Also see the `lock()` function.

    :param instance: The instance of `ReadOnly` (or similar) to interrogate.
    """
    assert (
        hasattr(instance, '__lock__') and callable(instance.__lock__)
    ), 'no __lock__() method: %r' % instance
    return instance.__islocked__()


def check_name(name):
    """
    Verify that ``name`` is suitable for a `NameSpace` member name.

    In short, ``name`` must be a valid lower-case Python identifier that
    neither starts nor ends with an underscore.  Otherwise an exception is
    raised.

    This function will raise a ``ValueError`` if ``name`` does not match the
    `constants.NAME_REGEX` regular expression.  For example:

    >>> check_name('MyName')
    Traceback (most recent call last):
      ...
    ValueError: name must match '^[a-z][_a-z0-9]*[a-z0-9]$|^[a-z]$'; got 'MyName'

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


class NameSpace(ReadOnly):
    """
    A read-only name-space with handy container behaviours.

    A `NameSpace` instance is an ordered, immutable mapping object whose values
    can also be accessed as attributes.  A `NameSpace` instance is constructed
    from an iterable providing its *members*, which are simply arbitrary objects
    with a ``name`` attribute whose value:

        1. Is unique among the members

        2. Passes the `check_name()` function

    Beyond that, no restrictions are placed on the members: they can be
    classes or instances, and of any type.

    The members can be accessed as attributes on the `NameSpace` instance or
    through a dictionary interface.  For example, say we create a `NameSpace`
    instance from a list containing a single member, like this:

    >>> class my_member(object):
    ...     name = 'my_name'
    ...
    >>> namespace = NameSpace([my_member])
    >>> namespace
    NameSpace(<1 member>, sort=True)

    We can then access ``my_member`` both as an attribute and as a dictionary
    item:

    >>> my_member is namespace.my_name  # As an attribute
    True
    >>> my_member is namespace['my_name']  # As dictionary item
    True

    For a more detailed example, say we create a `NameSpace` instance from a
    generator like this:

    >>> class Member(object):
    ...     def __init__(self, i):
    ...         self.i = i
    ...         self.name = self.__name__ = 'member%d' % i
    ...     def __repr__(self):
    ...         return 'Member(%d)' % self.i
    ...
    >>> ns = NameSpace(Member(i) for i in range(3))
    >>> ns
    NameSpace(<3 members>, sort=True)

    As above, the members can be accessed as attributes and as dictionary items:

    >>> ns.member0 is ns['member0']
    True
    >>> ns.member1 is ns['member1']
    True
    >>> ns.member2 is ns['member2']
    True

    Members can also be accessed by index and by slice.  For example:

    >>> ns[0]
    Member(0)
    >>> ns[-1]
    Member(2)
    >>> ns[1:]
    (Member(1), Member(2))

    (Note that slicing a `NameSpace` returns a ``tuple``.)

    `NameSpace` instances provide standard container emulation for membership
    testing, counting, and iteration.  For example:

    >>> 'member3' in ns  # Is there a member named 'member3'?
    False
    >>> 'member2' in ns  # But there is a member named 'member2'
    True
    >>> len(ns)  # The number of members
    3
    >>> list(ns)  # Iterate through the member names
    ['member0', 'member1', 'member2']

    Although not a standard container feature, the `NameSpace.__call__()` method
    provides a convenient (and efficient) way to iterate through the *members*
    (as opposed to the member names).  Think of it like an ordered version of
    the ``dict.itervalues()`` method.  For example:

    >>> list(ns[name] for name in ns)  # One way to do it
    [Member(0), Member(1), Member(2)]
    >>> list(ns())  # A more efficient, simpler way to do it
    [Member(0), Member(1), Member(2)]

    Another convenience method is `NameSpace.__todict__()`, which will return
    a copy of the ``dict`` mapping the member names to the members.
    For example:

    >>> ns.__todict__()
    {'member1': Member(1), 'member0': Member(0), 'member2': Member(2)}

    As `NameSpace.__init__()` locks the instance, `NameSpace` instances are
    read-only from the get-go.  An ``AttributeError`` is raised if you try to
    set *any* attribute on a `NameSpace` instance.  For example:

    >>> ns.member3 = Member(3)  # Lets add that missing 'member3'
    Traceback (most recent call last):
        ...
    AttributeError: locked: cannot set NameSpace.member3 to Member(3)

    (For information on the locking protocol, see the `ReadOnly` class, of which
    `NameSpace` is a subclass.)

    By default the members will be sorted alphabetically by the member name.
    For example:

    >>> sorted_ns = NameSpace([Member(7), Member(3), Member(5)])
    >>> sorted_ns
    NameSpace(<3 members>, sort=True)
    >>> list(sorted_ns)
    ['member3', 'member5', 'member7']
    >>> sorted_ns[0]
    Member(3)

    But if the instance is created with the ``sort=False`` keyword argument, the
    original order of the members is preserved.  For example:

    >>> unsorted_ns = NameSpace([Member(7), Member(3), Member(5)], sort=False)
    >>> unsorted_ns
    NameSpace(<3 members>, sort=False)
    >>> list(unsorted_ns)
    ['member7', 'member3', 'member5']
    >>> unsorted_ns[0]
    Member(7)

    As a special extension, NameSpace objects can be indexed by objects that
    have a "__name__" attribute (e.g. classes). These lookups are converted
    to lookups on the name:

    >>> class_ns = NameSpace([Member(7), Member(3), Member(5)], sort=False)
    >>> unsorted_ns[Member(3)]
    Member(3)

    The `NameSpace` class is used in many places throughout freeIPA.  For a few
    examples, see the `plugable.API` and the `frontend.Command` classes.
    """

    def __init__(self, members, sort=True, name_attr='name'):
        """
        :param members: An iterable providing the members.
        :param sort: Whether to sort the members by member name.
        """
        if type(sort) is not bool:
            raise TypeError(
                TYPE_ERROR % ('sort', bool, sort, type(sort))
            )
        self.__sort = sort
        if sort:
            self.__members = tuple(
                sorted(members, key=lambda m: getattr(m, name_attr))
            )
        else:
            self.__members = tuple(members)
        self.__names = tuple(getattr(m, name_attr) for m in self.__members)
        self.__map = dict()
        for member in self.__members:
            name = check_name(getattr(member,  name_attr))
            if name in self.__map:
                raise AttributeError(OVERRIDE_ERROR %
                    (self.__class__.__name__, name, self.__map[name], member)
                )
            assert not hasattr(self, name), 'Ouch! Has attribute %r' % name
            self.__map[name] = member
            setattr(self, name, member)
        lock(self)

    def __len__(self):
        """
        Return the number of members.
        """
        return len(self.__members)

    def __iter__(self):
        """
        Iterate through the member names.

        If this instance was created with ``sort=False``, the names will be in
        the same order as the members were passed to the constructor; otherwise
        the names will be in alphabetical order (which is the default).

        This method is like an ordered version of ``dict.iterkeys()``.
        """
        for name in self.__names:
            yield name

    def __call__(self):
        """
        Iterate through the members.

        If this instance was created with ``sort=False``, the members will be
        in the same order as they were passed to the constructor; otherwise the
        members will be in alphabetical order by name (which is the default).

        This method is like an ordered version of ``dict.itervalues()``.
        """
        for member in self.__members:
            yield member

    def __contains__(self, name):
        """
        Return ``True`` if namespace has a member named ``name``.
        """
        name = getattr(name, '__name__', name)
        return name in self.__map

    def __getitem__(self, key):
        """
        Return a member by name or index, or return a slice of members.

        :param key: The name or index of a member, or a slice object.
        """
        key = getattr(key, '__name__',  key)
        if isinstance(key, six.string_types):
            return self.__map[key]
        if type(key) in (int, slice):
            return self.__members[key]
        raise TypeError(
            TYPE_ERROR % ('key', (str, int, slice, 'object with __name__'),
                          key, type(key))
        )

    def __repr__(self):
        """
        Return a pseudo-valid expression that could create this instance.
        """
        cnt = len(self)
        if cnt == 1:
            m = 'member'
        else:
            m = 'members'
        return '%s(<%d %s>, sort=%r)' % (
            self.__class__.__name__,
            cnt,
            m,
            self.__sort,
        )

    def __todict__(self):
        """
        Return a copy of the private dict mapping member name to member.
        """
        return dict(self.__map)
