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
Plugin framework.

The classes in this module make heavy use of Python container emulation. If
you are unfamiliar with this Python feature, see
http://docs.python.org/ref/sequence-types.html
"""

import re
import inspect
import errors
from errors import check_type, check_isinstance


class ReadOnly(object):
    """
    Base class for classes with read-only attributes.

    Be forewarned that Python does not offer true read-only user defined
    classes. In particular, do not rely upon the read-only-ness of this
    class for security purposes.

    The point of this class is not to make it impossible to set or delete
    attributes, but to make it impossible to accidentally do so. The plugins
    are not thread-safe: in the server, they are loaded once and the same
    instances will be used to process many requests. Therefore, it is
    imperative that they not set any instance attributes after they have
    been initialized. This base class enforces that policy.

    For example:

    >>> ro = ReadOnly() # Initially unlocked, can setattr, delattr
    >>> ro.name = 'John Doe'
    >>> ro.message = 'Hello, world!'
    >>> del ro.message
    >>> ro.__lock__() # Now locked, cannot setattr, delattr
    >>> ro.message = 'How are you?'
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "/home/jderose/projects/freeipa2/ipalib/plugable.py", line 93, in __setattr__
        (self.__class__.__name__, name)
    AttributeError: read-only: cannot set ReadOnly.message
    >>> del ro.name
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "/home/jderose/projects/freeipa2/ipalib/plugable.py", line 104, in __delattr__
        (self.__class__.__name__, name)
    AttributeError: read-only: cannot del ReadOnly.name
    """

    __locked = False

    def __lock__(self):
        """
        Put this instance into a read-only state.

        After the instance has been locked, attempting to set or delete an
        attribute will raise AttributeError.
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

        If this instance is locked, AttributeError will be raised.
        """
        if self.__locked:
            raise AttributeError('read-only: cannot set %s.%s' %
                (self.__class__.__name__, name)
            )
        return object.__setattr__(self, name, value)

    def __delattr__(self, name):
        """
        If unlocked, delete attribute named ``name``.

        If this instance is locked, AttributeError will be raised.
        """
        if self.__locked:
            raise AttributeError('read-only: cannot del %s.%s' %
                (self.__class__.__name__, name)
            )
        return object.__delattr__(self, name)


def lock(readonly):
    """
    Locks a `ReadOnly` instance.

    This is mostly a convenience function to call `ReadOnly.__lock__()`. It
    also verifies that the locking worked using `ReadOnly.__islocked__()`

    :param readonly: An instance of the `ReadOnly` class.
    """
    if not isinstance(readonly, ReadOnly):
        raise ValueError('not a ReadOnly instance: %r' % readonly)
    readonly.__lock__()
    assert readonly.__islocked__(), 'Ouch! The locking failed?'
    return readonly


class SetProxy(ReadOnly):
    """
    A read-only container with set/sequence behaviour.

    This container acts as a proxy to an actual set-like object (a set,
    frozenset, or dict) that is passed to the constructor. To the extent
    possible in Python, this underlying set-like object cannot be modified
    through the SetProxy... which just means you wont do it accidentally.
    """
    def __init__(self, s):
        """
        :param s: The target set-like object (a set, frozenset, or dict)
        """
        allowed = (set, frozenset, dict)
        if type(s) not in allowed:
            raise TypeError('%r not in %r' % (type(s), allowed))
        self.__s = s
        lock(self)

    def __len__(self):
        """
        Returns the number of items in this container.
        """
        return len(self.__s)

    def __iter__(self):
        """
        Iterates (in ascending order) through the items (or keys) in this
        container.
        """
        for key in sorted(self.__s):
            yield key

    def __contains__(self, key):
        """
        Returns True if this container contains ``key``, False otherwise.

        :param key: The item (or key) to test for membership.
        """
        return key in self.__s


class DictProxy(SetProxy):
    """
    A read-only container with mapping behaviour.

    This container acts as a proxy to an actual mapping object (a dict) that
    is passed to the constructor. To the extent possible in Python, this
    underlying mapping object cannot be modified through the DictProxy...
    which just means you wont do it accidentally.

    Also see `SetProxy`.
    """
    def __init__(self, d):
        """
        :param d: The target mapping object (a dict)
        """
        if type(d) is not dict:
            raise TypeError('%r is not %r' % (type(d), dict))
        self.__d = d
        super(DictProxy, self).__init__(d)

    def __getitem__(self, key):
        """
        Returns the value corresponding to ``key``.

        :param key: The key of the value you wish to retrieve.
        """
        return self.__d[key]

    def __call__(self):
        """
        Iterates (in ascending order by key) through the values in this
        container.
        """
        for key in self:
            yield self.__d[key]


class MagicDict(DictProxy):
    """
    A read-only mapping container whose values can also be accessed as
    attributes.

    For example, assuming ``magic`` is a MagicDict instance that contains the
    key ``name``, you could do this:

    >>> magic[name] is getattr(magic, name)
    True

    This container acts as a proxy to an actual mapping object (a dict) that
    is passed to the constructor. To the extent possible in Python, this
    underlying mapping object cannot be modified through the MagicDict...
    which just means you wont do it accidentally.

    Also see `DictProxy` and `SetProxy`.
    """

    def __getattr__(self, name):
        """
        Returns the value corresponding to ``name``.

        :param name: The name of the attribute you wish to retrieve.
        """
        try:
            return self[name]
        except KeyError:
            raise AttributeError('no magic attribute %r' % name)


class Plugin(ReadOnly):
    """
    Base class for all plugins.
    """
    __public__ = frozenset()
    __proxy__ = True
    __api = None

    def __get_name(self):
        """
        Convenience property to return the class name.
        """
        return self.__class__.__name__
    name = property(__get_name)

    def __get_doc(self):
        """
        Convenience property to return the class docstring.
        """
        return self.__class__.__doc__
    doc = property(__get_doc)

    def __get_api(self):
        """
        Returns the `API` instance passed to `finalize()`, or
        or returns None if `finalize()` has not yet been called.
        """
        return self.__api
    api = property(__get_api)

    @classmethod
    def implements(cls, arg):
        """
        Returns True if this cls.__public__ frozenset contains `arg`;
        returns False otherwise.

        There are three different ways this can be called:

        With a <type 'str'> argument, e.g.:

        >>> class base(ProxyTarget):
        >>>     __public__ = frozenset(['some_attr', 'another_attr'])
        >>> base.implements('some_attr')
        True
        >>> base.implements('an_unknown_attribute')
        False

        With a <type 'frozenset'> argument, e.g.:

        >>> base.implements(frozenset(['some_attr']))
        True
        >>> base.implements(frozenset(['some_attr', 'an_unknown_attribute']))
        False

        With any object that has a `__public__` attribute that is
        <type 'frozenset'>, e.g.:

        >>> class whatever(object):
        >>>     __public__ = frozenset(['another_attr'])
        >>> base.implements(whatever)
        True

        Unlike ProxyTarget.implemented_by(), this returns an abstract answer
        because only the __public__ frozenset is checked... a ProxyTarget
        need not itself have attributes for all names in __public__
        (subclasses might provide them).
        """
        assert type(cls.__public__) is frozenset
        if isinstance(arg, str):
            return arg in cls.__public__
        if type(getattr(arg, '__public__', None)) is frozenset:
            return cls.__public__.issuperset(arg.__public__)
        if type(arg) is frozenset:
            return cls.__public__.issuperset(arg)
        raise TypeError(
            "must be str, frozenset, or have frozenset '__public__' attribute"
        )

    @classmethod
    def implemented_by(cls, arg):
        """
        Returns True if:

            1. ``arg`` is an instance of or subclass of this class, and

            2. ``arg`` (or ``arg.__class__`` if instance) has an attribute for
                each name in this class's ``__public__`` frozenset

        Otherwise, returns False.

        Unlike `Plugin.implements`, this returns a concrete answer because
        the attributes of the subclass are checked.

        :param arg: An instance of or subclass of this class.
        """
        if inspect.isclass(arg):
            subclass = arg
        else:
            subclass = arg.__class__
        assert issubclass(subclass, cls), 'must be subclass of %r' % cls
        for name in cls.__public__:
            if not hasattr(subclass, name):
                return False
        return True

    def finalize(self):
        """
        """
        lock(self)

    def set_api(self, api):
        """
        Set reference to `API` instance.
        """
        assert self.__api is None, 'set_api() can only be called once'
        assert api is not None, 'set_api() argument cannot be None'
        self.__api = api

    def __repr__(self):
        """
        Returns a fully qualified module_name.class_name() representation that
        could be used to construct this Plugin instance.
        """
        return '%s.%s()' % (
            self.__class__.__module__,
            self.__class__.__name__
        )


class PluginProxy(SetProxy):
    """
    Allows access to only certain attributes on a `Plugin`.

    Think of a proxy as an agreement that "I will have at most these
    attributes". This is different from (although similar to) an interface,
    which can be thought of as an agreement that "I will have at least these
    attributes".
    """
    __slots__ = (
        '__base',
        '__target',
        '__name_attr',
        '__public__',
        'name',
        'doc',
    )

    def __init__(self, base, target, name_attr='name'):
        """
        :param base: A subclass of `Plugin`.
        :param target: An instance ``base`` or a subclass of ``base``.
        :param name_attr: The name of the attribute on ``target`` from which
            to derive ``self.name``.
        """
        if not inspect.isclass(base):
            raise TypeError(
                '`base` must be a class, got %r' % base
            )
        if not isinstance(target, base):
            raise ValueError(
                '`target` must be an instance of `base`, got %r' % target
            )
        self.__base = base
        self.__target = target
        self.__name_attr = name_attr
        self.__public__ = base.__public__
        self.name = getattr(target, name_attr)
        self.doc = target.doc
        assert type(self.__public__) is frozenset
        super(PluginProxy, self).__init__(self.__public__)

    def implements(self, arg):
        """
        Returns True if this proxy implements `arg`. Calls the corresponding
        classmethod on ProxyTarget.

        Unlike ProxyTarget.implements(), this is not a classmethod as a Proxy
        only implements anything as an instance.
        """
        return self.__base.implements(arg)

    def __clone__(self, name_attr):
        """
        Returns a Proxy instance identical to this one except the proxy name
        might be derived from a different attribute on the target. The same
        base and target will be used.
        """
        return self.__class__(self.__base, self.__target, name_attr)

    def __getitem__(self, key):
        """
        If this proxy allows access to an attribute named ``key``, return that
        attribute.
        """
        if key in self.__public__:
            return getattr(self.__target, key)
        raise KeyError('no public attribute %s.%s' % (self.name, key))

    def __getattr__(self, name):
        """
        If this proxy allows access to an attribute named ``name``, return
        that attribute.
        """
        if name in self.__public__:
            return getattr(self.__target, name)
        raise AttributeError('no public attribute %s.%s' % (self.name, name))

    def __call__(self, *args, **kw):
        """
        Attempts to call target.__call__(); raises KeyError if `__call__` is
        not an attribute this proxy allows access to.
        """
        return self['__call__'](*args, **kw)

    def __repr__(self):
        """
        Returns a Python expression that could be used to construct this Proxy
        instance given the appropriate environment.
        """
        return '%s(%s, %r)' % (
            self.__class__.__name__,
            self.__base.__name__,
            self.__target,
        )


def check_name(name):
    """
    Verifies that ``name`` is suitable for a `NameSpace` member name.

    Raises `errors.NameSpaceError` if ``name`` is not a valid Python
    identifier suitable for use as the name of `NameSpace` member.

    :param name: Identifier to test.
    """
    check_type(name, str, 'name')
    regex = r'^[a-z][_a-z0-9]*[a-z0-9]$'
    if re.match(regex, name) is None:
        raise errors.NameSpaceError(name, regex)
    return name


class NameSpace(ReadOnly):
    """
    A read-only namespace with handy container behaviours.

    Each member of a NameSpace instance must have a ``name`` attribute whose
    value:

        1. Is unique among the members
        2. Passes the `check_name()` function

    Beyond that, no restrictions are placed on the members: they can be
    classes or instances, and of any type.

    The members can be accessed as attributes on the NameSpace instance or
    through a dictionary interface. For example, assuming ``obj`` is a member
    in the NameSpace instance ``namespace``, you could do this:

    >>> obj is getattr(namespace, obj.name) # As attribute
    True
    >>> obj is namespace[obj.name] # As dictionary item
    True

    Here is a more detailed example:

    >>> class member(object):
    ...     def __init__(self, i):
    ...             self.name = 'member_%d' % i
    ...
    >>> def get_members(cnt):
    ...     for i in xrange(cnt):
    ...             yield member(i)
    ...
    >>> namespace = NameSpace(get_members(2))
    >>> namespace.member_0 is namespace['member_0']
    True
    >>> len(namespace) # Returns the number of members in namespace
    2
    >>> list(namespace) # As iterable, iterates through the member names
    ['member_0', 'member_1']
    >>> list(namespace()) # Calling a NameSpace iterates through the members
    [<__main__.member object at 0x836710>, <__main__.member object at 0x836750>]
    >>> 'member_1' in namespace # NameSpace.__contains__()
    True
    """

    def __init__(self, members, sort=True):
        """
        :param members: An iterable providing the members.
        :param sort: Whether to sort the members by member name.
        """
        self.__sort = check_type(sort, bool, 'sort')
        if self.__sort:
            self.__members = tuple(sorted(members, key=lambda m: m.name))
        else:
            self.__members = tuple(members)
        self.__names = tuple(m.name for m in self.__members)
        self.__map = dict()
        for member in self.__members:
            name = check_name(member.name)
            assert name not in self.__map, 'already has key %r' % name
            self.__map[name] = member
            assert not hasattr(self, name), 'already has attribute %r' % name
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

        If this instance was created with ``sort=True``, the names will be in
        alphabetical order; otherwise the names will be in the same order as
        the members were passed to the constructor.

        This method is like an ordered version of dict.iterkeys().
        """
        for name in self.__names:
            yield name

    def __call__(self):
        """
        Iterate through the members.

        If this instance was created with ``sort=True``, the members will be
        in alphabetical order by name; otherwise the members will be in the
        same order as they were passed to the constructor.

        This method is like an ordered version of dict.itervalues().
        """
        for member in self.__members:
            yield member

    def __contains__(self, name):
        """
        Return True if namespace has a member named ``name``.
        """
        return name in self.__map

    def __getitem__(self, spec):
        """
        Return a member by name or index, or returns a slice of members.

        :param spec: The name or index of a member, or a slice object.
        """
        if type(spec) is str:
            return self.__map[spec]
        if type(spec) in (int, slice):
            return self.__members[spec]
        raise TypeError(
            'spec: must be %r, %r, or %r; got %r' % (str, int, slice, spec)
        )

    def __repr__(self):
        """
        Return a pseudo-valid expression that could create this instance.
        """
        return '%s(<%d members>, sort=%r)' % (
            self.__class__.__name__,
            len(self),
            self.__sort,
        )

    def __todict__(self):
        """
        Return a copy of the private dict mapping name to member.
        """
        return dict(self.__map)


class Registrar(DictProxy):
    """
    Collects plugin classes as they are registered.

    The Registrar does not instantiate plugins... it only implements the
    override logic and stores the plugins in a namespace per allowed base
    class.

    The plugins are instantiated when `API.finalize()` is called.
    """
    def __init__(self, *allowed):
        """
        :param allowed: Base classes from which plugins accepted by this
            Registrar must subclass.
        """
        self.__allowed = dict((base, {}) for base in allowed)
        self.__registered = set()
        super(Registrar, self).__init__(
            dict(self.__base_iter())
        )

    def __base_iter(self):
        for (base, sub_d) in self.__allowed.iteritems():
            assert inspect.isclass(base)
            name = base.__name__
            assert not hasattr(self, name)
            setattr(self, name, MagicDict(sub_d))
            yield (name, base)

    def __findbases(self, klass):
        """
        Iterates through allowed bases that ``klass`` is a subclass of.

        Raises `errors.SubclassError` if ``klass`` is not a subclass of any
        allowed base.

        :param klass: The class to find bases for.
        """
        assert inspect.isclass(klass)
        found = False
        for (base, sub_d) in self.__allowed.iteritems():
            if issubclass(klass, base):
                found = True
                yield (base, sub_d)
        if not found:
            raise errors.SubclassError(klass, self.__allowed.keys())

    def __call__(self, klass, override=False):
        """
        Register the plugin ``klass``.

        :param klass: A subclass of `Plugin` to attempt to register.
        :param override: If true, override an already registered plugin.
        """
        if not inspect.isclass(klass):
            raise TypeError('plugin must be a class: %r'  % klass)

        # Raise DuplicateError if this exact class was already registered:
        if klass in self.__registered:
            raise errors.DuplicateError(klass)

        # Find the base class or raise SubclassError:
        for (base, sub_d) in self.__findbases(klass):
            # Check override:
            if klass.__name__ in sub_d:
                if not override:
                    # Must use override=True to override:
                    raise errors.OverrideError(base, klass)
            else:
                if override:
                    # There was nothing already registered to override:
                    raise errors.MissingOverrideError(base, klass)

            # The plugin is okay, add to sub_d:
            sub_d[klass.__name__] = klass

        # The plugin is okay, add to __registered:
        self.__registered.add(klass)


class Environment(object):
    """
    A mapping object used to store the environment variables.
    """

    def __init__(self):
        object.__setattr__(self, '_Environment__map', {})

    def __getattr__(self, name):
        """
        Return the attribute named ``name``.
        """
        return self[name]

    def __setattr__(self, name, value):
        """
        Set the attribute named ``name`` to ``value``.
        """
        self[name] = value

    def __delattr__(self, name):
        """
        Raise AttributeError (deletion is not allowed).
        """
        raise AttributeError('cannot del %s.%s' %
            (self.__class__.__name__, name)
        )

    def __getitem__(self, key):
        """
        Return the value corresponding to ``key``.
        """
        val = self.__map[key]
        if hasattr(val, 'get_value'):
            return val.get_value()
        else:
            return val

    def __setitem__(self, key, value):
        """
        Set the item at ``key`` to ``value``.
        """
        if key in self or hasattr(self, key):
            raise AttributeError('cannot overwrite %s.%s' %
                        (self.__class__.__name__, key)
                    )
        self.__map[key] = value

    def __contains__(self, key):
        """
        Return True if instance contains ``key``; otherwise return False.
        """
        return key in self.__map

    def __iter__(self):
        """
        Iterate through keys in ascending order.
        """
        for key in sorted(self.__map):
            yield key

    def update(self, new_vals, ignore_errors = False):
        assert type(new_vals) == dict
        for key, value in new_vals.iteritems():
            if key in self and ignore_errors:
                continue
            self[key] = value

    def get(self, name, default=None):
        return self.__map.get(name, default)

class API(DictProxy):
    """
    Dynamic API object through which `Plugin` instances are accessed.
    """
    __finalized = False

    def __init__(self, *allowed):
        self.__d = dict()
        self.register = Registrar(*allowed)
        self.env = Environment()
        super(API, self).__init__(self.__d)

    def finalize(self):
        """
        Finalize the registration, instantiate the plugins.
        """
        assert not self.__finalized, 'finalize() can only be called once'

        class PluginInstance(object):
            """
            Represents a plugin instance.
            """

            i = 0

            def __init__(self, klass):
                self.created = self.next()
                self.klass = klass
                self.instance = klass()
                self.bases = []

            @classmethod
            def next(cls):
                cls.i += 1
                return cls.i

        class PluginInfo(ReadOnly):
            def __init__(self, p):
                assert isinstance(p, PluginInstance)
                self.created = p.created
                self.name = p.klass.__name__
                self.module = str(p.klass.__module__)
                self.plugin = '%s.%s' % (self.module, self.name)
                self.bases = tuple(b.__name__ for b in p.bases)
                lock(self)

        plugins = {}
        def plugin_iter(base, subclasses):
            for klass in subclasses:
                assert issubclass(klass, base)
                if klass not in plugins:
                    plugins[klass] = PluginInstance(klass)
                p = plugins[klass]
                assert base not in p.bases
                p.bases.append(base)
                if base.__proxy__:
                    yield PluginProxy(base, p.instance)
                else:
                    yield p.instance

        for name in self.register:
            base = self.register[name]
            magic = getattr(self.register, name)
            namespace = NameSpace(
                plugin_iter(base, (magic[k] for k in magic))
            )
            assert not (
                name in self.__d or hasattr(self, name)
            )
            self.__d[name] = namespace
            object.__setattr__(self, name, namespace)

        for p in plugins.itervalues():
            p.instance.set_api(self)
            assert p.instance.api is self

        for p in plugins.itervalues():
            p.instance.finalize()
        object.__setattr__(self, '_API__finalized', True)
        tuple(PluginInfo(p) for p in plugins.itervalues())
        object.__setattr__(self, 'plugins',
            tuple(PluginInfo(p) for p in plugins.itervalues())
        )
