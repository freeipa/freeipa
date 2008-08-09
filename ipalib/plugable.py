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
Base classes for plug-in architecture and generative API.
"""

import re
import inspect
import errors


def check_identifier(name):
    """
    Raises errors.NameSpaceError if `name` is not a valid Python identifier
    suitable for use in a NameSpace.
    """
    regex = r'^[a-z][_a-z0-9]*[a-z0-9]$'
    if re.match(regex, name) is None:
        raise errors.NameSpaceError(name, regex)


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

    >>> class givenName(ReadOnly):
    >>>     def __init__(self):
    >>>         self.whatever = 'some value' # Hasn't been locked yet
    >>>         self.__lock__()
    >>>
    >>>     def finalize(self, api):
    >>>         # After the instance has been locked, attributes can still be
    >>>         # set, but only in a round-about, unconventional way:
    >>>         object.__setattr__(self, 'api', api)
    >>>
    >>>     def normalize(self, value):
    >>>         # After the instance has been locked, trying to set an
    >>>         # attribute in the normal way will raise AttributeError.
    >>>         self.value = value # Not thread safe!
    >>>         return self.actually_normalize()
    >>>
    >>>     def actually_normalize(self):
    >>>         # Again, this is not thread safe:
    >>>         return unicode(self.value).strip()
    """
    __locked = False

    def __lock__(self):
        """
        Puts this instance into a read-only state, after which attempting to
        set or delete an attribute will raise AttributeError.
        """
        assert self.__locked is False, '__lock__() can only be called once'
        self.__locked = True

    def __islocked__(self):
        """
        Returns True if this instance is locked, False otherwise.
        """
        return self.__locked

    def __setattr__(self, name, value):
        """
        Raises an AttributeError if ReadOnly.__lock__() has already been called;
        otherwise calls object.__setattr__()
        """
        if self.__locked:
            raise AttributeError('read-only: cannot set %s.%s' %
                (self.__class__.__name__, name)
            )
        return object.__setattr__(self, name, value)

    def __delattr__(self, name):
        """
        Raises an AttributeError if ReadOnly.__lock__() has already been called;
        otherwise calls object.__delattr__()
        """
        if self.__locked:
            raise AttributeError('read-only: cannot del %s.%s' %
                (self.__class__.__name__, name)
            )
        return object.__delattr__(self, name)


class ProxyTarget(ReadOnly):
    __public__ = frozenset()

    def __get_name(self):
        """
        Convenience property to return the class name.
        """
        return self.__class__.__name__
    name = property(__get_name)

    @classmethod
    def implements(cls, arg):
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


class Proxy(ReadOnly):
    """
    Allows access to only certain attributes on its target object (a
    ProxyTarget).

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
    )

    def __init__(self, base, target, name_attr='name'):
        """
        `base` - the class defining the __public__ frozenset of attributes to
            proxy
        `target` - the target of the proxy (must be instance of `base`)
        `name_attr` - the name of the str attribute on `target` to assign
            to Proxy.name
        """
        if not inspect.isclass(base):
            raise TypeError('arg1 must be a class, got %r' % base)
        if not isinstance(target, base):
            raise ValueError('arg2 must be instance of arg1, got %r' % target)
        self.__base = base
        self.__target = target
        self.__name_attr = name_attr
        self.__public__ = base.__public__
        assert type(self.__public__) is frozenset
        self.name = getattr(target, name_attr)
        check_identifier(self.name)
        self.__lock__()

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

    def __iter__(self):
        """
        Iterates (in ascending order) though the attribute names this proxy is
        allowing access to.
        """
        for name in sorted(self.__public__):
            yield name

    def __getitem__(self, key):
        """
        If this proxy allows access to an attribute named `key`, return that
        attribute.
        """
        if key in self.__public__:
            return getattr(self.__target, key)
        raise KeyError('no proxy attribute %r' % key)

    def __getattr__(self, name):
        """
        If this proxy allows access to an attribute named `name`, return that
        attribute.
        """
        if name in self.__public__:
            return getattr(self.__target, name)
        raise AttributeError('no proxy attribute %r' % name)

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
        return '%s(%s, %r, %r)' % (
            self.__class__.__name__,
            self.__base.__name__,
            self.__target,
            self.__name_attr,
        )


class Plugin(ProxyTarget):
    """
    Base class for all plugins.
    """

    __api = None

    def __get_api(self):
        """
        Returns the plugable.API instance passed to Plugin.finalize(), or
        or returns None if finalize() has not yet been called.
        """
        return self.__api
    api = property(__get_api)

    def finalize(self, api):
        """
        After all the plugins are instantiated, the plugable.API calls this
        method, passing itself as the only argument. This is where plugins
        should check that other plugins they depend upon have actually be
        loaded.
        """
        assert self.__api is None, 'finalize() can only be called once'
        assert api is not None, 'finalize() argument cannot be None'
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


class NameSpace(ReadOnly):
    """
    A read-only namespace of (key, value) pairs that can be accessed
    both as instance attributes and as dictionary items.
    """

    def __init__(self, proxies):
        """
        NameSpace
        """
        self.__proxies = tuple(proxies)
        self.__d = dict()
        for proxy in self.__proxies:
            assert isinstance(proxy, Proxy)
            assert proxy.name not in self.__d
            self.__d[proxy.name] = proxy
            assert not hasattr(self, proxy.name)
            setattr(self, proxy.name, proxy)
        self.__lock__()

    def __iter__(self):
        """
        Iterates through the proxies in this NameSpace in the same order they
        were passed in the contructor.
        """
        for proxy in self.__proxies:
            yield proxy

    def __len__(self):
        """
        Returns number of proxies in this NameSpace.
        """
        return len(self.__proxies)

    def __contains__(self, key):
        """
        Returns True if a proxy named `key` is in this NameSpace.
        """
        return key in self.__d

    def __getitem__(self, key):
        """
        Returns proxy named `key`; otherwise raises KeyError.
        """
        if key in self.__d:
            return self.__d[key]
        raise KeyError('NameSpace has no item for key %r' % key)

    def __repr__(self):
        return '%s(<%d proxies>)' % (self.__class__.__name__, len(self))


class Registrar(object):
    def __init__(self, *allowed):
        """
        `*allowed` is a list of the base classes plugins can be subclassed
        from.
        """
        self.__allowed = frozenset(allowed)
        self.__d = {}
        self.__registered = set()
        assert len(self.__allowed) == len(allowed)
        for base in self.__allowed:
            assert inspect.isclass(base)
            assert base.__name__ not in self.__d
            self.__d[base.__name__] = {}

    def __findbase(self, cls):
        """
        If `cls` is a subclass of a base in self.__allowed, returns that
        base; otherwise raises SubclassError.
        """
        assert inspect.isclass(cls)
        found = False
        for base in self.__allowed:
            if issubclass(cls, base):
                found = True
                yield base
        if not found:
            raise errors.SubclassError(cls, self.__allowed)

    def __call__(self, cls, override=False):
        """
        Register the plugin `cls`.
        """
        if not inspect.isclass(cls):
            raise TypeError('plugin must be a class: %r'  % cls)

        # Raise DuplicateError if this exact class was already registered:
        if cls in self.__registered:
            raise errors.DuplicateError(cls)

        # Find the base class or raise SubclassError:
        for base in self.__findbase(cls):
            sub_d = self.__d[base.__name__]

            # Check override:
            if cls.__name__ in sub_d:
                # Must use override=True to override:
                if not override:
                    raise errors.OverrideError(base, cls)
            else:
                # There was nothing already registered to override:
                if override:
                    raise errors.MissingOverrideError(base, cls)

            # The plugin is okay, add to sub_d:
            sub_d[cls.__name__] = cls

        # The plugin is okay, add to __registered:
        self.__registered.add(cls)

    def __getitem__(self, item):
        """
        Returns a copy of the namespace dict of the base class named `name`.
        """
        if inspect.isclass(item):
            if item not in self.__allowed:
                raise KeyError(repr(item))
            key = item.__name__
        else:
            key = item
        return dict(self.__d[key])

    def __contains__(self, item):
        """
        Returns True if a base class named `name` is in this Registrar.
        """
        if inspect.isclass(item):
            return item in self.__allowed
        return item in self.__d

    def __iter__(self):
        """
        Iterates through a (base, registered_plugins) tuple for each allowed
        base.
        """
        for base in self.__allowed:
            sub_d = self.__d[base.__name__]
            yield (base, tuple(sub_d[k] for k in sorted(sub_d)))


class API(ReadOnly):
    def __init__(self, *allowed):
        keys = tuple(b.__name__ for b in allowed)
        self.register = Registrar(*allowed)
        self.__lock__()

    def __call__(self):
        """
        Finalize the registration, instantiate the plugins.
        """
        d = {}
        def plugin_iter(base, classes):
            for cls in classes:
                if cls not in d:
                    d[cls] = cls()
                plugin = d[cls]
                yield Proxy(base, plugin)

        for (base, classes) in self.register:
            ns = NameSpace(plugin_iter(base, classes))
            assert not hasattr(self, base.__name__)
            object.__setattr__(self, base.__name__, ns)
        for plugin in d.values():
            plugin.finalize(self)
            assert plugin.api is self

    def __iter__(self):
        for key in self.__keys:
            yield key
