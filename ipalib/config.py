# Authors:
#   Martin Nagy <mnagy@redhat.com>
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
Basic configuration management.

This module handles the reading and representation of basic local settings.
It will also take care of settings that can be discovered by different
methods, such as DNS.
"""

from ConfigParser import SafeConfigParser, ParsingError
import types
import os
import sys

from errors import check_isinstance, raise_TypeError

DEFAULT_CONF='/etc/ipa/ipa.conf'


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
            if hasattr(self.__map[key], 'set_value'):
                self.__map[key].set_value(value)
            else:
                raise AttributeError('cannot overwrite %s.%s' %
                            (self.__class__.__name__, key)
                )
        else:
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
        """
        Update variables using keys and values from ``new_vals``.

        Error will occur if there is an attempt to override variable that was
        already set, unless``ignore_errors`` is True.
        """
        assert type(new_vals) == dict
        for key, value in new_vals.iteritems():
            if ignore_errors:
                try:
                    self[key] = value
                except (AttributeError, KeyError):
                    pass
            else:
                self[key] = value

    def get(self, name, default=None):
        """
        Return the value corresponding to ``key``. Defaults to ``default``.
        """
        if name in self:
            return self[name]
        else:
            return default


class Env(object):
    """
    A mapping object used to store the environment variables.
    """

    __locked = False

    def __init__(self):
        object.__setattr__(self, '_Env__d', {})

    def __lock__(self):
        """
        Prevent further changes to environment.
        """
        if self.__locked is True:
            raise StandardError(
                '%s.__lock__() already called' % self.__class__.__name__
            )
        object.__setattr__(self, '_Env__locked', True)

    def __getattr__(self, name):
        """
        Return the attribute named ``name``.
        """
        if name in self.__d:
            return self[name]
        raise AttributeError('%s.%s' %
            (self.__class__.__name__, name)
        )

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
        if key not in self.__d:
            raise KeyError(key)
        value = self.__d[key]
        if callable(value):
            return value()
        return value

    def __setitem__(self, key, value):
        """
        Set ``key`` to ``value``.
        """
        if self.__locked:
            raise AttributeError('locked: cannot set %s.%s to %r' %
                (self.__class__.__name__, key, value)
            )
        if key in self.__d or hasattr(self, key):
            raise AttributeError('cannot overwrite %s.%s with %r' %
                (self.__class__.__name__, key, value)
            )
        self.__d[key] = value
        if not callable(value):
            assert type(value) in (str, int, bool)
            object.__setattr__(self, key, value)

    def __contains__(self, key):
        """
        Return True if instance contains ``key``; otherwise return False.
        """
        return key in self.__d

    def __iter__(self): # Fix
        """
        Iterate through keys in ascending order.
        """
        for key in sorted(self.__d):
            yield key


def set_default_env(env):
    """
    Set default values for ``env``.
    """
    assert isinstance(env, Environment)

    default = dict(
        basedn = EnvProp(basestring, 'dc=example,dc=com'),
        container_accounts = EnvProp(basestring, 'cn=accounts'),
        container_user = EnvProp(basestring, 'cn=users,cn=accounts'),
        container_group = EnvProp(basestring, 'cn=groups,cn=accounts'),
        container_service = EnvProp(basestring, 'cn=services,cn=accounts'),
        container_host = EnvProp(basestring, 'cn=computers,cn=accounts'),
        domain = LazyProp(basestring, get_domain),
        interactive = EnvProp(bool, True),
        query_dns = EnvProp(bool, True),
        realm = LazyProp(basestring, get_realm),
        server_context = EnvProp(bool, True),
        server = LazyIter(basestring, get_servers),
        verbose = EnvProp(bool, False),
        ldaphost = EnvProp(basestring, 'localhost'),
        ldapport = EnvProp(int, 389),
    )

    env.update(default)


class EnvProp(object):
    """
    Environment set-once property with optional default value.
    """
    def __init__(self, type_, default, multi_value=False):
        """
        :param type_: Type of the property.
        :param default: Default value.
        :param multi_value: Allow multiple values.
        """
        if multi_value:
            if isinstance(default, tuple) and len(default):
                check_isinstance(default[0], type_, allow_none=True)
        self._type = type_
        self._default = default
        self._value = None
        self._multi_value = multi_value

    def get_value(self):
        """
        Return the value if it was set.

        If the value is not set return the default. Otherwise raise an
        exception.
        """
        if self._get() != None:
            return self._get()
        else:
            raise KeyError, 'Value not set'

    def set_value(self, value):
        """
        Set the value.
        """
        if self._value != None:
            raise KeyError, 'Value already set'
        self._value = self._validate(value)

    def _get(self):
        """
        Return value, default, or None.
        """
        if self._value != None:
            return self._value
        elif self._default != None:
            return self._default
        else:
            return None

    def _validate(self, value):
        """
        Make sure ``value`` is of the right type. Do conversions if necessary.

        This will also handle multi value.
        """
        if self._multi_value and isinstance(value, tuple):
            converted = []
            for val in value:
                converted.append(self._validate_value(val))
            return tuple(converted)
        else:
            return self._validate_value(value)

    def _validate_value(self, value):
        """
        Validate and convert a single value.
        """
        bool_true = ('true', 'yes', 'on')
        bool_false = ('false', 'no', 'off')

        if self._type == bool and isinstance(value, basestring):
            if value.lower() in bool_true:
                return True
            elif value.lower() in bool_false:
                return False
            else:
                raise raise_TypeError(value, bool, 'value')
        check_isinstance(value, self._type, 'value')
        return value


class LazyProp(EnvProp):
    def __init__(self, type_, func, default=None, multi_value=False):
        check_isinstance(func, types.FunctionType, 'func')
        self._func = func
        EnvProp.__init__(self, type_, default, multi_value)

    def get_value(self):
        if self._get() != None:
            return self._get()
        else:
            return self._func()


class LazyIter(LazyProp):
    def __init__(self, type_, func, default=None):
        LazyProp.__init__(self, type_, func, default, multi_value=True)

    def get_value(self):
        val = self._get()
        if val != None:
            if type(val) == tuple:
                for item in val:
                    yield item
            else:
                yield val
        for item in self._func():
            if not val or item not in val:
                yield item


# TODO: Make it possible to use var = 'foo, bar' without
#       turning it into ("'foo", "bar'")
def read_config(config_file=None):
    assert config_file == None or isinstance(config_file, (basestring, file))

    parser = SafeConfigParser()
    if config_file == None:
        files = [DEFAULT_CONF, os.path.expanduser('~/.ipa.conf')]
    else:
        files = [config_file]

    for f in files:
        try:
            if isinstance(f, file):
                parser.readfp(f)
            else:
                parser.read(f)
        except ParsingError:
            print "Can't read %s" % f

    ret = {}
    if parser.has_section('defaults'):
        for name, value in parser.items('defaults'):
            value = tuple(elem.strip() for elem in value.split(','))
            if len(value) == 1:
                value = value[0]
            ret[name] = value

    return ret


# these functions are here just to "emulate" dns resolving for now
def get_domain():
    return "ipatest.com"


def get_realm():
    return "IPATEST.COM"


def get_servers():
    yield "server.ipatest.com"
    yield "backup.ipatest.com"
    yield "fake.ipatest.com"
