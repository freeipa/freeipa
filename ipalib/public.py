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
Base classes for the public plugable.API instance, which the XML-RPC, CLI,
and UI all use.
"""

import re
import inspect
import plugable
from plugable import lock, check_name
import errors
from errors import check_type, check_isinstance, raise_TypeError
import ipa_types


RULE_FLAG = 'validation_rule'

def rule(obj):
    assert not hasattr(obj, RULE_FLAG)
    setattr(obj, RULE_FLAG, True)
    return obj

def is_rule(obj):
    return callable(obj) and getattr(obj, RULE_FLAG, False) is True


class DefaultFrom(plugable.ReadOnly):
    """
    Derives a default for one value using other supplied values.

    Here is an example that constructs a user's initials from his first
    and last name:

    >>> df = DefaultFrom(lambda f, l: f[0] + l[0], 'first', 'last')
    >>> df(first='John', last='Doe') # Both keys
    'JD'
    >>> df() is None # Returns None if any key is missing
    True
    >>> df(first='John', middle='Q') is None # Still returns None
    True
    """
    def __init__(self, callback, *keys):
        """
        :param callback: The callable to call when all ``keys`` are present.
        :param keys: The keys used to map from keyword to position arguments.
        """
        assert callable(callback), 'not a callable: %r' % callback
        assert len(keys) > 0, 'must have at least one key'
        for key in keys:
            assert type(key) is str, 'not an str: %r' % key
        self.callback = callback
        self.keys = keys
        lock(self)

    def __call__(self, **kw):
        """
        If all keys are present, calls the callback; otherwise returns None.

        :param kw: The keyword arguments.
        """
        vals = tuple(kw.get(k, None) for k in self.keys)
        if None in vals:
            return None
        try:
            return self.callback(*vals)
        except Exception:
            return None


class Option(plugable.ReadOnly):
    def __init__(self, name, doc, type_,
            required=False,
            multivalue=False,
            default=None,
            default_from=None,
            rules=tuple(),
            normalize=None):
        self.name = check_name(name)
        self.doc = check_type(doc, str, 'doc')
        self.type = check_isinstance(type_, ipa_types.Type, 'type_')
        self.required = check_type(required, bool, 'required')
        self.multivalue = check_type(multivalue, bool, 'multivalue')
        self.default = default
        self.default_from = check_type(default_from,
            DefaultFrom, 'default_from', allow_none=True)
        self.__normalize = normalize
        self.rules = (type_.validate,) + rules
        lock(self)

    def __convert_scalar(self, value, index=None):
        if value is None:
            raise TypeError('value cannot be None')
        converted = self.type(value)
        if converted is None:
            raise errors.ConversionError(
                self.name, value, self.type, index=index
            )
        return converted

    def convert(self, value):
        if self.multivalue:
            if type(value) in (tuple, list):
                return tuple(
                    self.__convert_scalar(v, i) for (i, v) in enumerate(value)
                )
            return (self.__convert_scalar(value, 0),) # tuple
        return self.__convert_scalar(value)

    def __normalize_scalar(self, value):
        if type(value) is not self.type.type:
            raise_TypeError(value, self.type.type, 'value')
        return self.__normalize(value)

    def normalize(self, value):
        if self.__normalize is None:
            return value
        if self.multivalue:
            if type(value) is not tuple:
                raise_TypeError(value, tuple, 'value')
            return tuple(self.__normalize_scalar(v) for v in value)
        return self.__normalize_scalar(value)

    def __validate_scalar(self, value, index=None):
        if type(value) is not self.type.type:
            raise_TypeError(value, self.type.type, 'value')
        for rule in self.rules:
            error = rule(value)
            if error is not None:
                raise errors.RuleError(
                    self.name, value, error, rule, index=index
                )

    def validate(self, value):
        if self.multivalue:
            if type(value) is not tuple:
                raise_TypeError(value, tuple, 'value')
            for (i, v) in enumerate(value):
                self.__validate_scalar(v, i)
        else:
            self.__validate_scalar(value)

    def get_default(self, **kw):
        if self.default_from is not None:
            default = self.default_from(**kw)
            if default is not None:
                return self.convert(default)
        return self.convert(self.default)

    def get_values(self):
        if self.type.name in ('Enum', 'CallbackEnum'):
            return self.type.values
        return tuple()


class Command(plugable.Plugin):
    __public__ = frozenset((
        'get_default',
        'normalize',
        'validate',
        'execute',
        '__call__',
        'Option',
    ))
    __Option = None
    options = tuple()

    def get_options(self):
        return self.options

    def __get_Option(self):
        """
        Returns the NameSpace containing the Option instances.
        """
        if self.__Option is None:
            object.__setattr__(self, '_Command__Option',
                plugable.NameSpace(self.get_options()),
            )
        return self.__Option
    Option = property(__get_Option)

    def __normalize_iter(self, kw):
        for (key, value) in kw.items():
            if key in self.Option:
                yield (
                    key, self.Option[key].normalize(value)
                )
            else:
                yield (key, value)

    def normalize(self, **kw):
        self.print_call('normalize', kw, 1)
        return dict(self.__normalize_iter(kw))

    def __get_default_iter(self, kw):
        for option in self.Option():
            if option.name not in kw:
                value = option.get_default(**kw)
                if value is not None:
                    yield(option.name, value)

    def get_default(self, **kw):
        self.print_call('default', kw, 1)
        return dict(self.__get_default_iter(kw))

    def validate(self, **kw):
        self.print_call('validate', kw, 1)
        for option in self.Option():
            value = kw.get(option.name, None)
            if value is not None:
                option.validate(value)
            elif option.required:
                raise errors.RequirementError(option.name)

    def execute(self, **kw):
        self.print_call('execute', kw, 1)
        pass

    def print_call(self, method, kw, tab=0):
        print '%s%s.%s(%s)\n' % (
            ' ' * (tab *2),
            self.name,
            method,
            ', '.join('%s=%r' % (k, kw[k]) for k in sorted(kw)),
        )

    def __call__(self, *args, **kw):
        print ''
        self.print_call('__call__', kw)
        kw = self.normalize(**kw)
        kw.update(self.get_default(**kw))
        self.validate(**kw)
        self.execute(**kw)


class Object(plugable.Plugin):
    __public__ = frozenset((
        'Method',
        'Property',
    ))
    __Method = None
    __Property = None

    def __get_Method(self):
        return self.__Method
    Method = property(__get_Method)

    def __get_Property(self):
        return self.__Property
    Property = property(__get_Property)

    def finalize(self, api):
        super(Object, self).finalize(api)
        self.__Method = self.__create_namespace('Method')
        self.__Property = self.__create_namespace('Property')

    def __create_namespace(self, name):
        return plugable.NameSpace(self.__filter_members(name))

    def __filter_members(self, name):
        namespace = getattr(self.api, name)
        assert type(namespace) is plugable.NameSpace
        for proxy in namespace(): # Equivalent to dict.itervalues()
            if proxy.obj_name == self.name:
                yield proxy.__clone__('attr_name')


class Attribute(plugable.Plugin):
    __public__ = frozenset((
        'obj',
        'obj_name',
    ))
    __obj = None

    def __init__(self):
        m = re.match(
            '^([a-z][a-z0-9]+)_([a-z][a-z0-9]+)$',
            self.__class__.__name__
        )
        assert m
        self.__obj_name = m.group(1)
        self.__attr_name = m.group(2)

    def __get_obj_name(self):
        return self.__obj_name
    obj_name = property(__get_obj_name)

    def __get_attr_name(self):
        return self.__attr_name
    attr_name = property(__get_attr_name)

    def __get_obj(self):
        """
        Returns the obj instance this attribute is associated with, or None
        if no association has been set.
        """
        return self.__obj
    obj = property(__get_obj)

    def finalize(self, api):
        super(Attribute, self).finalize(api)
        self.__obj = api.Object[self.obj_name]


class Method(Attribute, Command):
    __public__ = Attribute.__public__.union(Command.__public__)

    def get_options(self):
        for option in self.options:
            yield option
        if self.obj is not None and self.obj.Property is not None:
            for proxy in self.obj.Property():
                yield proxy.option


class Property(Attribute):
    __public__ = frozenset((
        'rules',
        'option',
        'type',
    )).union(Attribute.__public__)

    type = ipa_types.Unicode()
    required = False
    multivalue = False
    default = None
    default_from = None
    normalize = None

    def __init__(self):
        super(Property, self).__init__()
        self.rules = tuple(sorted(
            self.__rules_iter(),
            key=lambda f: getattr(f, '__name__'),
        ))
        self.option = Option(self.attr_name, self.doc, self.type,
            required=self.required,
            multivalue=self.multivalue,
            default=self.default,
            default_from=self.default_from,
            rules=self.rules,
            normalize=self.normalize,
        )

    def __rules_iter(self):
        """
        Iterates through the attributes in this instance to retrieve the
        methods implementing validation rules.
        """
        for name in dir(self.__class__):
            if name.startswith('_'):
                continue
            base_attr = getattr(self.__class__, name)
            if is_rule(base_attr):
                attr = getattr(self, name)
                if is_rule(attr):
                    yield attr
