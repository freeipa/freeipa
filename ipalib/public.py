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
from plugable import lock
import errors


RULE_FLAG = 'validation_rule'

def rule(obj):
    assert not hasattr(obj, RULE_FLAG)
    setattr(obj, RULE_FLAG, True)
    return obj

def is_rule(obj):
    return callable(obj) and getattr(obj, RULE_FLAG, False) is True


class DefaultFrom(plugable.ReadOnly):
    def __init__(self, callback, *keys):
        assert callable(callback), 'not a callable: %r' % callback
        self.callback = callback
        self.keys = keys
        lock(self)

    def __call__(self, **kw):
        vals = tuple(kw.get(k, None) for k in self.keys)
        if None in vals:
            return None
        try:
            ret = self.callback(*vals)
        except Exception:
            return None
        if isinstance(ret, basestring):
            return ret
        return None


class option(plugable.Plugin):
    """
    The option class represents a kw argument from a command.
    """

    __public__ = frozenset((
        'normalize',
        'default',
        'validate',
        'required',
        'type',
    ))
    __rules = None
    type = unicode
    required = False

    def normalize(self, value):
        """
        Returns the normalized form of `value`. If `value` cannot be
        normalized, NormalizationError is raised, which is a subclass of
        ValidationError.

        The base class implementation only does type coercion, but subclasses
        might do other normalization (e.g., a unicode option might strip
        leading and trailing white-space).
        """
        try:
            return self.type(value)
        except (TypeError, ValueError):
            raise errors.NormalizationError(
                self.__class__.__name__, value, self.type
            )

    def validate(self, value):
        """
        Calls each validation rule and if any rule fails, raises RuleError,
        which is a subclass of ValidationError.
        """
        for rule in self.rules:
            msg = rule(value)
            if msg is not None:
                raise errors.RuleError(
                    self.__class__.__name__,
                    value,
                    rule,
                    msg,
                )

    def __get_rules(self):
        """
        Returns the tuple of rule methods used for input validation. This
        tuple is lazily initialized the first time the property is accessed.
        """
        if self.__rules is None:
            rules = tuple(sorted(
                self.__rules_iter(),
                key=lambda f: getattr(f, '__name__'),
            ))
            object.__setattr__(self, '_option__rules', rules)
        return self.__rules
    rules = property(__get_rules)

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

    def default(self, **kw):
        """
        Returns a default or auto-completed value for this option. If no
        default is available, this method should return None.

        All the keywords are passed so it's possible to build an
        auto-completed value from other options values, e.g., build 'initials'
        from 'givenname' + 'sn'.
        """
        return None


class Command(plugable.Plugin):
    __public__ = frozenset((
        'normalize',
        'default',
        'validate',
        'execute',
        '__call__',
        'get_doc',
        'options',
    ))
    __options = None
    option_classes = tuple()

    def get_doc(self, _):
        """
        Returns the gettext translated doc-string for this command.

        For example:

        >>> def get_doc(self, _):
        >>>     return _('add new user')
        """
        raise NotImplementedError('%s.get_doc()' % self.name)

    def get_options(self):
        """
        Returns iterable with option proxy objects used to create the option
        NameSpace when __get_option() is called.
        """
        for cls in self.option_classes:
            assert inspect.isclass(cls)
            o = cls()
            o.__lock__()
            yield plugable.PluginProxy(option, o)

    def __get_options(self):
        """
        Returns the NameSpace containing the option proxy objects.
        """
        if self.__options is None:
            object.__setattr__(self, '_Command__options',
                plugable.NameSpace(self.get_options()),
            )
        return self.__options
    options = property(__get_options)

    def normalize_iter(self, kw):
        for (key, value) in kw.items():
            if key in self.options:
                yield (
                    key, self.options[key].normalize(value)
                )
            else:
                yield (key, value)

    def normalize(self, **kw):
        self.print_call('normalize', kw, 1)
        return dict(self.normalize_iter(kw))

    def default_iter(self, kw):
        for option in self.options():
            if option.name not in kw:
                value = option.default(**kw)
                if value is not None:
                    yield(option.name, value)

    def default(self, **kw):
        self.print_call('default', kw, 1)
        return dict(self.default_iter(kw))

    def validate(self, **kw):
        self.print_call('validate', kw, 1)
        for opt in self.options():
            value = kw.get(opt.name, None)
            if value is None:
                if opt.required:
                    raise errors.RequirementError(opt.name)
                continue
            opt.validate(value)

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
        kw.update(self.default(**kw))
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
        for proxy in Command.get_options(self):
            yield proxy
        if self.obj is not None and self.obj.Property is not None:
            for proxy in self.obj.Property():
                yield proxy


class Property(Attribute, option):
    __public__ = Attribute.__public__.union(option.__public__)

    def get_doc(self, _):
        return _('Property doc')


class PublicAPI(plugable.API):
    def __init__(self):
        super(PublicAPI, self).__init__(Command, Object, Method, Property)
