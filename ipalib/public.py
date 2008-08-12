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
import errors


RULE_FLAG = 'validation_rule'

def rule(obj):
    assert not hasattr(obj, RULE_FLAG)
    setattr(obj, RULE_FLAG, True)
    return obj

def is_rule(obj):
    return callable(obj) and getattr(obj, RULE_FLAG, False) is True


class option(plugable.Plugin):
    """
    The option class represents a kw argument from a command.
    """

    __public__ = frozenset((
        'get_doc',
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


class cmd(plugable.Plugin):
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
            yield plugable.Proxy(option, o)

    def __get_options(self):
        """
        Returns the NameSpace containing the option proxy objects.
        """
        if self.__options is None:
            object.__setattr__(self, '_cmd__options',
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
        for option in self.options:
            if option.name not in kw:
                value = option.default(**kw)
                if value is not None:
                    yield(option.name, value)

    def default(self, **kw):
        self.print_call('default', kw, 1)
        return dict(self.default_iter(kw))

    def validate(self, **kw):
        self.print_call('validate', kw, 1)
        for (key, value) in kw.items():
            if key in self.options:
                self.options[key].validate(value)

    def execute(self, **kw):
        self.print_call('execute', kw, 1)
        pass

    def print_call(self, method, kw, tab=0):
        print '%s%s.%s(%s)\n' % (
            ' ' * (tab *2),
            self.name,
            method,
            ', '.join('%s=%r' % (k, v) for (k, v) in kw.items()),
        )

    def __call__(self, **kw):
        print ''
        self.print_call('__call__', kw)
        kw = self.normalize(**kw)
        kw.update(self.default(**kw))
        self.validate(**kw)
        self.execute(**kw)


class obj(plugable.Plugin):
    __public__ = frozenset((
        'mthd',
        'prop',
    ))
    __mthd = None
    __prop = None

    def __get_mthd(self):
        return self.__mthd
    mthd = property(__get_mthd)

    def __get_prop(self):
        return self.__prop
    prop = property(__get_prop)

    def finalize(self, api):
        super(obj, self).finalize(api)
        self.__mthd = self.__create_ns('mthd')
        self.__prop = self.__create_ns('prop')

    def __create_ns(self, name):
        return plugable.NameSpace(self.__filter(name))

    def __filter(self, name):
        for i in getattr(self.api, name):
            if i.obj_name == self.name:
                yield i.__clone__('attr_name')


class attr(plugable.Plugin):
    __public__ = frozenset((
        'obj',
        'obj_name',
    ))
    __obj = None

    def __init__(self):
        m = re.match('^([a-z][a-z0-9]+)_([a-z][a-z0-9]+)$', self.__class__.__name__)
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
        super(attr, self).finalize(api)
        self.__obj = api.obj[self.obj_name]


class mthd(attr, cmd):
    __public__ = attr.__public__.union(cmd.__public__)

    def get_options(self):
        for proxy in cmd.get_options(self):
            yield proxy
        if self.obj is not None and self.obj.prop is not None:
            for proxy in self.obj.prop:
                yield proxy


class prop(attr, option):
    __public__ = attr.__public__.union(option.__public__)

    def get_doc(self, _):
        return _('prop doc')


class PublicAPI(plugable.API):
    __max_cmd_len = None

    def __init__(self):
        super(PublicAPI, self).__init__(cmd, obj, mthd, prop)

    def __get_max_cmd_len(self):
        if self.__max_cmd_len is None:
            if not hasattr(self, 'cmd'):
                return None
            max_cmd_len = max(len(str(cmd)) for cmd in self.cmd)
            object.__setattr__(self, '_PublicAPI__max_cmd_len', max_cmd_len)
        return self.__max_cmd_len
    max_cmd_len = property(__get_max_cmd_len)
