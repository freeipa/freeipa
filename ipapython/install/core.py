#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
The framework core.
"""

import sys
import abc
import itertools

from ipapython.ipa_log_manager import root_logger

from . import util
from .util import from_

__all__ = ['InvalidStateError', 'KnobValueError', 'Property', 'Knob',
           'Configurable', 'Group', 'Component', 'Composite']

# Configurable states
_VALIDATE_PENDING = 'VALIDATE_PENDING'
_VALIDATE_RUNNING = 'VALIDATE_RUNNING'
_EXECUTE_PENDING = 'EXECUTE_PENDING'
_EXECUTE_RUNNING = 'EXECUTE_RUNNING'
_STOPPED = 'STOPPED'
_FAILED = 'FAILED'
_CLOSED = 'CLOSED'

_missing = object()
_counter = itertools.count()


def _class_cmp(a, b):
    if a is b:
        return 0
    elif issubclass(a, b):
        return -1
    elif issubclass(b, a):
        return 1
    else:
        return 0


class InvalidStateError(Exception):
    pass


class KnobValueError(ValueError):
    def __init__(self, name, message):
        super(KnobValueError, self).__init__(message)
        self.name = name


class InnerClass(object):
    __metaclass__ = util.InnerClassMeta
    __outer_class__ = None
    __outer_name__ = None


class PropertyBase(InnerClass):
    @property
    def default(self):
        raise AttributeError('default')

    def __init__(self, outer):
        self.outer = outer

    def __get__(self, obj, obj_type):
        try:
            return obj._get_property(self.__outer_name__)
        except AttributeError:
            if not hasattr(self, 'default'):
                raise
            return self.default


def Property(default=_missing):
    class_dict = {}
    if default is not _missing:
        class_dict['default'] = default

    return util.InnerClassMeta('Property', (PropertyBase,), class_dict)


class KnobBase(PropertyBase):
    type = None
    initializable = True
    sensitive = False
    deprecated = False
    description = None
    cli_name = None
    cli_short_name = None
    cli_aliases = None
    cli_metavar = None

    _order = None

    def __set__(self, obj, value):
        try:
            self.validate(value)
        except KnobValueError:
            raise
        except ValueError as e:
            raise KnobValueError(self.__outer_name__, str(e))

        obj.__dict__[self.__outer_name__] = value

    def __delete__(self, obj):
        try:
            del obj.__dict__[self.__outer_name__]
        except KeyError:
            raise AttributeError(self.__outer_name__)

    def validate(self, value):
        pass

    @classmethod
    def default_getter(cls, func):
        @property
        def default(self):
            return func(self.outer)
        cls.default = default

        return cls

    @classmethod
    def validator(cls, func):
        def validate(self, value):
            func(self.outer, value)
            super(cls, self).validate(value)
        cls.validate = validate

        return cls


def Knob(type, default=_missing, initializable=_missing, sensitive=_missing,
         deprecated=_missing, description=_missing, cli_name=_missing,
         cli_short_name=_missing, cli_aliases=_missing, cli_metavar=_missing):
    class_dict = {}
    class_dict['_order'] = next(_counter)
    class_dict['type'] = type
    if default is not _missing:
        class_dict['default'] = default
    if sensitive is not _missing:
        class_dict['sensitive'] = sensitive
    if deprecated is not _missing:
        class_dict['deprecated'] = deprecated
    if description is not _missing:
        class_dict['description'] = description
    if cli_name is not _missing:
        class_dict['cli_name'] = cli_name
    if cli_short_name is not _missing:
        class_dict['cli_short_name'] = cli_short_name
    if cli_aliases is not _missing:
        class_dict['cli_aliases'] = cli_aliases
    if cli_metavar is not _missing:
        class_dict['cli_metavar'] = cli_metavar

    return util.InnerClassMeta('Knob', (KnobBase,), class_dict)


class Configurable(object):
    """
    Base class of all configurables.

    FIXME: details of validate/execute, properties and knobs
    """

    __metaclass__ = abc.ABCMeta

    @classmethod
    def knobs(cls):
        """
        Iterate over knobs defined for the configurable.
        """

        assert not hasattr(super(Configurable, cls), 'knobs')

        result = []
        for name in dir(cls):
            knob_cls = getattr(cls, name)
            if isinstance(knob_cls, type) and issubclass(knob_cls, KnobBase):
                result.append(knob_cls)
        result = sorted(result, key=lambda knob_cls: knob_cls._order)
        for knob_cls in result:
            yield knob_cls.__outer_class__, knob_cls.__outer_name__

    @classmethod
    def group(cls):
        assert not hasattr(super(Configurable, cls), 'group')

        return None

    def __init__(self, **kwargs):
        """
        Initialize the configurable.
        """

        self.log = root_logger

        for name in dir(self.__class__):
            if name.startswith('_'):
                continue
            property_cls = getattr(self.__class__, name)
            if not isinstance(property_cls, type):
                continue
            if not issubclass(property_cls, PropertyBase):
                continue
            if issubclass(property_cls, KnobBase):
                continue
            try:
                value = kwargs.pop(name)
            except KeyError:
                pass
            else:
                setattr(self, name, value)

        for owner_cls, name in self.knobs():
            knob_cls = getattr(owner_cls, name)
            if not knob_cls.initializable:
                continue

            try:
                value = kwargs.pop(name)
            except KeyError:
                pass
            else:
                setattr(self, name, value)

        if kwargs:
            extra = sorted(kwargs.keys())
            raise TypeError(
                "{0}() got {1} unexpected keyword arguments: {2}".format(
                    type(self).__name__,
                    len(extra),
                    ', '.join(repr(name) for name in extra)))

        self._reset()

    def _reset(self):
        assert not hasattr(super(Configurable, self), '_reset')

        self.__state = _VALIDATE_PENDING
        self.__gen = util.run_generator_with_yield_from(self._configure())

    def _get_components(self):
        assert not hasattr(super(Configurable, self), '_get_components')

        raise TypeError("{0} is not composite".format(self))

    def _get_property(self, name):
        assert not hasattr(super(Configurable, self), '_get_property')

        try:
            return self.__dict__[name]
        except KeyError:
            raise AttributeError(name)

    @abc.abstractmethod
    def _configure(self):
        """
        Coroutine which defines the logic of the configurable.
        """

        assert not hasattr(super(Configurable, self), '_configure')

        self.__transition(_VALIDATE_RUNNING, _EXECUTE_PENDING)

        while self.__state != _EXECUTE_RUNNING:
            yield

    def run(self):
        """
        Run the configurable.
        """

        self.validate()
        if self.__state == _EXECUTE_PENDING:
            self.execute()

    def validate(self):
        """
        Run the validation part of the configurable.
        """

        for nothing in self._validator():
            pass

    def _validator(self):
        """
        Coroutine which runs the validation part of the configurable.
        """

        return self.__runner(_VALIDATE_PENDING, _VALIDATE_RUNNING)

    def execute(self):
        """
        Run the execution part of the configurable.
        """

        for nothing in self._executor():
            pass

    def _executor(self):
        """
        Coroutine which runs the execution part of the configurable.
        """

        return self.__runner(_EXECUTE_PENDING, _EXECUTE_RUNNING)

    def done(self):
        """
        Return True if the configurable has finished.
        """

        return self.__state in (_STOPPED, _FAILED, _CLOSED)

    def run_until_executing(self, gen):
        while self.__state != _EXECUTE_RUNNING:
            try:
                yield gen.next()
            except StopIteration:
                break

    def __runner(self, pending_state, running_state):
        self.__transition(pending_state, running_state)

        step = self.__gen.next
        while True:
            try:
                step()
            except StopIteration:
                self.__transition(running_state, _STOPPED)
                break
            except GeneratorExit:
                self.__transition(running_state, _CLOSED)
                break
            except BaseException:
                exc_info = sys.exc_info()
                try:
                    self._handle_exception(exc_info)
                except BaseException:
                    raise
                else:
                    break
                finally:
                    self.__transition(running_state, _FAILED)

            if self.__state != running_state:
                break

            try:
                yield
            except BaseException:
                exc_info = sys.exc_info()
                step = lambda: self.__gen.throw(*exc_info)
            else:
                step = self.__gen.next

    def _handle_exception(self, exc_info):
        assert not hasattr(super(Configurable, self), '_handle_exception')

        util.raise_exc_info(exc_info)

    def __transition(self, from_state, to_state):
        if self.__state != from_state:
            raise InvalidStateError(self.__state)

        self.__state = to_state


class Group(Configurable):
    @classmethod
    def group(cls):
        return cls


class ComponentMeta(util.InnerClassMeta, abc.ABCMeta):
    pass


class ComponentBase(InnerClass, Configurable):
    __metaclass__ = ComponentMeta

    _order = None

    @classmethod
    def group(cls):
        result = super(ComponentBase, cls).group()
        if result is not None:
            return result
        else:
            return cls.__outer_class__.group()

    def __init__(self, parent, **kwargs):
        self.__parent = parent

        super(ComponentBase, self).__init__(**kwargs)

    @property
    def parent(self):
        return self.__parent

    def __get__(self, obj, obj_type):
        obj.__dict__[self.__outer_name__] = self
        return self

    def _get_property(self, name):
        try:
            return super(ComponentBase, self)._get_property(name)
        except AttributeError:
            return self.__parent._get_property(name)

    def _handle_exception(self, exc_info):
        try:
            super(ComponentBase, self)._handle_exception(exc_info)
        except BaseException:
            exc_info = sys.exc_info()
            self.__parent._handle_exception(exc_info)


def Component(cls):
    class_dict = {}
    class_dict['_order'] = next(_counter)

    return ComponentMeta('Component', (ComponentBase, cls), class_dict)


class Composite(Configurable):
    """
    Configurable composed of any number of components.

    Provides knobs of all child components.
    """

    @classmethod
    def knobs(cls):
        name_dict = {}
        owner_dict = {}

        for owner_cls, name in super(Composite, cls).knobs():
            knob_cls = getattr(owner_cls, name)
            name_dict[name] = owner_cls
            owner_dict.setdefault(owner_cls, []).append(knob_cls)

        for owner_cls, name in cls.components():
            comp_cls = getattr(cls, name)
            for owner_cls, name in comp_cls.knobs():
                if hasattr(cls, name):
                    continue

                knob_cls = getattr(owner_cls, name)
                try:
                    last_owner_cls = name_dict[name]
                except KeyError:
                    name_dict[name] = owner_cls
                    owner_dict.setdefault(owner_cls, []).append(knob_cls)
                else:
                    if last_owner_cls is not owner_cls:
                        raise TypeError("{0}.knobs(): conflicting definitions "
                                        "of '{1}' in {2} and {3}".format(
                                            cls.__name__,
                                            name,
                                            last_owner_cls.__name__,
                                            owner_cls.__name__))

        for owner_cls in sorted(owner_dict, _class_cmp):
            for knob_cls in owner_dict[owner_cls]:
                yield knob_cls.__outer_class__, knob_cls.__outer_name__

    @classmethod
    def components(cls):
        assert not hasattr(super(Composite, cls), 'components')

        result = []
        for name in dir(cls):
            comp_cls = getattr(cls, name)
            if (isinstance(comp_cls, type) and
                    issubclass(comp_cls, ComponentBase)):
                result.append(comp_cls)
        result = sorted(result, key=lambda comp_cls: comp_cls._order)
        for comp_cls in result:
            yield comp_cls.__outer_class__, comp_cls.__outer_name__

    def _reset(self):
        self.__components = list(self._get_components())

        super(Composite, self)._reset()

    def _get_components(self):
        for owner_cls, name in self.components():
            yield getattr(self, name)

    def _configure(self):
        validate = [(c, c._validator()) for c in self.__components]
        while True:
            new_validate = []
            for child, validator in validate:
                try:
                    validator.next()
                except StopIteration:
                    if child.done():
                        self.__components.remove(child)
                else:
                    new_validate.append((child, validator))
            if not new_validate:
                break
            validate = new_validate

            yield

        if not self.__components:
            return

        yield from_(super(Composite, self)._configure())

        execute = [(c, c._executor()) for c in self.__components]
        while True:
            new_execute = []
            for child, executor in execute:
                try:
                    executor.next()
                except StopIteration:
                    pass
                else:
                    new_execute.append((child, executor))
            if not new_execute:
                break
            execute = new_execute

            yield
