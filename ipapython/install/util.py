#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
Utilities.
"""

import sys

import six


class from_:
    """
    Wrapper for delegating to a subgenerator.

    See `run_generator_with_yield_from`.
    """
    __slots__ = ('obj',)

    def __init__(self, obj):
        self.obj = obj


def run_generator_with_yield_from(gen):
    """
    Iterate over a generator object with subgenerator delegation.

    This implements Python 3's ``yield from`` expressions, using Python 2
    syntax:

    >>> def subgen():
    ...     yield 'B'
    ...     yield 'C'
    ...
    >>> def gen():
    ...     yield 'A'
    ...     yield from_(subgen())
    ...     yield 'D'
    ...
    >>> list(run_generator_with_yield_from(gen()))
    ['A', 'B', 'C', 'D']

    Returning value from a subgenerator is not supported.
    """

    exc_info = None
    value = None

    stack = [gen]
    while stack:
        prev_exc_info, exc_info = exc_info, None
        prev_value, value = value, None

        gen = stack[-1]
        try:
            if prev_exc_info is None:
                value = gen.send(prev_value)
            else:
                value = gen.throw(*prev_exc_info)
        except StopIteration:
            stack.pop()
            continue
        except BaseException:
            exc_info = sys.exc_info()
            stack.pop()
            continue
        else:
            if isinstance(value, from_):
                stack.append(value.obj)
                value = None
                continue

        try:
            value = (yield value)
        except BaseException:
            exc_info = sys.exc_info()

    if exc_info is not None:
        six.reraise(*exc_info)


class InnerClassMeta(type):
    # pylint: disable=no-value-for-parameter
    def __new__(cls, name, bases, class_dict):
        class_dict.pop('__outer_class__', None)
        class_dict.pop('__outer_name__', None)

        return super(InnerClassMeta, cls).__new__(cls, name, bases, class_dict)

    def __get__(cls, obj, obj_type):
        outer_class, outer_name = cls.__bind(obj_type)
        if obj is None:
            return cls
        assert isinstance(obj, outer_class)

        try:
            return obj.__dict__[outer_name]
        except KeyError:
            inner = cls(obj)
            try:
                getter = inner.__get__
            except AttributeError:
                return inner
            else:
                return getter(obj, obj_type)

    def __set__(cls, obj, value):
        outer_class, outer_name = cls.__bind(obj.__class__)
        assert isinstance(obj, outer_class)

        inner = cls(obj)
        try:
            setter = inner.__set__
        except AttributeError:
            try:
                inner.__delete__
            except AttributeError:
                obj.__dict__[outer_name] = value
            else:
                raise AttributeError('__set__')
        else:
            setter(obj, value)

    def __delete__(cls, obj):
        outer_class, outer_name = cls.__bind(obj.__class__)
        assert isinstance(obj, outer_class)

        inner = cls(obj)
        try:
            deleter = inner.__delete__
        except AttributeError:
            try:
                inner.__set__
            except AttributeError:
                try:
                    del obj.__dict__[outer_name]
                except KeyError:
                    raise AttributeError(outer_name)
            else:
                raise AttributeError('__delete__')
        else:
            deleter(obj)

    def __bind(cls, obj_type):
        try:
            outer_class = cls.__dict__['__outer_class__']
            name = cls.__dict__['__outer_name__']
        except KeyError:
            outer_class, name, value = None, None, None
            for outer_class in obj_type.__mro__:
                for name, value in six.iteritems(outer_class.__dict__):
                    if value is cls:
                        break
                if value is cls:
                    break
            assert value is cls

            cls.__outer_class__ = outer_class
            cls.__outer_name__ = name
            cls.__name__ = '.'.join((outer_class.__name__, name))
            cls.__qualname__ = cls.__name__

        return outer_class, name
