#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
Utilities.
"""

import sys


def raise_exc_info(exc_info):
    """
    Raise exception from exception info tuple as returned by `sys.exc_info()`.
    """

    raise exc_info[0], exc_info[1], exc_info[2]


class from_(object):
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
        raise_exc_info(exc_info)


class InnerClassMeta(type):
    def __new__(cls, name, bases, class_dict):
        class_dict.pop('__outer_class__', None)
        class_dict.pop('__outer_name__', None)

        return super(InnerClassMeta, cls).__new__(cls, name, bases, class_dict)

    def __get__(self, obj, obj_type):
        outer_class, outer_name = self.__bind(obj_type)
        if obj is None:
            return self
        assert isinstance(obj, outer_class)

        try:
            return obj.__dict__[outer_name]
        except KeyError:
            inner = self(obj)
            try:
                getter = inner.__get__
            except AttributeError:
                return inner
            else:
                return getter(obj, obj_type)

    def __set__(self, obj, value):
        outer_class, outer_name = self.__bind(obj.__class__)
        assert isinstance(obj, outer_class)

        inner = self(obj)
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

    def __delete__(self, obj):
        outer_class, outer_name = self.__bind(obj.__class__)
        assert isinstance(obj, outer_class)

        inner = self(obj)
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

    def __bind(self, obj_type):
        try:
            cls = self.__dict__['__outer_class__']
            name = self.__dict__['__outer_name__']
        except KeyError:
            cls, name, value = None, None, None
            for cls in obj_type.__mro__:
                for name, value in cls.__dict__.iteritems():
                    if value is self:
                        break
                if value is self:
                    break
            assert value is self

            self.__outer_class__ = cls
            self.__outer_name__ = name
            self.__name__ = '.'.join((cls.__name__, name))

        return cls, name
