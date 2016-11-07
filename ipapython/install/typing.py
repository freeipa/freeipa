#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import weakref

import six

_cache = weakref.WeakValueDictionary()


class ListMeta(type):
    def __getitem__(cls, key):
        if not isinstance(key, type):
            raise TypeError("Parameters to generic types must be types. "
                            "Got {!r}.".format(key))

        t = ListMeta(
            cls.__name__,
            cls.__bases__,
            {
                '__parameters__': (key,),
                '__init__': cls.__init__,
            }
        )

        return _cache.get(key, t)


class List(six.with_metaclass(ListMeta, list)):
    __parameters__ = ()

    def __init__(self, *_args, **_kwargs):
        raise TypeError("Type List cannot be instantiated; use list() instead")
