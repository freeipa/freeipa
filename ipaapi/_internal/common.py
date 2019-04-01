#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#
"""FreeIPA API package -- internal API wrapper
"""
from __future__ import absolute_import

import sys

try:
    from collections.abc import Mapping
except ImportError:
    from collections import Mapping


class _Default(object):  # pylint: disable=useless-object-inheritance
    def __repr__(self):
        return "<default>"


default = _Default()


class APIWrapper(object):  # pylint: disable=useless-object-inheritance
    """A wrapper for an ipalib.api object
    """

    __slots__ = ("_api",)

    def __init__(self, api):
        self._api = api


class APIMapping(APIWrapper, Mapping):
    __slots__ = ()

    def __dir__(self):
        return tuple(
            e
            for e in dir(type(self))
            if e.endswith("__") or not e.startswith("_")
        )


def mangle_exports(module_name):
    """Modify module members to change their fully qualified module name
    """
    mod = sys.modules[module_name]
    for name in mod.__all__:
        obj = getattr(mod, name)
        if hasattr(obj, "__module__"):
            obj.__module__ = module_name
