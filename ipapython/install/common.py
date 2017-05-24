#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
Common stuff.
"""

import logging
import traceback

from . import core
from .util import from_

__all__ = ['step', 'Installable', 'Interactive', 'Continuous', 'installer',
           'uninstaller']

logger = logging.getLogger(__name__)


def step():
    def decorator(func):
        cls = core.Component(Step)
        cls._installer = staticmethod(func)
        return cls

    return decorator


class Installable(core.Configurable):
    """
    Configurable which does install or uninstall.
    """

    uninstalling = core.Property(False)

    def _get_components(self):
        components = super(Installable, self)._get_components()
        if self.uninstalling:
            components = reversed(list(components))
        return components

    def _configure(self):
        if self.uninstalling:
            return self._uninstall()
        else:
            return self._install()

    def _install(self):
        assert not hasattr(super(Installable, self), '_install')

        return super(Installable, self)._configure()

    def _uninstall(self):
        assert not hasattr(super(Installable, self), '_uninstall')

        return super(Installable, self)._configure()


class Step(Installable):
    @property
    def parent(self):
        raise AttributeError('parent')

    def _install(self):
        for _nothing in self._installer(self.parent):
            yield from_(super(Step, self)._install())

    @staticmethod
    def _installer(obj):
        yield

    def _uninstall(self):
        for _nothing in self._uninstaller(self.parent):
            yield from_(super(Step, self)._uninstall())

    @staticmethod
    def _uninstaller(obj):
        yield

    @classmethod
    def uninstaller(cls, func):
        cls._uninstaller = staticmethod(func)
        return cls


class Interactive(core.Configurable):
    interactive = core.Property(False)


class Continuous(core.Configurable):
    def _handle_execute_exception(self, exc_info):
        try:
            super(Continuous, self)._handle_execute_exception(exc_info)
        except BaseException as e:
            logger.debug("%s", traceback.format_exc())
            if isinstance(e, Exception):
                logger.error("%s", e)


def installer(cls):
    class Installer(cls, Installable):
        def __init__(self, **kwargs):
            super(Installer, self).__init__(uninstalling=False,
                                            **kwargs)
    Installer.__name__ = 'installer({0})'.format(cls.__name__)

    return Installer


def uninstaller(cls):
    class Uninstaller(Continuous, cls, Installable):
        def __init__(self, **kwargs):
            super(Uninstaller, self).__init__(uninstalling=True,
                                              **kwargs)
    Uninstaller.__name__ = 'uninstaller({0})'.format(cls.__name__)

    return Uninstaller
