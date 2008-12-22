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

from ConfigParser import RawConfigParser, ParsingError
import types
import os
from os import path
import sys
import constants



class Env(object):
    """
    A mapping object used to store the environment variables.
    """

    __locked = False

    def __init__(self):
        object.__setattr__(self, '_Env__d', {})
        object.__setattr__(self, '_Env__done', set())
        self.ipalib = path.dirname(path.abspath(__file__))
        self.site_packages = path.dirname(self.ipalib)
        self.script = path.abspath(sys.argv[0])
        self.bin = path.dirname(self.script)
        self.home = path.abspath(os.environ['HOME'])
        self.dot_ipa = path.join(self.home, '.ipa')

    def __doing(self, name):
        if name in self.__done:
            raise StandardError(
                '%s.%s() already called' % (self.__class__.__name__, name)
            )
        self.__done.add(name)

    def __do_if_not_done(self, name):
        if name not in self.__done:
            getattr(self, name)()

    def _isdone(self, name):
        return name in self.__done

    def _bootstrap(self, **overrides):
        """
        Initialize basic environment.

        This method will initialize only enough environment information to
        determine whether ipa is running in-tree, what the context is,
        and the location of the configuration file.
        """
        self.__doing('_bootstrap')
        for (key, value) in overrides.iteritems():
            self[key] = value
        if 'in_tree' not in self:
            if self.bin == self.site_packages and \
                    path.isfile(path.join(self.bin, 'setup.py')):
                self.in_tree = True
            else:
                self.in_tree = False
        if 'context' not in self:
            self.context = 'default'
        if self.in_tree:
            base = self.dot_ipa
        else:
            base = path.join('/', 'etc', 'ipa')
        if 'conf' not in self:
            self.conf = path.join(base, '%s.conf' % self.context)
        if 'conf_default' not in self:
            self.conf_default = path.join(base, 'default.conf')
        if 'conf_dir' not in self:
            self.conf_dir = base

    def _finalize_core(self, **defaults):
        """
        Complete initialization of standard IPA environment.

        After this method is called, the all environment variables
        used by all the built-in plugins will be available.

        This method should be called before loading any plugins. It will
        automatically call `Env._bootstrap()` if it has not yet been called.

        After this method has finished, the `Env` instance is still writable
        so that third
        """
        self.__doing('_finalize_core')
        self.__do_if_not_done('_bootstrap')
        if self.__d.get('mode', None) != 'dummy':
            self._merge_config(self.conf)
            self._merge_config(self.conf_default)
        if 'in_server' not in self:
            self.in_server = (self.context == 'server')
        if 'log' not in self:
            name = '%s.log' % self.context
            if self.in_tree or self.context == 'cli':
                self.log = path.join(self.dot_ipa, 'log', name)
            else:
                self.log = path.join('/', 'var', 'log', 'ipa', name)
        for (key, value) in defaults.iteritems():
            if key not in self:
                self[key] = value

    def _finalize(self, **lastchance):
        """
        Finalize and lock environment.

        This method should be called after all plugins have bean loaded and
        after `plugable.API.finalize()` has been called.
        """
        self.__doing('_finalize')
        self.__do_if_not_done('_finalize_core')
        for (key, value) in lastchance.iteritems():
            if key not in self:
                self[key] = value
        self.__lock__()

    def _merge_config(self, conf_file):
        """
        Merge values from ``conf_file`` into this `Env`.
        """
        section = constants.CONFIG_SECTION
        if not path.isfile(conf_file):
            return
        parser = RawConfigParser()
        try:
            parser.read(conf_file)
        except ParsingError:
            return
        if not parser.has_section(section):
            parser.add_section(section)
        items = parser.items(section)
        if len(items) == 0:
            return
        i = 0
        for (key, value) in items:
            if key not in self:
                self[key] = value
                i += 1
        return (i, len(items))

    def __lock__(self):
        """
        Prevent further changes to environment.
        """
        if self.__locked is True:
            raise StandardError(
                '%s.__lock__() already called' % self.__class__.__name__
            )
        object.__setattr__(self, '_Env__locked', True)

    def __islocked__(self):
        return self.__locked

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
        return self.__d[key]

    def __setitem__(self, key, value):
        """
        Set ``key`` to ``value``.
        """
        # FIXME: the key should be checked with check_name()
        if self.__locked:
            raise AttributeError('locked: cannot set %s.%s to %r' %
                (self.__class__.__name__, key, value)
            )
        if key in self.__d or hasattr(self, key):
            raise AttributeError('cannot overwrite %s.%s with %r' %
                (self.__class__.__name__, key, value)
            )
        if isinstance(value, basestring):
            value = str(value.strip())
            if value.lower() == 'true':
                value = True
            elif value.lower() == 'false':
                value = False
            elif value.isdigit():
                value = int(value)
        assert type(value) in (str, int, bool)
        object.__setattr__(self, key, value)
        self.__d[key] = value

    def __contains__(self, key):
        """
        Return True if instance contains ``key``; otherwise return False.
        """
        return key in self.__d

    def __len__(self):
        """
        Return number of variables currently set.
        """
        return len(self.__d)

    def __iter__(self):
        """
        Iterate through keys in ascending order.
        """
        for key in sorted(self.__d):
            yield key
