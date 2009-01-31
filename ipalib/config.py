# Authors:
#   Martin Nagy <mnagy@redhat.com>
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
Process-wide static configuration and environment.

The standard run-time instance of the `Env` class is initialized early in the
`ipalib` process and is then locked into a read-only state, after which no
further changes can be made to the environment throughout the remaining life
of the process.

For the per-request thread-local information, see `ipalib.request`.
"""

from ConfigParser import RawConfigParser, ParsingError
from types import NoneType
import os
from os import path
import sys
from socket import gethostname

from base import check_name
from constants import CONFIG_SECTION
from constants import TYPE_ERROR, OVERRIDE_ERROR, SET_ERROR, DEL_ERROR


class Env(object):
    """
    Store and retrieve environment variables.

    First an foremost, the `Env` class provides a handy container for
    environment variables.  These variables can be both set *and* retrieved
    either as attributes *or* as dictionary items.

    For example, you can set a variable as an attribute:

    >>> env = Env()
    >>> env.attr = 'I was set as an attribute.'
    >>> env.attr
    'I was set as an attribute.'
    >>> env['attr']  # Also retrieve as a dictionary item
    'I was set as an attribute.'

    Or you can set a variable as a dictionary item:

    >>> env['item'] = 'I was set as a dictionary item.'
    >>> env['item']
    'I was set as a dictionary item.'
    >>> env.item  # Also retrieve as an attribute
    'I was set as a dictionary item.'

    The variable names must be valid lower-case Python identifiers that neither
    start nor end with an underscore.  If your variable name doesn't meet these
    criteria, a ``ValueError`` will be raised when you try to set the variable
    (compliments of the `base.check_name()` function).  For example:

    >>> env.BadName = 'Wont work as an attribute'
    Traceback (most recent call last):
      ...
    ValueError: name must match '^[a-z][_a-z0-9]*[a-z0-9]$'; got 'BadName'
    >>> env['BadName'] = 'Also wont work as a dictionary item'
    Traceback (most recent call last):
      ...
    ValueError: name must match '^[a-z][_a-z0-9]*[a-z0-9]$'; got 'BadName'

    The variable values can be ``str``, ``int``, or ``float`` instances, or the
    ``True``, ``False``, or ``None`` constants.  When the value provided is an
    ``str`` instance, some limited automatic type conversion is performed, which
    allows values of specific types to be set easily from configuration files or
    command-line options.

    So in addition to their actual values, the ``True``, ``False``, and ``None``
    constants can be specified with an ``str`` equal to what ``repr()`` would
    return.  For example:

    >>> env.true = True
    >>> env.also_true = 'True'  # Equal to repr(True)
    >>> env.true
    True
    >>> env.also_true
    True

    Note that the automatic type conversion is case sensitive.  For example:

    >>> env.not_false = 'false'  # Not equal to repr(False)!
    >>> env.not_false
    'false'

    If an ``str`` value looks like an integer, it's automatically converted to
    the ``int`` type.  Likewise, if an ``str`` value looks like a floating-point
    number, it's automatically converted to the ``float`` type.  For example:

    >>> env.lucky = '7'
    >>> env.lucky
    7
    >>> env.three_halves = '1.5'
    >>> env.three_halves
    1.5

    Leading and trailing white-space is automatically stripped from ``str``
    values.  For example:

    >>> env.message = '  Hello!  '  # Surrounded by double spaces
    >>> env.message
    'Hello!'
    >>> env.number = ' 42 '  # Still converted to an int
    >>> env.number
    42
    >>> env.false = ' False '  # Still equal to repr(False)
    >>> env.false
    False

    Also, empty ``str`` instances are converted to ``None``.  For example:

    >>> env.empty = ''
    >>> env.empty is None
    True

    `Env` variables are all set-once (first-one-wins).  Once a variable has been
    set, trying to override it will raise an ``AttributeError``.  For example:

    >>> env.date = 'First'
    >>> env.date = 'Second'
    Traceback (most recent call last):
      ...
    AttributeError: cannot override Env.date value 'First' with 'Second'

    An `Env` instance can be *locked*, after which no further variables can be
    set.  Trying to set variables on a locked `Env` instance will also raise
    an ``AttributeError``.  For example:

    >>> env = Env()
    >>> env.okay = 'This will work.'
    >>> env.__lock__()
    >>> env.nope = 'This wont work!'
    Traceback (most recent call last):
      ...
    AttributeError: locked: cannot set Env.nope to 'This wont work!'

    `Env` instances also provide standard container emulation for membership
    testing, counting, and iteration.  For example:

    >>> env = Env()
    >>> 'key1' in env  # Has key1 been set?
    False
    >>> env.key1 = 'value 1'
    >>> 'key1' in env
    True
    >>> env.key2 = 'value 2'
    >>> len(env)  # How many variables have been set?
    2
    >>> list(env)  # What variables have been set?
    ['key1', 'key2']

    Lastly, in addition to all the handy container functionality, the `Env`
    class provides high-level methods for bootstraping a fresh `Env` instance
    into one containing all the run-time and configuration information needed
    by the built-in freeIPA plugins.

    These are the `Env` bootstraping methods, in the order they must be called:

        1. `Env._bootstrap()` - initialize the run-time variables and then
           merge-in variables specified on the command-line.

        2. `Env._finalize_core()` - merge-in variables from the configuration
           files and then merge-in variables from the internal defaults, after
           which at least all the standard variables will be set.  After this
           method is called, the plugins will be loaded, during which
           third-party plugins can merge-in defaults for additional variables
           they use (likely using the `Env._merge()` method).

        3. `Env._finalize()` - one last chance to merge-in variables and then
           the instance is locked.  After this method is called, no more
           environment variables can be set during the remaining life of the
           process.

    However, normally none of these three bootstraping methods are called
    directly and instead only `plugable.API.bootstrap()` is called, which itself
    takes care of correctly calling the `Env` bootstrapping methods.
    """

    __locked = False

    def __init__(self):
        object.__setattr__(self, '_Env__d', {})
        object.__setattr__(self, '_Env__done', set())

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
        """
        Return ``True`` if locked.
        """
        return self.__locked

    def __setattr__(self, name, value):
        """
        Set the attribute named ``name`` to ``value``.

        This just calls `Env.__setitem__()`.
        """
        self[name] = value

    def __setitem__(self, key, value):
        """
        Set ``key`` to ``value``.
        """
        if self.__locked:
            raise AttributeError(
                SET_ERROR % (self.__class__.__name__, key, value)
            )
        check_name(key)
        if key in self.__d:
            raise AttributeError(OVERRIDE_ERROR %
                (self.__class__.__name__, key, self.__d[key], value)
            )
        assert not hasattr(self, key)
        if isinstance(value, basestring):
            value = str(value.strip())
            m = {
                'True': True,
                'False': False,
                'None': None,
                '': None,
            }
            if value in m:
                value = m[value]
            elif value.isdigit():
                value = int(value)
            else:
                try:
                    value = float(value)
                except (TypeError, ValueError):
                    pass
        assert type(value) in (str, int, float, bool, NoneType)
        object.__setattr__(self, key, value)
        self.__d[key] = value

    def __getitem__(self, key):
        """
        Return the value corresponding to ``key``.
        """
        return self.__d[key]

    def __delattr__(self, name):
        """
        Raise an ``AttributeError`` (deletion is never allowed).

        For example:

        >>> env = Env()
        >>> env.name = 'A value'
        >>> del env.name
        Traceback (most recent call last):
          ...
        AttributeError: locked: cannot delete Env.name
        """
        raise AttributeError(
            DEL_ERROR % (self.__class__.__name__, name)
        )

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

    def _merge(self, **kw):
        """
        Merge variables from ``kw`` into the environment.

        Any variables in ``kw`` that have already been set will be ignored
        (meaning this method will *not* try to override them, which would raise
        an exception).

        This method returns a ``(num_set, num_total)`` tuple containing first
        the number of variables that were actually set, and second the total
        number of variables that were provided.

        For example:

        >>> env = Env()
        >>> env._merge(one=1, two=2)
        (2, 2)
        >>> env._merge(one=1, three=3)
        (1, 2)
        >>> env._merge(one=1, two=2, three=3)
        (0, 3)

        Also see `Env._merge_from_file()`.

        :param kw: Variables provides as keyword arguments.
        """
        i = 0
        for (key, value) in kw.iteritems():
            if key not in self:
                self[key] = value
                i += 1
        return (i, len(kw))

    def _merge_from_file(self, config_file):
        """
        Merge variables from ``config_file`` into the environment.

        Any variables in ``config_file`` that have already been set will be
        ignored (meaning this method will *not* try to override them, which
        would raise an exception).

        If ``config_file`` does not exist or is not a regular file, or if there
        is an error parsing ``config_file``, ``None`` is returned.

        Otherwise this method returns a ``(num_set, num_total)`` tuple
        containing first the number of variables that were actually set, and
        second the total number of variables found in ``config_file``.

        This method will raise a ``ValueError`` if ``config_file`` is not an
        absolute path.  For example:

        >>> env = Env()
        >>> env._merge_from_file('my/config.conf')
        Traceback (most recent call last):
          ...
        ValueError: config_file must be an absolute path; got 'my/config.conf'

        Also see `Env._merge()`.

        :param config_file: Absolute path of the configuration file to load.
        """
        if path.abspath(config_file) != config_file:
            raise ValueError(
                'config_file must be an absolute path; got %r' % config_file
            )
        if not path.isfile(config_file):
            return
        parser = RawConfigParser()
        try:
            parser.read(config_file)
        except ParsingError:
            return
        if not parser.has_section(CONFIG_SECTION):
            parser.add_section(CONFIG_SECTION)
        items = parser.items(CONFIG_SECTION)
        if len(items) == 0:
            return (0, 0)
        i = 0
        for (key, value) in items:
            if key not in self:
                self[key] = value
                i += 1
        return (i, len(items))

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

        This method will perform the following steps:

            1. Initialize certain run-time variables.  These run-time variables
               are strictly determined by the external environment the process
               is running in; they cannot be specified on the command-line nor
               in the configuration files.

            2. Merge-in the variables in ``overrides`` by calling
               `Env._merge()`.  The intended use of ``overrides`` is to merge-in
               variables specified on the command-line.

            3. Intelligently fill-in the *in_tree*, *context*, *conf*, and
               *conf_default* variables if they haven't been set already.

        Also see `Env._finalize_core()`, the next method in the bootstrap
        sequence.

        :param overrides: Variables specified via command-line options.
        """
        self.__doing('_bootstrap')

        # Set run-time variables:
        self.host = gethostname()
        self.ipalib = path.dirname(path.abspath(__file__))
        self.site_packages = path.dirname(self.ipalib)
        self.script = path.abspath(sys.argv[0])
        self.bin = path.dirname(self.script)
        self.home = os.environ.get('HOME', None)
        self.dot_ipa = self._join('home', '.ipa')
        self._merge(**overrides)
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

    def _join(self, key, *parts):
        if key in self and self[key] is not None:
            return path.join(self[key], *parts)

    def _finalize_core(self, **defaults):
        """
        Complete initialization of standard IPA environment.

        This method will perform the following steps:

            1. Call `Env._bootstrap()` if it hasn't already been called.

            2. Merge-in variables from the configuration file ``self.conf``
               (if it exists) by calling `Env._merge_from_file()`.

            3. Merge-in variables from the defaults configuration file
               ``self.conf_default`` (if it exists) by calling
               `Env._merge_from_file()`.

            4. Intelligently fill-in the *in_server* and *log* variables
               if they haven't already been set.

            5. Merge-in the variables in ``defaults`` by calling `Env._merge()`.
               In normal circumstances ``defaults`` will simply be those
               specified in `constants.DEFAULT_CONFIG`.

        After this method is called, all the environment variables used by all
        the built-in plugins will be available.  As such, this method should be
        called *before* any plugins are loaded.

        After this method has finished, the `Env` instance is still writable
        so that 3rd-party plugins can set variables they may require as the
        plugins are registered.

        Also see `Env._finalize()`, the final method in the bootstrap sequence.

        :param defaults: Internal defaults for all built-in variables.
        """
        self.__doing('_finalize_core')
        self.__do_if_not_done('_bootstrap')
        if self.__d.get('mode', None) != 'dummy':
            self._merge_from_file(self.conf)
            self._merge_from_file(self.conf_default)
        if 'in_server' not in self:
            self.in_server = (self.context == 'server')
        if 'log' not in self:
            name = '%s.log' % self.context
            if self.in_tree or self.context == 'cli':
                self.log = path.join(self.dot_ipa, 'log', name)
            else:
                self.log = path.join('/', 'var', 'log', 'ipa', name)
        if 'ca_host' not in self:
            self.ca_host = self.host
        self._merge(**defaults)

    def _finalize(self, **lastchance):
        """
        Finalize and lock environment.

        This method will perform the following steps:

            1. Call `Env._finalize_core()` if it hasn't already been called.

            2. Merge-in the variables in ``lastchance`` by calling
               `Env._merge()`.

            3. Lock this `Env` instance, after which no more environment
               variables can be set on this instance.  Aside from unit-tests
               and example code, normally only one `Env` instance is created,
               which means that after this step, no more variables can be set
               during the remaining life of the process.

        This method should be called after all plugins have been loaded and
        after `plugable.API.finalize()` has been called.

        :param lastchance: Any final variables to merge-in before locking.
        """
        self.__doing('_finalize')
        self.__do_if_not_done('_finalize_core')
        self._merge(**lastchance)
        self.__lock__()
