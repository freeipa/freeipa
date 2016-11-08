# Authors: John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2011  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

#-------------------------------------------------------------------------------

# Module exports
__all__ = ['log_mgr', 'root_logger', 'standard_logging_setup',
           'IPA_ROOT_LOGGER_NAME', 'ISO8601_UTC_DATETIME_FMT',
           'LOGGING_FORMAT_STDERR', 'LOGGING_FORMAT_STDOUT', 'LOGGING_FORMAT_FILE']

#-------------------------------------------------------------------------------

import sys
import re
import copy

from ipapython.log_manager import LogManager, parse_log_level

#-------------------------------------------------------------------------------

# Our root logger, all loggers will be descendents of this.
IPA_ROOT_LOGGER_NAME = 'ipa'

# Format string for time.strftime() to produce a ISO 8601 date time
# formatted string in the UTC time zone.
ISO8601_UTC_DATETIME_FMT = '%Y-%m-%dT%H:%M:%SZ'

# Logging format string for use with logging stderr handlers
LOGGING_FORMAT_STDERR = 'ipa: %(levelname)s: %(message)s'

# Logging format string for use with logging stdout handlers
LOGGING_FORMAT_STDOUT = '[%(asctime)s %(name)s] <%(levelname)s>: %(message)s'

# Logging format string for use with logging file handlers
LOGGING_FORMAT_FILE = '\t'.join([
    '%(asctime)s',
    '%(process)d',
    '%(threadName)s',
    '%(name)s',
    '%(levelname)s',
    '%(message)s',
])

# Used by standard_logging_setup() for console message
LOGGING_FORMAT_STANDARD_CONSOLE = '%(name)-12s: %(levelname)-8s %(message)s'

# Used by standard_logging_setup() for file message
LOGGING_FORMAT_STANDARD_FILE = '%(asctime)s %(levelname)s %(message)s'

#-------------------------------------------------------------------------------

class IPALogManager(LogManager):
    '''
    Subclass the LogManager to enforce some IPA specfic logging
    conventions.

    * Default to timestamps in UTC.
    * Default to ISO 8601 timestamp format.
    * Default the message format.
    '''

    log_logger_level_config_re = re.compile(r'^log_logger_level_(debug|info|warn|warning|error|critical|\d+)$')

    def __init__(self, configure_state=None):
        '''
        :parameters:
          configure_state
            Used by clients of the log manager to track the
            configuration state, may be any object.
        '''

        super(IPALogManager, self).__init__(IPA_ROOT_LOGGER_NAME, configure_state)

    def configure_from_env(self, env, configure_state=None):
        '''
        Read the loggger configuration from the Env config. The
        following items may be configured:

        Logger Levels
          *log_logger_XXX = comma separated list of regexps*

          Logger levels can be explicitly specified for specific loggers as
          opposed to a global logging level. Specific loggers are indiciated
          by a list of regular expressions bound to a level. If a logger's
          name matches the regexp then it is assigned that level. The keys
          in the Env config must begin with "log_logger_level\_" and then be
          followed by a symbolic or numeric log level, for example::

            log_logger_level_debug = ipapython\.dn\..*
            log_logger_level_35 = ipalib\.plugins\.dogtag

          The first line says any logger belonging to the ipapython.dn module
          will have it's level configured to debug.

          The second line say the ipa.plugins.dogtag logger will be
          configured to level 35.

          Note: logger names are a dot ('.') separated list forming a path
          in the logger tree.  The dot character is also a regular
          expression metacharacter (matches any character) therefore you
          will usually need to escape the dot in the logger names by
          preceeding it with a backslash.

        The return value of this function is a dict with the following
        format:

        logger_regexps
          List of (regexp, level) tuples

        :parameters:
          env
            Env object configuration values are read from.
          configure_state
            If other than None update the log manger's configure_state
            variable to this object. Clients of the log manager can
            use configure_state to track the state of the log manager.
        '''
        logger_regexps = []
        config = {'logger_regexps' : logger_regexps,
                 }

        for attr in ('debug', 'verbose'):
            value = getattr(env, attr, None)
            if value is not None:
                config[attr] = value

        for attr in list(env):
            # Get logger level configuration
            match = IPALogManager.log_logger_level_config_re.search(attr)
            if match:
                value = match.group(1)
                level = parse_log_level(value)
                value = getattr(env, attr)
                regexps = re.split('\s*,\s*', value)
                # Add the regexp, it maps to the configured level
                for regexp in regexps:
                    logger_regexps.append((regexp, level))
                continue

        self.configure(config, configure_state)
        return config

    def create_log_handlers(self, configs, logger=None, configure_state=None):
        'Enforce some IPA specific configurations'
        configs = copy.copy(configs)

        for cfg in configs:
            if not 'time_zone_converter' in cfg:
                cfg['time_zone_converter'] = 'utc'
            if not 'datefmt' in cfg:
                cfg['datefmt'] = ISO8601_UTC_DATETIME_FMT
            if not 'format' in cfg:
                cfg['format'] = LOGGING_FORMAT_STDOUT

        return super(IPALogManager, self).create_log_handlers(configs, logger, configure_state)

#-------------------------------------------------------------------------------

def standard_logging_setup(filename=None, verbose=False, debug=False,
                           filemode='w', console_format=None):
    if console_format is None:
        console_format = LOGGING_FORMAT_STANDARD_CONSOLE

    handlers = []

    # File output is always logged at debug level
    if filename is not None:
        file_handler = dict(name='file',
                            filename=filename,
                            filemode=filemode,
                            permission=0o600,
                            level='debug',
                            format=LOGGING_FORMAT_STANDARD_FILE)
        handlers.append(file_handler)

    if 'console' in log_mgr.handlers:
        log_mgr.remove_handler('console')
    level = 'error'
    if verbose:
        level = 'info'
    if debug:
        level = 'debug'

    console_handler = dict(name='console',
                           stream=sys.stderr,
                           level=level,
                           format=console_format)
    handlers.append(console_handler)


    # default_level must be debug becuase we want the file handler to
    # always log at the debug level.
    log_mgr.configure(dict(default_level='debug',
                           handlers=handlers),
                      configure_state='standard')

    return log_mgr.root_logger

#-------------------------------------------------------------------------------

# Single shared instance of log manager
#
# By default always starts with stderr console handler at error level
# so messages generated before logging is fully configured have some
# place to got and won't get lost.

log_mgr = IPALogManager()
log_mgr.configure(dict(default_level='error',
                       handlers=[dict(name='console',
                                      stream=sys.stderr)]),
                  configure_state='default')
root_logger = log_mgr.root_logger
