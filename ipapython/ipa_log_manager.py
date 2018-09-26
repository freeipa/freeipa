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

import logging
import os
import re
import time
import warnings
import sys

import six

# Module exports
__all__ = ['log_mgr', 'root_logger', 'standard_logging_setup',
           'ISO8601_UTC_DATETIME_FMT',
           'LOGGING_FORMAT_STDERR', 'LOGGING_FORMAT_STDOUT', 'LOGGING_FORMAT_FILE']

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


class _DeprecatedLogger:
    def __init__(self, logger, name):
        self._logger = logger
        self._name = name

    def _warn(self):
        warnings.warn(
            "{} is deprecated, use a module-level logger".format(self._name),
            DeprecationWarning)

    def debug(self, *args, **kwargs):
        self._warn()
        self._logger.debug(*args, **kwargs)

    def info(self, *args, **kwargs):
        self._warn()
        self._logger.info(*args, **kwargs)

    def warning(self, *args, **kwargs):
        self._warn()
        self._logger.warning(*args, **kwargs)

    def error(self, *args, **kwargs):
        self._warn()
        self._logger.error(*args, **kwargs)

    def critical(self, *args, **kwargs):
        self._warn()
        self._logger.critical(*args, **kwargs)

    def exception(self, *args, **kwargs):
        self._warn()
        self._logger.exception(*args, **kwargs)


def get_logger(who, bind_logger_names=False):
    if isinstance(who, six.string_types):
        warnings.warn(
            "{}.log_mgr.get_logger is deprecated, use "
            "logging.getLogger".format(__name__),
            DeprecationWarning)

        logger_name = who
    else:
        caller_globals = sys._getframe(1).f_globals
        logger_name = caller_globals.get('__name__', '__main__')
        if logger_name == '__main__':
            logger_name = caller_globals.get('__file__', logger_name)
            logger_name = os.path.basename(logger_name)

    logger = logging.getLogger(logger_name)

    if not isinstance(who, six.string_types):
        obj_name = '%s.%s' % (who.__module__, who.__class__.__name__)
        logger = _DeprecatedLogger(logger, obj_name)

    if bind_logger_names:
        method = 'log'
        if hasattr(who, method):
            raise ValueError('%s is already bound to %s' % (method, repr(who)))
        setattr(who, method, logger)

        for method in ('debug',
                       'info',
                       'warning',
                       'error',
                       'exception',
                       'critical'):
            if hasattr(who, method):
                raise ValueError(
                    '%s is already bound to %s' % (method, repr(who)))
            setattr(who, method, getattr(logger, method))

    return logger


class Filter:
    def __init__(self, regexp, level):
        self.regexp = re.compile(regexp)
        self.level = level

    def filter(self, record):
        return (not self.regexp.match(record.name) or
                record.levelno >= self.level)


class Formatter(logging.Formatter):
    def __init__(
            self, fmt=LOGGING_FORMAT_STDOUT, datefmt=ISO8601_UTC_DATETIME_FMT):
        super(Formatter, self).__init__(fmt, datefmt)
        self.converter = time.gmtime


def standard_logging_setup(filename=None, verbose=False, debug=False,
                           filemode='w', console_format=None):
    if console_format is None:
        console_format = LOGGING_FORMAT_STANDARD_CONSOLE

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # File output is always logged at debug level
    if filename is not None:
        umask = os.umask(0o177)
        try:
            file_handler = logging.FileHandler(filename, mode=filemode)
        finally:
            os.umask(umask)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(Formatter(LOGGING_FORMAT_STANDARD_FILE))
        root_logger.addHandler(file_handler)

    level = logging.ERROR
    if verbose:
        level = logging.INFO
    if debug:
        level = logging.DEBUG

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(Formatter(console_format))
    root_logger.addHandler(console_handler)


def convert_log_level(value):
    try:
        level = int(value)
    except ValueError:
        try:
            level = {
                'debug': logging.DEBUG,
                'info': logging.INFO,
                'warn': logging.WARNING,
                'warning': logging.WARNING,
                'error': logging.ERROR,
                'critical': logging.CRITICAL
            }[value.lower()]
        except KeyError:
            raise ValueError('unknown log level (%s)' % value)
    return level


# Single shared instance of log manager
log_mgr = sys.modules[__name__]

root_logger = _DeprecatedLogger(logging.getLogger(),
                                '{}.log_mgr.root_logger'.format(__name__))
