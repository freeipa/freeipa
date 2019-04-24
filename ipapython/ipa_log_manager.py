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

# Module exports
__all__ = ['standard_logging_setup', 'CommandOutput',
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

# Used by standard_logging_setup() for command line output
LOGGING_FORMAT_CMD_OUTPUT = '%(message)s'


class CommandOutput:
    """Command output -- log and print to user

    The CommandOutput type is a wrapper for a logger instance. It
    marks log calls to be printed out on stdout.

    Usage:

        import logging
        from ipapython.ipa_log_manager import CommandOutput

        logger = logging.getLogger(__name__)
        logcm = CommandOutput(logger)

        def install():
            logcm("Installing ...")

    Design note
    -----------

    The command logger instance is called ``logcm``, because the name has the
    same length as the ``print`` function. It may not be the prettiest name,
    but it avoids code reformatting and therefore merge conflicts.

    At first we considered to add a ``log_cmd`` method to all loggers.
    The ``logging.setLoggerClass`` is the public function to set a new logger
    class. To make it work, is has to be called before the first logger
    objects is instantiated. It's not appropriate to modify the logger
    early in ``ipalib``, because ``ipalib`` is also designed to get embedded
    into applications. And monkey-patching the ``logging.Logger`` class is
    a hack.
    """
    __slots__ = ('_logger',)

    def __init__(self, logger):
        self._logger = logger

    def __call__(self, msg, *args, **kwargs):
        if 'extra' not in kwargs:
            kwargs["extra"] = {"cmd_output": True}
        else:
            kwargs["extra"]["cmd_output"] = True
        level = kwargs.pop("level", logging.INFO)
        self._logger.log(level, msg, *args, **kwargs)


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


class ConsoleFormatter(logging.Formatter):
    def __init__(
            self, fmt=LOGGING_FORMAT_STDOUT, datefmt=ISO8601_UTC_DATETIME_FMT):
        super().__init__(fmt, datefmt)
        self.converter = time.gmtime
        self.cmd_output_formatter = logging.Formatter(
            LOGGING_FORMAT_CMD_OUTPUT)

    def format(self, record):
        """
        Format the specified record as text.

        Uses LOGGING_FORMAT_CMD_OUTPUT for info_cmd, otherwise normal logging
        format. For info_cmd record.__dict__["cmd_output"] is set to True.
        """
        if record.levelno >= logging.INFO and \
           getattr(record, "cmd_output", False):
            return self.cmd_output_formatter.format(record)

        # Return normal format
        return super().format(record)


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
    console_handler.setFormatter(ConsoleFormatter(console_format))
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
