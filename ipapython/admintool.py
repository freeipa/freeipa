# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2012  Red Hat
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

"""A common framework for command-line admin tools, e.g. install scripts

Handles common operations like option parsing and logging
"""

import logging
import sys
import os
import traceback
from optparse import OptionGroup  # pylint: disable=deprecated-module

from ipapython import version
from ipapython import config
from ipapython.ipa_log_manager import standard_logging_setup

SUCCESS = 0
SERVER_INSTALL_ERROR = 1
SERVER_NOT_CONFIGURED = 2

logger = logging.getLogger(__name__)


class ScriptError(Exception):
    """An exception that records an error message and a return value
    """
    def __init__(self, msg='', rval=1):
        if msg is None:
            msg = ''
        super(ScriptError, self).__init__(msg)
        self.rval = rval

    @property
    def msg(self):
        return str(self)


class AdminTool(object):
    """Base class for command-line admin tools

    To run the tool, call the main() classmethod with a list of command-line
    arguments.
    Alternatively, call run_cli() to run with command-line arguments in
    sys.argv, and call sys.exit() with the return value.

    Some commands actually represent multiple related tools, e.g.
    ``ipa-server-install`` and ``ipa-server-install --uninstall`` would be
    represented by separate classes. Only their options are the same.

    To handle this, AdminTool provides classmethods for option parsing
    and selecting the appropriate command class.

    A class-wide option parser is made by calling add_options.
    The options are then parsed into options and arguments, and
    get_command_class is called with those to retrieve the class.
    That class is then instantiated and run.

    Running consists of a few steps:
    - validating options or the environment (validate_options)
    - setting up logging (setup_logging)
    - running the actual command (run)

    Any unhandled exceptions are handled in handle_error.
    And at the end, either log_success or log_failure is called.

    Class attributes to define in subclasses:
    command_name - shown in logs
    log_file_name - if None, logging is to stderr only
    usage - text shown in help
    description - text shown in help

    See the setup_logging method for more info on logging.
    """
    command_name = None
    log_file_name = None
    usage = None
    description = None

    _option_parsers = dict()

    @classmethod
    def make_parser(cls):
        """Create an option parser shared across all instances of this class"""
        parser = config.IPAOptionParser(version=version.VERSION,
            usage=cls.usage, formatter=config.IPAFormatter(),
            description=cls.description)
        cls.option_parser = parser
        cls.add_options(parser)

    @classmethod
    def add_options(cls, parser, debug_option=False):
        """Add command-specific options to the option parser

        :param parser: The parser to add options to
        :param debug_option: Add a --debug option as an alias to --verbose
        """
        group = OptionGroup(parser, "Logging and output options")
        group.add_option("-v", "--verbose", dest="verbose", default=False,
            action="store_true", help="print debugging information")
        if debug_option:
            group.add_option("-d", "--debug", dest="verbose", default=False,
                action="store_true", help="alias for --verbose (deprecated)")
        group.add_option("-q", "--quiet", dest="quiet", default=False,
            action="store_true", help="output only errors")
        group.add_option("--log-file", dest="log_file", default=None,
            metavar="FILE", help="log to the given file")
        parser.add_option_group(group)

    @classmethod
    def run_cli(cls):
        """Run this command with sys.argv, exit process with the return value
        """
        sys.exit(cls.main(sys.argv))

    @classmethod
    def main(cls, argv):
        """The main entry point

        Parses command-line arguments, selects the actual command class to use
        based on them, and runs that command.

        :param argv: Command-line arguments.
        :return: Command exit code
        """
        if cls not in cls._option_parsers:
            # We use cls._option_parsers, a dictionary keyed on class, to check
            # if we need to create a parser. This is because cls.option_parser
            # can refer to the parser of a superclass.
            cls.make_parser()
            cls._option_parsers[cls] = cls.option_parser

        options, args = cls.option_parser.parse_args(argv[1:])

        command_class = cls.get_command_class(options, args)
        command = command_class(options, args)

        return command.execute()

    @classmethod
    def get_command_class(cls, options, args):
        return cls

    def __init__(self, options, args):
        self.options = options
        self.args = args
        self.safe_options = self.option_parser.get_safe_opts(options)

    def execute(self):
        """Do everything needed after options are parsed

        This includes validating options, setting up logging, doing the
        actual work, and handling the result.
        """
        self._setup_logging(no_file=True)
        return_value = 1
        try:
            self.validate_options()
            self.ask_for_options()
            self.setup_logging()
            return_value = self.run()
        except BaseException as exception:
            if isinstance(exception, ScriptError):
                # pylint: disable=no-member
                if exception.rval and exception.rval > return_value:
                    return_value = exception.rval  # pylint: disable=no-member
            traceback = sys.exc_info()[2]
            error_message, return_value = self.handle_error(exception)
            if return_value:
                self.log_failure(error_message, return_value, exception,
                    traceback)
                return return_value
        self.log_success()
        return return_value

    def validate_options(self, needs_root=False):
        """Validate self.options

        It's also possible to compute and store information that will be
        useful later, but no changes to the system should be made here.
        """
        if needs_root and os.getegid() != 0:
            raise ScriptError('Must be root to run %s' % self.command_name, 1)
        if self.options.verbose and self.options.quiet:
            raise ScriptError(
                'The --quiet and --verbose options are mutually exclusive')

    def ask_for_options(self):
        """Ask for missing options interactively

        Similar to validate_options. This is separate method because we want
        any validation errors to abort the script before bothering the user
        with prompts.

        Any options that might be asked for should also be validated here.
        """

    def setup_logging(self, log_file_mode='w'):
        """Set up logging

        :param _to_file: Setting this to false will disable logging to file.
            For internal use.

        If the --log-file option was given or if a filename is in
        self.log_file_name, the tool will log to that file. In this case,
        all messages are logged.

        What is logged to the console depends on command-line options:
        the default is INFO; --quiet sets ERROR; --verbose sets DEBUG.

        Rules of thumb for logging levels:
        - CRITICAL for fatal errors
        - ERROR for critical things that the admin must see, even with --quiet
        - WARNING for things that need to stand out in the log
        - INFO to display normal messages
        - DEBUG to spam about everything the program does
        - a plain print for things that should not be log (for example,
            interactive prompting)

        To log, use a module-level logger.

        Logging to file is only set up after option validation and prompting;
        before that, all output will go to the console only.
        """
        root_logger = logging.getLogger()
        for handler in root_logger.handlers:
            if (isinstance(handler, logging.StreamHandler) and
                    handler.stream is sys.stderr):  # pylint: disable=no-member
                root_logger.removeHandler(handler)
                break

        self._setup_logging(log_file_mode=log_file_mode)

    def _setup_logging(self, log_file_mode='w', no_file=False):
        if no_file:
            log_file_name = None
        elif self.options.log_file:
            log_file_name = self.options.log_file
        else:
            log_file_name = self.log_file_name
        if self.options.verbose:
            console_format = '%(name)s: %(levelname)s: %(message)s'
            verbose = True
            debug = True
        else:
            console_format = '%(message)s'
            debug = False
            if self.options.quiet:
                verbose = False
            else:
                verbose = True
        standard_logging_setup(
            log_file_name, console_format=console_format,
            filemode=log_file_mode, debug=debug, verbose=verbose)
        if log_file_name:
            logger.debug('Logging to %s', log_file_name)
        elif not no_file:
            logger.debug('Not logging to a file')


    def handle_error(self, exception):
        """Given an exception, return a message (or None) and process exit code
        """
        if isinstance(exception, ScriptError):
            return exception.msg, exception.rval or 1
        elif isinstance(exception, SystemExit):
            if isinstance(exception.code, int):
                return None, exception.code
            return str(exception.code), 1

        return str(exception), 1

    def run(self):
        """Actual running of the command

        This is where the hard work is done. The base implementation logs
        the invocation of the command.

        If this method returns (i.e. doesn't raise an exception), the tool is
        assumed to have run successfully, and the return value is used as the
        SystemExit code.
        """
        logger.debug('%s was invoked with arguments %s and options: %s',
                     self.command_name, self.args, self.safe_options)
        logger.debug('IPA version %s', version.VENDOR_VERSION)

    def log_failure(self, error_message, return_value, exception, backtrace):
        logger.debug('%s', ''.join(traceback.format_tb(backtrace)))
        logger.debug('The %s command failed, exception: %s: %s',
                     self.command_name, type(exception).__name__, exception)
        if error_message:
            logger.error('%s', error_message)
        message = "The %s command failed." % self.command_name
        if self.log_file_name and return_value != 2:
            # magic value because this is common between server and client
            # but imports are not straigthforward
            message += " See %s for more information" % self.log_file_name
        logger.error('%s', message)

    def log_success(self):
        logger.info('The %s command was successful', self.command_name)
