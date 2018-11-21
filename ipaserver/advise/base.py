# Authors: Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2013  Red Hat
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
#

from __future__ import print_function, absolute_import

from contextlib import contextmanager
import logging
import os
from textwrap import wrap

from ipalib import api
from ipalib.plugable import Plugin, API
from ipalib.errors import ValidationError
from ipaplatform.paths import paths
from ipapython import admintool
from ipapython.ipa_log_manager import Filter
from ipaserver.install import installutils


"""
To add configuration instructions for a new use case, define a new class that
inherits from Advice class.

You should create a plugin file for it in ipaserver/advise/plugins folder.

The class can run any arbitrary code or IPA command via api.Command['command']()
calls. It needs to override get_info() method, which returns the formatted
advice string.

Important! Do not forget to register the class to the API.

>>> @register()
>>> class sample_advice(Advice):
>>>     description = 'Instructions for machine with SSSD 1.0 setup.'

Description provided shows itself as a header and in the list of all advices
currently available via ipa-advise.

Optionally, you can require root privileges for your plugin:

>>>     require_root = True

The following method should be implemented in your plugin:

>>>     def get_info():
>>>         self.log.debug('Entering execute() method')
>>>         self.log.comment('Providing useful advice just for you')
>>>         self.log.command('yum update sssd -y')

As you can see, Advice's log has 3 different levels. Debug lines are printed
out with '# DEBUG:' prefix if --verbose had been used. Comment lines utilize
'# ' prefix and command lines are printed raw.

Please note that comments are automatically wrapped after 70 characters.
Use wrapped=False option to force the unwrapped line in the comment.

>>>         self.log.comment("This line should not be wrapped", wrapped=False)

As a result, you can redirect the advice's output directly to a script file.

# ipa-advise sample-advice > script.sh
# ./script.sh
"""

DEFAULT_INDENTATION_INCREMENT = 2


class _IndentationTracker(object):
    """
    A simple wrapper that tracks the indentation level of the generated bash
    commands
    """
    def __init__(self, spaces_per_indent=0):
        if spaces_per_indent <= 0:
            raise ValueError(
                "Indentation increments cannot be zero or negative")
        self.spaces_per_indent = spaces_per_indent
        self._indentation_stack = []
        self._total_indentation_level = 0

    @property
    def indentation_string(self):
        """
        return a string containing number of spaces corresponding to
        indentation level
        """
        return " " * self._total_indentation_level

    def indent(self):
        """
        track a single indentation of the generated code
        """
        self._indentation_stack.append(self.spaces_per_indent)
        self._recompute_indentation_level()

    def _recompute_indentation_level(self):
        """
        Track total indentation level of the generated code
        """
        self._total_indentation_level = sum(self._indentation_stack)

    def dedent(self):
        """
        track a single dedentation of the generated code
        dedents that would result in zero or negative indentation level will be
        ignored
        """
        try:
            self._indentation_stack.pop()
        except IndexError:
            # can not dedent any further
            pass

        self._recompute_indentation_level()


class CompoundStatement(object):
    """
    Wrapper around indented blocks of Bash statements.

    Override `begin_statement` and `end_statement` methods to issue
    opening/closing commands using the passed in _AdviceOutput instance
    """

    def __init__(self, advice_output):
        self.advice_output = advice_output

    def __enter__(self):
        self.begin_statement()
        self.advice_output.indent()

    def begin_statement(self):
        pass

    def __exit__(self, exc_type, exc_value, traceback):
        self.advice_output.dedent()
        self.end_statement()

    def end_statement(self):
        pass


class IfBranch(CompoundStatement):
    """
    Base wrapper around `if` branch. The closing statement is empty so it
    leaves trailing block that can be closed off or continued by else branches
    """
    def __init__(self, advice_output, conditional):
        super(IfBranch, self).__init__(advice_output)
        self.conditional = conditional

    def begin_statement(self):
        self.advice_output.command('if {}'.format(self.conditional))
        self.advice_output.command('then')


class ElseIfBranch(CompoundStatement):
    """
    Wrapper for `else if <CONDITIONAL>`
    """
    def __init__(self, advice_output, alternative_conditional):
        super(ElseIfBranch, self).__init__(advice_output)
        self.alternative_conditional = alternative_conditional

    def begin_statement(self):
        command = 'else if {}'.format(self.alternative_conditional)

        self.advice_output.command(command)


class ElseBranch(CompoundStatement):
    """
    Wrapper for final `else` block
    """
    def begin_statement(self):
        self.advice_output.command('else')

    def end_statement(self):
        self.advice_output.command('fi')


class UnbranchedIfStatement(IfBranch):
    """
    Plain `if` without branches
    """
    def end_statement(self):
        self.advice_output.command('fi')


class ForLoop(CompoundStatement):
    """
    Wrapper around the for loop
    """
    def __init__(self, advice_output, loop_variable, iterable):
        super(ForLoop, self).__init__(advice_output)
        self.loop_variable = loop_variable
        self.iterable = iterable

    def begin_statement(self):
        self.advice_output.command(
            'for {} in {}'.format(self.loop_variable, self.iterable))
        self.advice_output.command('do')

    def end_statement(self):
        self.advice_output.command('done')


class _AdviceOutput(object):

    def __init__(self):
        self.content = []
        self.prefix = '# '
        self.options = None
        self.pkgmgr_detected = False
        self._indentation_tracker = _IndentationTracker(
            spaces_per_indent=DEFAULT_INDENTATION_INCREMENT)

    def indent(self):
        """
        Indent the statements by one level
        """
        self._indentation_tracker.indent()

    def dedent(self):
        """
        Dedent the statements by one level
        """
        self._indentation_tracker.dedent()

    @contextmanager
    def indented_block(self):
        self.indent()
        try:
            yield
        finally:
            self.dedent()

    def comment(self, line, wrapped=True):
        if wrapped:
            self.append_wrapped_and_indented_comment(line)
        else:
            self.append_comment(line)

    def append_wrapped_and_indented_comment(self, line, character_limit=70):
        """
        append wrapped and indented comment to the output
        """
        for wrapped_indented_line in wrap(
                self.indent_statement(line), character_limit):
            self.append_comment(wrapped_indented_line)

    def append_comment(self, line):
        self.append_statement(self.prefix + line)

    def append_statement(self, statement):
        """
        Append a line to the generated content indenting it by tracked number
        of spaces
        """
        self.content.append(self.indent_statement(statement))

    def indent_statement(self, statement):
        return '{indent}{statement}'.format(
            indent=self._indentation_tracker.indentation_string,
            statement=statement)

    def debug(self, line):
        if self.options.verbose:
            self.comment('DEBUG: ' + line)

    def command(self, line):
        self.append_statement(line)

    def echo_error(self, error_message):
        self.command(self._format_error(error_message))

    def _format_error(self, error_message):
        return 'echo "{}" >&2'.format(error_message)

    def exit_on_failed_command(self, command_to_run,
                               error_message_lines):
        self.command(command_to_run)
        self.exit_on_predicate(
            '[ "$?" -ne "0" ]',
            error_message_lines)

    def exit_on_nonroot_euid(self):
        self.exit_on_predicate(
            '[ "$(id -u)" -ne "0" ]',
            ["This script has to be run as root user"]
        )

    def exit_on_predicate(self, predicate, error_message_lines):
        with self.unbranched_if(predicate):
            for error_message_line in error_message_lines:
                self.command(self._format_error(error_message_line))

            self.command('exit 1')

    def detect_pkgmgr(self):
        self.commands_on_predicate(
            'which yum >/dev/null',
            commands_to_run_when_true=['PKGMGR=yum'],
            commands_to_run_when_false=['PKGMGR=dnf']
        )
        self.pkgmgr_detected = True

    def install_packages(self, names, error_message_lines):
        assert isinstance(names, list)
        self.detect_pkgmgr()
        self.command('rpm -qi {} > /dev/null'.format(' '.join(names)))
        self.commands_on_predicate(
            '[ "$?" -ne "0" ]',
            ['$PKGMGR install -y {}'.format(' '.join(names))]
        )
        self.exit_on_predicate(
            '[ "$?" -ne "0" ]',
            error_message_lines
        )

    def remove_package(self, name, error_message_lines):
        # remove only supports one package name
        assert ' ' not in name
        self.detect_pkgmgr()
        self.command('rpm -qi {} > /dev/null'.format(name))
        self.commands_on_predicate(
            '[ "$?" -eq "0" ]',
            ['$PKGMGR remove -y {} || exit 1'.format(name)]
        )
        self.exit_on_predicate(
            '[ "$?" -ne "0" ]',
            error_message_lines
        )

    @contextmanager
    def unbranched_if(self, predicate):
        with self._compound_statement(UnbranchedIfStatement, predicate):
            yield

    @contextmanager
    def _compound_statement(self, statement_cls, *args):
        with statement_cls(self, *args):
            yield

    def commands_on_predicate(self, predicate, commands_to_run_when_true,
                              commands_to_run_when_false=None):
        if commands_to_run_when_false is not None:
            if_statement = self.if_branch
        else:
            if_statement = self.unbranched_if

        with if_statement(predicate):
            for command_to_run_when_true in commands_to_run_when_true:
                self.command(
                    command_to_run_when_true)

        if commands_to_run_when_false is not None:
            with self.else_branch():
                for command_to_run_when_false in commands_to_run_when_false:
                    self.command(command_to_run_when_false)

    @contextmanager
    def if_branch(self, predicate):
        with self._compound_statement(IfBranch, predicate):
            yield

    @contextmanager
    def else_branch(self):
        with self._compound_statement(ElseBranch):
            yield

    @contextmanager
    def else_if_branch(self, predicate):
        with self._compound_statement(ElseIfBranch, predicate):
            yield

    @contextmanager
    def for_loop(self, loop_variable, iterable):
        with self._compound_statement(ForLoop, loop_variable, iterable):
            yield


class Advice(Plugin):
    """
    Base class for advices, plugins for ipa-advise.
    """

    options = None
    require_root = False
    description = ''

    def __init__(self, api):
        super(Advice, self).__init__(api)
        self.log = _AdviceOutput()

    def set_options(self, options):
        self.options = options
        self.log.options = options

    def get_info(self):
        """
        This method should be overridden by child Advices.

        Returns a string with instructions.
        """

        raise NotImplementedError


class AdviseAPI(API):
    bases = (Advice,)

    @property
    def packages(self):
        import ipaserver.advise.plugins
        return (ipaserver.advise.plugins,)

advise_api = AdviseAPI()


class IpaAdvise(admintool.AdminTool):
    """
    Admin tool that given systems's configuration provides instructions how to
    configure the systems for various use cases.
    """

    command_name = 'ipa-advise'
    usage = "%prog ADVICE"
    description = "Provides configuration advice for various use cases. To "\
                  "see the list of possible ADVICEs, run ipa-advise without "\
                  "any arguments."

    def __init__(self, options, args):
        super(IpaAdvise, self).__init__(options, args)

    @classmethod
    def add_options(cls, parser):
        super(IpaAdvise, cls).add_options(parser)

    def validate_options(self):
        super(IpaAdvise, self).validate_options(needs_root=False)
        installutils.check_server_configuration()

        if len(self.args) > 1:
            raise self.option_parser.error("You can only provide one "
                                           "positional argument.")

    def log_success(self):
        pass

    def print_config_list(self):
        self.print_header('List of available advices')

        max_keyword_len = max(
            (len(advice.name) for advice in advise_api.Advice))

        for advice in advise_api.Advice:
            description = getattr(advice, 'description', '')
            keyword = advice.name.replace('_', '-')

            # Compute the number of spaces needed for the table to be aligned
            offset = max_keyword_len - len(keyword)
            prefix = "    {key} {off}: ".format(key=keyword, off=' ' * offset)
            wrapped_description = wrap(description, 80 - len(prefix))

            # Print the first line with the prefix (keyword)
            print(prefix + wrapped_description[0])

            # Print the rest wrapped behind the colon
            for line in wrapped_description[1:]:
                print("{off}{line}".format(off=' ' * len(prefix), line=line))

    def print_header(self, header, print_shell=False):
        header_size = len(header)

        prefix = ''
        if print_shell:
            prefix = '# '
            print('#!/bin/sh')

        # Do not print out empty header
        if header_size > 0:
            print((prefix + '-' * 70))
            for line in wrap(header, 70):
                print((prefix + line))
            print((prefix + '-' * 70))

    def print_advice(self, keyword):
        advice = getattr(advise_api.Advice, keyword, None)

        # Ensure that Configuration class for given --setup option value exists
        if advice is None:
            raise ValidationError(
                name="advice",
                error="No instructions are available for '{con}'. "
                      "See the list of available configuration "
                      "by invoking the ipa-advise command with no argument."
                      .format(con=keyword.replace('_', '-')))

        # Check whether root privileges are needed
        if advice.require_root and os.getegid() != 0:
            raise admintool.ScriptError(
                'Must be root to get advice for {adv}'
                .format(adv=keyword.replace('_', '-')), 1)

        # Print out nicely formatted header
        self.print_header(advice.description, print_shell=True)

        # Set options so that plugin can use verbose/quiet options
        advice.set_options(self.options)

        # Print out the actual advice
        api.Backend.rpcclient.connect()
        advice.get_info()
        api.Backend.rpcclient.disconnect()
        for line in advice.log.content:
            print(line)

    def run(self):
        super(IpaAdvise, self).run()

        api.bootstrap(in_server=False,
                      context='cli',
                      confdir=paths.ETC_IPA)
        api.finalize()
        advise_api.bootstrap(in_server=False,
                             context='cli',
                             confdir=paths.ETC_IPA)
        advise_api.finalize()
        if not self.options.verbose:
            # Do not print connection information by default
            logger_name = r'ipalib\.rpc'
            root_logger = logging.getLogger()
            root_logger.addFilter(Filter(logger_name, logging.WARNING))

        # With no argument, print the list out and exit
        if not self.args:
            self.print_config_list()
            return
        else:
            keyword = self.args[0].replace('-', '_')
            self.print_advice(keyword)
