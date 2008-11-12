# Authors:
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
Functionality for Command Line Interface.
"""

import re
import textwrap
import sys
import code
import optparse
import socket

import frontend
import backend
import errors
import plugable
import ipa_types
from config import set_default_env, read_config
import util
from constants import CLI_TAB


def to_cli(name):
    """
    Takes a Python identifier and transforms it into form suitable for the
    Command Line Interface.
    """
    assert isinstance(name, str)
    return name.replace('_', '-')


def from_cli(cli_name):
    """
    Takes a string from the Command Line Interface and transforms it into a
    Python identifier.
    """
    return str(cli_name).replace('-', '_')


class textui(backend.Backend):
    """
    Backend plugin to nicely format output to stdout.
    """

    def get_tty_width(self):
        """
        Return the width (in characters) of output tty.

        If stdout is not a tty, this method will return ``None``.
        """
        if sys.stdout.isatty():
            return 80 # FIXME: we need to return the actual tty width

    def max_col_width(self, rows, col=None):
        """
        Return the max width (in characters) of a specified column.

        For example:

        >>> ui = textui()
        >>> rows = [
        ...     ('a', 'package'),
        ...     ('an', 'egg'),
        ... ]
        >>> ui.max_col_width(rows, col=0)  # len('an')
        2
        >>> ui.max_col_width(rows, col=1)  # len('package')
        7
        >>> ui.max_col_width(['a', 'cherry', 'py'])  # len('cherry')
        6
        """
        if type(rows) not in (list, tuple):
            raise TypeError(
                'rows: need %r or %r; got %r' % (list, tuple, rows)
            )
        if len(rows) == 0:
            return 0
        if col is None:
            return max(len(row) for row in rows)
        return max(len(row[col]) for row in rows)

    def print_dashed(self, string, above=True, below=True):
        """
        Print a string with with a dashed line above and/or below.

        For example:

        >>> ui = textui()
        >>> ui.print_dashed('Dashed above and below.')
        -----------------------
        Dashed above and below.
        -----------------------
        >>> ui.print_dashed('Only dashed below.', above=False)
        Only dashed below.
        ------------------
        >>> ui.print_dashed('Only dashed above.', below=False)
        ------------------
        Only dashed above.
        """
        dashes = '-' * len(string)
        if above:
            print dashes
        print string
        if below:
            print dashes

    def print_line(self, text, width=None):
        """
        Force printing on a single line, using ellipsis if needed.

        For example:

        >>> ui = textui()
        >>> ui.print_line('This line can fit!', width=18)
        This line can fit!
        >>> ui.print_line('This line wont quite fit!', width=18)
        This line wont ...

        The above example aside, you normally should not specify the
        ``width``.  When you don't, it is automatically determined by calling
        `textui.get_tty_width()`.
        """
        if width is None:
            width = self.get_tty_width()
        if width is not None and width < len(text):
            text = text[:width - 3] + '...'
        print text

    def print_indented(self, text, indent=1):
        """
        Print at specified indentation level.

        For example:

        >>> ui = textui()
        >>> ui.print_indented('One indentation level.')
          One indentation level.
        >>> ui.print_indented('Two indentation levels.', indent=2)
            Two indentation levels.
        >>> ui.print_indented('No indentation.', indent=0)
        No indentation.
        """
        print (CLI_TAB * indent + text)

    def print_name(self, name):
        """
        Print a command name.

        The typical use for this is to mark the start of output from a
        command.  For example, a hypothetical ``show_status`` command would
        output something like this:

        >>> ui = textui()
        >>> ui.print_name('show_status')
        ------------
        show-status:
        ------------
        """
        self.print_dashed('%s:' % to_cli(name))

    def print_keyval(self, rows, indent=1):
        """
        Print (key = value) pairs, one pair per line.

        For example:

        >>> items = [
        ...     ('in_server', True),
        ...     ('mode', 'production'),
        ... ]
        >>> ui = textui()
        >>> ui.print_keyval(items)
          in_server = True
          mode = 'production'
        >>> ui.print_keyval(items, indent=0)
        in_server = True
        mode = 'production'

        Also see `textui.print_indented`.
        """
        for row in rows:
            self.print_indented('%s = %r' % row, indent)

    def print_count(self, count, singular, plural=None):
        """
        Print a summary count.

        The typical use for this is to print the number of items returned
        by a command, especially when this return count can vary.  This
        preferably should be used as a summary and should be the final text
        a command outputs.

        For example:

        >>> ui = textui()
        >>> ui.print_count(1, '%d goose', '%d geese')
        -------
        1 goose
        -------
        >>> ui.print_count(['Don', 'Sue'], 'Found %d user', 'Found %d users')
        -------------
        Found 2 users
        -------------

        If ``count`` is not an integer, it must be a list or tuple, and then
        ``len(count)`` is used as the count.
        """
        if type(count) is not int:
            assert type(count) in (list, tuple)
            count = len(count)
        self.print_dashed(
            self.choose_number(count, singular, plural)
        )

    def choose_number(self, n, singular, plural=None):
        if n == 1 or plural is None:
            return singular % n
        return plural % n


def exit_error(error):
    sys.exit('ipa: ERROR: %s' % error)


class help(frontend.Application):
    'Display help on a command.'

    takes_args = ['command']

    def run(self, key):
        key = str(key)
        if key not in self.application:
            print 'help: no such command %r' % key
            sys.exit(2)
        cmd = self.application[key]
        print 'Purpose: %s' % cmd.doc
        self.application.build_parser(cmd).print_help()


class console(frontend.Application):
    """Start the IPA interactive Python console."""

    def run(self):
        code.interact(
            '(Custom IPA interactive Python console)',
            local=dict(api=self.api)
        )


class show_api(frontend.Application):
    'Show attributes on dynamic API object'

    takes_args = ('namespaces*',)

    def run(self, namespaces):
        if namespaces is None:
            names = tuple(self.api)
        else:
            for name in namespaces:
                if name not in self.api:
                    exit_error('api has no such namespace: %s' % name)
            names = namespaces
        lines = self.__traverse(names)
        ml = max(len(l[1]) for l in lines)
        self.print_name()
        first = True
        for line in lines:
            if line[0] == 0 and not first:
                print ''
            if first:
                first = False
            print '%s%s %r' % (
                ' ' * line[0],
                line[1].ljust(ml),
                line[2],
            )
        if len(lines) == 1:
            s = '1 attribute shown.'
        else:
            s = '%d attributes show.' % len(lines)
        self.print_dashed(s)


    def __traverse(self, names):
        lines = []
        for name in names:
            namespace = self.api[name]
            self.__traverse_namespace('%s' % name, namespace, lines)
        return lines

    def __traverse_namespace(self, name, namespace, lines, tab=0):
        lines.append((tab, name, namespace))
        for member_name in namespace:
            member = namespace[member_name]
            lines.append((tab + 1, member_name, member))
            if not hasattr(member, '__iter__'):
                continue
            for n in member:
                attr = member[n]
                if isinstance(attr, plugable.NameSpace) and len(attr) > 0:
                    self.__traverse_namespace(n, attr, lines, tab + 2)


class plugins(frontend.Application):
    """Show all loaded plugins"""

    def run(self):
        plugins = sorted(self.api.plugins, key=lambda o: o.plugin)
        return tuple(
            (p.plugin, p.bases) for p in plugins
        )

    def output_for_cli(self, textui, result, **kw):
        textui.print_name(self.name)
        for (plugin, bases) in result:
            textui.print_indented(
                '%s: %s' % (plugin, ', '.join(bases))
            )
        textui.print_count(result, '%d plugin loaded', '%s plugins loaded')


cli_application_commands = (
    help,
    console,
    show_api,
    plugins,
)


class KWCollector(object):
    def __init__(self):
        object.__setattr__(self, '_KWCollector__d', {})

    def __setattr__(self, name, value):
        if name in self.__d:
            v = self.__d[name]
            if type(v) is tuple:
                value = v + (value,)
            else:
                value = (v, value)
        self.__d[name] = value
        object.__setattr__(self, name, value)

    def __todict__(self):
        return dict(self.__d)


class CLI(object):
    """
    All logic for dispatching over command line interface.
    """

    __d = None
    __mcl = None

    def __init__(self, api, argv):
        self.api = api
        self.argv = tuple(argv)
        self.__done = set()

    def run(self, init_only=False):
        """
        Parse ``argv`` and potentially run a command.

        This method requires several initialization steps to be completed
        first, all of which all automatically called with a single call to
        `CLI.finalize()`. The initialization steps are broken into separate
        methods simply to make it easy to write unit tests.

        The initialization involves these steps:

            1. `CLI.parse_globals` parses the global options, which get stored
               in ``CLI.options``, and stores the remaining args in
               ``CLI.cmd_argv``.

            2. `CLI.bootstrap` initializes the environment information in
               ``CLI.api.env``.

            3. `CLI.load_plugins` registers all plugins, including the
               CLI-specific plugins.

            4. `CLI.finalize` instantiates all plugins and performs the
               remaining initialization needed to use the `plugable.API`
               instance.
        """
        self.__doing('run')
        self.finalize()
        if self.api.env.mode == 'unit_test':
            return
        if len(self.cmd_argv) < 1:
            self.print_commands()
            print 'Usage: ipa [global-options] COMMAND'
            sys.exit(2)
        key = self.cmd_argv[0]
        if key not in self:
            self.print_commands()
            print 'ipa: ERROR: unknown command %r' % key
            sys.exit(2)
        return self.run_cmd(self[key])

    def finalize(self):
        """
        Fully initialize ``CLI.api`` `plugable.API` instance.

        This method first calls `CLI.load_plugins` to perform some dependant
        initialization steps, after which `plugable.API.finalize` is called.

        Finally, the CLI-specific commands are passed a reference to this
        `CLI` instance by calling `frontend.Application.set_application`.
        """
        self.__doing('finalize')
        self.load_plugins()
        self.api.finalize()
        for a in self.api.Application():
            a.set_application(self)
        assert self.__d is None
        self.__d = dict(
            (c.name.replace('_', '-'), c) for c in self.api.Command()
        )

    def load_plugins(self):
        """
        Load all standard plugins plus the CLI-specific plugins.

        This method first calls `CLI.bootstrap` to preform some dependant
        initialization steps, after which `plugable.API.load_plugins` is
        called.

        Finally, all the CLI-specific plugins are registered.
        """
        self.__doing('load_plugins')
        self.bootstrap()
        self.api.load_plugins()
        for klass in cli_application_commands:
            self.api.register(klass)
        self.api.register(textui)

    def bootstrap(self):
        """
        Initialize the ``CLI.api.env`` environment variables.

        This method first calls `CLI.parse_globals` to perform some dependant
        initialization steps. Then, using environment variables that may have
        been passed in the global options, the ``overrides`` are constructed
        and `plugable.API.bootstrap` is called.
        """
        self.__doing('bootstrap')
        self.parse_globals()
        self.api.bootstrap_with_global_options(self.options, context='cli')

    def parse_globals(self):
        """
        Parse out the global options.

        This method parses the global options out of the ``CLI.argv`` instance
        attribute, after which two new instance attributes are available:

            1. ``CLI.options`` - an ``optparse.Values`` instance containing
               the global options.

            2. ``CLI.cmd_argv`` - a tuple containing the remainder of
               ``CLI.argv`` after the global options have been consumed.

        The common global options are added using the
        `util.add_global_options` function.
        """
        self.__doing('parse_globals')
        parser = optparse.OptionParser()
        parser.disable_interspersed_args()
        parser.add_option('-a', dest='prompt_all', action='store_true',
                help='Prompt for all missing options interactively')
        parser.add_option('-n', dest='interactive', action='store_false',
                help='Don\'t prompt for any options interactively')
        parser.set_defaults(
            prompt_all=False,
            interactive=True,
        )
        util.add_global_options(parser)
        (options, args) = parser.parse_args(list(self.argv))
        self.options = options
        self.cmd_argv = tuple(args)

    def __doing(self, name):
        if name in self.__done:
            raise StandardError(
                '%s.%s() already called' % (self.__class__.__name__, name)
            )
        self.__done.add(name)

    def print_commands(self):
        std = set(self.api.Command) - set(self.api.Application)
        print '\nStandard IPA commands:'
        for key in sorted(std):
            cmd = self.api.Command[key]
            self.print_cmd(cmd)
        print '\nSpecial CLI commands:'
        for cmd in self.api.Application():
            self.print_cmd(cmd)
        print '\nUse the --help option to see all the global options'
        print ''

    def print_cmd(self, cmd):
        print '  %s  %s' % (
            to_cli(cmd.name).ljust(self.mcl),
            cmd.doc,
        )

    def run_cmd(self, cmd):
        kw = self.parse(cmd)
        # If options.interactive, interactively validate params:
        if self.options.interactive:
            try:
                kw = self.prompt_interactively(cmd, kw)
            except KeyboardInterrupt:
                return 0
        # Now run the command
        try:
            ret = cmd(**kw)
            if callable(cmd.output_for_cli):
                cmd.output_for_cli(self.api.Backend.textui, ret, **kw)
            return 0
        except socket.error, e:
            print e[1]
            return 1
        except errors.GenericError, err:
            code = getattr(err,'faultCode',None)
            faultString = getattr(err,'faultString',None)
            if not code:
                raise err
            if code < errors.IPA_ERROR_BASE:
                print "%s: %s" % (code, faultString)
            else:
                print "%s: %s" % (code, getattr(err,'__doc__',''))
            return 1
        except StandardError, e:
            print e
            return 2

    def prompt_interactively(self, cmd, kw):
        """
        Interactively prompt for missing or invalid values.

        By default this method will only prompt for *required* Param that
        have a missing or invalid value.  However, if
        ``CLI.options.prompt_all`` is True, this method will prompt for any
        params that have a missing or required values, even if the param is
        optional.
        """
        for param in cmd.params():
            if param.name not in kw:
                if not (param.required or self.options.prompt_all):
                    continue
                default = param.get_default(**kw)
                if default is None:
                    prompt = '%s: ' % param.cli_name
                else:
                    prompt = '%s [%s]: ' % (param.cli_name, default)
                error = None
                while True:
                    if error is not None:
                        print '>>> %s: %s' % (param.cli_name, error)
                    raw = raw_input(prompt)
                    try:
                        value = param(raw, **kw)
                        if value is not None:
                            kw[param.name] = value
                        break
                    except errors.ValidationError, e:
                        error = e.error
        return kw

# FIXME: This should be done as the plugins are loaded
#        if self.api.env.server_context:
#            try:
#                import krbV
#                import ldap
#                from ipa_server import conn
#                from ipa_server.servercore import context
#                krbccache =  krbV.default_context().default_ccache().name
#                context.conn = conn.IPAConn(self.api.env.ldaphost, self.api.env.ldapport, krbccache)
#            except ImportError:
#                print >> sys.stderr, "There was a problem importing a Python module: %s" % sys.exc_value
#                return 2
#            except ldap.LDAPError, e:
#                print >> sys.stderr, "There was a problem connecting to the LDAP server: %s" % e[0].get('desc')
#                return 2
#        ret = cmd(**kw)
#        if callable(cmd.output_for_cli):
#            return cmd.output_for_cli(ret)
#        else:
#            return 0

    def parse(self, cmd):
        parser = self.build_parser(cmd)
        (kwc, args) = parser.parse_args(
            list(self.cmd_argv[1:]), KWCollector()
        )
        kw = kwc.__todict__()
        try:
            arg_kw = cmd.args_to_kw(*args)
        except errors.ArgumentError, e:
            exit_error('%s %s' % (to_cli(cmd.name), e.error))
        assert set(arg_kw).intersection(kw) == set()
        kw.update(arg_kw)
        return kw

    def build_parser(self, cmd):
        parser = optparse.OptionParser(
            usage=self.get_usage(cmd),
        )
        for option in cmd.options():
            o = optparse.make_option('--%s' % to_cli(option.cli_name),
                dest=option.name,
                metavar=option.type.name.upper(),
                help=option.doc,
            )
            if isinstance(option.type, ipa_types.Bool):
                o.action = 'store_true'
                o.default = option.default
                o.type = None
            parser.add_option(o)
        return parser

    def get_usage(self, cmd):
        return ' '.join(self.get_usage_iter(cmd))

    def get_usage_iter(self, cmd):
        yield 'Usage: %%prog [global-options] %s' % to_cli(cmd.name)
        for arg in cmd.args():
            name = to_cli(arg.cli_name).upper()
            if arg.multivalue:
                name = '%s...' % name
            if arg.required:
                yield name
            else:
                yield '[%s]' % name

    def __get_mcl(self):
        """
        Returns the Max Command Length.
        """
        if self.__mcl is None:
            if self.__d is None:
                return None
            self.__mcl = max(len(k) for k in self.__d)
        return self.__mcl
    mcl = property(__get_mcl)

    def isdone(self, name):
        """
        Return True in method named ``name`` has already been called.
        """
        return name in self.__done

    def __contains__(self, key):
        assert self.__d is not None, 'you must call finalize() first'
        return key in self.__d

    def __getitem__(self, key):
        assert self.__d is not None, 'you must call finalize() first'
        return self.__d[key]
