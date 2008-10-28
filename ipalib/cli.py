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
import sys
import code
import optparse

import frontend
import errors
import plugable
import ipa_types
from config import set_default_env, read_config

def exit_error(error):
    sys.exit('ipa: ERROR: %s' % error)


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


class text_ui(frontend.Application):
    """
    Base class for CLI commands with special output needs.
    """

    def print_dashed(self, string, top=True, bottom=True):
        dashes = '-' * len(string)
        if top:
            print dashes
        print string
        if bottom:
            print dashes

    def print_name(self, **kw):
        self.print_dashed('%s:' % self.name, **kw)


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
    'Start the IPA interactive Python console.'

    def run(self):
        code.interact(
            '(Custom IPA interactive Python console)',
            local=dict(api=self.api)
        )



class show_api(text_ui):
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


class plugins(text_ui):
    """Show all loaded plugins"""

    def run(self):
        plugins = sorted(self.api.plugins, key=lambda o: o.plugin)
        return tuple(
            (p.plugin, p.bases) for p in plugins
        )

    def output_for_cli(self, result):
        self.print_name()
        first = True
        for (plugin, bases) in result:
            if first:
                first = False
            else:
                print ''
            print '  Plugin: %s' % plugin
            print '  In namespaces: %s' % ', '.join(bases)
        if len(result) == 1:
            s = '1 plugin loaded.'
        else:
            s = '%d plugins loaded.' % len(result)
        self.print_dashed(s)


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
        if self.api.env.mode == 'unit-test':
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
        self.api.env.verbose = self.options.verbose
        if self.options.config_file:
            self.api.env.conf = self.options.config_file
        overrides = {}
        if self.options.environment:
            for a in self.options.environment.split(','):
                a = a.split('=', 1)
                if len(a) < 2:
                    parser.error('badly specified environment string,'\
                            'use var1=val1[,var2=val2]..')
                overrides[a[0].strip()] = a[1].strip()
        overrides['context'] = 'cli'
        self.api.bootstrap(**overrides)

    def parse_globals(self):
        """
        Parse out the global options.

        This method parses the global options out of the ``CLI.argv`` instance
        attribute, after which two new instance attributes are available:

            1. ``CLI.options`` - an ``optparse.Values`` instance containing
               the global options.

            2. ``CLI.cmd_argv`` - a tuple containing the remainder of
               ``CLI.argv`` after the global options have been consumed.
        """
        self.__doing('parse_globals')
        parser = optparse.OptionParser()
        parser.disable_interspersed_args()
        parser.add_option('-a', dest='prompt_all', action='store_true',
                help='Prompt for all missing options interactively')
        parser.add_option('-n', dest='interactive', action='store_false',
                help='Don\'t prompt for any options interactively')
        parser.add_option('-c', dest='config_file',
                help='Specify different configuration file')
        parser.add_option('-e', dest='environment',
                help='Specify or override environment variables')
        parser.add_option('-v', dest='verbose', action='store_true',
                help='Verbose output')
        parser.set_defaults(
            prompt_all=False,
            interactive=True,
            verbose=False,
        )
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
                cmd.output_for_cli(ret)
            return 0
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
            list(self.cmd_argv), KWCollector()
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
