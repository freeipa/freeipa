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
import getpass
import code
import optparse
import socket
import fcntl
import termios
import struct

import frontend
import backend
import plugable
import util
from errors2 import PublicError, CommandError, HelpError, InternalError
from constants import CLI_TAB
from parameters import Password, Bytes
from request import ugettext as _


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
        # /usr/include/asm/termios.h says that struct winsize has four
        # unsigned shorts, hence the HHHH
        if sys.stdout.isatty():
            try:
                winsize = fcntl.ioctl(sys.stdout, termios.TIOCGWINSZ,
                                      struct.pack('HHHH', 0, 0, 0, 0))
                return struct.unpack('HHHH', winsize)[1]
            except IOError:
                return None

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

    def __get_encoding(self, stream):
        assert stream in (sys.stdin, sys.stdout)
        if stream.encoding is None:
            return 'UTF-8'
        return stream.encoding

    def decode(self, value):
        """
        Decode text from stdin.
        """
        if type(value) is str:
            encoding = self.__get_encoding(sys.stdin)
            return value.decode(encoding)
        elif type(value) in (list, tuple):
            return tuple(self.decode(v) for v in value)
        return value

    def encode(self, unicode_text):
        """
        Encode text for output to stdout.
        """
        assert type(unicode_text) is unicode
        encoding = self.__get_encoding(sys.stdout)
        return unicode_text.encode(encoding)

    def choose_number(self, n, singular, plural=None):
        if n == 1 or plural is None:
            return singular % n
        return plural % n

    def print_plain(self, string):
        """
        Print exactly like ``print`` statement would.
        """
        print string

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

    def print_paragraph(self, text, width=None):
        """
        Print a paragraph, automatically word-wrapping to tty width.

        For example:

        >>> text = '''
        ... Python is a dynamic object-oriented programming language that can
        ... be used for many kinds of software development.
        ... '''
        >>> ui = textui()
        >>> ui.print_paragraph(text, width=45)
        Python is a dynamic object-oriented
        programming language that can be used for
        many kinds of software development.

        The above example aside, you normally should not specify the
        ``width``.  When you don't, it is automatically determined by calling
        `textui.get_tty_width()`.

        The word-wrapping is done using the Python ``textwrap`` module.  See:

            http://docs.python.org/library/textwrap.html
        """
        if width is None:
            width = self.get_tty_width()
        for line in textwrap.wrap(text.strip(), width):
            print line

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
        for (key, value) in rows:
            self.print_indented('%s = %r' % (key, value), indent)

    def print_entry(self, entry, indent=1):
        """
        Print an ldap entry dict.

        For example:

        >>> entry = dict(sn='Last', givenname='First', uid='flast')
        >>> ui = textui()
        >>> ui.print_entry(entry)
          givenname: 'First'
          sn: 'Last'
          uid: 'flast'
        """
        assert type(entry) is dict
        for key in sorted(entry):
            value = entry[key]
            if type(value) in (list, tuple):
                for v in value:
                    self.print_indented('%s: %s' % (key, repr(v)), indent)
            else:
                self.print_indented('%s: %s' % (key, repr(value)), indent)

    def print_dashed(self, string, above=True, below=True, indent=0, dash='-'):
        """
        Print a string with a dashed line above and/or below.

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
        assert isinstance(dash, basestring)
        assert len(dash) == 1
        dashes = dash * len(string)
        if above:
            self.print_indented(dashes, indent)
        self.print_indented(string, indent)
        if below:
            self.print_indented(dashes, indent)

    def print_h1(self, text):
        """
        Print a primary header at indentation level 0.

        For example:

        >>> ui = textui()
        >>> ui.print_h1('A primary header')
        ================
        A primary header
        ================
        """
        self.print_dashed(text, indent=0, dash='=')

    def print_h2(self, text):
        """
        Print a secondary header at indentation level 1.

        For example:

        >>> ui = textui()
        >>> ui.print_h2('A secondary header')
          ------------------
          A secondary header
          ------------------
        """
        self.print_dashed(text, indent=1, dash='-')

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

    def print_error(self, text):
        print '  ** %s **' % text

    def prompt(self, label, default=None, get_values=None):
        """
        Prompt user for input.
        """
        # TODO: Add tab completion using readline
        if default is None:
            prompt = u'%s: ' % label
        else:
            prompt = u'%s [%s]: ' % (label, default)
        return self.decode(
            raw_input(self.encode(prompt))
        )

    def prompt_password(self, label):
        """
        Prompt user for a password.
        """
        try:
            while True:
                pw1 = getpass.getpass('%s: ' % label)
                pw2 = getpass.getpass(
                    _('Enter %(label)s again to verify: ') % dict(label=label)
                )
                if pw1 == pw2:
                    return self.decode(pw1)
                self.print_error( _('Passwords do not match!'))
        except KeyboardInterrupt:
            print ''
            self.print_error(_('Cancelled.'))


class help(frontend.Command):
    """
    Display help for a command or topic.
    """

    takes_args = [Bytes('command?')]

    def finalize(self):
        self.__topics = dict(
            (to_cli(c.name), c) for c in self.Command()
        )
        super(help, self).finalize()

    def run(self, key):

        if key is None:
            self.print_commands()
            return
        name = from_cli(key)
        if name not in self.Command:
            raise HelpError(topic=key)
        cmd = self.Command[name]
        print 'Purpose: %s' % cmd.doc
        self.Backend.cli.build_parser(cmd).print_help()

    def print_commands(self):
        mcl = self.get_mcl()
        for cmd in self.api.Command():
            print '  %s  %s' % (
                to_cli(cmd.name).ljust(mcl),
                cmd.doc,
            )
        print '\nUse the --help option to see all the global options'
        print ''

    def get_mcl(self):
        return max(len(k) for k in self.Command)


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
                    raise errors.NoSuchNamespaceError(name)
            names = namespaces
        lines = self.__traverse(names)
        ml = max(len(l[1]) for l in lines)
        self.Backend.textui.print_name('run')
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
        self.Backend.textui.print_dashed(s)


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


cli_application_commands = (
    help,
    console,
    show_api,
)


class Collector(object):
    def __init__(self):
        object.__setattr__(self, '_Collector__options', {})

    def __setattr__(self, name, value):
        if name in self.__options:
            v = self.__options[name]
            if type(v) is tuple:
                value = v + (value,)
            else:
                value = (v, value)
        self.__options[name] = value
        object.__setattr__(self, name, value)

    def __todict__(self):
        return dict(self.__options)


class cli(backend.Executioner):
    """
    Backend plugin for executing from command line interface.
    """

    def run(self, argv):
        if len(argv) == 0:
            self.Command.help()
            return
        self.create_context()
        (key, argv) = (argv[0], argv[1:])
        name = from_cli(key)
        if name not in self.Command:
            raise CommandError(name=key)
        cmd = self.Command[name]
        kw = self.parse(cmd, argv)
        if self.env.interactive:
            self.prompt_interactively(cmd, kw)
        result = self.execute(name, **kw)
        if callable(cmd.output_for_cli):
            for param in cmd.params():
                if param.password and param.name in kw:
                    del kw[param.name]
            (args, options) = cmd.params_2_args_options(**kw)
            cmd.output_for_cli(self.api.Backend.textui, result, *args, **options)

    def parse(self, cmd, argv):
        parser = self.build_parser(cmd)
        (collector, args) = parser.parse_args(argv, Collector())
        options = collector.__todict__()
        kw = cmd.args_options_2_params(*args, **options)
        return dict(self.parse_iter(cmd, kw))

    # FIXME: Probably move decoding to Command, use same method regardless of
    # request source:
    def parse_iter(self, cmd, kw):
        """
        Decode param values if appropriate.
        """
        for (key, value) in kw.iteritems():
            param = cmd.params[key]
            if isinstance(param, Bytes):
                yield (key, value)
            else:
                yield (key, self.Backend.textui.decode(value))

    def build_parser(self, cmd):
        parser = optparse.OptionParser(
            usage=' '.join(self.usage_iter(cmd))
        )
        for option in cmd.options():
            kw = dict(
                dest=option.name,
                help=option.doc,
            )
            if option.password and self.env.interactive:
                kw['action'] = 'store_true'
            elif option.type is bool:
                if option.default is True:
                    kw['action'] = 'store_false'
                else:
                    kw['action'] = 'store_true'
            else:
                kw['metavar'] = metavar=option.__class__.__name__.upper()
            o = optparse.make_option('--%s' % to_cli(option.cli_name), **kw)
            parser.add_option(o)
        return parser

    def usage_iter(self, cmd):
        yield 'Usage: %%prog [global-options] %s' % to_cli(cmd.name)
        for arg in cmd.args():
            if arg.password:
                continue
            name = to_cli(arg.cli_name).upper()
            if arg.multivalue:
                name = '%s...' % name
            if arg.required:
                yield name
            else:
                yield '[%s]' % name

    def prompt_interactively(self, cmd, kw):
        """
        Interactively prompt for missing or invalid values.

        By default this method will only prompt for *required* Param that
        have a missing or invalid value.  However, if
        ``self.env.prompt_all`` is ``True``, this method will prompt for any
        params that have a missing values, even if the param is optional.
        """
        for param in cmd.params():
            if param.password:
                if kw.get(param.name, False) is True or param.name in cmd.args:
                    kw[param.name] = \
                        self.Backend.textui.prompt_password(param.cli_name)
            elif param.autofill or param.name in kw:
                continue
            elif param.required or self.env.prompt_all:
                default = param.get_default(**kw)
                error = None
                while True:
                    if error is not None:
                        print '>>> %s: %s' % (param.cli_name, error)
                    raw = self.Backend.textui.prompt(param.cli_name, default)
                    try:
                        value = param(raw, **kw)
                        if value is not None:
                            kw[param.name] = value
                        break
                    except errors.ValidationError, e:
                        error = e.error


cli_plugins = (
    cli,
    textui,
    console,
    help,
)


def run(api):
    error = None
    try:
        argv = api.bootstrap_with_global_options(context='cli')
        for klass in cli_plugins:
            api.register(klass)
        api.load_plugins()
        api.finalize()
        api.Backend.cli.run(argv)
    except KeyboardInterrupt:
        print ''
        api.log.info('operation aborted')
    except PublicError, e:
        error = e
    except Exception, e:
        api.log.exception('%s: %s', e.__class__.__name__, str(e))
        error = InternalError()
    if error is not None:
        assert isinstance(error, PublicError)
        api.log.error(error.strerror)
        sys.exit(error.errno)
