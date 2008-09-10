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
Functionality for Command Line Inteface.
"""

import re
import sys
import code
import optparse
import public
import errors
import plugable
import ipa_types


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


class help(public.Application):
    'Display help on a command.'

    takes_args = (
        public.Option('command', ipa_types.Unicode(),
            required=True,
            multivalue=True,
        ),
    )

    def __call__(self, key):
        key = str(key)
        if key not in self.application:
            print 'help: no such command %r' % key
            sys.exit(2)
        cmd = self.application[key]
        print 'Purpose: %s' % cmd.doc
        self.application.build_parser(cmd).print_help()


class console(public.Application):
    'Start the IPA interactive Python console.'

    def __call__(self):
        code.interact(
            '(Custom IPA interactive Python console)',
            local=dict(api=self.api)
        )

class show_plugins(public.Application):
    'Print details on the loaded plugins.'

    def __call__(self):
        lines = self.__traverse()
        ml = max(len(l[1]) for l in lines)
        for line in lines:
            if line[0] == 0:
                print ''
            print '%s%s %r' % (
                ' ' * line[0],
                line[1].ljust(ml),
                line[2],
            )

    def __traverse(self):
        lines = []
        for name in self.api:
            namespace = self.api[name]
            self.__traverse_namespace(name, namespace, lines)
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
    __d = None
    __mcl = None

    def __init__(self, api):
        self.__api = api

    def __get_api(self):
        return self.__api
    api = property(__get_api)

    def print_commands(self):
        std = set(self.api.Command) - set(self.api.Application)
        print '\nStandard IPA commands:'
        for key in sorted(std):
            cmd = self.api.Command[key]
            self.print_cmd(cmd)
        print '\nSpecial CLI commands:'
        for cmd in self.api.Application():
            self.print_cmd(cmd)
        print ''

    def print_cmd(self, cmd):
        print '  %s  %s' % (
            to_cli(cmd.name).ljust(self.mcl),
            cmd.doc,
        )

    def __contains__(self, key):
        assert self.__d is not None, 'you must call finalize() first'
        return key in self.__d

    def __getitem__(self, key):
        assert self.__d is not None, 'you must call finalize() first'
        return self.__d[key]

    def finalize(self):
        api = self.api
        api.register(help)
        api.register(console)
        api.register(show_plugins)
        api.finalize()
        for a in api.Application():
            a.set_application(self)
        self.build_map()

    def build_map(self):
        assert self.__d is None
        self.__d = dict(
            (c.name.replace('_', '-'), c) for c in self.api.Command()
        )

    def run(self):
        self.finalize()
        if len(sys.argv) < 2:
            self.print_commands()
            print 'Usage: ipa COMMAND'
            sys.exit(2)
        key = sys.argv[1]
        if key not in self:
            self.print_commands()
            print 'ipa: ERROR: unknown command %r' % key
            sys.exit(2)
        self.run_cmd(
            self[key],
            list(s.decode('utf-8') for s in sys.argv[2:])
        )

    def run_cmd(self, cmd, argv):
        (args, kw) = self.parse(cmd, argv)
        self.run_interactive(cmd, args, kw)

    def run_interactive(self, cmd, args, kw):
        for option in cmd.smart_option_order():
            if option.name not in kw:
                default = option.get_default(**kw)
                if default is None:
                    prompt = '%s: ' % option.name
                else:
                    prompt = '%s [%s]: ' % (option.name, default)
                error = None
                while True:
                    if error is not None:
                        print '>>> %s: %s' % (option.name, error)
                    raw = raw_input(prompt)
                    try:
                        value = option(raw, **kw)
                        if value is not None:
                            kw[option.name] = value
                        break
                    except errors.ValidationError, e:
                        error = e.error
        cmd(*args, **kw)

    def parse(self, cmd, argv):
        parser = self.build_parser(cmd)
        (kwc, args) = parser.parse_args(argv, KWCollector())
        return (args, kwc.__todict__())

    def build_parser(self, cmd):
        parser = optparse.OptionParser(
            usage=self.get_usage(cmd),
        )
        for option in cmd.Option():
            parser.add_option('--%s' % to_cli(option.name),
                metavar=option.type.name.upper(),
                help=option.doc,
            )
        return parser

    def get_usage(self, cmd):
        return ' '.join(self.get_usage_iter(cmd))

    def get_usage_iter(self, cmd):
        yield 'Usage: %%prog %s' % to_cli(cmd.name)
        for arg in cmd.takes_args:
            name = to_cli(arg.name).upper()
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
