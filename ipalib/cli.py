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
import optparse


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
    assert isinstance(cli_name, basestring)
    return cli_name.replace('-', '_')


def _(arg):
    return arg


class CLI(object):
    __d = None
    __mcl = None

    def __init__(self, api):
        self.__api = api

    def __get_api(self):
        return self.__api
    api = property(__get_api)

    def print_commands(self):
        for cmd in self.api.cmd:
            print ' %s  %s' % (
                to_cli(cmd.name).ljust(self.mcl),
                cmd.get_doc(_),
            )

    def __contains__(self, key):
        assert self.__d is not None, 'you must call finalize() first'
        return key in self.__d

    def __getitem__(self, key):
        assert self.__d is not None, 'you must call finalize() first'
        return self.__d[key]

    def finalize(self):
        api = self.api
        api.finalize()
        def d_iter():
            for cmd in api.cmd:
                yield (to_cli(cmd.name), cmd)
        self.__d = dict(d_iter())

    def run(self):
        self.finalize()
        if len(sys.argv) < 2:
            self.print_commands()
            print 'Usage: ipa COMMAND [OPTIONS]'
            sys.exit(2)
        cmd = sys.argv[1]
        if cmd not in self:
            self.print_commands()
            print 'ipa: ERROR: unknown command %r' % cmd
            sys.exit(2)
        self.run_cmd(cmd, sys.argv[2:])

    def run_cmd(self, cmd, args):
        kw = dict(self.parse_kw(args))
        self[cmd](**kw)

    def parse_kw(self, args):
        for arg in args:
            m = re.match(r'^--([a-z][-a-z0-9]*)=(.+)$', arg)
            if m is not None:
                yield (
                    from_cli(m.group(1)),
                    m.group(2),
                )

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
