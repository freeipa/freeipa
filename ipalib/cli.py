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

import sys
import re

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


class CLI(object):
    def __init__(self, api):
        self.__api = api

    def __get_api(self):
        return self.__api
    api = property(__get_api)

    def print_commands(self):
        for cmd in self.api.cmd:
            print to_cli(cmd.name)

    def run(self):
        if len(sys.argv) < 2:
            self.print_commands()
            print 'Usage: ipa COMMAND [OPTIONS]'
            sys.exit(2)
        return
        name= sys.argv[1]
        if name == '_api_':
            print_api()
            sys.exit()
        elif name not in api.cmd:
            print_commands()
            print 'ipa: ERROR: unknown command %r' % name
            sys.exit(2)
        api.cmd[name]()
