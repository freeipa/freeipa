# Authors:
#   Martin Nagy <mnagy@redhat.com>
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

from ConfigParser import SafeConfigParser, ParsingError
import types
import os

DEFAULT_CONF='/etc/ipa/ipa.conf'

def generate_env(d={}):
    default = dict(
        basedn = 'dc=example,dc=com',
        container_user = 'cn=users,cn=accounts',
        domain = LazyProp(get_domain),
        interactive = True,
        query_dns = True,
        realm = LazyProp(get_realm),
        server_context = True,
        server = LazyIter(get_servers),
        verbose = False,
    )
    for key, value in d.iteritems():
        if key in default:
            if isinstance(default[key], (LazyIter, LazyProp)):
                default[key].set_value(value)
            else:
                default[key] = convert_val(type(default[key]), value)
        else:
             default[key] = value

    return default


# TODO: Add a validation function
def convert_val(target_type, value):
    bool_true = ('true', 'yes', 'on')
    bool_false = ('false', 'no', 'off')

    if target_type == bool and isinstance(value, basestring):
        if value.lower() in bool_true:
            return True
        elif value.lower() in bool_false:
            return False
    return target_type(value)


class LazyProp(object):
    def __init__(self, func, value=None):
        assert isinstance(func, types.FunctionType)
        self._func = func
        self._value = value

    def set_value(self, value):
        self._value = value

    def get_value(self):
        if self._value == None:
            return self._func()
        else:
            return self._value


class LazyIter(LazyProp):
    def get_value(self):
        if self._value != None:
            if type(self._value) == tuple:
                for item in self._value:
                    yield item
            else:
                yield self._value
        for item in self._func():
            if not self._value or item not in self._value:
                yield item


# TODO: Make it possible to use var = 'foo, bar' without
#       turning it into ("'foo", "bar'")
def read_config(config_file=None):
    assert config_file == None or isinstance(config_file, (basestring, file))

    parser = SafeConfigParser()
    if config_file == None:
        files = [DEFAULT_CONF, os.path.expanduser('~/.ipa.conf')]
    else:
        files = [config_file]

    for f in files:
        try:
            if isinstance(f, file):
                parser.readfp(f)
            else:
                parser.read(f)
        except ParsingError:
            print "Can't read %s" % f

    ret = {}
    if parser.has_section('defaults'):
        for name, value in parser.items('defaults'):
            value = tuple(elem.strip() for elem in value.split(','))
            if len(value) == 1:
                value = value[0]
            ret[name] = value

    return ret


# these functions are here just to "emulate" dns resolving for now
def get_domain():
    return "ipatest.com"


def get_realm():
    return "IPATEST.COM"


def get_servers():
    yield "server.ipatest.com"
    yield "backup.ipatest.com"
    yield "fake.ipatest.com"
