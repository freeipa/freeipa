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

import types

DEFAULT_CONF='/etc/ipa/ipa.conf'

def generate_env(d={}):
    default = dict(
        server_context = True,
        query_dns = True,
        verbose = False,
        servers = LazyIter(get_servers),
        realm = LazyProp(get_realm),
        domain = LazyProp(get_domain),
    )
    for key, value in d.iteritems():
        if key in default and type(default[key]) in (LazyIter, LazyProp):
            default[key].set_value(value)
        else:
            default[key] = value
            
    return default


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


def read_config(file=DEFAULT_CONF):
    assert isinstance(file, basestring)
    # open the file and read configuration, return a dict
    # for now, these are here just for testing purposes
    return dict(servers="server.ipatest.com", realm="IPATEST.COM")


# these functions are here just to "emulate" dns resolving for now
def get_domain():
    return "ipatest.com"


def get_realm():
    return "IPATEST.COM"


def get_servers():
    yield "server.ipatest.com"
    yield "backup.ipatest.com"
    yield "fake.ipatest.com"
