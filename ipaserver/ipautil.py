# Authors: Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2007    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import xmlrpclib
import re

def realm_to_suffix(realm_name):
    """
    Convert a kerberos realm into the IPA suffix.
    """
    s = realm_name.split(".")
    terms = ["dc=" + x.lower() for x in s]
    return ",".join(terms)

class CIDict(dict):
    """
    Case-insensitive but case-respecting dictionary.

    This code is derived from python-ldap's cidict.py module,
    written by stroeder: http://python-ldap.sourceforge.net/

    This version extends 'dict' so it works properly with TurboGears.
    If you extend UserDict, isinstance(foo, dict) returns false.
    """

    def __init__(self, default=None):
        super(CIDict, self).__init__()
        self._keys = {}
        self.update(default or {})

    def __getitem__(self, key):
        return super(CIDict, self).__getitem__(key.lower())

    def __setitem__(self, key, value):
        lower_key = key.lower()
        self._keys[lower_key] = key
        return super(CIDict, self).__setitem__(lower_key, value)

    def __delitem__(self, key):
        lower_key = key.lower()
        del self._keys[lower_key]
        return super(CIDict, self).__delitem__(key.lower())

    def update(self, dict):
        for key in dict.keys():
            self[key] = dict[key]

    def has_key(self, key):
        return super(CIDict, self).has_key(key.lower())

    def get(self, key, failobj=None):
        try:
            return self[key]
        except KeyError:
            return failobj

    def keys(self):
        return self._keys.values()

    def items(self):
        result = []
        for k in self._keys.values():
            result.append((k, self[k]))
        return result

    def copy(self):
        copy = {}
        for k in self._keys.values():
            copy[k] = self[k]
        return copy

    def iteritems(self):
        return self.copy().iteritems()

    def iterkeys(self):
        return self.copy().iterkeys()

    def setdefault(self, key, value=None):
        try:
            return self[key]
        except KeyError:
            self[key] = value
            return value

    def pop(self, key, *args):
        try:
            value = self[key]
            del self[key]
            return value
        except KeyError:
            if len(args) == 1:
                return args[0]
            raise

    def popitem(self):
        (lower_key, value) = super(CIDict, self).popitem()
        key = self._keys[lower_key]
        del self._keys[lower_key]

        return (key, value)


#
# The safe_string_re regexp and needs_base64 function are extracted from the
# python-ldap ldif module, which was
# written by Michael Stroeder <michael@stroeder.com>
# http://python-ldap.sourceforge.net
#
# It was extracted because ipaldap.py is naughtily reaching into the ldif
# module and squashing this regexp.
#
SAFE_STRING_PATTERN = '(^(\000|\n|\r| |:|<)|[\000\n\r\200-\377]+|[ ]+$)'
safe_string_re = re.compile(SAFE_STRING_PATTERN)

def needs_base64(s):
    """
    returns 1 if s has to be base-64 encoded because of special chars
    """
    return not safe_string_re.search(s) is None


def wrap_binary_data(data):
    """Converts all binary data strings into Binary objects for transport
       back over xmlrpc."""
    if isinstance(data, str):
        if needs_base64(data):
            return xmlrpclib.Binary(data)
        else:
            return data
    elif isinstance(data, list) or isinstance(data,tuple):
        retval = []
        for value in data:
            retval.append(wrap_binary_data(value))
        return retval
    elif isinstance(data, dict):
        retval = {}
        for (k, v) in data.iteritems():
            retval[k] = wrap_binary_data(v)
        return retval
    else:
        return data


def unwrap_binary_data(data):
    """Converts all Binary objects back into strings."""
    if isinstance(data, xmlrpclib.Binary):
        # The data is decoded by the xmlproxy, but is stored
        # in a binary object for us.
        return str(data)
    elif isinstance(data, str):
        return data
    elif isinstance(data, list) or isinstance(data,tuple):
        retval = []
        for value in data:
            retval.append(unwrap_binary_data(value))
        return retval
    elif isinstance(data, dict):
        retval = {}
        for (k, v) in data.iteritems():
            retval[k] = unwrap_binary_data(v)
        return retval
    else:
        return data

def get_gsserror(e):
    """A GSSError exception looks differently in python 2.4 than it does
       in python 2.5, deal with it."""

    try:
        primary = e[0]
        secondary = e[1]
    except Exception:
        primary = e[0][0]
        secondary = e[0][1]

    return (primary[0], secondary[0])

def utf8_encode_value(value):
    if isinstance(value, unicode):
        return value.encode('utf-8')
    return value

def utf8_encode_values(values):
    if isinstance(values, list) or isinstance(values, tuple):
        return map(utf8_encode_value, values)
    else:
        return utf8_encode_value(values)
