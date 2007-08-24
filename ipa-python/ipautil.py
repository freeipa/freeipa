#! /usr/bin/python -E
#
# Copyright (C) 2007    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 or later
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

from string import lower

class CIDict(dict):
    """
    Case-insensitive but case-respecting dictionary.

    Idea from python-ldap cidict, however this version extends 'dict'
    so it works properly with TurboGears.

    If you extend UserDict, isinstance(foo, dict) returns false.
    """

    def __init__(self,default=None):
        super(CIDict, self).__init__()
        self._keys = {}
        self.update(default or {})

    def __getitem__(self,key):
        return super(CIDict,self).__getitem__(lower(key))

    def __setitem__(self,key,value):
        lower_key = lower(key)
        self._keys[lower_key] = key
        return super(CIDict,self).__setitem__(lower(key),value)

    def __delitem__(self,key):
        lower_key = lower(key)
        del self._keys[lower_key]
        return super(CIDict,self).__delitem__(lower(key))

    def update(self,dict):
        for key in dict.keys():
            self[key] = dict[key]

    def has_key(self,key):
        return super(CIDict, self).has_key(lower(key))

    def get(self,key,failobj=None):
        try:
            return self[key]
        except KeyError:
            return failobj

    def keys(self):
        return self._keys.values()

    def items(self):
        result = []
        for k in self._keys.values():
            result.append((k,self[k]))
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

    def setdefault(self,key,value=None):
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
        (lower_key,value) = super(CIDict,self).popitem()
        key = self._keys[lower_key]
        del self._keys[lower_key]

        return (key,value)


