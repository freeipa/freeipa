# Authors: Simo Sorce <ssorce@redhat.com>
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

SHARE_DIR = "/usr/share/ipa/"

import string
import tempfile
import logging
import subprocess
from random import Random
from time import gmtime
import os
import stat
import socket

from string import lower
import re
import xmlrpclib
import datetime

def realm_to_suffix(realm_name):
    s = realm_name.split(".")
    terms = ["dc=" + x.lower() for x in s]
    return ",".join(terms)

def template_str(txt, vars):
    return string.Template(txt).substitute(vars)

def template_file(infilename, vars):
    txt = open(infilename).read()
    return template_str(txt, vars)

def write_tmp_file(txt):
    fd = tempfile.NamedTemporaryFile()
    fd.write(txt)
    fd.flush()

    return fd

def run(args, stdin=None):
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if stdin:
        stdout,stderr = p.communicate(stdin)
    else:
        stdout,stderr = p.communicate()
    logging.info(stdout)
    logging.info(stderr)

    if p.returncode != 0:
        raise subprocess.CalledProcessError(p.returncode, ' '.join(args))

def file_exists(filename):
    try:
        mode = os.stat(filename)[stat.ST_MODE]
        if stat.S_ISREG(mode):
            return True
        else:
            return False
    except:
        return False

def dir_exists(filename):
    try:
        mode = os.stat(filename)[stat.ST_MODE]
        if stat.S_ISDIR(mode):
            return True
        else:
            return False
    except:
        return False

class CIDict(dict):
    """
    Case-insensitive but case-respecting dictionary.

    This code is derived from python-ldap's cidict.py module,
    written by stroeder: http://python-ldap.sourceforge.net/

    This version extends 'dict' so it works properly with TurboGears.
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
        for (k,v) in data.iteritems():
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
        for (k,v) in data.iteritems():
            retval[k] = unwrap_binary_data(v)
        return retval
    else:
        return data

class GeneralizedTimeZone(datetime.tzinfo):
    """This class is a basic timezone wrapper for the offset specified
       in a Generalized Time.  It is dst-ignorant."""
    def __init__(self,offsetstr="Z"):
        super(GeneralizedTimeZone, self).__init__()

        self.name = offsetstr
        self.houroffset = 0
        self.minoffset = 0

        if offsetstr == "Z":
            self.houroffset = 0
            self.minoffset = 0
        else:
            if (len(offsetstr) >= 3) and re.match(r'[-+]\d\d', offsetstr):
                self.houroffset = int(offsetstr[0:3])
                offsetstr = offsetstr[3:]
            if (len(offsetstr) >= 2) and re.match(r'\d\d', offsetstr):
                self.minoffset = int(offsetstr[0:2])
                offsetstr = offsetstr[2:]
            if len(offsetstr) > 0:
                raise ValueError()
        if self.houroffset < 0:
            self.minoffset *= -1

    def utcoffset(self, dt):
        return datetime.timedelta(hours=self.houroffset, minutes=self.minoffset)

    def dst(self, dt):
        return datetime.timedelta(0)

    def tzname(self, dt):
        return self.name


def parse_generalized_time(timestr):
    """Parses are Generalized Time string (as specified in X.680),
       returning a datetime object.  Generalized Times are stored inside
       the krbPasswordExpiration attribute in LDAP.

       This method doesn't attempt to be perfect wrt timezones.  If python
       can't be bothered to implement them, how can we..."""

    if len(timestr) < 8:
        return None
    try:
        date = timestr[:8]
        time = timestr[8:]

        year = int(date[:4])
        month = int(date[4:6])
        day = int(date[6:8])

        hour = min = sec = msec = 0
        tzone = None

        if (len(time) >= 2) and re.match(r'\d', time[0]):
            hour = int(time[:2])
            time = time[2:]
            if len(time) >= 2 and (time[0] == "," or time[0] == "."):
                hour_fraction = "."
                time = time[1:]
                while (len(time) > 0) and re.match(r'\d', time[0]):
                    hour_fraction += time[0]
                    time = time[1:]
                total_secs = int(float(hour_fraction) * 3600)
                min, sec = divmod(total_secs, 60)

        if (len(time) >= 2) and re.match(r'\d', time[0]):
            min = int(time[:2])
            time = time[2:]
            if len(time) >= 2 and (time[0] == "," or time[0] == "."):
                min_fraction = "."
                time = time[1:]
                while (len(time) > 0) and re.match(r'\d', time[0]):
                    min_fraction += time[0]
                    time = time[1:]
                sec = int(float(min_fraction) * 60)

        if (len(time) >= 2) and re.match(r'\d', time[0]):
            sec = int(time[:2])
            time = time[2:]
            if len(time) >= 2 and (time[0] == "," or time[0] == "."):
                sec_fraction = "."
                time = time[1:]
                while (len(time) > 0) and re.match(r'\d', time[0]):
                    sec_fraction += time[0]
                    time = time[1:]
                msec = int(float(sec_fraction) * 1000000)

        if (len(time) > 0):
            tzone = GeneralizedTimeZone(time)

        return datetime.datetime(year, month, day, hour, min, sec, msec, tzone)

    except ValueError:
        return None


def ipa_generate_password():
    rndpwd = ''
    r = Random()
    r.seed(gmtime())
    for x in range(12):
#        rndpwd += chr(r.randint(32,126))
        rndpwd += chr(r.randint(65,90)) #stricter set for testing
    return rndpwd

