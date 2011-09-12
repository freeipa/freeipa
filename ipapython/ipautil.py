# Authors: Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2007-2011  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

SHARE_DIR = "/usr/share/ipa/"
PLUGINS_SHARE_DIR = "/usr/share/ipa/plugins"

GEN_PWD_LEN = 12

import string
import tempfile
import logging
import subprocess
import random
import os, sys, traceback, readline
import copy
import stat
import shutil
import urllib2
import socket

from ipapython import ipavalidate
from types import *

import re
import xmlrpclib
import datetime
import netaddr
from ipapython import config
try:
    from subprocess import CalledProcessError
except ImportError:
    # Python 2.4 doesn't implement CalledProcessError
    class CalledProcessError(Exception):
        """This exception is raised when a process run by check_call() returns
        a non-zero exit status. The exit status will be stored in the
        returncode attribute."""
        def __init__(self, returncode, cmd):
            self.returncode = returncode
            self.cmd = cmd
        def __str__(self):
            return "Command '%s' returned non-zero exit status %d" % (self.cmd, self.returncode)

def get_domain_name():
    try:
        config.init_config()
        domain_name = config.config.get_domain()
    except Exception:
        return None

    return domain_name

class CheckedIPAddress(netaddr.IPAddress):
    def __init__(self, addr, match_local=False, parse_netmask=True):
        if isinstance(addr, CheckedIPAddress):
            super(CheckedIPAddress, self).__init__(addr)
            self.prefixlen = addr.prefixlen
            self.defaultnet = addr.defaultnet
            self.interface = addr.interface
            return

        net = None
        iface = None
        defnet = False

        if isinstance(addr, netaddr.IPNetwork):
            net = addr
            addr = net.ip
        elif isinstance(addr, netaddr.IPAddress):
            pass
        else:
            try:
                addr = netaddr.IPAddress(addr)
            except ValueError:
                net = netaddr.IPNetwork(addr)
                if not parse_netmask:
                    raise ValueError("netmask and prefix length not allowed here")
                addr = net.ip

        if addr.version not in (4, 6):
            raise ValueError("unsupported IP version")
        if addr.is_loopback():
            raise ValueError("cannot use loopback IP address")
        if addr.is_reserved() or addr in netaddr.ip.IPV4_6TO4:
            raise ValueError("cannot use IANA reserved IP address")
        if addr.is_link_local():
            raise ValueError("cannot use link-local IP address")
        if addr.is_multicast():
            raise ValueError("cannot use multicast IP address")

        if match_local:
            if addr.version == 4:
                family = 'inet'
            elif addr.version == 6:
                family = 'inet6'

            ipresult = run(['/sbin/ip', '-family', family, '-oneline', 'address', 'show'])
            lines = ipresult[0].split('\n')
            for line in lines:
                fields = line.split()
                if len(fields) < 4:
                    continue

                ifnet = netaddr.IPNetwork(fields[3])
                if ifnet == net or (net is None and ifnet.ip == addr):
                    net = ifnet
                    iface = fields[1]
                    break

            if iface is None:
                raise ValueError('No network interface matches the provided IP address and netmask')

        if net is None:
            defnet = True
            if addr.version == 4:
                net = netaddr.IPNetwork(netaddr.cidr_abbrev_to_verbose(str(addr)))
            elif addr.version == 6:
                net = netaddr.IPNetwork(str(addr) + '/64')

        if addr == net.network:
            raise ValueError("cannot use IP network address")
        if addr.version == 4 and addr == net.broadcast:
            raise ValueError("cannot use broadcast IP address")

        super(CheckedIPAddress, self).__init__(addr)
        self.prefixlen = net.prefixlen
        self.defaultnet = defnet
        self.interface = iface

    def is_local(self):
        return self.interface is not None

def valid_ip(addr):
    return netaddr.valid_ipv4(addr) or netaddr.valid_ipv6(addr)

def realm_to_suffix(realm_name):
    s = realm_name.split(".")
    terms = ["dc=" + x.lower() for x in s]
    return ",".join(terms)

def template_str(txt, vars):
    val = string.Template(txt).substitute(vars)

    # eval() is a special string one can insert into a template to have the
    # Python interpreter evaluate the string. This is intended to allow
    # math to be performed in templates.
    pattern = re.compile('(eval\s*\(([^()]*)\))')
    val = pattern.sub(lambda x: str(eval(x.group(2))), val)

    return val

def template_file(infilename, vars):
    txt = open(infilename).read()
    return template_str(txt, vars)

def write_tmp_file(txt):
    fd = tempfile.NamedTemporaryFile()
    fd.write(txt)
    fd.flush()

    return fd

def run(args, stdin=None, raiseonerr=True,
        nolog=(), env=None, capture_output=True):
    """
    Execute a command and return stdin, stdout and the process return code.

    args is a list of arguments for the command

    stdin is used if you want to pass input to the command

    raiseonerr raises an exception if the return code is not zero

    nolog is a tuple of strings that shouldn't be logged, like passwords.
    Each tuple consists of a string to be replaced by XXXXXXXX.

    For example, the command ['/usr/bin/setpasswd', '--password', 'Secret123', 'someuser']

    We don't want to log the password so nolog would be set to:
    ('Secret123',)

    The resulting log output would be:

    /usr/bin/setpasswd --password XXXXXXXX someuser

    If an value isn't found in the list it is silently ignored.
    """
    p_in = None
    p_out = None
    p_err = None

    if env is None:
        # copy default env
        env = copy.deepcopy(os.environ)
        env["PATH"] = "/bin:/sbin:/usr/kerberos/bin:/usr/kerberos/sbin:/usr/bin:/usr/sbin"
    if stdin:
        p_in = subprocess.PIPE
    if capture_output:
        p_out = subprocess.PIPE
        p_err = subprocess.PIPE

    p = subprocess.Popen(args, stdin=p_in, stdout=p_out, stderr=p_err,
                         close_fds=True, env=env)
    stdout,stderr = p.communicate(stdin)
    stdout,stderr = str(stdout), str(stderr)    # Make pylint happy

    # The command and its output may include passwords that we don't want
    # to log. Run through the nolog items.
    args = ' '.join(args)
    for value in nolog:
        if not isinstance(value, basestring):
            continue

        quoted = urllib2.quote(value)
        for nolog_value in (value, quoted):
            if capture_output:
                stdout = stdout.replace(nolog_value, 'XXXXXXXX')
                stderr = stderr.replace(nolog_value, 'XXXXXXXX')
            args = args.replace(nolog_value, 'XXXXXXXX')

    logging.debug('args=%s' % args)
    if capture_output:
        logging.debug('stdout=%s' % stdout)
        logging.debug('stderr=%s' % stderr)

    if p.returncode != 0 and raiseonerr:
        raise CalledProcessError(p.returncode, args)

    return (stdout, stderr, p.returncode)

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

def install_file(fname, dest):
    if file_exists(dest):
        os.rename(dest, dest + ".orig")
    shutil.move(fname, dest)

def backup_file(fname):
    if file_exists(fname):
        os.rename(fname, fname + ".orig")

# uses gpg to compress and encrypt a file
def encrypt_file(source, dest, password, workdir = None):
    if type(source) is not StringType or not len(source):
        raise ValueError('Missing Source File')
    #stat it so that we get back an exception if it does no t exist
    os.stat(source)

    if type(dest) is not StringType or not len(dest):
        raise ValueError('Missing Destination File')

    if type(password) is not StringType or not len(password):
        raise ValueError('Missing Password')

    #create a tempdir so that we can clean up with easily
    tempdir = tempfile.mkdtemp('', 'ipa-', workdir)
    gpgdir = tempdir+"/.gnupg"

    try:
        try:
            #give gpg a fake dir so that we can leater remove all
            #the cruft when we clean up the tempdir
            os.mkdir(gpgdir)
            args = ['/usr/bin/gpg', '--batch', '--homedir', gpgdir, '--passphrase-fd', '0', '--yes', '--no-tty', '-o', dest, '-c', source]
            run(args, password)
        except:
            raise
    finally:
        #job done, clean up
        shutil.rmtree(tempdir, ignore_errors=True)


def decrypt_file(source, dest, password, workdir = None):
    if type(source) is not StringType or not len(source):
        raise ValueError('Missing Source File')
    #stat it so that we get back an exception if it does no t exist
    os.stat(source)

    if type(dest) is not StringType or not len(dest):
        raise ValueError('Missing Destination File')

    if type(password) is not StringType or not len(password):
        raise ValueError('Missing Password')

    #create a tempdir so that we can clean up with easily
    tempdir = tempfile.mkdtemp('', 'ipa-', workdir)
    gpgdir = tempdir+"/.gnupg"

    try:
        try:
            #give gpg a fake dir so that we can leater remove all
            #the cruft when we clean up the tempdir
            os.mkdir(gpgdir)
            args = ['/usr/bin/gpg', '--batch', '--homedir', gpgdir, '--passphrase-fd', '0', '--yes', '--no-tty', '-o', dest, '-d', source]
            run(args, password)
        except:
            raise
    finally:
        #job done, clean up
        shutil.rmtree(tempdir, ignore_errors=True)


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
        return super(CIDict,self).__getitem__(string.lower(key))

    def __setitem__(self,key,value):
        lower_key = string.lower(key)
        self._keys[lower_key] = key
        return super(CIDict,self).__setitem__(string.lower(key),value)

    def __delitem__(self,key):
        lower_key = string.lower(key)
        del self._keys[lower_key]
        return super(CIDict,self).__delitem__(string.lower(key))

    def update(self,dict):
        for key in dict.keys():
            self[key] = dict[key]

    def has_key(self,key):
        return super(CIDict, self).has_key(string.lower(key))

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

    def dst(self):
        return datetime.timedelta(0)

    def tzname(self):
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
    r = random.SystemRandom()
    for x in range(GEN_PWD_LEN):
        # do not generate space (chr(32)) as the first or last character
        if x == 0 or x == (GEN_PWD_LEN-1):
            rndchar = chr(r.randint(33,126))
        else:
            rndchar = chr(r.randint(32,126))

        rndpwd += rndchar

    return rndpwd


def format_list(items, quote=None, page_width=80):
    '''Format a list of items formatting them so they wrap to fit the
    available width. The items will be sorted.

    The items may optionally be quoted. The quote parameter may either be
    a string, in which case it is added before and after the item. Or the
    quote parameter may be a pair (either a tuple or list). In this case
    quote[0] is left hand quote and quote[1] is the right hand quote.
    '''
    left_quote = right_quote = ''
    num_items = len(items)
    if not num_items: return ""

    if quote is not None:
        if type(quote) in StringTypes:
            left_quote = right_quote = quote
        elif type(quote) is TupleType or type(quote) is ListType:
            left_quote = quote[0]
            right_quote = quote[1]

    max_len = max(map(len, items))
    max_len += len(left_quote) + len(right_quote)
    num_columns = (page_width + max_len) / (max_len+1)
    num_rows = (num_items + num_columns - 1) / num_columns
    items.sort()

    rows = [''] * num_rows
    i = row = col = 0

    while i < num_items:
        row = 0
        if col == 0:
            separator = ''
        else:
            separator = ' '

        while i < num_items and row < num_rows:
            rows[row] += "%s%*s" % (separator, -max_len, "%s%s%s" % (left_quote, items[i], right_quote))
            i += 1
            row += 1
        col += 1
    return '\n'.join(rows)

key_value_re = re.compile("(\w+)\s*=\s*(([^\s'\\\"]+)|(?P<quote>['\\\"])((?P=quote)|(.*?[^\\\])(?P=quote)))")
def parse_key_value_pairs(input):
    ''' Given a string composed of key=value pairs parse it and return
    a dict of the key/value pairs. Keys must be a word, a key must be followed
    by an equal sign (=) and a value. The value may be a single word or may be
    quoted. Quotes may be either single or double quotes, but must be balanced.
    Inside the quoted text the same quote used to start the quoted value may be
    used if it is escaped by preceding it with a backslash (\).
    White space between the key, the equal sign, and the value is ignored.
    Values are always strings. Empty values must be specified with an empty
    quoted string, it's value after parsing will be an empty string.

    Example: The string

    arg0 = '' arg1 = 1 arg2='two' arg3 = "three's a crowd" arg4 = "this is a \" quote"

    will produce

    arg0=   arg1=1
    arg2=two
    arg3=three's a crowd
    arg4=this is a " quote
    '''

    kv_dict = {}
    for match in key_value_re.finditer(input):
        key = match.group(1)
        quote = match.group('quote')
        if match.group(5):
            value = match.group(6)
            if value is None: value = ''
            value = re.sub('\\\%s' % quote, quote, value)
        else:
            value = match.group(2)
        kv_dict[key] = value
    return kv_dict

def parse_items(text):
    '''Given text with items separated by whitespace or comma, return a list of those items'''
    split_re = re.compile('[ ,\t\n]+')
    items = split_re.split(text)
    for item in items[:]:
        if not item: items.remove(item)
    return items

def read_pairs_file(filename):
    comment_re = re.compile('#.*$', re.MULTILINE)
    if filename == '-':
        fd = sys.stdin
    else:
        fd = open(filename)
    text = fd.read()
    text = comment_re.sub('', text) # kill comments
    pairs = parse_key_value_pairs(text)
    if fd != sys.stdin: fd.close()
    return pairs

def read_items_file(filename):
    comment_re = re.compile('#.*$', re.MULTILINE)
    if filename == '-':
        fd = sys.stdin
    else:
        fd = open(filename)
    text = fd.read()
    text = comment_re.sub('', text) # kill comments
    items = parse_items(text)
    if fd != sys.stdin: fd.close()
    return items

def user_input(prompt, default = None, allow_empty = True):
    if default == None:
        while True:
            ret = raw_input("%s: " % prompt)
            if allow_empty or ret.strip():
                return ret

    if isinstance(default, basestring):
        while True:
            ret = raw_input("%s [%s]: " % (prompt, default))
            if not ret and (allow_empty or default):
                return default
            elif ret.strip():
                return ret
    if isinstance(default, bool):
        if default:
            choice = "yes"
        else:
            choice = "no"
        while True:
            ret = raw_input("%s [%s]: " % (prompt, choice))
            if not ret:
                return default
            elif ret.lower()[0] == "y":
                return True
            elif ret.lower()[0] == "n":
                return False
    if isinstance(default, int):
        while True:
            try:
                ret = raw_input("%s [%s]: " % (prompt, default))
                if not ret:
                    return default
                ret = int(ret)
            except ValueError:
                pass
            else:
                return ret

def user_input_plain(prompt, default = None, allow_empty = True, allow_spaces = True):
    while True:
        ret = user_input(prompt, default, allow_empty)
        if ipavalidate.Plain(ret, not allow_empty, allow_spaces):
            return ret

class AttributeValueCompleter:
    '''
    Gets input from the user in the form "lhs operator rhs"
    TAB completes partial input.
    lhs completes to a name in @lhs_names
    The lhs is fully parsed if a lhs_delim delimiter is seen, then TAB will
    complete to the operator and a default value.
    Default values for a lhs value can specified as:
      - a string, all lhs values will use this default
      - a dict, the lhs value is looked up in the dict to return the default or None
      - a function with a single arg, the lhs value, it returns the default or None

    After creating the completer you must open it to set the terminal
    up, Then get a line of input from the user by calling read_input()
    which returns two values, the lhs and rhs, which might be None if
    lhs or rhs was not parsed.  After you are done getting input you
    should close the completer to restore the terminal.

    Example: (note this is essentially what the convenience function get_pairs() does)

    This will allow the user to autocomplete foo & foobar, both have
    defaults defined in a dict. In addition the foobar attribute must
    be specified before the prompting loop will exit. Also, this
    example show how to require that each attrbute entered by the user
    is valid.

    attrs = ['foo', 'foobar']
    defaults = {'foo' : 'foo_default', 'foobar' : 'foobar_default'}
    mandatory_attrs = ['foobar']

    c = AttributeValueCompleter(attrs, defaults)
    c.open()
    mandatory_attrs_remaining = mandatory_attrs[:]

    while True:
        if mandatory_attrs_remaining:
            attribute, value = c.read_input("Enter: ", mandatory_attrs_remaining[0])
            try:
                mandatory_attrs_remaining.remove(attribute)
            except ValueError:
                pass
        else:
            attribute, value = c.read_input("Enter: ")
        if attribute is None:
            # Are we done?
            if mandatory_attrs_remaining:
                print "ERROR, you must specify: %s" % (','.join(mandatory_attrs_remaining))
                continue
            else:
                break
        if attribute not in attrs:
            print "ERROR: %s is not a valid attribute" % (attribute)
        else:
            print "got '%s' = '%s'" % (attribute, value)

    c.close()
    print "exiting..."
    '''

    def __init__(self, lhs_names, default_value=None, lhs_regexp=r'^\s*(?P<lhs>[^ =]+)', lhs_delims=' =',
                 operator='=', strip_rhs=True):
        self.lhs_names = lhs_names
        self.default_value = default_value
        # lhs_regexp must have named group 'lhs' which returns the contents of the lhs
        self.lhs_regexp = lhs_regexp
        self.lhs_re = re.compile(self.lhs_regexp)
        self.lhs_delims = lhs_delims
        self.operator = operator
        self.strip_rhs = strip_rhs
        self.pairs = None
        self._reset()

    def _reset(self):
        self.lhs = None
        self.lhs_complete = False
        self.operator_complete = False
        self.rhs = None

    def open(self):
        # Save state
        self.prev_completer = readline.get_completer()
        self.prev_completer_delims = readline.get_completer_delims()

        # Set up for ourself
        readline.parse_and_bind("tab: complete")
        readline.set_completer(self.complete)
        readline.set_completer_delims(self.lhs_delims)

    def close(self):
        # Restore previous state
        readline.set_completer_delims(self.prev_completer_delims)
        readline.set_completer(self.prev_completer)

    def parse_input(self):
        '''We are looking for 3 tokens: <lhs,op,rhs>
        Extract as much of each token as possible.
        Set flags indicating if token is fully parsed.
        '''
        try:
            self._reset()
            buf_len = len(self.line_buffer)
            pos = 0
            lhs_match = self.lhs_re.search(self.line_buffer, pos)
            if not lhs_match: return            # no lhs content
            self.lhs = lhs_match.group('lhs')   # get lhs contents
            pos = lhs_match.end('lhs')          # new scanning position
            if pos == buf_len: return           # nothing after lhs, lhs incomplete
            self.lhs_complete = True            # something trails the lhs, lhs is complete
            operator_beg = self.line_buffer.find(self.operator, pos) # locate operator
            if operator_beg == -1: return	# did not find the operator
            self.operator_complete = True       # operator fully parsed
            operator_end = operator_beg + len(self.operator)
            pos = operator_end                  # step over the operator
            self.rhs = self.line_buffer[pos:]
        except Exception, e:
            traceback.print_exc()
            print "Exception in %s.parse_input(): %s" % (self.__class__.__name__, e)

    def get_default_value(self):
        '''default_value can be a string, a dict, or a function.
        If it's a string it's a global default for all attributes.
        If it's a dict the default is looked up in the dict index by attribute.
        If it's a function, the function is called with 1 parameter, the attribute
        and it should return the default value for the attriubte or None'''

        if not self.lhs_complete: raise ValueError("attribute not parsed")

        # If the user previously provided a value let that override the supplied default
        if self.pairs is not None:
            prev_value = self.pairs.get(self.lhs)
            if prev_value is not None: return prev_value

        # No previous user provided value, query for a default
        default_value_type = type(self.default_value)
        if default_value_type is DictType:
            return self.default_value.get(self.lhs, None)
        elif default_value_type is FunctionType:
            return self.default_value(self.lhs)
        elif default_value_type is StringType:
            return self.default_value
        else:
            return None

    def get_lhs_completions(self, text):
        if text:
            self.completions = [lhs for lhs in self.lhs_names if lhs.startswith(text)]
        else:
            self.completions = self.lhs_names

    def complete(self, state):
        self.line_buffer= readline.get_line_buffer()
        self.parse_input()
        if not self.lhs_complete:
            # lhs is not complete, set up to complete the lhs
            if state == 0:
                beg = readline.get_begidx()
                end = readline.get_endidx()
                self.get_lhs_completions(self.line_buffer[beg:end])
            if state >= len(self.completions): return None
            return self.completions[state]


        elif not self.operator_complete:
            # lhs is complete, but the operator is not so we complete
            # by inserting the operator manually.
            # Also try to complete the default value at this time.
            readline.insert_text('%s ' % self.operator)
            default_value = self.get_default_value()
            if default_value is not None:
                readline.insert_text(default_value)
            readline.redisplay()
            return None
        else:
            # lhs and operator are complete, if the rhs is blank
            # (either empty or only only whitespace) then attempt
            # to complete by inserting the default value, otherwise
            # there is nothing we can complete to so we're done.
            if self.rhs.strip():
                return None
            default_value = self.get_default_value()
            if default_value is not None:
                readline.insert_text(default_value)
                readline.redisplay()
            return None

    def pre_input_hook(self):
        readline.insert_text('%s %s ' % (self.initial_lhs, self.operator))
        readline.redisplay()

    def read_input(self, prompt, initial_lhs=None):
        self.initial_lhs = initial_lhs
        try:
            self._reset()
            if initial_lhs is None:
                readline.set_pre_input_hook(None)
            else:
                readline.set_pre_input_hook(self.pre_input_hook)
            self.line_buffer = raw_input(prompt).strip()
            self.parse_input()
            if self.strip_rhs and self.rhs is not None:
                return self.lhs, self.rhs.strip()
            else:
                return self.lhs, self.rhs
        except EOFError:
            return None, None

    def get_pairs(self, prompt, mandatory_attrs=None, validate_callback=None, must_match=True, value_required=True):
        self.pairs = {}
        if mandatory_attrs:
            mandatory_attrs_remaining = mandatory_attrs[:]
        else:
            mandatory_attrs_remaining = []

        print "Enter name = value"
        print "Press <ENTER> to accept, a blank line terminates input"
        print "Pressing <TAB> will auto completes name, assignment, and value"
        print
        while True:
            if mandatory_attrs_remaining:
                attribute, value = self.read_input(prompt, mandatory_attrs_remaining[0])
            else:
                attribute, value = self.read_input(prompt)
            if attribute is None:
                # Are we done?
                if mandatory_attrs_remaining:
                    print "ERROR, you must specify: %s" % (','.join(mandatory_attrs_remaining))
                    continue
                else:
                    break
            if value is None:
                if value_required:
                    print "ERROR: you must specify a value for %s" % attribute
                    continue
            else:
                if must_match and attribute not in self.lhs_names:
                    print "ERROR: %s is not a valid name" % (attribute)
                    continue
            if validate_callback is not None:
                if not validate_callback(attribute, value):
                    print "ERROR: %s is not valid for %s" % (value, attribute)
                    continue
            try:
                mandatory_attrs_remaining.remove(attribute)
            except ValueError:
                pass

            self.pairs[attribute] = value
        return self.pairs

class ItemCompleter:
    '''
    Prompts the user for items in a list of items with auto completion.
    TAB completes partial input.
    More than one item can be specifed during input, whitespace and/or comma's seperate.
    Example:

    possible_items = ['foo', 'bar']
    c = ItemCompleter(possible_items)
    c.open()
    # Use read_input() to limit input to a single carriage return (e.g. <ENTER>)
    #items = c.read_input("Enter: ")
    # Use get_items to iterate until a blank line is entered.
    items = c.get_items("Enter: ")
    c.close()
    print "items=%s" % (items)

    '''

    def __init__(self, items):
        self.items = items
        self.initial_input = None
        self.item_delims = ' \t,'
        self.operator = '='
        self.split_re = re.compile('[%s]+' % self.item_delims)

    def open(self):
        # Save state
        self.prev_completer = readline.get_completer()
        self.prev_completer_delims = readline.get_completer_delims()

        # Set up for ourself
        readline.parse_and_bind("tab: complete")
        readline.set_completer(self.complete)
        readline.set_completer_delims(self.item_delims)

    def close(self):
        # Restore previous state
        readline.set_completer_delims(self.prev_completer_delims)
        readline.set_completer(self.prev_completer)

    def get_item_completions(self, text):
        if text:
            self.completions = [lhs for lhs in self.items if lhs.startswith(text)]
        else:
            self.completions = self.items

    def complete(self, state):
        self.line_buffer= readline.get_line_buffer()
        if state == 0:
            beg = readline.get_begidx()
            end = readline.get_endidx()
            self.get_item_completions(self.line_buffer[beg:end])
        if state >= len(self.completions): return None
        return self.completions[state]

    def pre_input_hook(self):
        readline.insert_text('%s %s ' % (self.initial_input, self.operator))
        readline.redisplay()

    def read_input(self, prompt, initial_input=None):
        items = []

        self.initial_input = initial_input
        try:
            if initial_input is None:
                readline.set_pre_input_hook(None)
            else:
                readline.set_pre_input_hook(self.pre_input_hook)
            self.line_buffer = raw_input(prompt).strip()
            items = self.split_re.split(self.line_buffer)
            for item in items[:]:
                if not item: items.remove(item)
            return items
        except EOFError:
            return items

    def get_items(self, prompt, must_match=True):
        items = []

        print "Enter name [name ...]"
        print "Press <ENTER> to accept, blank line or control-D terminates input"
        print "Pressing <TAB> auto completes name"
        print
        while True:
            new_items = self.read_input(prompt)
            if not new_items: break
            for item in new_items:
                if must_match:
                    if item not in self.items:
                        print "ERROR: %s is not valid" % (item)
                        continue
                if item in items: continue
                items.append(item)

        return items

def get_gsserror(e):
    """
    A GSSError exception looks differently in python 2.4 than it does
    in python 2.5. Deal with it.
    """

    try:
       major = e[0]
       minor = e[1]
    except:
       major = e[0][0]
       minor = e[0][1]

    return (major, minor)



def host_port_open(host, port, socket_stream=True, socket_timeout=None):
    families = (socket.AF_INET, socket.AF_INET6)
    success = False

    if socket_stream:
        socket_type = socket.SOCK_STREAM
    else:
        socket_type = socket.SOCK_DGRAM

    for family in families:
        try:
            try:
                s = socket.socket(family, socket_type)
            except socket.error:
                continue

            if socket_timeout is not None:
                s.settimeout(socket_timeout)

            s.connect((host, port))
            success = True
        except socket.error, e:
            pass
        finally:
            s.close()

        if success:
            return True

    return False

def bind_port_responder(port, socket_stream=True, socket_timeout=None, responder_data=None):
    families = (socket.AF_INET, socket.AF_INET6)

    if socket_stream:
        socket_type = socket.SOCK_STREAM
    else:
        socket_type = socket.SOCK_DGRAM

    host = ''   # all available interfaces

    for family in families:
        try:
            s = socket.socket(family, socket_type)
        except socket.error, e:
            if family == families[-1]:  # last available family
                raise e

    if socket_timeout is not None:
        s.settimeout(socket_timeout)

    if socket_stream:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        s.bind((host, port))

        if socket_stream:
            s.listen(1)
            connection, client_address = s.accept()
            try:
                if responder_data:
                    connection.sendall(responder_data) #pylint: disable=E1101
            finally:
                connection.close()
        else:
            data, addr = s.recvfrom( 512 ) # buffer size is 1024 bytes

            if responder_data:
                s.sendto(responder_data, addr)
    finally:
        s.close()

