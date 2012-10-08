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

IPA_BASEDN_INFO = 'ipa v2.0'

import string
import tempfile
import subprocess
import random
import os, sys, traceback, readline
import copy
import stat
import shutil
import urllib2
import socket
import ldap
import struct
from types import *
import re
import xmlrpclib
import datetime
import netaddr
import time
import krbV
from dns import resolver, rdatatype
from dns.exception import DNSException

from ipapython.ipa_log_manager import *
from ipapython import ipavalidate
from ipapython import config
from ipapython.dn import DN

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

    # Use inet_pton() rather than inet_aton() for IP address parsing. We
    # will use the same function in IPv4/IPv6 conversions + be stricter
    # and don't allow IP addresses such as '1.1.1' in the same time
    netaddr_ip_flags = netaddr.INET_PTON

    def __init__(self, addr, match_local=False, parse_netmask=True,
                 allow_network=False, allow_loopback=False,
                 allow_broadcast=False, allow_multicast=False):
        if isinstance(addr, CheckedIPAddress):
            super(CheckedIPAddress, self).__init__(addr, flags=self.netaddr_ip_flags)
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
                try:
                    addr = netaddr.IPAddress(addr, flags=self.netaddr_ip_flags)
                except netaddr.AddrFormatError:
                    # netaddr.IPAddress doesn't handle zone indices in textual
                    # IPv6 addresses. Try removing zone index and parse the
                    # address again.
                    if not isinstance(addr, basestring):
                        raise
                    addr, sep, foo = addr.partition('%')
                    if sep != '%':
                        raise
                    addr = netaddr.IPAddress(addr, flags=self.netaddr_ip_flags)
                    if addr.version != 6:
                        raise
            except ValueError:
                net = netaddr.IPNetwork(addr, flags=self.netaddr_ip_flags)
                if not parse_netmask:
                    raise ValueError("netmask and prefix length not allowed here")
                addr = net.ip

        if addr.version not in (4, 6):
            raise ValueError("unsupported IP version")

        if not allow_loopback and addr.is_loopback():
            raise ValueError("cannot use loopback IP address")
        if (not addr.is_loopback() and addr.is_reserved()) \
                or addr in netaddr.ip.IPV4_6TO4:
            raise ValueError("cannot use IANA reserved IP address")

        if addr.is_link_local():
            raise ValueError("cannot use link-local IP address")
        if not allow_multicast and addr.is_multicast():
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

        if not allow_network and  addr == net.network:
            raise ValueError("cannot use IP network address")
        if not allow_broadcast and addr.version == 4 and addr == net.broadcast:
            raise ValueError("cannot use broadcast IP address")

        super(CheckedIPAddress, self).__init__(addr, flags=self.netaddr_ip_flags)
        self.prefixlen = net.prefixlen
        self.defaultnet = defnet
        self.interface = iface

    def is_local(self):
        return self.interface is not None

def valid_ip(addr):
    return netaddr.valid_ipv4(addr) or netaddr.valid_ipv6(addr)

def format_netloc(host, port=None):
    """
    Format network location (host:port).

    If the host part is a literal IPv6 address, it must be enclosed in square
    brackets (RFC 2732).
    """
    host = str(host)
    try:
        socket.inet_pton(socket.AF_INET6, host)
        host = '[%s]' % host
    except socket.error:
        pass
    if port is None:
        return host
    else:
        return '%s:%s' % (host, str(port))

def realm_to_suffix(realm_name):
    'Convert a kerberos realm to a IPA suffix.'
    s = realm_name.split(".")
    suffix_dn = DN(*[('dc', x.lower()) for x in s])
    return suffix_dn

def suffix_to_realm(suffix_dn):
    'Convert a IPA suffix to a kerberos realm.'
    assert isinstance(suffix_dn, DN)
    realm = '.'.join([x.value for x in suffix_dn])
    return realm

def template_str(txt, vars):
    val = string.Template(txt).substitute(vars)

    # eval() is a special string one can insert into a template to have the
    # Python interpreter evaluate the string. This is intended to allow
    # math to be performed in templates.
    pattern = re.compile('(eval\s*\(([^()]*)\))')
    val = pattern.sub(lambda x: str(eval(x.group(2))), val)

    return val

def template_file(infilename, vars):
    """Read a file and perform template substitutions"""
    with open(infilename) as f:
        return template_str(f.read(), vars)


def copy_template_file(infilename, outfilename, vars):
    """Copy a file, performing template substitutions"""
    txt = template_file(infilename, vars)
    with open(outfilename, 'w') as file:
        file.write(txt)


def write_tmp_file(txt):
    fd = tempfile.NamedTemporaryFile()
    fd.write(txt)
    fd.flush()

    return fd

def shell_quote(string):
    return "'" + string.replace("'", "'\\''") + "'"

def run(args, stdin=None, raiseonerr=True,
        nolog=(), env=None, capture_output=True, cwd=None):
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

    if isinstance(nolog, basestring):
        # We expect a tuple (or list, or other iterable) of nolog strings.
        # Passing just a single string is bad: strings are also, so this
        # would result in every individual character of that string being
        # replaced by XXXXXXXX.
        # This is a sanity check to prevent that.
        raise ValueError('nolog must be a tuple of strings.')

    if env is None:
        # copy default env
        env = copy.deepcopy(os.environ)
        env["PATH"] = "/bin:/sbin:/usr/kerberos/bin:/usr/kerberos/sbin:/usr/bin:/usr/sbin"
    if stdin:
        p_in = subprocess.PIPE
    if capture_output:
        p_out = subprocess.PIPE
        p_err = subprocess.PIPE

    try:
        p = subprocess.Popen(args, stdin=p_in, stdout=p_out, stderr=p_err,
                             close_fds=True, env=env, cwd=cwd)
        stdout,stderr = p.communicate(stdin)
        stdout,stderr = str(stdout), str(stderr)    # Make pylint happy
    except KeyboardInterrupt:
        p.wait()
        raise

    # The command and its output may include passwords that we don't want
    # to log. Replace those.
    args = ' '.join(args)
    if capture_output:
        stdout = nolog_replace(stdout, nolog)
        stderr = nolog_replace(stderr, nolog)
    args = nolog_replace(args, nolog)

    root_logger.debug('args=%s' % args)
    if capture_output:
        root_logger.debug('stdout=%s' % stdout)
        root_logger.debug('stderr=%s' % stderr)

    if p.returncode != 0 and raiseonerr:
        raise CalledProcessError(p.returncode, args)

    return (stdout, stderr, p.returncode)


def nolog_replace(string, nolog):
    """Replace occurences of strings given in `nolog` with XXXXXXXX"""
    for value in nolog:
        if not isinstance(value, basestring):
            continue

        quoted = urllib2.quote(value)
        shquoted = shell_quote(value)
        for nolog_value in (shquoted, value, quoted):
            string = string.replace(nolog_value, 'XXXXXXXX')
    return string


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

def ipa_generate_password(characters=None,pwd_len=None):
    ''' Generates password. Password cannot start or end with a whitespace
    character. It also cannot be formed by whitespace characters only.
    Length of password as well as string of characters to be used by
    generator could be optionaly specified by characters and pwd_len
    parameters, otherwise default values will be used: characters string
    will be formed by all printable non-whitespace characters and space,
    pwd_len will be equal to value of GEN_PWD_LEN.
    '''
    if not characters:
        characters=string.digits + string.ascii_letters + string.punctuation + ' '
    else:
        if characters.isspace():
            raise ValueError("password cannot be formed by whitespaces only")
    if not pwd_len:
        pwd_len = GEN_PWD_LEN

    upper_bound = len(characters) - 1
    rndpwd = ''
    r = random.SystemRandom()

    for x in range(pwd_len):
        rndchar = characters[r.randint(0,upper_bound)]
        if (x == 0) or (x == pwd_len-1):
            while rndchar.isspace():
                rndchar = characters[r.randint(0,upper_bound)]
        rndpwd += rndchar
    return rndpwd

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



def host_port_open(host, port, socket_type=socket.SOCK_STREAM, socket_timeout=None):
    for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket_type):
        af, socktype, proto, canonname, sa = res
        try:
            try:
                s = socket.socket(af, socktype, proto)
            except socket.error:
                s = None
                continue

            if socket_timeout is not None:
                s.settimeout(socket_timeout)

            s.connect(sa)

            if socket_type == socket.SOCK_DGRAM:
                s.send('')
                s.recv(512)

            return True
        except socket.error, e:
            pass
        finally:
            if s:
                s.close()

    return False

def bind_port_responder(port, socket_type=socket.SOCK_STREAM, socket_timeout=None, responder_data=None):
    host = None   # all available interfaces
    last_socket_error = None

    # At first try to create IPv6 socket as it is able to accept both IPv6 and
    # IPv4 connections (when not turned off)
    families = (socket.AF_INET6, socket.AF_INET)
    s = None

    for family in families:
        try:
            addr_infos = socket.getaddrinfo(host, port, family, socket_type, 0,
                            socket.AI_PASSIVE)
        except socket.error, e:
            last_socket_error = e
            continue
        for res in addr_infos:
            af, socktype, proto, canonname, sa = res
            try:
                s = socket.socket(af, socktype, proto)
            except socket.error, e:
                last_socket_error = e
                s = None
                continue

            if socket_timeout is not None:
                s.settimeout(1)

            if af == socket.AF_INET6:
                try:
                    # Make sure IPv4 clients can connect to IPv6 socket
                    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                except socket.error:
                    pass

            if socket_type == socket.SOCK_STREAM:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                s.bind(sa)

                while True:
                    if socket_type == socket.SOCK_STREAM:
                        s.listen(1)
                        connection, client_address = s.accept()
                        try:
                            if responder_data:
                                connection.sendall(responder_data) #pylint: disable=E1101
                        finally:
                            connection.close()
                    elif socket_type == socket.SOCK_DGRAM:
                        data, addr = s.recvfrom(1)

                        if responder_data:
                            s.sendto(responder_data, addr)
            except socket.timeout:
                # Timeout is expectable as it was requested by caller, raise
                # the exception back to him
                raise
            except socket.error, e:
                last_socket_error = e
                s.close()
                s = None
                continue
            finally:
                if s:
                    s.close()

    if s is None and last_socket_error is not None:
        raise last_socket_error # pylint: disable=E0702

def is_host_resolvable(fqdn):
    for rdtype in (rdatatype.A, rdatatype.AAAA):
        try:
            resolver.query(fqdn, rdtype)
        except DNSException:
            continue
        else:
            return True

    return False

def get_ipa_basedn(conn):
    """
    Get base DN of IPA suffix in given LDAP server.

    None is returned if the suffix is not found

    :param conn: Bound LDAP connection that will be used for searching
    """
    entries = conn.search_ext_s(
        '', scope=ldap.SCOPE_BASE, attrlist=['defaultnamingcontext', 'namingcontexts']
    )

    contexts = entries[0][1]['namingcontexts']
    if entries[0][1].get('defaultnamingcontext'):
        # If there is a defaultNamingContext examine that one first
        default = entries[0][1]['defaultnamingcontext'][0]
        if default in contexts:
            contexts.remove(default)
        contexts.insert(0, entries[0][1]['defaultnamingcontext'][0])
    for context in contexts:
        root_logger.debug("Check if naming context '%s' is for IPA" % context)
        try:
            entry = conn.search_s(context, ldap.SCOPE_BASE, "(info=IPA*)")
        except ldap.NO_SUCH_OBJECT:
            root_logger.debug("LDAP server did not return info attribute to check for IPA version")
            continue
        if len(entry) == 0:
            root_logger.debug("Info attribute with IPA server version not found")
            continue
        info = entry[0][1]['info'][0].lower()
        if info != IPA_BASEDN_INFO:
            root_logger.debug("Detected IPA server version (%s) did not match the client (%s)" \
                % (info, IPA_BASEDN_INFO))
            continue
        root_logger.debug("Naming context '%s' is a valid IPA context" % context)
        return DN(context)

    return None

def config_replace_variables(filepath, replacevars=dict(), appendvars=dict()):
    """
    Take a key=value based configuration file, and write new version
    with certain values replaced or appended

    All (key,value) pairs from replacevars and appendvars that were not found
    in the configuration file, will be added there.

    It is responsibility of a caller to ensure that replacevars and
    appendvars do not overlap.

    It is responsibility of a caller to back up file.

    returns dictionary of affected keys and their previous values

    One have to run restore_context(filepath) afterwards or
    security context of the file will not be correct after modification
    """
    pattern = re.compile('''
(^
                        \s*
        (?P<option>     [^\#;]+?)
                        (\s*=\s*)
        (?P<value>      .+?)?
                        (\s*((\#|;).*)?)?
$)''', re.VERBOSE)
    orig_stat = os.stat(filepath)
    old_values = dict()
    temp_filename = None
    with tempfile.NamedTemporaryFile(delete=False) as new_config:
        temp_filename = new_config.name
        with open(filepath, 'r') as f:
            for line in f:
                new_line = line
                m = pattern.match(line)
                if m:
                    option, value = m.group('option', 'value')
                    if option is not None:
                        if replacevars and option in replacevars:
                            # replace value completely
                            new_line = u"%s=%s\n" % (option, replacevars[option])
                            old_values[option] = value
                        if appendvars and option in appendvars:
                            # append new value unless it is already existing in the original one
                            if not value:
                                new_line = u"%s=%s\n" % (option, appendvars[option])
                            elif value.find(appendvars[option]) == -1:
                                new_line = u"%s=%s %s\n" % (option, value, appendvars[option])
                            old_values[option] = value
                new_config.write(new_line)
        # Now add all options from replacevars and appendvars that were not found in the file
        new_vars = replacevars.copy()
        new_vars.update(appendvars)
        newvars_view = set(new_vars.keys()) - set(old_values.keys())
        append_view = (set(appendvars.keys()) - newvars_view)
        for item in newvars_view:
            new_config.write("%s=%s\n" % (item,new_vars[item]))
        for item in append_view:
            new_config.write("%s=%s\n" % (item,appendvars[item]))
        new_config.flush()
        # Make sure the resulting file is readable by others before installing it
        os.fchmod(new_config.fileno(), orig_stat.st_mode)
        os.fchown(new_config.fileno(), orig_stat.st_uid, orig_stat.st_gid)

    # At this point new_config is closed but not removed due to 'delete=False' above
    # Now, install the temporary file as configuration and ensure old version is available as .orig
    # While .orig file is not used during uninstall, it is left there for administrator.
    install_file(temp_filename, filepath)

    return old_values

def inifile_replace_variables(filepath, section, replacevars=dict(), appendvars=dict()):
    """
    Take a section-structured key=value based configuration file, and write new version
    with certain values replaced or appended within the section

    All (key,value) pairs from replacevars and appendvars that were not found
    in the configuration file, will be added there.

    It is responsibility of a caller to ensure that replacevars and
    appendvars do not overlap.

    It is responsibility of a caller to back up file.

    returns dictionary of affected keys and their previous values

    One have to run restore_context(filepath) afterwards or
    security context of the file will not be correct after modification
    """
    pattern = re.compile('''
(^
                        \[
        (?P<section>    .+) \]
                        (\s+((\#|;).*)?)?
$)|(^
                        \s*
        (?P<option>     [^\#;]+?)
                        (\s*=\s*)
        (?P<value>      .+?)?
                        (\s*((\#|;).*)?)?
$)''', re.VERBOSE)
    def add_options(config, replacevars, appendvars, oldvars):
        # add all options from replacevars and appendvars that were not found in the file
        new_vars = replacevars.copy()
        new_vars.update(appendvars)
        newvars_view = set(new_vars.keys()) - set(oldvars.keys())
        append_view = (set(appendvars.keys()) - newvars_view)
        for item in newvars_view:
            config.write("%s=%s\n" % (item,new_vars[item]))
        for item in append_view:
            config.write("%s=%s\n" % (item,appendvars[item]))

    orig_stat = os.stat(filepath)
    old_values = dict()
    temp_filename = None
    with tempfile.NamedTemporaryFile(delete=False) as new_config:
        temp_filename = new_config.name
        with open(filepath, 'r') as f:
            in_section = False
            finished = False
            line_idx = 1
            for line in f:
                line_idx = line_idx + 1
                new_line = line
                m = pattern.match(line)
                if m:
                    sect, option, value = m.group('section', 'option', 'value')
                    if in_section and sect is not None:
                        # End of the searched section, add remaining options
                        add_options(new_config, replacevars, appendvars, old_values)
                        finished = True
                    if sect is not None:
                        # New section is found, check whether it is the one we are looking for
                        in_section = (str(sect).lower() == str(section).lower())
                    if option is not None and in_section:
                        # Great, this is an option from the section we are loking for
                        if replacevars and option in replacevars:
                            # replace value completely
                            new_line = u"%s=%s\n" % (option, replacevars[option])
                            old_values[option] = value
                        if appendvars and option in appendvars:
                            # append a new value unless it is already existing in the original one
                            if not value:
                                new_line = u"%s=%s\n" % (option, appendvars[option])
                            elif value.find(appendvars[option]) == -1:
                                new_line = u"%s=%s %s\n" % (option, value, appendvars[option])
                            old_values[option] = value
                    new_config.write(new_line)
            # We have finished parsing the original file.
            # There are two remaining cases:
            # 1. Section we were looking for was not found, we need to add it.
            if not (in_section or finished):
                new_config.write("[%s]\n" % (section))
            # 2. The section is the last one but some options were not found, add them.
            if in_section or not finished:
                add_options(new_config, replacevars, appendvars, old_values)

        new_config.flush()
        # Make sure the resulting file is readable by others before installing it
        os.fchmod(new_config.fileno(), orig_stat.st_mode)
        os.fchown(new_config.fileno(), orig_stat.st_uid, orig_stat.st_gid)

    # At this point new_config is closed but not removed due to 'delete=False' above
    # Now, install the temporary file as configuration and ensure old version is available as .orig
    # While .orig file is not used during uninstall, it is left there for administrator.
    install_file(temp_filename, filepath)

    return old_values

def backup_config_and_replace_variables(
        fstore, filepath, replacevars=dict(), appendvars=dict()):
    """
    Take a key=value based configuration file, back up it, and
    write new version with certain values replaced or appended

    All (key,value) pairs from replacevars and appendvars that
    were not found in the configuration file, will be added there.
    The file must exist before this function is called.

    It is responsibility of a caller to ensure that replacevars and
    appendvars do not overlap.

    returns dictionary of affected keys and their previous values

    One have to run restore_context(filepath) afterwards or
    security context of the file will not be correct after modification
    """
    # Backup original filepath
    fstore.backup_file(filepath)
    old_values = config_replace_variables(filepath, replacevars, appendvars)

    return old_values


def utf8_encode_value(value):
    if isinstance(value, unicode):
        return value.encode('utf-8')
    return value


def utf8_encode_values(values):
    if isinstance(values, list) or isinstance(values, tuple):
        return map(utf8_encode_value, values)
    else:
        return utf8_encode_value(values)

def wait_for_open_ports(host, ports, timeout=0):
    """
    Wait until the specified port(s) on the remote host are open. Timeout
    in seconds may be specified to limit the wait. If the timeout is
    exceeded, socket.timeout exception is raised.
    """
    if not isinstance(ports, (tuple, list)):
        ports = [ports]

    root_logger.debug('wait_for_open_ports: %s %s timeout %d', host, ports, timeout)
    op_timeout = time.time() + timeout

    for port in ports:
        while True:
            port_open = host_port_open(host, port)

            if port_open:
                break
            if timeout and time.time() > op_timeout: # timeout exceeded
                raise socket.timeout()
            time.sleep(1)

def wait_for_open_socket(socket_name, timeout=0):
    """
    Wait until the specified socket on the local host is open. Timeout
    in seconds may be specified to limit the wait.
    """
    op_timeout = time.time() + timeout

    while True:
        try:
            s = socket.socket(socket.AF_UNIX)
            s.connect(socket_name)
            s.close()
            break
        except socket.error, e:
            if e.errno in (2,111):  # 111: Connection refused, 2: File not found
                if timeout and time.time() > op_timeout: # timeout exceeded
                    raise e
                time.sleep(1)
            else:
                raise e

def kinit_hostprincipal(keytab, ccachedir, principal):
    """
    Given a ccache directory and a principal kinit as that user.

    This blindly overwrites the current CCNAME so if you need to save
    it do so before calling this function.

    Thus far this is used to kinit as the local host.
    """
    try:
        ccache_file = 'FILE:%s/ccache' % ccachedir
        krbcontext = krbV.default_context()
        ktab = krbV.Keytab(name=keytab, context=krbcontext)
        princ = krbV.Principal(name=principal, context=krbcontext)
        os.environ['KRB5CCNAME'] = ccache_file
        ccache = krbV.CCache(name=ccache_file, context=krbcontext, primary_principal=princ)
        ccache.init(princ)
        ccache.init_creds_keytab(keytab=ktab, principal=princ)
        return ccache_file
    except krbV.Krb5Error, e:
        raise StandardError('Error initializing principal %s in %s: %s' % (principal, keytab, str(e)))

def dn_attribute_property(private_name):
    '''
    Create a property for a dn attribute which assures the attribute
    is a DN or None. If the value is not None the setter converts it to
    a DN. The getter assures it's either None or a DN instance.

    The private_name parameter is the class internal attribute the property
    shadows.

    For example if a class has an attribute called base_dn, then:

        base_dn = dn_attribute_property('_base_dn')

    Thus the class with have an attriubte called base_dn which can only
    ever be None or a DN instance. The actual value is stored in _base_dn.
    '''

    def setter(self, value):
        if value is not None:
            value = DN(value)
        setattr(self, private_name, value)

    def getter(self):
        value = getattr(self, private_name)
        if value is not None:
            assert isinstance(value, DN)
        return value

    return property(getter, setter)
