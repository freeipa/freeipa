# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Various utility functions.
"""

import os
import imp
import time
import socket
import re
from types import NoneType

from ipalib import errors
from ipalib.text import _
from ipapython import dnsclient


def json_serialize(obj):
    if isinstance(obj, (list, tuple)):
        return [json_serialize(o) for o in obj]
    if isinstance(obj, dict):
        return dict((k, json_serialize(v)) for (k, v) in obj.iteritems())
    if isinstance(obj, (bool, float, int, unicode, NoneType)):
        return obj
    if isinstance(obj, str):
        return obj.decode('utf-8')
    if not callable(getattr(obj, '__json__', None)):
        # raise TypeError('%r is not JSON serializable')
        return ''
    return json_serialize(obj.__json__())

def get_current_principal():
    try:
        # krbV isn't necessarily available on client machines, fail gracefully
        import krbV
        return unicode(krbV.default_context().default_ccache().principal().name)
    except ImportError:
        raise RuntimeError('python-krbV is not available.')
    except krbV.Krb5Error:
        #TODO: do a kinit?
        raise errors.CCacheError()

def get_fqdn():
    fqdn = ""
    try:
        fqdn = socket.getfqdn()
    except:
        try:
            fqdn = socket.gethostname()
        except:
            fqdn = ""
    return fqdn

# FIXME: This function has no unit test
def find_modules_in_dir(src_dir):
    """
    Iterate through module names found in ``src_dir``.
    """
    if not (os.path.abspath(src_dir) == src_dir and os.path.isdir(src_dir)):
        return
    if os.path.islink(src_dir):
        return
    suffix = '.py'
    for name in sorted(os.listdir(src_dir)):
        if not name.endswith(suffix):
            continue
        pyfile = os.path.join(src_dir, name)
        if os.path.islink(pyfile) or not os.path.isfile(pyfile):
            continue
        module = name[:-len(suffix)]
        if module == '__init__':
            continue
        yield (module, pyfile)


# FIXME: This function has no unit test
def load_plugins_in_dir(src_dir):
    """
    Import each Python module found in ``src_dir``.
    """
    for module in find_modules_in_dir(src_dir):
        imp.load_module(module, *imp.find_module(module, [src_dir]))


# FIXME: This function has no unit test
def import_plugins_subpackage(name):
    """
    Import everythig in ``plugins`` sub-package of package named ``name``.
    """
    try:
        plugins = __import__(name + '.plugins').plugins
    except ImportError:
        return
    src_dir = os.path.dirname(os.path.abspath(plugins.__file__))
    for name in find_modules_in_dir(src_dir):
        full_name = '%s.%s' % (plugins.__name__, name)
        __import__(full_name)


def make_repr(name, *args, **kw):
    """
    Construct a standard representation of a class instance.
    """
    args = [repr(a) for a in args]
    kw = ['%s=%r' % (k, kw[k]) for k in sorted(kw)]
    return '%s(%s)' % (name, ', '.join(args + kw))

def realm_to_suffix(realm_name):
    s = realm_name.split(".")
    terms = ["dc=" + x.lower() for x in s]
    return ",".join(terms)

def validate_host_dns(log, fqdn):
    """
    See if the hostname has a DNS A record.
    """
    rs = dnsclient.query(fqdn + '.', dnsclient.DNS_C_IN, dnsclient.DNS_T_A)
    if len(rs) == 0:
        log.debug(
            'IPA: DNS A record lookup failed for %s' % fqdn
        )
        raise errors.DNSNotARecordError()
    else:
        log.debug(
            'IPA: found %d records for %s' % (len(rs), fqdn)
        )

def isvalid_base64(data):
    """
    Validate the incoming data as valid base64 data or not.

    The character set must only include of a-z, A-Z, 0-9, + or / and
    be padded with = to be a length divisible by 4 (so only 0-2 =s are
    allowed). Its length must be divisible by 4. White space is
    not significant so it is removed.

    This doesn't guarantee we have a base64-encoded value, just that it
    fits the base64 requirements.
    """

    data = ''.join(data.split())

    if len(data) % 4 > 0 or \
        re.match('^[a-zA-Z0-9\+\/]+\={0,2}$', data) is None:
        return False
    else:
        return True

def validate_ipaddr(ipaddr):
    """
    Check to see if the given IP address is a valid IPv4 or IPv6 address.

    Returns True or False
    """
    try:
        socket.inet_pton(socket.AF_INET, ipaddr)
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ipaddr)
        except socket.error:
            return False
    return True

def check_writable_file(filename):
    """
    Determine if the file is writable. If the file doesn't exist then
    open the file to test writability.
    """
    if filename is None:
        raise errors.FileError(reason='Filename is empty')
    try:
        if os.path.exists(filename):
            if not os.access(filename, os.W_OK):
                raise errors.FileError(reason=_('Permission denied: %(file)s') % dict(file=filename))
        else:
            fp = open(filename, 'w')
            fp.close()
    except (IOError, OSError), e:
        raise errors.FileError(reason=str(e))

def normalize_zonemgr(zonemgr):
    if not zonemgr:
        # do not normalize empty or None value
        return zonemgr
    if '@' in zonemgr:
        # local-part needs to be normalized
        name, at, domain = zonemgr.partition('@')
        name = name.replace('.', '\\.')
        zonemgr = u''.join((name, u'.', domain))

    if not zonemgr.endswith('.'):
        zonemgr = zonemgr + u'.'

    return zonemgr

def validate_zonemgr(zonemgr):
    """ See RFC 1033, 1035 """
    regex_domain = re.compile(r'^[a-z0-9]([a-z0-9-]?[a-z0-9])*$', re.IGNORECASE)
    regex_local_part = re.compile(r'^[a-z0-9]([a-z0-9-_\.]?[a-z0-9])*$',
                                    re.IGNORECASE)

    local_part_errmsg = _('mail account may only include letters, numbers, -, _ and a dot. There may not be consecutive -, _ and . characters')

    if len(zonemgr) > 255:
        raise ValueError(_('cannot be longer that 255 characters'))

    if zonemgr.endswith('.'):
        zonemgr = zonemgr[:-1]

    if zonemgr.count('@') == 1:
        local_part, dot, domain = zonemgr.partition('@')
        if not regex_local_part.match(local_part):
            raise ValueError(local_part_errmsg)
    elif zonemgr.count('@') > 1:
        raise ValueError(_('too many \'@\' characters'))
    else:
        last_fake_sep = zonemgr.rfind('\\.')
        if last_fake_sep != -1: # there is a 'fake' local-part/domain separator
            sep = zonemgr.find('.', last_fake_sep+2)
            if sep == -1:
                raise ValueError(_('address domain is not fully qualified ' \
                          '("example.com" instead of just "example")'))
            local_part = zonemgr[:sep]
            domain = zonemgr[sep+1:]

            if not all(regex_local_part.match(part) for part in local_part.split('\\.')):
                raise ValueError(local_part_errmsg)
        else:
            local_part, dot, domain = zonemgr.partition('.')

            if not regex_local_part.match(local_part):
                raise ValueError(local_part_errmsg)

    if '.' not in domain:
        raise ValueError(_('address domain is not fully qualified ' \
                          '("example.com" instead of just "example")'))

    if not all(regex_domain.match(part) for part in domain.split(".")):
        raise ValueError(_('domain name may only include letters, numbers, and -'))

def validate_hostname(hostname):
    """ See RFC 952, 1123"""
    regex_name = re.compile(r'^[a-z0-9]([a-z0-9-]?[a-z0-9])*$', re.IGNORECASE)

    if len(hostname) > 255:
        raise ValueError(_('cannot be longer that 255 characters'))

    if hostname.endswith('.'):
        hostname = hostname[:-1]

    if '.' not in hostname:
        raise ValueError(_('hostname is not fully qualified'))

    if not all(regex_name.match(part) for part in hostname.split(".")):
        raise ValueError(_('hostname parts may only include letters, numbers, and - ' \
                           '(which is not allowed as the last character)'))
