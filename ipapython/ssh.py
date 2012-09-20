# Authors:
#   Jan Cholasta <jcholast@redhat.com>
#
# Copyright (C) 2012  Red Hat
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
#

"""
SSH utilities.
"""

import base64
import re
import struct

from ipapython.compat import md5, sha1

__all__ = ['SSHPublicKey']

OPENSSH_BASE_REGEX = re.compile(r'^[\t ]*(?P<keytype>[^\x00\n\r]+?) [\t ]*(?P<key>[^\x00\n\r]+?)(?:[\t ]+(?P<comment>[^\x00\n\r]*?)[\t ]*)?$')
OPENSSH_OPTIONS_REGEX = re.compile(r'(?P<name>[-0-9A-Za-z]+)(?:="(?P<value>(?:\\"|[^\x00\n\r"])*)")?')

class SSHPublicKey(object):
    """
    SSH public key object.
    """

    __slots__ = ('_key', '_keytype', '_comment', '_options')

    def __init__(self, key, comment=None, options=None, encoding='utf-8'):
        if isinstance(key, SSHPublicKey):
            self._key = key._key
            self._keytype = key._keytype
            self._comment = key._comment
            self._options = key._options
            return

        if not isinstance(key, (str, unicode)):
            raise TypeError("argument must be str or unicode, got %s" % type(key).__name__)

        # All valid public key blobs start with 3 null bytes (see RFC 4253
        # section 6.6, RFC 4251 section 5 and RFC 4250 section 4.6)
        if isinstance(key, str) and key[:3] != '\0\0\0':
            key = key.decode(encoding)

        valid = self._parse_raw(key) or self._parse_base64(key) or self._parse_openssh(key)
        if not valid:
            raise ValueError("not a valid SSH public key")

        if comment is not None:
            self._comment = comment
        if options is not None:
            self._options = options

    def _parse_raw(self, key):
        if not isinstance(key, str):
            return False

        try:
            (ktlen,) = struct.unpack('>I', key[:4])
        except struct.error:
            return False

        if ktlen < 1 or ktlen > len(key) - 4:
            return False

        try:
            keytype = key[4:ktlen+4].decode('ascii')
        except UnicodeDecodeError:
            return False

        self._key = key
        self._keytype = keytype
        self._options = {}
        self._comment = None

        return True

    def _parse_base64(self, key):
        if not isinstance(key, unicode):
            return False

        try:
            key = base64.b64decode(key)
        except TypeError:
            return False

        return self._parse_raw(key)

    def _parse_openssh_without_options(self, key):
        match = OPENSSH_BASE_REGEX.match(key)
        if not match:
            return False

        if not self._parse_base64(match.group('key')):
            return False

        if self._keytype != match.group('keytype'):
            return False

        self._comment = match.group('comment')

        return True

    def _parse_openssh_with_options(self, key):
        key = key.lstrip('\t ')

        options = {}
        while True:
            match = OPENSSH_OPTIONS_REGEX.match(key)
            if not match:
                return False

            name = match.group('name').lower()
            value = match.group('value')
            if value:
                value = value.replace('\\"', '"')

            options[name] = value

            key = key[len(match.group(0)):]
            key0, key = key[:1], key[1:]

            if key0 != ',':
                break

        if not self._parse_openssh_without_options(key):
            return False

        self._options = options

        return True

    def _parse_openssh(self, key):
        if not isinstance(key, unicode):
            return False

        if self._parse_openssh_without_options(key):
            return True
        else:
            return self._parse_openssh_with_options(key)

    def keytype(self):
        return self._keytype

    def comment(self):
        return self._comment

    def has_options(self):
        return bool(self._options)

    def openssh(self):
        out = u'%s %s' % (self._keytype, base64.b64encode(self._key))

        if self._options:
            options = []
            for name in sorted(self._options):
                value = self._options[name]
                if value is None:
                    options.append(name)
                else:
                    value = value.replace('"', '\\"')
                    options.append(u'%s="%s"' % (name, value))
            options = u','.join(options)

            out = u'%s %s' % (options, out)

        if self._comment:
            out = u'%s %s' % (out, self._comment)

        return out

    def fingerprint_hex_md5(self):
        fp = md5(self._key).hexdigest().upper()
        fp = u':'.join([fp[j:j+2] for j in range(0, len(fp), 2)])
        return fp

    def fingerprint_dns_sha1(self):
        if self._keytype == 'ssh-rsa':
            keytype = 1
        elif self._keytype == 'ssh-dss':
            keytype = 2
        else:
            return
        fp = sha1(self._key).hexdigest().upper()
        return u'%d 1 %s' % (keytype, fp)
