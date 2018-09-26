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
from hashlib import sha1
from hashlib import sha256  # pylint: disable=E0611

import six

if six.PY3:
    unicode = str

__all__ = ['SSHPublicKey']

OPENSSH_BASE_REGEX = re.compile(r'^[\t ]*(?P<keytype>[^\x00\n\r]+?) [\t ]*(?P<key>[^\x00\n\r]+?)(?:[\t ]+(?P<comment>[^\x00\n\r]*?)[\t ]*)?$')
OPENSSH_OPTIONS_REGEX = re.compile(r'(?P<name>[-0-9A-Za-z]+)(?:="(?P<value>(?:\\"|[^\x00\n\r"])*)")?')


class SSHPublicKey:
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

        if not isinstance(key, (bytes, unicode)):
            raise TypeError("argument must be bytes or unicode, got %s" % type(key).__name__)

        # All valid public key blobs start with 3 null bytes (see RFC 4253
        # section 6.6, RFC 4251 section 5 and RFC 4250 section 4.6)
        if isinstance(key, bytes) and key[:3] != b'\0\0\0':
            key = key.decode(encoding)

        valid = self._parse_raw(key) or self._parse_base64(key) or self._parse_openssh(key)

        if not valid:
            raise ValueError("not a valid SSH public key")

        if comment is not None:
            self._comment = comment
        if options is not None:
            self._options = options

    def _parse_raw(self, key):
        if not isinstance(key, bytes):
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
        except (TypeError, ValueError):
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
        key = base64.b64encode(self._key).decode('ascii')
        out = u'%s %s' % (self._keytype, key)

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

    def fingerprint_hex_sha256(self):
        # OpenSSH trims the trailing '=' of base64 sha256 FP representation
        fp = base64.b64encode(sha256(self._key).digest()).rstrip(b'=')
        return u'SHA256:{fp}'.format(fp=fp.decode('utf-8'))

    def _fingerprint_dns(self, fpfunc, fptype):
        if self._keytype == 'ssh-rsa':
            keytype = 1
        elif self._keytype == 'ssh-dss':
            keytype = 2
        elif self._keytype.startswith('ecdsa-sha2-') and '@' not in self._keytype:
            keytype = 3
        elif self._keytype == 'ssh-ed25519':
            keytype = 4
        else:
            return None
        fp = fpfunc(self._key).hexdigest().upper()
        return u'%d %d %s' % (keytype, fptype, fp)

    def fingerprint_dns_sha1(self):
        return self._fingerprint_dns(sha1, 1)

    def fingerprint_dns_sha256(self):
        return self._fingerprint_dns(sha256, 2)
