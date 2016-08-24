#!/usr/bin/python3
#
# Authors:
#     Christian Heimes <cheimes@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2016 Red Hat, Inc.
# All rights reserved.
#
"""Generate safe NSSCipherSuite stanza for mod_nss
"""
from __future__ import print_function

import operator
import re

# pylint: disable=import-error,no-name-in-module
from urllib.request import urlopen
# pylint: enable=import-error,no-name-in-module

SOURCE = "https://git.fedorahosted.org/cgit/mod_nss.git/plain/nss_engine_cipher.c"

CIPHER_RE = re.compile(
    r'\s*\{'
    r'\"(?P<name>\w+)\",\s*'
    r'(?P<num>(TLS|SSL)_\w+),\s*'
    r'\"(?P<openssl_name>[\w-]+)\",\s*'
    r'(?P<attr>[\w|]+),\s*'
    r'(?P<version>\w+),\s*'
    r'(?P<strength>\w+),\s*'
    r'(?P<bits>\d+),\s*'
    r'(?P<alg_bits>\d+)'
)

DISABLED_CIPHERS = {
    # ciphers without encryption or authentication
    'SSL_eNULL', 'SSL_aNULL',
    # MD5 is broken
    # SHA-1 is still required as PRF algorithm for TLSv1.0
    'SSL_MD5',
    # RC2 and RC4 stream ciphers are broken.
    'SSL_RC2', 'SSL_RC4',
    # DES is broken and Triple DES is too weak.
    'SSL_DES', 'SSL_3DES',
    # DSA is problematic.
    'SSL_DSS', 'SSL_aDSS',
    # prefer AES over Camellia.
    'SSL_CAMELLIA128', 'SSL_CAMELLIA256', 'SSL_CAMELLIA',
    # non-ephemeral EC Diffie-Hellmann with fixed parameters are not
    # used by common browser and are therefore irrelevant for HTTPS.
    'kECDH', 'SSL_kECDHr', 'SSL_kECDHe'
}

WEAK_STRENGTH = {
    'SSL_STRONG_NONE',
    'SSL_EXPORT40',
    'SSL_EXPORT56',
    'SSL_LOW'
}


def parse_nss_engine_cipher(lines, encoding='utf-8'):
    """Parse nss_engine_cipher.c and get list of ciphers

    :param lines: iterable or list of lines
    :param encoding: default encoding
    :return: list of cipher dicts
    """
    ciphers = []
    start = False
    for line in lines:
        if not isinstance(line, str):
            line = line.decode(encoding)

        if line.startswith('cipher_properties'):
            start = True
        elif not start:
            continue
        elif line.startswith('};'):
            break

        mo = CIPHER_RE.match(line)
        if not mo:
            continue

        match = mo.groupdict()
        match['attr'] = set(match['attr'].split('|'))
        match['bits'] = int(match['bits'])
        match['alg_bits'] = int(match['alg_bits'])

        # some cipher elemets aren't flagged
        for algo in ['SHA256', 'SHA384']:
            if match['num'].endswith(algo):
                match['attr'].add('SSL_{}'.format(algo))

        # cipher block chaining isn't tracked
        if '_CBC' in match['num']:
            match['attr'].add('SSL_CBC')

        if match['attr'].intersection(DISABLED_CIPHERS):
            match['enabled'] = False
        elif match['strength'] in WEAK_STRENGTH:
            match['enabled'] = False
        else:
            match['enabled'] = True

        # EECDH + AES-CBC and large hash functions is slow and not more secure
        if (match['attr'].issuperset({'SSL_CBC', 'SSL_kEECDH'}) and
                match['attr'].intersection({'SSL_SHA256', 'SSL_SHA384'})):
            match['enabled'] = False

        ciphers.append(match)

    ciphers.sort(key=operator.itemgetter('name'))
    return ciphers


def main():
    with urlopen(SOURCE) as r:
        ciphers = parse_nss_engine_cipher(r)
    # with open('nss_engine_cipher.c') as f:
    #     ciphers = parse_nss_engine_cipher(f)

    print("# disabled cipher attributes: {}".format(
        ', '.join(sorted(DISABLED_CIPHERS))))
    print("# weak strength: {}".format(', '.join(sorted(WEAK_STRENGTH))))
    print("# enabled cipher suites:")
    suite = []
    for cipher in ciphers:
        if cipher['enabled']:
            print("#   {:36}".format(cipher['num']))
            suite.append('+{}'.format(cipher['name']))
    print()
    print("NSSCipherSuite {}".format(','.join(suite)))


if __name__ == '__main__':
    main()
