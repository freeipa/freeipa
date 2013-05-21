# Authors:
#   Jan Cholasta <jcholast@redhat.com>
#
# Copyright (C) 2011  Red Hat
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
Test the `ipapython/ssh.py` module.
"""

import base64
import nose

from ipapython import ssh

class CheckPublicKey:
    def __init__(self, pk):
        self.description = "Test SSH public key parsing (%s)" % repr(pk)

    def __call__(self, pk, out):
        try:
            parsed = ssh.SSHPublicKey(pk)
            assert parsed.openssh() == out
        except Exception, e:
            assert type(e) is out

def test_public_key_parsing():
    b64 = 'AAAAB3NzaC1yc2EAAAADAQABAAABAQDGAX3xAeLeaJggwTqMjxNwa6XHBUAikXPGMzEpVrlLDCZtv00djsFTBi38PkgxBJVkgRWMrcBsr/35lq7P6w8KGIwA8GI48Z0qBS2NBMJ2u9WQ2hjLN6GdMlo77O0uJY3251p12pCVIS/bHRSq8kHO2No8g7KA9fGGcagPfQH+ee3t7HUkpbQkFTmbPPN++r3V8oVUk5LxbryB3UIIVzNmcSIn3JrXynlvui4MixvrtX6zx+O/bBo68o8/eZD26QrahVbA09fivrn/4h3TM019Eu/c2jOdckfU3cHUV/3Tno5d6JicibyaoDDK7S/yjdn5jhaz8MSEayQvFkZkiF0L'
    raw = base64.b64decode(b64)
    openssh = 'ssh-rsa %s' % b64

    pks = [
        ('\xff',                    UnicodeDecodeError),

        (raw,                       openssh),
        ('\0\0\0\x04none',          u'none AAAABG5vbmU='),
        ('\0\0\0',                  ValueError),
        ('\0\0\0\0',                ValueError),
        ('\0\0\0\x01',              ValueError),
        ('\0\0\0\x01\xff',          ValueError),

        (b64,                       openssh),
        (unicode(b64),              openssh),
        (u'\n%s\n\n' % b64,         openssh),
        (u'AAAABG5vbmU=',           u'none AAAABG5vbmU='),
        (u'AAAAB',                  ValueError),

        (openssh,                   openssh),
        (unicode(openssh),          openssh),
        (u'none AAAABG5vbmU=',      u'none AAAABG5vbmU='),
        (u'\t \t ssh-rsa \t \t%s\t \tthis is a comment\t \t ' % b64,
                                    u'%s this is a comment' % openssh),
        (u'opt3,opt2="\tx ",opt1,opt2="\\"x " %s comment ' % openssh,
                                    u'opt1,opt2="\\"x ",opt3 %s comment' % openssh),
        (u'ssh-rsa\n%s' % b64,      ValueError),
        (u'ssh-rsa\t%s' % b64,      ValueError),
        (u'vanitas %s' % b64,       ValueError),
        (u'@opt %s' % openssh,      ValueError),
        (u'opt=val %s' % openssh,   ValueError),
        (u'opt, %s' % openssh,      ValueError),
    ]

    for pk in pks:
        yield (CheckPublicKey(pk[0]),) + pk
