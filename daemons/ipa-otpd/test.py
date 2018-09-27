#
# FreeIPA 2FA companion daemon
#
# Authors: Nathaniel McCallum <npmccallum@redhat.com>
#
# Copyright (C) 2013  Nathaniel McCallum, Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software you can redistribute it and/or modify
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

from io import StringIO
import struct
import subprocess
import sys

try:
    from pyrad import packet
    from pyrad.dictionary import Dictionary
except ImportError:
    sys.stdout.write("pyrad not found!\n")
    sys.exit(0)

# We could use a dictionary file, but since we need
# such few attributes, we'll just include them here
DICTIONARY = """
ATTRIBUTE	User-Name	1	string
ATTRIBUTE	User-Password	2	string
ATTRIBUTE	NAS-Identifier	32	string
"""


def main():
    dct = Dictionary(StringIO(DICTIONARY))

    proc = subprocess.Popen(["./ipa-otpd", sys.argv[1]],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE)

    pkt = packet.AuthPacket(secret="", dict=dct)
    pkt["User-Name"] = sys.argv[2]
    pkt["User-Password"] = pkt.PwCrypt(sys.argv[3])
    pkt["NAS-Identifier"] = "localhost"
    proc.stdin.write(pkt.RequestPacket())

    rsp = packet.Packet(secret="", dict=dict)
    buf = proc.stdout.read(4)
    buf += proc.stdout.read(struct.unpack("!BBH", buf)[2] - 4)
    rsp.DecodePacket(buf)
    pkt.VerifyReply(rsp)

    proc.terminate()  # pylint: disable=E1101
    proc.wait()

if __name__ == '__main__':
    main()
