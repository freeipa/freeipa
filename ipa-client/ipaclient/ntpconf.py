# Authors: Karl MacMillan <kmacmillan@redhat.com>
#
# Copyright (C) 2007  Red Hat
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

from ipapython import ipautil
from ipapython import services as ipaservices
import shutil
import os

ntp_conf = """# Permit time synchronization with our time source, but do not
# permit the source to query or modify the service on this system.
restrict default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery

# Permit all access over the loopback interface.  This could
# be tightened as well, but to do so would effect some of
# the administrative functions.
restrict 127.0.0.1
restrict -6 ::1

# Hosts on local network are less restricted.
#restrict 192.168.1.0 mask 255.255.255.0 nomodify notrap

# Use public servers from the pool.ntp.org project.
# Please consider joining the pool (http://www.pool.ntp.org/join.html).
server $SERVER

#broadcast 192.168.1.255 key 42		# broadcast server
#broadcastclient			# broadcast client
#broadcast 224.0.1.1 key 42		# multicast server
#multicastclient 224.0.1.1		# multicast client
#manycastserver 239.255.254.254		# manycast server
#manycastclient 239.255.254.254 key 42	# manycast client

# Undisciplined Local Clock. This is a fake driver intended for backup
# and when no outside source of synchronized time is available.
server	127.127.1.0	# local clock
#fudge	127.127.1.0 stratum 10

# Drift file.  Put this in a directory which the daemon can write to.
# No symbolic links allowed, either, since the daemon updates the file
# by creating a temporary in the same directory and then rename()'ing
# it to the file.
driftfile /var/lib/ntp/drift

# Key file containing the keys and key identifiers used when operating
# with symmetric key cryptography.
keys /etc/ntp/keys

# Specify the key identifiers which are trusted.
#trustedkey 4 8 42

# Specify the key identifier to use with the ntpdc utility.
#requestkey 8

# Specify the key identifier to use with the ntpq utility.
#controlkey 8
"""

ntp_sysconfig = """# Drop root to id 'ntp:ntp' by default.
OPTIONS="-x -u ntp:ntp -p /var/run/ntpd.pid"

# Set to 'yes' to sync hw clock after successful ntpdate
SYNC_HWCLOCK=yes

# Additional options for ntpdate
NTPDATE_OPTIONS=""
"""
ntp_step_tickers = """# Use IPA-provided NTP server for initial time
$SERVER
"""
def __backup_config(path, fstore = None):
    if fstore:
        fstore.backup_file(path)
    else:
        shutil.copy(path, "%s.ipasave" % (path))

def __write_config(path, content):
    fd = open(path, "w")
    fd.write(content)
    fd.close()

def config_ntp(server_fqdn, fstore = None, sysstore = None):
    path_step_tickers = "/etc/ntp/step-tickers"
    path_ntp_conf = "/etc/ntp.conf"
    path_ntp_sysconfig = "/etc/sysconfig/ntpd"
    sub_dict = { }
    sub_dict["SERVER"] = server_fqdn

    nc = ipautil.template_str(ntp_conf, sub_dict)
    config_step_tickers = False


    if os.path.exists(path_step_tickers):
        config_step_tickers = True
        ns = ipautil.template_str(ntp_step_tickers, sub_dict)
        __backup_config(path_step_tickers, fstore)
        __write_config(path_step_tickers, ns)
        ipaservices.restore_context(path_step_tickers)

    if sysstore:
        module = 'ntp'
        sysstore.backup_state(module, "enabled", ipaservices.knownservices.ntpd.is_enabled())
        if config_step_tickers:
            sysstore.backup_state(module, "step-tickers", True)

    __backup_config(path_ntp_conf, fstore)
    __write_config(path_ntp_conf, nc)
    ipaservices.restore_context(path_ntp_conf)

    __backup_config(path_ntp_sysconfig, fstore)
    __write_config(path_ntp_sysconfig, ntp_sysconfig)
    ipaservices.restore_context(path_ntp_sysconfig)

    # Set the ntpd to start on boot
    ipaservices.knownservices.ntpd.enable()

    # Restart ntpd
    ipaservices.knownservices.ntpd.restart()


def synconce_ntp(server_fqdn):
    """
    Syncs time with specified server using ntpdate.
    Primarily designed to be used before Kerberos setup
    to get time following the KDC time

    Returns True if sync was successful
    """
    ntpdate="/usr/sbin/ntpdate"
    if os.path.exists(ntpdate):
        # retry several times -- logic follows /etc/init.d/ntpdate
        # implementation
        cmd = [ntpdate, "-U", "ntp", "-s", "-b", "-v", server_fqdn]
        for retry in range(0, 3):
            try:
                ipautil.run(cmd)
                return True
            except:
                pass
    return False
