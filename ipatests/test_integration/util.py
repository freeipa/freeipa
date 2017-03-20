# Authors:
#   Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2013  Red Hat
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

import re

from ipaplatform.paths import paths
from ipalib.constants import DEFAULT_CONFIG


def get_host_ip_with_hostmask(host):
    """
    Detects the IP of the host including the hostmask.

    Returns None if the IP could not be detected.
    """

    ip = host.ip
    result = host.run_command(['ip', 'addr'])
    full_ip_regex = r'(?P<full_ip>%s/\d{1,2}) ' % re.escape(ip)
    match = re.search(full_ip_regex, result.stdout_text)

    if match:
        return match.group('full_ip')


def ldappasswd_user_change(user, oldpw, newpw, master):
    container_user = dict(DEFAULT_CONFIG)['container_user']
    basedn = master.domain.basedn

    userdn = "uid={},{},{}".format(user, container_user, basedn)

    args = [paths.LDAPPASSWD, '-D', userdn, '-w', oldpw, '-a', oldpw,
            '-s', newpw, '-x']
    master.run_command(args)
