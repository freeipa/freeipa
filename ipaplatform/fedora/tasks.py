# Authors: Simo Sorce <ssorce@redhat.com>
#          Alexander Bokovoy <abokovoy@redhat.com>
#          Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2007-2014  Red Hat
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

'''
This module contains default Fedora-specific implementations of system tasks.
'''

import os
import ipautil

from ipaplatform.base.tasks import *


def restore_context(filepath, restorecon='/sbin/restorecon'):
    """
    restore security context on the file path
    SELinux equivalent is /path/to/restorecon <filepath>

    restorecon's return values are not reliable so we have to
    ignore them (BZ #739604).

    ipautil.run() will do the logging.
    """
    try:
        if os.path.exists('/usr/sbin/selinuxenabled'):
            ipautil.run(["/usr/sbin/selinuxenabled"])
        else:
            # No selinuxenabled, no SELinux
            return
    except ipautil.CalledProcessError:
        # selinuxenabled returns 1 if not enabled
        return

    if (os.path.exists(restorecon)):
        ipautil.run([restorecon, filepath], raiseonerr=False)


def check_selinux_status(restorecon='/sbin/restorecon'):
    """
    We don't have a specific package requirement for policycoreutils
    which provides restorecon. This is because we don't require
    SELinux on client installs. However if SELinux is enabled then
    this package is required.

    This function returns nothing but may raise a Runtime exception
    if SELinux is enabled but restorecon is not available.
    """
    try:
        if os.path.exists('/usr/sbin/selinuxenabled'):
            ipautil.run(["/usr/sbin/selinuxenabled"])
        else:
            # No selinuxenabled, no SELinux
            return
    except ipautil.CalledProcessError:
        # selinuxenabled returns 1 if not enabled
        return

    if not os.path.exists(restorecon):
        raise RuntimeError('SELinux is enabled but %s does not exist.\n'
                           'Install the policycoreutils package and start the '
                           'installation again.' % restorecon)
