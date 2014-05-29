# Author: Alexander Bokovoy <abokovoy@redhat.com>
from ipaplatform.paths import paths
#
# Copyright (C) 2011   Red Hat
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

from ipapython.platform import redhat

def restore_context(filepath, restorecon=paths.RESTORECON):
    return redhat.restore_context(filepath, restorecon)

def check_selinux_status(restorecon=paths.RESTORECON):
    return redhat.check_selinux_status(restorecon)
