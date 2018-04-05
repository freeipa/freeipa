# Authors: Martin Kosek <mkosek@redhat.com>
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

from __future__ import absolute_import

import logging
import os
import os.path

from ipalib.install import sysrestore
from ipaplatform.paths import paths

logger = logging.getLogger(__name__)

STATEFILE_FILE = 'sysupgrade.state'

_sstore = None

def _load_sstore():
    global _sstore
    if _sstore is None:
        _sstore = sysrestore.StateFile(paths.STATEFILE_DIR, STATEFILE_FILE)

def get_upgrade_state(module, state):
    _load_sstore()
    return _sstore.get_state(module, state)

def set_upgrade_state(module, state, value):
    _load_sstore()
    _sstore.backup_state(module, state, value)

def remove_upgrade_state(module, state):
    _load_sstore()
    _sstore.delete_state(module, state)

def remove_upgrade_file():
    try:
        os.remove(os.path.join(paths.STATEFILE_DIR, STATEFILE_FILE))
    except Exception as e:
        logger.debug('Cannot remove sysupgrade state file: %s', e)
