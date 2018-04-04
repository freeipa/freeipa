# Author: Mega Tonnage <m3gat0nn4ge@gmail.com>
#
# Copyright (C) 2018
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

'''
This base module contains a find_library() replacement for 
 ctypes.util.find_library.
'''

from __future__ import print_function
from __future__ import unicode_literals

import os
import subprocess
import logging

logger = logging.getLogger(__name__)

def find_library(name):
    logger.debug("Checking ldconfig output for: %s", name)
    process = subprocess.Popen(
              "ldconfig -N -p | awk '{print $1, $NF}' | grep '^%s'"
              % name, shell=True, stdout=subprocess.PIPE, 
              stderr=subprocess.STDOUT)
    output,stderr = process.communicate()
    status = process.poll()

    # do we need to check we only have one matching line?
    if output:
        return output.rsplit(None, 1)[-1].decode('utf8')
    else:
        return None
        
assert(find_library("libcrypto.so") == "/lib64/libcrypto.so")
assert(find_library("librpm.so.8") == "/lib64/librpm.so.8")
assert(find_library("libp11-kit.so.0") == "/lib64/libp11-kit.so.0")
