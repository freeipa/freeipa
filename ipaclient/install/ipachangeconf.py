#
# ipachangeconf - configuration file manipulation classes and functions
# partially based on authconfig code
# Copyright (c) 1999-2007 Red Hat, Inc.
# Author: Simo Sorce <ssorce@redhat.com>
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

import warnings
from ipapython.ipachangeconf import IPAChangeConf as realIPAChangeConf


class IPAChangeConf(realIPAChangeConf):
    """Advertise the old name"""

    def __init__(self, name):
        """something"""
        warnings.warn(
            "Use 'ipapython.ipachangeconf.IPAChangeConfg'",
            DeprecationWarning,
            stacklevel=2
        )
        super(IPAChangeConf, self).__init__(name)
