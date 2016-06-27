# Authors:
#   Jr Aquino <jr.aquino@citrix.com>
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

from ipaclient.frontend import MethodOverride
from ipalib.frontend import Str
from ipalib.plugable import Registry
from ipalib.text import _

register = Registry()


@register(override=True, no_fail=True)
class automember_add_condition(MethodOverride):
    has_output_params = (
        Str('failed',
        label=_('Failed to add'),
        flags=['suppress_empty'],
        ),
    )
