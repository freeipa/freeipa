# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
from ipalib.plugable import Registry

register = Registry()


#@register()
class hbacrule_add_accesstime(MethodOverride):
    def output_for_cli(self, textui, result, cn, **options):
        textui.print_name(self.name)
        textui.print_dashed(
            'Added access time "%s" to HBAC rule "%s"' % (
                options['accesstime'], cn
            )
        )


#@register()
class hbacrule_remove_accesstime(MethodOverride):
    def output_for_cli(self, textui, result, cn, **options):
        textui.print_name(self.name)
        textui.print_dashed(
            'Removed access time "%s" from HBAC rule "%s"' % (
                options['accesstime'], cn
            )
        )
