# Authors:
#   Jr Aquino <jr.aquino@citrixonline.com>
#
# Copyright (C) 2010-2014  Red Hat
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
from ipalib import _

register = Registry()


@register(override=True, no_fail=True)
class sudorule_enable(MethodOverride):
    def output_for_cli(self, textui, result, cn, **options):
        textui.print_dashed(_('Enabled Sudo Rule "%s"') % cn)


@register(override=True, no_fail=True)
class sudorule_disable(MethodOverride):
    def output_for_cli(self, textui, result, cn, **options):
        textui.print_dashed(_('Disabled Sudo Rule "%s"') % cn)


@register(override=True, no_fail=True)
class sudorule_add_option(MethodOverride):
    def output_for_cli(self, textui, result, cn, **options):
        textui.print_dashed(
            _('Added option "%(option)s" to Sudo Rule "%(rule)s"')
              % dict(option=options['ipasudoopt'], rule=cn))

        super(sudorule_add_option, self).output_for_cli(textui, result, cn,
                                                        **options)


@register(override=True, no_fail=True)
class sudorule_remove_option(MethodOverride):
    def output_for_cli(self, textui, result, cn, **options):
        textui.print_dashed(
            _('Removed option "%(option)s" from Sudo Rule "%(rule)s"')
              % dict(option=options['ipasudoopt'], rule=cn))
        super(sudorule_remove_option, self).output_for_cli(textui, result, cn,
                                                           **options)
