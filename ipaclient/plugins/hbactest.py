# Authors:
#   Alexander Bokovoy <abokovoy@redhat.com>
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

from ipaclient.frontend import CommandOverride
from ipalib.plugable import Registry

import six

if six.PY3:
    unicode = str

register = Registry()


@register(override=True, no_fail=True)
class hbactest(CommandOverride):
    def output_for_cli(self, textui, output, *args, **options):
        """
        Command.output_for_cli() uses --all option to decide whether to print detailed output.
        We use --detail to allow that, thus we need to redefine output_for_cli().
        """
        # Note that we don't actually use --detail below to see if details need
        # to be printed as our execute() method will return None for corresponding
        # entries and None entries will be skipped.
        for o in self.output:
            if o == 'value':
                continue
            outp = self.output[o]
            if 'no_display' in outp.flags:
                continue
            result = output[o]
            if isinstance(result, (list, tuple)):
                textui.print_attribute(unicode(outp.doc), result, '%s: %s', 1, True)
            elif isinstance(result, unicode):
                if o == 'summary':
                    textui.print_summary(result)
                else:
                    textui.print_indented(result)

        # Propagate integer value for result. It will give proper command line result for scripts
        return int(not output['value'])
