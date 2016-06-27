# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
from ipalib import errors
from ipalib import Flag
from ipalib import util
from ipalib.plugable import Registry
from ipalib import _
from ipalib import x509

register = Registry()


@register(override=True, no_fail=True)
class user_del(MethodOverride):
    def get_options(self):
        for option in super(user_del, self).get_options():
            yield option
        yield Flag(
            'preserve?',
            include='cli',
            doc=_('Delete a user, keeping the entry available for future use'),
        )
        yield Flag(
            'no_preserve?',
            include='cli',
            doc=_('Delete a user'),
        )

    def forward(self, *keys, **options):
        if self.api.env.context == 'cli':
            no_preserve = options.pop('no_preserve', False)
            preserve = options.pop('preserve', False)
            if no_preserve and preserve:
                raise errors.MutuallyExclusiveError(
                    reason=_("preserve and no-preserve cannot be both set"))
            elif no_preserve:
                options['preserve'] = False
            elif preserve:
                options['preserve'] = True

        return super(user_del, self).forward(*keys, **options)


@register(override=True, no_fail=True)
class user_show(MethodOverride):
    def forward(self, *keys, **options):
        if 'out' in options:
            util.check_writable_file(options['out'])
            result = super(user_show, self).forward(*keys, **options)
            if 'usercertificate' in result['result']:
                x509.write_certificate_list(
                    result['result']['usercertificate'],
                    options['out']
                )
                result['summary'] = (
                    _('Certificate(s) stored in file \'%(file)s\'')
                    % dict(file=options['out'])
                )
                return result
            else:
                raise errors.NoCertificateError(entry=keys[-1])
        else:
            return super(user_show, self).forward(*keys, **options)
