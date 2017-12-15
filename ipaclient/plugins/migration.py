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

import six

from ipaclient.frontend import CommandOverride
from ipalib.parameters import File
from ipalib.plugable import Registry
from ipalib import _

if six.PY3:
    unicode = str

register = Registry()


@register(override=True, no_fail=True)
class migrate_ds(CommandOverride):
    migrate_order = ('user', 'group')

    migration_disabled_msg = _('''\
Migration mode is disabled.
Use \'ipa config-mod --enable-migration=TRUE\' to enable it.''')

    pwd_migration_msg = _('''\
Passwords have been migrated in pre-hashed format.
IPA is unable to generate Kerberos keys unless provided
with clear text passwords. All migrated users need to
login at https://your.domain/ipa/migration/ before they
can use their Kerberos accounts.''')

    def get_options(self):
        for option in super(migrate_ds, self).get_options():
            if option.name == 'cacertfile':
                option = option.clone_retype(option.name, File)
            yield option

    def output_for_cli(self, textui, result, ldapuri, **options):
        textui.print_name(self.name)
        if not result['enabled']:
            textui.print_plain(self.migration_disabled_msg)
            return 1
        if not result['compat']:
            textui.print_plain("The compat plug-in is enabled. This can increase the memory requirements during migration. Disable the compat plug-in with \'ipa-compat-manage disable\' or re-run this script with \'--with-compat\' option.")
            return 1
        any_migrated = any(result['result'].values())
        textui.print_plain('Migrated:')
        textui.print_entry1(
            result['result'], attr_order=self.migrate_order,
            one_value_per_line=False
        )
        for ldap_obj_name in self.migrate_order:
            textui.print_plain('Failed %s:' % ldap_obj_name)
            textui.print_entry1(
                result['failed'][ldap_obj_name], attr_order=self.migrate_order,
                one_value_per_line=True,
            )
        textui.print_plain('-' * len(self.name))
        if not any_migrated:
            textui.print_plain('No users/groups were migrated from %s' %
                               ldapuri)
            return 1
        textui.print_plain(unicode(self.pwd_migration_msg))
        return None
