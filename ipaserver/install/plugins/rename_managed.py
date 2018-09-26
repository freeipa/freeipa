# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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

import logging

import six

from ipalib import Registry, errors
from ipalib import Updater
from ipapython import ipautil
from ipapython.dn import DN

logger = logging.getLogger(__name__)

register = Registry()

if six.PY3:
    unicode = str


def entry_to_update(entry):
    """
    Convert an entry into a name/value pair list that looks like an update.

    An entry is a dict.

    An update is a list of name/value pairs.
    """
    update = []
    for attr in entry.keys():
        if isinstance(entry[attr], list):
            for item in entry[attr]:
                update.append(dict(attr=str(attr), value=str(item)))
        else:
            update.append(dict(attr=str(attr), value=str(entry[attr])))

    return update


class GenerateUpdateMixin:
    def _dn_suffix_replace(self, dn, old_suffix, new_suffix):
        """Replace all occurences of "old" AVAs in a DN by "new"

        If the input DN doesn't end with old_suffix, log, an raise ValueError.
        """
        if not dn.endswith(old_suffix):
            logger.error("unable to replace suffix '%s' with '%s' in '%s'",
                         old_suffix, new_suffix, dn)
            raise ValueError('no replacement made')
        return DN(*dn[:-len(old_suffix)]) + new_suffix

    def generate_update(self, deletes=False):
        """
        We need to separate the deletes that need to happen from the
        new entries that need to be added.
        """
        ldap = self.api.Backend.ldap2

        suffix = ipautil.realm_to_suffix(self.api.env.realm)
        searchfilter = '(objectclass=*)'
        definitions_managed_entries = []

        old_template_container = DN(('cn', 'etc'), suffix)
        new_template_container = DN(('cn', 'Templates'), ('cn', 'Managed Entries'), ('cn', 'etc'), suffix)

        old_definition_container = DN(('cn', 'managed entries'), ('cn', 'plugins'), ('cn', 'config'), suffix)
        new_definition_container = DN(('cn', 'Definitions'), ('cn', 'Managed Entries'), ('cn', 'etc'), suffix)

        update_list = []
        restart = False

        # If the old entries don't exist the server has already been updated.
        try:
            definitions_managed_entries, _truncated = ldap.find_entries(
                searchfilter, ['*'], old_definition_container,
                ldap.SCOPE_ONELEVEL)
        except errors.NotFound:
            return (False, update_list)

        for entry in definitions_managed_entries:
            assert isinstance(entry.dn, DN)
            if deletes:
                old_dn = entry['managedtemplate'][0]
                assert isinstance(old_dn, DN)
                try:
                    entry = ldap.get_entry(old_dn, ['*'])
                except errors.NotFound:
                    pass
                else:
                    # Compute the new dn by replacing the old container with the new container
                    try:
                        new_dn = self._dn_suffix_replace(
                            entry.dn,
                            old_suffix=old_template_container,
                            new_suffix=new_template_container)
                    except ValueError:
                        continue

                    # The old attributes become defaults for the new entry
                    new_update = {'dn': new_dn,
                                  'default': entry_to_update(entry)}

                    # Delete the old entry
                    old_update = {'dn': entry.dn, 'deleteentry': None}

                    # Add the delete and replacement updates to the list of all updates
                    update_list.append(old_update)
                    update_list.append(new_update)

            else:
                # Update the template dn by replacing the old containter with the new container
                try:
                    new_dn = self._dn_suffix_replace(
                        entry['managedtemplate'][0],
                        old_suffix=old_template_container,
                        new_suffix=new_template_container)
                except ValueError:
                    continue
                entry['managedtemplate'] = new_dn

                # Update the entry dn similarly
                try:
                    new_dn = self._dn_suffix_replace(
                        entry.dn,
                        old_suffix=old_definition_container,
                        new_suffix=new_definition_container)
                except ValueError:
                    continue

                # The old attributes become defaults for the new entry
                new_update = {'dn': new_dn,
                              'default': entry_to_update(entry)}

                # Add the replacement update to the collection of all updates
                update_list.append(new_update)

        if len(update_list) > 0:
            restart = True
            update_list.sort(reverse=True, key=lambda x: x['dn'])

        return (restart, update_list)


@register()
class update_managed_post_first(Updater, GenerateUpdateMixin):
    """
    Update managed entries
    """

    def execute(self, **options):
        # Never need to restart with the pre-update changes
        _ignore, update_list = self.generate_update(False)

        return False, update_list


@register()
class update_managed_post(Updater, GenerateUpdateMixin):
    """
    Update managed entries
    """

    def execute(self, **options):
        (restart, update_list) = self.generate_update(True)

        return restart, update_list
