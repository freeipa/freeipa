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

from ipaserver.install.plugins import PRE_UPDATE, POST_UPDATE, FIRST, LAST
from ipaserver.install.plugins import PRE_UPDATE, POST_UPDATE, FIRST, LAST
from ipaserver.install.plugins.baseupdate import PreUpdate, PostUpdate
from ipalib.frontend import Updater
from ipaserver.install.plugins import baseupdate
from ipalib import api, errors
from ipapython import ipautil
from ipapython.dn import DN, EditableDN
import ldap as _ldap

def entry_to_update(entry):
    """
    Convert an entry into a name/value pair list that looks like an update.

    An entry is a dict.

    An update is a list of name/value pairs.
    """
    update = []
    for attr in entry.keys():
        if isinstance(entry[attr], list):
            for i in xrange(len(entry[attr])):
                update.append('%s:%s' % (str(attr), str(entry[attr][i])))
        else:
            update.append('%s:%s' % (str(attr), str(entry[attr])))

    return update

class GenerateUpdateMixin(object):
    def generate_update(self, deletes=False):
        """
        We need to separate the deletes that need to happen from the
        new entries that need to be added.
        """
        ldap = self.obj.backend

        suffix = ipautil.realm_to_suffix(api.env.realm)
        searchfilter = '(objectclass=*)'
        definitions_managed_entries = []

        old_template_container = DN(('cn', 'etc'), suffix)
        new_template_container = DN(('cn', 'Templates'), ('cn', 'Managed Entries'), ('cn', 'etc'), suffix)

        old_definition_container = DN(('cn', 'managed entries'), ('cn', 'plugins'), ('cn', 'config'), suffix)
        new_definition_container = DN(('cn', 'Definitions'), ('cn', 'Managed Entries'), ('cn', 'etc'), suffix)

        definitions_dn = DN(('cn', 'Definitions'))
        update_list = []
        restart = False

        # If the old entries don't exist the server has already been updated.
        try:
            (definitions_managed_entries, truncated) = ldap.find_entries(
                searchfilter, ['*'], old_definition_container, _ldap.SCOPE_ONELEVEL, normalize=False
            )
        except errors.NotFound, e:
            return (False, update_list)

        for entry in definitions_managed_entries:
            assert isinstance(entry.dn, DN)
            if deletes:
                old_dn = entry.data['managedtemplate'][0]
                assert isinstance(old_dn, DN)
                try:
                    (old_dn, entry) = ldap.get_entry(old_dn, ['*'], normalize=False)
                except errors.NotFound, e:
                    pass
                else:
                    # Compute the new dn by replacing the old container with the new container
                    new_dn = EditableDN(old_dn)
                    if new_dn.replace(old_template_container, new_template_container) != 1:
                        self.error("unable to replace '%s' with '%s' in '%s'",
                                   old_template_container, new_template_container, old_dn)
                        continue

                    new_dn = DN(new_dn)

                    # The old attributes become defaults for the new entry
                    new_update = {'dn': new_dn,
                                  'default': entry_to_update(entry)}

                    # Delete the old entry
                    old_update = {'dn': old_dn, 'deleteentry': None}

                    # Add the delete and replacement updates to the list of all updates
                    update_list.append({old_dn: old_update, new_dn: new_update})

            else:
                # Update the template dn by replacing the old containter with the new container
                old_dn = entry.data['managedtemplate'][0]
                new_dn = EditableDN(old_dn)
                if new_dn.replace(old_template_container, new_template_container) != 1:
                    self.error("unable to replace '%s' with '%s' in '%s'",
                               old_template_container, new_template_container, old_dn)
                    continue
                new_dn = DN(new_dn)
                entry.data['managedtemplate'] = new_dn

                # Edit the dn, then convert it back to an immutable DN
                old_dn = entry.dn
                new_dn = EditableDN(old_dn)
                if new_dn.replace(old_definition_container, new_definition_container) != 1:
                    self.error("unable to replace '%s' with '%s' in '%s'",
                               old_definition_container, new_definition_container, old_dn)
                    continue
                new_dn = DN(new_dn)

                # The old attributes become defaults for the new entry
                new_update = {'dn': new_dn,
                              'default': entry_to_update(entry.data)}

                # Add the replacement update to the collection of all updates
                update_list.append({new_dn: new_update})

        if len(update_list) > 0:
            restart = True
            update_list.sort(reverse=True)

        return (restart, update_list)

class update_managed_post_first(PreUpdate, GenerateUpdateMixin):
    """
    Update managed entries
    """
    order=FIRST

    def execute(self, **options):
        # Never need to restart with the pre-update changes
        (ignore, update_list) = self.generate_update(False)

        return (False, True, update_list)

api.register(update_managed_post_first)

class update_managed_post(PostUpdate, GenerateUpdateMixin):
    """
    Update managed entries
    """
    order=LAST

    def execute(self, **options):
        (restart, update_list) = self.generate_update(True)

        return (restart, True, update_list)

api.register(update_managed_post)
