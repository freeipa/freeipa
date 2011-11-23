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

def generate_update(ldap, deletes=False):
    """
    We need to separate the deletes that need to happen from the
    new entries that need to be added.
    """
    suffix = ipautil.realm_to_suffix(api.env.realm)
    searchfilter = '(objectclass=*)'
    definitions_managed_entries = []
    old_template_container = 'cn=etc,%s' % suffix
    old_definition_container = 'cn=managed entries,cn=plugins,cn=config'
    new = 'cn=Managed Entries,cn=etc,%s' % suffix
    sub = ['cn=Definitions,', 'cn=Templates,']
    new_managed_entries = []
    old_templates = []
    template = None
    restart = False

    # If the old entries don't exist the server has already been updated.
    try:
        (definitions_managed_entries, truncated) = ldap.find_entries(
            searchfilter, ['*'], old_definition_container, _ldap.SCOPE_ONELEVEL, normalize=False
        )
    except errors.NotFound, e:
        return (False, new_managed_entries)

    for entry in definitions_managed_entries:
        new_definition = {}
        definition_managed_entry_updates = {}
        if deletes:
            old_definition = {'dn': str(entry[0]), 'deleteentry': ['dn: %s' % str(entry[0])]}
            old_template = str(entry[1]['managedtemplate'][0])
            definition_managed_entry_updates[old_definition['dn']] = old_definition
            old_templates.append(old_template)
        else:
            entry[1]['managedtemplate'] = str(entry[1]['managedtemplate'][0].replace(old_template_container, sub[1] + new))
            new_definition['dn'] = str(entry[0].replace(old_definition_container, sub[0] + new))
            new_definition['default'] = entry_to_update(entry[1])
            definition_managed_entry_updates[new_definition['dn']] = new_definition
            new_managed_entries.append(definition_managed_entry_updates)
    for old_template in old_templates: # Only happens when deletes is True
        try:
            (dn, template) = ldap.get_entry(old_template, ['*'], normalize=False)
            dn = str(dn)
            new_template = {}
            template_managed_entry_updates = {}
            old_template = {'dn': dn, 'deleteentry': ['dn: %s' % dn]}
            new_template['dn'] = str(dn.replace(old_template_container, sub[1] + new))
            new_template['default'] = entry_to_update(template)
            template_managed_entry_updates[new_template['dn']] = new_template
            template_managed_entry_updates[old_template['dn']] = old_template
            new_managed_entries.append(template_managed_entry_updates)
        except errors.NotFound, e:
            pass

    if len(new_managed_entries) > 0:
        restart = True
        new_managed_entries.sort(reverse=True)

    return (restart, new_managed_entries)

class update_managed_post_first(PreUpdate):
    """
    Update managed entries
    """
    order=FIRST

    def execute(self, **options):
        # Never need to restart with the pre-update changes
        (ignore, new_managed_entries) = generate_update(self.obj.backend, False)

        return (False, True, new_managed_entries)

api.register(update_managed_post_first)

class update_managed_post(PostUpdate):
    """
    Update managed entries
    """
    order=LAST

    def execute(self, **options):
        (restart, new_managed_entries) = generate_update(self.obj.backend, True)

        return (restart, True, new_managed_entries)

api.register(update_managed_post)
