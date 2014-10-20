# Authors:
#   Alexander Bokovoy <abokovoy@redhat.com>
#
# Copyright (C) 2014  Red Hat
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

from ipaserver.install.plugins import MIDDLE
from ipaserver.install.plugins.baseupdate import PostUpdate
from ipalib import api, errors
from ipapython.dn import DN
from ipapython.ipa_log_manager import *


class update_uid_uniqueness(PostUpdate):
    """
    Create plugin configuration to ensure uid uniqueness
    """
    order = MIDDLE

    uid_uniqueness_dn = DN(('cn', 'uid uniqueness'), ('cn', 'plugins'), ('cn', 'config'))

    uid_uniqueness_template = {
     'objectClass'                   : ["top", "nsSlapdPlugin", "extensibleObject"],
     'cn'                            : 'uid uniqueness',
     'nsslapd-pluginPath'            : 'libattr-unique-plugin',
     'nsslapd-pluginInitfunc'        : 'NSUniqueAttr_Init',
     'nsslapd-pluginType'            : 'betxnpreoperation',
     'nsslapd-pluginEnabled'         : 'on',
     'uniqueness-attribute-name'     : 'uid',
     'uniqueness-subtrees'           : 'dc=example,dc=com',
     'uniqueness-across-all-subtrees': 'off',
     'uniqueness-subtree-entries-oc' : 'posixAccount',
     'nsslapd-plugin-depends-on-type': 'database',
     'nsslapd-pluginId'              : 'none',
     'nsslapd-pluginVersion'         : 'none',
     'nsslapd-pluginVendor'          : 'none',
     'nsslapd-pluginDescription'     : 'none',
    }

    def execute(self, **options):
        ldap = self.obj.backend

        config_dn = DN(('cn','config'))
        search_filter = ("(&(objectclass=nsslapdplugin)"
                           "(nsslapd-pluginpath=libattr-unique-plugin)"
                           "(nsslapd-pluginInitfunc=NSUniqueAttr_Init)"
                           "(!(nsslapd-pluginenabled=off))"
                           "(|(uniqueness-attribute-name=uid)(nsslapd-plugarg0=uid)))")
        root_logger.debug("update_uid_uniqueness: search for existing uid uniqueness "
                          "configuration")

        try:
            (entries, truncated) = ldap.find_entries(search_filter, ['*'], config_dn,
                                                     time_limit=0, size_limit=0)
        except errors.NotFound:
            # add entry
            entries = []
        except errors.ExecutionError, e:
            root_logger.error("update_uid_uniqueness: cannot retrieve "
                              "list of uniqueness plugin instances: %s", e)
            return (False, False, [])

        if len(entries) > 1:
            root_logger.error("update_uid_uniqueness: found more than one uid "
                              "uniqueness plugin definition: %s", [str(x.dn) for x in entries])
            return (False, False, [])

        error = False
        if not entries:
            root_logger.debug("update_uid_uniqueness: adding new uid uniqueness "
                              "plugin definition")
            uid_uniqueness_plugin_attrs = dict(self.uid_uniqueness_template)
            uid_uniqueness_plugin_attrs['uniqueness-subtrees'] = api.env.basedn
            uid_uniqueness_plugin = ldap.make_entry(self.uid_uniqueness_dn, uid_uniqueness_plugin_attrs)

            try:
                ldap.add_entry(uid_uniqueness_plugin)
            except errors.ExecutionError, e:
                root_logger.debug("update_uid_uniqueness: cannot "
                                  "create uid uniqueness plugin entry: %s", e)
                error = True
        else:
            root_logger.debug("update_uid_uniqueness: updating existing uid uniqueness "
                              "plugin definition")
            uid_uniqueness_plugin_attrs = dict(self.uid_uniqueness_template)
            uid_uniqueness_plugin_attrs['uniqueness-subtrees'] = api.env.basedn
            uid_uniqueness_plugin_attrs['cn'] = entries[0]['cn']
            uid_uniqueness_plugin = ldap.make_entry(entries[0].dn, uid_uniqueness_plugin_attrs)

            try:
                ldap.update_entry(uid_uniqueness_plugin)
            except errors.ExecutionError, e:
                root_logger.debug("update_uid_uniqueness: cannot "
                                  "update uid uniqueness plugin entry: %s", e)
                error = True

        if error:
            root_logger.error("update_uid_uniqueness: error(s)"
                              "detected during plugin update")
        return (True, False, [])

api.register(update_uid_uniqueness)
