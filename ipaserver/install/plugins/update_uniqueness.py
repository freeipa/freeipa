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
from ipaserver.install.plugins.baseupdate import PostUpdate, PreUpdate
from ipalib import api, errors
from ipapython.dn import DN
from ipapython.ipa_log_manager import *


class update_uniqueness_plugins_to_new_syntax(PreUpdate):
    """
    Migrate uniqueness plugins to new style syntax

    * OLD: *
    nsslapd-pluginarg0: uid
    nsslapd-pluginarg1: dc=people,dc=example,dc=com
    nsslapd-pluginarg2: dc=sales, dc=example,dc=com

    or

    nsslapd-pluginarg0: attribute=uid
    nsslapd-pluginarg1: markerobjectclass=organizationalUnit
    nsslapd-pluginarg2: requiredobjectclass=person

    * NEW: *
    uniqueness-attribute-name: uid
    uniqueness-subtrees: dc=people,dc=example,dc=com
    uniqueness-subtrees: dc=sales, dc=example,dc=com
    uniqueness-across-all-subtrees: on

    or

    uniqueness-attribute-name: uid
    uniqueness-top-entry-oc: organizationalUnit
    uniqueness-subtree-entries-oc: person
    """

    plugins_dn = DN(('cn', 'plugins'), ('cn', 'config'))

    def __remove_update(self, update, key, value):
        # ldapupdate uses CSV, use '' for DN value
        statement = "remove:%s:'%s'" % (key, value)
        update.setdefault('updates', []).append(statement)

    def __add_update(self, update, key, value):
        # ldapupdate uses CSV, use '' for DN value
        statement = "add:%s:'%s'" % (key, value)
        update.setdefault('updates', []).append(statement)

    def __subtree_style(self, entry):
        """
        old attr              -> new attr
        nsslapd-pluginArg0    -> uniqueness-attribute-name
        nsslapd-pluginArg1..N    -> uniqueness-subtrees[1..N]
        """
        update = {
            'dn': entry.dn,
            'updates': [],
        }

        # nsslapd-pluginArg0    -> referint-update-delay
        attribute = entry.single_value['nsslapd-pluginArg0']
        if not attribute:
            raise ValueError("'nsslapd-pluginArg0' not found")
        self.__remove_update(update, 'nsslapd-pluginArg0', attribute)
        self.__add_update(update, 'uniqueness-attribute-name', attribute)
        entry['nsslapd-pluginArg0'] = None

        # nsslapd-pluginArg1..N    -> uniqueness-subtrees[1..N]
        for key in entry.keys():
            if key.lower().startswith('nsslapd-pluginarg'):
                subtree_dn = entry.single_value[key]
                if subtree_dn:
                    self.__remove_update(update, key, subtree_dn)
                    self.__add_update(update, 'uniqueness-subtrees', subtree_dn)

        return update

    def __objectclass_style(self, entry):
        """
        old attr              -> new attr
        nsslapd-pluginArg?[attribute]           -> uniqueness-attribute-name
        nsslapd-pluginArg?[markerobjectclass]   -> uniqueness-top-entry-oc
        nsslapd-pluginArg?[requiredobjectclass](optional)
                                                -> uniqueness-subtree-entries-oc
        nsslapd-pluginArg?[others]              -> ERROR: unexpected args

        Single value attributes.
        """

        update = {
            'dn': entry.dn,
            'updates': [],
        }

        attribute = None
        markerobjectclass = None
        requiredobjectclass = None

        for key in entry.keys():
            if key.lower().startswith('nsslapd-pluginarg'):
                try:
                    # split argument name and value
                    value = entry.single_value[key]
                    arg_name, arg_val = value.split('=', 1)
                except ValueError:
                    # unable to split
                    raise ValueError("unexpected argument %s: %s" %
                                     (key, value))
                arg_name = arg_name.lower()
                if arg_name == 'attribute':
                    if attribute:
                        raise ValueError("single value argument 'attribute' "
                                         "is specified mutliple times")
                    attribute = arg_val
                    self.__remove_update(update, key, value)
                elif arg_name == 'markerobjectclass':
                    if markerobjectclass:
                        raise ValueError("single value argument "
                                         "'markerobjectclass' "
                                         "is specified mutliple times")
                    markerobjectclass = arg_val
                    self.__remove_update(update, key, value)
                elif arg_name == 'requiredobjectclass':
                    if requiredobjectclass:
                        raise ValueError("single value argument "
                                         "'requiredobjectclass' "
                                         "is specified mutliple times")
                    requiredobjectclass = arg_val
                    self.__remove_update(update, key, value)
                else:
                    raise ValueError("unexpected argument '%s: %s'" %
                                     (key, value))

        if not attribute:
            raise ValueError("missing required argument 'attribute'")
        if not markerobjectclass:
            raise ValueError("missing required argument 'markerobjectclass'")

        self.__add_update(update, 'uniqueness-attribute-name', attribute)
        self.__add_update(update, 'uniqueness-top-entry-oc', markerobjectclass)

        if requiredobjectclass:
            # optional argument
            self.__add_update(update, 'uniqueness-subtree-entries-oc',
                              requiredobjectclass)

        return update

    def execute(self, **options):
        ldap = self.obj.backend

        old_style_plugin_search_filter = (
            "(&"
            "(objectclass=nsSlapdPlugin)"
            "(nsslapd-pluginId=NSUniqueAttr)"
            "(nsslapd-pluginPath=libattr-unique-plugin)"
            "(nsslapd-pluginarg0=*)"  # only entries with old configuration
            ")"
        )

        try:
            entries, truncated = ldap.find_entries(
                filter=old_style_plugin_search_filter,
                base_dn=self.plugins_dn,
            )
        except errors.NotFound:
            root_logger.debug("No uniqueness plugin entries with old style "
                              "configuration found")
            return False, False, []

        update_list = []
        new_attributes = [
            'uniqueness-subtree-entries-oc',
            'uniqueness-top-entry-oc',
            'uniqueness-attribute-name',
            'uniqueness-subtrees',
            'uniqueness-across-all-subtrees',
        ]

        for entry in entries:
            # test for mixed configuration
            if any(attr in entry for attr in new_attributes):
                root_logger.critical("Mixed old and new style configuration "
                                     "for plugin %s. Plugin will not work. "
                                     "Skipping plugin migration, please fix it "
                                     "manually",
                                     entry.dn)
                continue
            root_logger.debug("Configuration of plugin %s will be migrated "
                             "to new style", entry.dn)
            try:
                # detect which configuration was used
                arg0 = entry.get('nsslapd-pluginarg0')
                if '=' in arg0:
                    update = self.__objectclass_style(entry)
                else:
                    update = self.__subtree_style(entry)
            except ValueError as e:
                root_logger.error("Unable to migrate configuration of "
                                  "plugin %s (%s)",
                                  entry.dn, e)

            update_list.append({entry.dn: update})

        return False, True, update_list

api.register(update_uniqueness_plugins_to_new_syntax)


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
