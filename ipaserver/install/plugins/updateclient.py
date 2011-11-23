# Authors: Rob Crittenden <rcritten@redhat.com>
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
#

import os
from ipaserver.install import installutils
from ipaserver.install.plugins import FIRST, MIDDLE, LAST
from ipaserver.install.plugins import POST_UPDATE
from ipaserver.install.plugins.baseupdate import DSRestart
from ipaserver.install.ldapupdate import LDAPUpdate
from ipalib import api
from ipalib import backend
import ldap as _ldap

class updateclient(backend.Executioner):
    """
    Backend used for applying LDAP updates via plugins

    An update plugin can be executed before the file-based plugins or
    afterward. Each plugin returns three values:

    1. restart: dirsrv needs to be restarted BEFORE this update is
                 applied.
    2. apply_now: when True the update is applied when the plugin
                  returns. Otherwise the update is cached until all
                  plugins of that update type are complete, then they
                  are applied together.
    3. updates: A dictionary of updates to be applied.

    updates is a dictionary keyed on dn. The value of an update is a
    dictionary with the following possible values:
      - dn: str, duplicate of the key
      - updates: list of updates against the dn
      - default: list of the default entry to be added if it doesn't
                 exist
      - deleteentry: list of dn's to be deleted (typically single dn)

    For example, this update file:

      dn: cn=global_policy,cn=$REALM,cn=kerberos,$SUFFIX
      replace:krbPwdLockoutDuration:10::600
      replace: krbPwdMaxFailure:3::6

    Generates this update dictionary:

    dict('cn=global_policy,cn=EXAMPLE.COM,cn=kerberos,dc=example,dc=com':
      dict(
        'dn': 'cn=global_policy,cn=EXAMPLE.COM,cn=kerberos,dc=example,dc=com',
        'updates': ['replace:krbPwdLockoutDuration:10::600',
                    'replace:krbPwdMaxFailure:3::6']
      )
    )

    Here is another example showing how a default entry is configured:

      dn: cn=Managed Entries,cn=etc,$SUFFIX
      default: objectClass: nsContainer
      default: objectClass: top
      default: cn: Managed Entries

    This generates:

    dict('cn=Managed Entries,cn=etc,dc=example,dc=com',
      dict(
        'dn': 'cn=Managed Entries,cn=etc,dc=example,dc=com',
        'default': ['objectClass:nsContainer',
                    'objectClass:top',
                    'cn:Managed Entries'
                   ]
       )
    )

    Note that the variable substitution in both examples has been completed.

    A PRE_UPDATE plugin is executed before file-based updates.

    A POST_UPDATE plugin is executed after file-based updates.

    Plugins are executed automatically when ipa-ldap-updater is run
    in upgrade mode (--upgrade). They are not executed normally otherwise.
    To execute plugins as well use the --plugins flag.

    Either may make changes directly in LDAP or can return updates in
    update format.
    """
    def create_context(self, dm_password):
        if dm_password:
            autobind = False
        else:
            autobind = True
        self.Backend.ldap2.connect(bind_dn='cn=Directory Manager', bind_pw=dm_password, autobind=autobind)

    def order(self, updatetype):
        """
        Calculate rough order of plugins.
        """
        order = []
        for plugin in api.Updater(): #pylint: disable=E1101
            if plugin.updatetype != updatetype:
                continue
            if plugin.order == FIRST:
                order.insert(0, plugin)
            elif plugin.order == MIDDLE:
                order.insert(len(order)/2, plugin)
            else:
                order.append(plugin)

        for o in order:
            yield o

    def update(self, updatetype, dm_password, ldapi, live_run):
        """
        Execute all update plugins of type updatetype.
        """
        self.create_context(dm_password)
        kw = dict(live_run=live_run)
        result = []
        ld = LDAPUpdate(dm_password=dm_password, sub_dict={}, live_run=live_run, ldapi=ldapi)
        for update in self.order(updatetype):
            (restart, apply_now, res) = self.run(update.name, **kw)
            if restart:
                self.restart(dm_password, live_run)
            dn_list = {}
            for upd in res:
                for dn in upd:
                    dn_explode = _ldap.explode_dn(dn.lower())
                    l = len(dn_explode)
                    if dn_list.get(l):
                        if dn not in dn_list[l]:
                            dn_list[l].append(dn)
                    else:
                        dn_list[l] = [dn]
            updates = {}
            for entry in res:
                updates.update(entry)

            if apply_now:
                ld.update_from_dict(dn_list, updates)
            elif res:
                result.extend(res)

        self.destroy_context()

        return result

    def run(self, method, **kw):
        """
        Execute the update plugin.
        """
        return self.Updater[method](**kw) #pylint: disable=E1101

    def restart(self, dm_password, live_run):
        if os.getegid() != 0:
            self.log.warn("Not root, skipping restart")
            return
        dsrestart = DSRestart()
        socket_name = '/var/run/slapd-%s.socket' % \
            api.env.realm.replace('.','-')
        if live_run:
            self.destroy_context()
            dsrestart.create_instance()
            installutils.wait_for_open_socket(socket_name)
            self.create_context(dm_password)
        else:
            self.log.warn("Test mode, skipping restart")

api.register(updateclient)
