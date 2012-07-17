# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2012  Red Hat
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

import os
import pwd
from ipaserver.install.plugins import PRE_UPDATE, MIDDLE
from ipaserver.install.plugins.baseupdate import PreUpdate
from ipaserver import ipaldap
from ipaserver.install import replication
from ipalib import api

EXCLUDE_TEMPLATE = '(objectclass=*) $ EXCLUDE %s'


class update_replica_attribute_lists(PreUpdate):
    """
    Run through all replication agreements and ensure that EXCLUDE list
    has all the required attributes so that we don't cause replication
    storms.
    """
    order=MIDDLE

    def execute(self, **options):
        # We need an IPAdmin connection to the backend
        self.log.debug("Start replication agreement exclude list update task")
        conn = ipaldap.IPAdmin(api.env.host, ldapi=True, realm=api.env.realm)
        conn.do_external_bind(pwd.getpwuid(os.geteuid()).pw_name)

        repl = replication.ReplicationManager(api.env.realm, api.env.host,
                                              None, conn=conn)
        entries = repl.find_replication_agreements()
        self.log.debug("Found %d agreement(s)", len(entries))
        for replica in entries:
            self.log.debug(replica.getValue('description'))

            self._update_attr(repl, replica,
                'nsDS5ReplicatedAttributeList',
                replication.EXCLUDES, template=EXCLUDE_TEMPLATE)
            self._update_attr(repl, replica,
                'nsDS5ReplicatedAttributeListTotal',
                replication.TOTAL_EXCLUDES, template=EXCLUDE_TEMPLATE)
            self._update_attr(repl, replica,
                'nsds5ReplicaStripAttrs', replication.STRIP_ATTRS)

        self.log.debug("Done updating agreements")

        return (False, False, [])  # No restart, no apply now, no updates

    def _update_attr(self, repl, replica, attribute, values, template='%s'):
        """Add or update an attribute of a replication agreement

        If the attribute doesn't already exist, it is added and set to
        `template` with %s substituted by a space-separated `values`.
        If the attribute does exist, `values` missing from it are just
        appended to the end, also space-separated.

        :param repl: Replication manager
        :param replica: Replica agreement
        :param attribute: Attribute to add or update
        :param values: List of values the attribute should hold
        :param template: Template to use when adding attribute
        """
        attrlist = replica.getValue(attribute)
        if attrlist is None:
            self.log.debug("Adding %s", attribute)

            current = replica.toDict()
            # Need to add it altogether
            replica.setValues(attribute, template % " ".join(values))

            try:
                repl.conn.updateEntry(replica.dn, current, replica.toDict())
                self.log.debug("Updated")
            except Exception, e:
                self.log.error("Error caught updating replica: %s", str(e))

        else:
            attrlist_normalized = attrlist.lower().split()
            missing = [a for a in values
                if a.lower() not in attrlist_normalized]

            if missing:
                self.log.debug("%s needs updating (missing: %s)", attribute,
                    ', '.join(missing))
                current = replica.toDict()

                replica.setValue(attribute,
                    '%s %s' % (attrlist, ' '.join(missing)))

                try:
                    repl.conn.updateEntry(replica.dn, current, replica.toDict())
                    self.log.debug("Updated %s", attribute)
                except Exception, e:
                    self.log.error("Error caught updating %s: %s",
                        attribute, str(e))
            else:
                self.log.debug("%s: No update necessary" % attribute)

api.register(update_replica_attribute_lists)
