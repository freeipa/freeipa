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

class update_replica_memberof(PreUpdate):
    """
    Run through all replication agreements and ensure that memberOf is
    included in the EXCLUDE list so we don't cause replication storms.
    """
    order=MIDDLE

    def execute(self, **options):
        totalexcludes = ('entryusn',
                         'krblastsuccessfulauth',
                         'krblastfailedauth',
                         'krbloginfailedcount')
        excludes = ('memberof', ) + totalexcludes

        # We need an IPAdmin connection to the backend
        conn = ipaldap.IPAdmin(api.env.host, ldapi=True, realm=api.env.realm)
        conn.do_external_bind(pwd.getpwuid(os.geteuid()).pw_name)

        repl = replication.ReplicationManager(api.env.realm, api.env.host,
                                              None, conn=conn)
        entries = repl.find_replication_agreements()
        self.log.debug("Found %d agreement(s)" % len(entries))
        for replica in entries:
            self.log.debug(replica.description)
            attrlist = replica.getValue('nsDS5ReplicatedAttributeList')
            if attrlist is None:
                self.log.debug("Adding nsDS5ReplicatedAttributeList and nsDS5ReplicatedAttributeListTotal")
                current = replica.toDict()
                # Need to add it altogether
                replica.setValues('nsDS5ReplicatedAttributeList',
                    '(objectclass=*) $ EXCLUDE %s' % " ".join(excludes))
                replica.setValues('nsDS5ReplicatedAttributeListTotal',
                    '(objectclass=*) $ EXCLUDE %s' % " ".join(totalexcludes))
                try:
                    repl.conn.updateEntry(replica.dn, current, replica.toDict())
                    self.log.debug("Updated")
                except Exception, e:
                    self.log.error("Error caught updating replica: %s" % str(e))
            elif 'memberof' not in attrlist.lower():
                self.log.debug("Attribute list needs updating")
                current = replica.toDict()
                replica.setValue('nsDS5ReplicatedAttributeList',
                    replica.nsDS5ReplicatedAttributeList + ' memberof')
                try:
                    repl.conn.updateEntry(replica.dn, current, replica.toDict())
                    self.log.debug("Updated")
                except Exception, e:
                    self.log.error("Error caught updating replica: %s" % str(e))
            else:
                self.log.debug("No update necessary")
        self.log.debug("Done updating agreements")

        return (False, False, []) # No restart, no apply now, no updates

api.register(update_replica_memberof)
