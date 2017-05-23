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

import logging

from ipaserver.install import replication
from ipalib import Registry
from ipalib import Updater

logger = logging.getLogger(__name__)

register = Registry()

EXCLUDE_TEMPLATE = '(objectclass=*) $ EXCLUDE %s'


@register()
class update_replica_attribute_lists(Updater):
    """
    Run through all replication agreements and ensure that EXCLUDE list
    has all the required attributes so that we don't cause replication
    storms.
    """

    def execute(self, **options):
        # We need an LDAPClient connection to the backend
        logger.debug("Start replication agreement exclude list update task")
        conn = self.api.Backend.ldap2

        repl = replication.ReplicationManager(self.api.env.realm,
                                              self.api.env.host,
                                              None, conn=conn)

        # We need to update only IPA replica agreements, not winsync
        ipa_replicas = repl.find_ipa_replication_agreements()

        logger.debug("Found %d agreement(s)", len(ipa_replicas))

        for replica in ipa_replicas:
            for desc in replica.get('description', []):
                logger.debug('%s', desc)

            self._update_attr(repl, replica,
                'nsDS5ReplicatedAttributeList',
                replication.EXCLUDES, template=EXCLUDE_TEMPLATE)
            self._update_attr(repl, replica,
                'nsDS5ReplicatedAttributeListTotal',
                replication.TOTAL_EXCLUDES, template=EXCLUDE_TEMPLATE)
            self._update_attr(repl, replica,
                'nsds5ReplicaStripAttrs', replication.STRIP_ATTRS)

        logger.debug("Done updating agreements")

        return False, []  # No restart, no updates

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
        attrlist = replica.single_value.get(attribute)
        if attrlist is None:
            logger.debug("Adding %s", attribute)

            # Need to add it altogether
            replica[attribute] = [template % " ".join(values)]

            try:
                repl.conn.update_entry(replica)
                logger.debug("Updated")
            except Exception as e:
                logger.error("Error caught updating replica: %s", str(e))

        else:
            attrlist_normalized = attrlist.lower().split()
            missing = [a for a in values
                if a.lower() not in attrlist_normalized]

            if missing:
                logger.debug("%s needs updating (missing: %s)", attribute,
                             ', '.join(missing))

                replica[attribute] = [
                    '%s %s' % (attrlist, ' '.join(missing))]

                try:
                    repl.conn.update_entry(replica)
                    logger.debug("Updated %s", attribute)
                except Exception as e:
                    logger.error("Error caught updating %s: %s",
                                 attribute, str(e))
            else:
                logger.debug("%s: No update necessary", attribute)
