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
from ipalib import errors

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

        # Find suffixes
        suffixes = self.api.Command.topologysuffix_find()['result']
        for suffix in suffixes:
            suffix_name = suffix['cn'][0]
            # Find segments
            sgmts = self.api.Command.topologysegment_find(
                suffix_name, all=True)['result']
            for segment in sgmts:
                updates = {}
                updates = self._update_attr(
                    segment, updates,
                    'nsds5replicatedattributelist',
                    replication.EXCLUDES, template=EXCLUDE_TEMPLATE)
                updates = self._update_attr(
                    segment, updates,
                    'nsds5replicatedattributelisttotal',
                    replication.TOTAL_EXCLUDES, template=EXCLUDE_TEMPLATE)
                updates = self._update_attr(
                    segment, updates,
                    'nsds5replicastripattrs', replication.STRIP_ATTRS)
                if updates:
                    try:
                        self.api.Command.topologysegment_mod(
                            suffix_name, segment['cn'][0],
                            **updates)
                    except errors.EmptyModlist:
                        # No update done
                        logger.debug("No update required for the segment %s",
                                     segment['cn'][0])

        logger.debug("Done updating agreements")

        return False, []  # No restart, no updates

    def _update_attr(self, segment, updates, attribute, values, template='%s'):
        """Add or update an attribute of a replication agreement

        If the attribute doesn't already exist, it is added and set to
        `template` with %s substituted by a space-separated `values`.
        If the attribute does exist, `values` missing from it are just
        appended to the end, also space-separated.

        :param: updates: dict containing the updates
        :param segment: dict containing segment information
        :param attribute: Attribute to add or update
        :param values: List of values the attribute should hold
        :param template: Template to use when adding attribute
        """
        attrlist = segment.get(attribute)
        if attrlist is None:
            logger.debug("Adding %s", attribute)

            # Need to add it altogether
            updates[attribute] = template % " ".join(values)

        else:
            attrlist_normalized = attrlist[0].lower().split()
            missing = [a for a in values
                if a.lower() not in attrlist_normalized]

            if missing:
                logger.debug("%s needs updating (missing: %s)", attribute,
                             ', '.join(missing))

                updates[attribute] = '%s %s' % (attrlist[0], ' '.join(missing))

            else:
                logger.debug("%s: No update necessary", attribute)
        return updates
