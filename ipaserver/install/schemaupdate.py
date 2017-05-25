# Authors: Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2013 Red Hat
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

import logging
import pprint

import ldap.schema

import ipapython.version
from ipalib import api
from ipapython.dn import DN
from ipaserver.install.ldapupdate import connect
from ipaserver.install import installutils


SCHEMA_ELEMENT_CLASSES = (
    # All schema model classes this tool can modify
    # Depends on order, attributes first, then objectclasses
    ('attributetypes', ldap.schema.models.AttributeType),
    ('objectclasses', ldap.schema.models.ObjectClass),
)

ORIGIN = 'IPA v%s' % ipapython.version.VERSION

logger = logging.getLogger(__name__)


def _get_oid_dependency_order(schema, cls):
    """
    Returns a ordered list of OIDs sets, in order which respects inheritance in LDAP
    OIDs in second set, depend on first set, etc.

    :return [set(1st-tree-level), set(2nd-tree-level), ...]
    """
    top_node = '_'
    ordered_oid_groups = []

    tree = schema.tree(cls)  # tree structure of schema

    # remove top_node from tree, it breaks ordering
    # we don't need this, tree from file is not consistent
    del tree[top_node]
    unordered_oids = set(tree.keys())

    # split into two groups, parents and child nodes, and iterate until
    # child nodes are not empty
    while unordered_oids:
        parent_nodes = set()
        child_nodes = set()

        for node in unordered_oids:
            if node not in child_nodes:
                # if node was child once, must remain as child
                parent_nodes.add(node)

            for child_oid in tree[node]:
                # iterate over all child nodes stored in tree[node] per node
                # child node must be removed from parents
                parent_nodes.discard(child_oid)
                child_nodes.add(child_oid)

        ordered_oid_groups.append(parent_nodes)  # parents nodes are not dependent

        assert len(child_nodes) < len(unordered_oids)  # while iteration must be finite
        unordered_oids = child_nodes  # extract new parent nodes in next iteration

    return ordered_oid_groups


def update_schema(schema_files, ldapi=False, dm_password=None,):
    """Update schema to match the given ldif files

    Schema elements present in the LDIF files but missing from the DS schema
    are added.
    Schema elements that differ between LDIF files and DS schema are updated
    to match the LDIF files. The comparison ignores tags that python-ldap's
    schema parser does not understand (such as X-ORIGIN).
    Extra elements present only in the DS schema are left untouched.

    An X-ORIGIN tag containing the current IPA version is added to all new
    and updated schema elements.

    :param schema_files: List of filenames to update from
    :param ldapi: if true, use ldapi to connect
    :param dm_password: directory manager password

    :return:
        True if modifications were made
    """
    SCHEMA_ELEMENT_CLASSES_KEYS = [x[0] for x in SCHEMA_ELEMENT_CLASSES]

    conn = connect(ldapi=ldapi, dm_password=dm_password,
                   realm=api.env.realm,
                   fqdn=installutils.get_fqdn())

    old_schema = conn.schema


    schema_entry = conn.get_entry(DN(('cn', 'schema')),
                                  SCHEMA_ELEMENT_CLASSES_KEYS)

    modified = False

    # The exact representation the DS gives us for each OID
    # (for debug logging)
    old_entries_by_oid = {cls(attr).oid: attr.decode('utf-8')
                          for (attrname, cls) in SCHEMA_ELEMENT_CLASSES
                          for attr in schema_entry[attrname]}

    for filename in schema_files:
        logger.debug('Processing schema LDIF file %s', filename)
        url = "file://{}".format(filename)
        _dn, new_schema = ldap.schema.subentry.urlfetch(url)

        for attrname, cls in SCHEMA_ELEMENT_CLASSES:
            for oids_set in _get_oid_dependency_order(new_schema, cls):
                # Set of all elements of this class, as strings given by the DS
                new_elements = []
                for oid in oids_set:
                    new_obj = new_schema.get_obj(cls, oid)
                    old_obj = old_schema.get_obj(cls, oid)
                    # Compare python-ldap's sanitized string representations
                    # to see if the value is different
                    # This can give false positives, e.g. with case differences
                    # in case-insensitive names.
                    # But, false positives are harmless (and infrequent)
                    if not old_obj or str(new_obj) != str(old_obj):
                        # Note: An add will automatically replace any existing
                        # schema with the same OID. So, we only add.
                        value = add_x_origin(new_obj)

                        if old_obj:
                            old_attr = old_entries_by_oid.get(oid)
                            logger.debug('Replace: %s', old_attr)
                            logger.debug('   with: %s', value)
                        else:
                            logger.debug('Add: %s', value)

                        new_elements.append(value.encode('utf-8'))

                modified = modified or new_elements
                schema_entry[attrname].extend(new_elements)
                # we need to iterate schema updates, due to dependencies (SUP)
                # schema_entry doesn't respect order of objectclasses/attributes
                # so updates must be executed with groups of independent OIDs
                if new_elements:
                    modlist = schema_entry.generate_modlist()
                    logger.debug("Schema modlist:\n%s",
                                 pprint.pformat(modlist))
                    conn.update_entry(schema_entry)

    if not modified:
        logger.debug('Not updating schema')

    return modified


def add_x_origin(element):
    """Add X-ORIGIN tag to a schema element if it does not already contain one
    """
    # Note that python-ldap drops X-ORIGIN when it parses schema elements,
    # so we need to resort to string manipulation
    element = str(element)
    if 'X-ORIGIN' not in element:
        assert element[-2:] == ' )'
        element = element[:-1] + "X-ORIGIN '%s' )" % ORIGIN
    return element
