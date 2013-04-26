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

import pprint

import ldap.schema
import krbV

import ipapython.version
from ipapython.ipa_log_manager import log_mgr
from ipapython.dn import DN
from ipaserver.install.ldapupdate import connect
from ipaserver.install import installutils


SCHEMA_ELEMENT_CLASSES = {
    # All schema model classes this tool can modify
    'objectclasses': ldap.schema.models.ObjectClass,
    'attributetypes': ldap.schema.models.AttributeType,
}

ORIGIN = 'IPA v%s' % ipapython.version.VERSION

log = log_mgr.get_logger(__name__)


def update_schema(schema_files, ldapi=False, dm_password=None, live_run=True):
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
    :live_run: if false, changes will not be applied

    :return:
        True if modifications were made
        (or *would be* made, for live_run=false)
    """
    conn = connect(ldapi=ldapi, dm_password=dm_password,
                   realm=krbV.default_context().default_realm,
                   fqdn=installutils.get_fqdn())

    old_schema = conn.schema

    schema_entry = conn.get_entry(DN(('cn', 'schema')),
                                  SCHEMA_ELEMENT_CLASSES.keys())

    modified = False

    # The exact representation the DS gives us for each OID
    # (for debug logging)
    old_entries_by_oid = {cls(str(attr)).oid: str(attr)
                          for attrname, cls in SCHEMA_ELEMENT_CLASSES.items()
                          for attr in schema_entry[attrname]}

    for filename in schema_files:
        log.info('Processing schema LDIF file %s', filename)
        dn, new_schema = ldap.schema.subentry.urlfetch(filename)

        for attrname, cls in SCHEMA_ELEMENT_CLASSES.items():

            # Set of all elements of this class, as strings given by the DS
            new_elements = []

            for oid in new_schema.listall(cls):
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
                    new_elements.append(value)

                    if old_obj:
                        old_attr = old_entries_by_oid.get(oid)
                        log.info('Replace: %s', old_attr)
                        log.info('   with: %s', value)
                    else:
                        log.info('Add: %s', value)

            modified = modified or new_elements
            schema_entry[attrname].extend(new_elements)

    # FIXME: We should have a better way to display the modlist,
    # for now display raw output of our internal routine
    modlist = conn._generate_modlist(schema_entry.dn, schema_entry)
    log.debug("Complete schema modlist:\n%s", pprint.pformat(modlist))

    if modified and live_run:
        conn.update_entry(schema_entry)
    else:
        log.info('Not updating schema')

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
