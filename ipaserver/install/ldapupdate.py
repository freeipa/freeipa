# Authors: Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2008  Red Hat
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

# Documentation can be found at http://freeipa.org/page/LdapUpdate

# TODO
# save undo files?

UPDATES_DIR="/usr/share/ipa/updates/"

import sys
from ipaserver.install import installutils
from ipaserver.install import service
from ipaserver import ipaldap
from ipapython import entity, ipautil
import uuid
from ipalib import util
from ipalib import errors
from ipalib import api
from ipapython.dn import DN
import ldap
from ldap.schema.models import ObjectClass, AttributeType
from ipapython.ipa_log_manager import *
import krbV
import platform
import time
import random
import os
import pwd
import fnmatch
import csv
import inspect
from ipaserver.install.plugins import PRE_UPDATE, POST_UPDATE
from ipaserver.install.plugins import FIRST, MIDDLE, LAST

class BadSyntax(installutils.ScriptError):
    def __init__(self, value):
        self.value = value
        self.msg = "LDAPUpdate: syntax error: \n  %s" % value
        self.rval = 1

    def __str__(self):
        return repr(self.value)

class LDAPUpdate:
    action_keywords = ["default", "add", "remove", "only", "deleteentry", "replace", "addifnew", "addifexist"]

    def __init__(self, dm_password, sub_dict={}, live_run=True,
                 online=True, ldapi=False, plugins=False):
        '''
        :parameters:
            dm_password
                Directory Manager password
            sub_dict
                substitution dictionary
            live_run
                Apply the changes or just test
            online
                Do an online LDAP update or use an experimental LDIF updater
            ldapi
                Bind using ldapi. This assumes autobind is enabled.
            plugins
                execute the pre/post update plugins

        Data Structure Example:
        -----------------------

        dn_by_rdn_count = {
            3: 'cn=config,dc=example,dc=com':
            4: 'cn=bob,ou=people,dc=example,dc=com',
        }

        all_updates = {
        'dn': 'cn=config,dc=example,dc=com':
            {
                'dn': 'cn=config,dc=example,dc=com',
                'default': ['attr1':default1'],
                'updates': ['action:attr1:value1',
                            'action:attr2:value2]
            },
        'dn': 'cn=bob,ou=people,dc=example,dc=com':
            {
                'dn': 'cn=bob,ou=people,dc=example,dc=com',
                'default': ['attr3':default3'],
                'updates': ['action:attr3:value3',
                            'action:attr4:value4],
            }
        }

        The default and update lists are "dispositions"


        '''
        log_mgr.get_logger(self, True)
        self.sub_dict = sub_dict
        self.live_run = live_run
        self.dm_password = dm_password
        self.conn = None
        self.modified = False
        self.online = online
        self.ldapi = ldapi
        self.plugins = plugins
        self.pw_name = pwd.getpwuid(os.geteuid()).pw_name
        self.realm = None
        suffix = None

        if sub_dict.get("REALM"):
            self.realm = sub_dict["REALM"]
        else:
            krbctx = krbV.default_context()
            try:
                self.realm = krbctx.default_realm
                suffix = ipautil.realm_to_suffix(self.realm)
            except krbV.Krb5Error:
                self.realm = None
                suffix = None

        if suffix is not None:
            assert isinstance(suffix, DN)
        domain = ipautil.get_domain_name()
        libarch = self._identify_arch()

        fqdn = installutils.get_fqdn()
        if fqdn is None:
            raise RuntimeError("Unable to determine hostname")
        fqhn = fqdn # Save this for the sub_dict variable
        if self.ldapi:
            fqdn = "ldapi://%%2fvar%%2frun%%2fslapd-%s.socket" % "-".join(
                self.realm.split(".")
            )

        if not self.sub_dict.get("REALM") and self.realm is not None:
            self.sub_dict["REALM"] = self.realm
        if not self.sub_dict.get("FQDN"):
            self.sub_dict["FQDN"] = fqhn
        if not self.sub_dict.get("DOMAIN"):
            self.sub_dict["DOMAIN"] = domain
        if not self.sub_dict.get("SUFFIX") and suffix is not None:
            self.sub_dict["SUFFIX"] = suffix
        if not self.sub_dict.get("ESCAPED_SUFFIX"):
            self.sub_dict["ESCAPED_SUFFIX"] = str(suffix)
        if not self.sub_dict.get("LIBARCH"):
            self.sub_dict["LIBARCH"] = libarch
        if not self.sub_dict.get("TIME"):
            self.sub_dict["TIME"] = int(time.time())
        if not self.sub_dict.get("DOMAIN") and domain is not None:
            self.sub_dict["DOMAIN"] = domain

        if online:
            # Try out the connection/password
            try:
                conn = ipaldap.IPAdmin(fqdn, ldapi=self.ldapi, realm=self.realm)
                if self.dm_password:
                    conn.do_simple_bind(binddn=DN(('cn', 'directory manager')), bindpw=self.dm_password)
                elif os.getegid() == 0:
                    try:
                        # autobind
                        conn.do_external_bind(self.pw_name)
                    except errors.NotFound:
                        # Fall back
                        conn.do_sasl_gssapi_bind()
                else:
                    conn.do_sasl_gssapi_bind()
                conn.unbind()
            except (ldap.CONNECT_ERROR, ldap.SERVER_DOWN):
                raise RuntimeError("Unable to connect to LDAP server %s" % fqdn)
            except ldap.INVALID_CREDENTIALS:
                raise RuntimeError("The password provided is incorrect for LDAP server %s" % fqdn)
            except ldap.LOCAL_ERROR, e:
                raise RuntimeError('%s' % e.args[0].get('info', '').strip())
        else:
            raise RuntimeError("Offline updates are not supported.")

    # The following 2 functions were taken from the Python
    # documentation at http://docs.python.org/library/csv.html
    def _utf_8_encoder(self, unicode_csv_data):
        for line in unicode_csv_data:
            yield line.encode('utf-8')

    def _unicode_csv_reader(self, unicode_csv_data, quote_char="'", dialect=csv.excel, **kwargs):
        # csv.py doesn't do Unicode; encode temporarily as UTF-8:
        csv_reader = csv.reader(self._utf_8_encoder(unicode_csv_data),
                                dialect=dialect, delimiter=',',
                                quotechar=quote_char,
                                skipinitialspace=True,
                                **kwargs)
        for row in csv_reader:
            # decode UTF-8 back to Unicode, cell by cell:
            yield [unicode(cell, 'utf-8') for cell in row]

    def _identify_arch(self):
        """On multi-arch systems some libraries may be in /lib64, /usr/lib64,
           etc.  Determine if a suffix is needed based on the current
           architecture.
        """
        bits = platform.architecture()[0]

        if bits == "64bit":
            return "64"
        else:
            return ""

    def _template_str(self, s):
        try:
            return ipautil.template_str(s, self.sub_dict)
        except KeyError, e:
            raise BadSyntax("Unknown template keyword %s" % e)

    def _parse_values(self, line):
        """Parse a comma-separated string into separate values and convert them
           into a list. This should handle quoted-strings with embedded commas
        """
        if   line[0] == "'":
            quote_char = "'"
        else:
            quote_char = '"'
        reader = self._unicode_csv_reader([line], quote_char)
        value = []
        for row in reader:
            value = value + row
        return value

    def read_file(self, filename):
        if filename == '-':
            fd = sys.stdin
        else:
            fd = open(filename)
        text = fd.readlines()
        if fd != sys.stdin: fd.close()
        return text

    def _entry_to_entity(self, ent):
        """Tne Entry class is a bare LDAP entry. The Entity class has a lot more
           helper functions that we need, so convert to dict and then to Entity.
        """
        entry = dict(ent.data)
        entry['dn'] = ent.dn
        for key,value in entry.iteritems():
            if isinstance(value,list) or isinstance(value,tuple):
                if len(value) == 0:
                    entry[key] = ''
                elif len(value) == 1:
                    entry[key] = value[0]
        return entity.Entity(entry)

    def _combine_updates(self, all_updates, update):
        'Combine a new update with the list of total updates'
        dn = update.get('dn')
        assert isinstance(dn, DN)

        if not all_updates.get(dn):
            all_updates[dn] = update
            return

        existing_update = all_updates[dn]
        if 'default' in update:
            disposition_list = existing_update.setdefault('default', [])
            disposition_list.extend(update['default'])
        elif 'updates' in update:
            disposition_list = existing_update.setdefault('updates', [])
            disposition_list.extend(update['updates'])
        else:
            self.debug("Unknown key in updates %s" % update.keys())

    def merge_updates(self, all_updates, updates):
        '''
        Add the new_update dict to the all_updates dict.  If an entry
        in the new_update already has an entry in all_updates merge
        the two entries sensibly assuming the new entries take
        precedence. Otherwise just add the new entry.
        '''

        for new_update in updates:
            for new_dn, new_entry in new_update.iteritems():
                existing_entry = all_updates.get(new_dn)
                if existing_entry:
                    # If the existing entry is marked for deletion but the
                    # new entry is not also a delete then clear the delete
                    # flag otherwise the newer update will be lost.
                    if existing_entry.has_key('deleteentry') and not new_entry.has_key('deleteentry'):
                        self.warning("ldapupdate: entry '%s' previously marked for deletion but" +
                                     " this subsequent update reestablishes it: %s", new_dn, new_entry)
                        del existing_entry['deleteentry']
                    existing_entry.update(new_entry)
                else:
                    all_updates[new_dn] = new_entry


    def parse_update_file(self, data_source_name, source_data, all_updates):
        """Parse the update file into a dictonary of lists and apply the update
           for each DN in the file."""
        update = {}
        logical_line = ""
        action = ""
        dn = None
        lcount = 0

        def emit_item(logical_line):
            '''
            Given a logical line containing an item to process perform the following:

            * Strip leading & trailing whitespace
            * Substitute any variables
            * Get the action, attribute, and value
            * Each update has one list per disposition, append to specified disposition list
            '''

            logical_line = logical_line.strip()
            if logical_line == '':
                return

            # Perform variable substitution on constructued line
            logical_line = self._template_str(logical_line)

            items = logical_line.split(':', 2)

            if len(items) == 0:
                raise BadSyntax, "Bad formatting on line %s:%d: %s" % (data_source_name, lcount, logical_line)

            action = items[0].strip().lower()

            if action not in self.action_keywords:
                raise BadSyntax, "Unknown update action '%s', data source=%s" % (action, data_source_name)

            if action == 'deleteentry':
                new_value = None
                disposition = "deleteentry"
            else:
                if len(items) != 3:
                    raise BadSyntax, "Bad formatting on line %s:%d: %s" % (data_source_name, lcount, logical_line)

                attr = items[1].strip()
                value = items[2].strip()

                if action == "default":
                    new_value = attr + ":" + value
                    disposition = "default"
                else:
                    new_value = action + ":" + attr + ":" + value
                    disposition = "updates"

            disposition_list = update.setdefault(disposition, [])
            disposition_list.append(new_value)

        def emit_update(update):
            '''
            When processing a dn is completed emit the update by merging it into
            the set of all updates.
            '''

            self._combine_updates(all_updates, update)

        # Iterate over source input lines
        for source_line in source_data:
            lcount += 1

            # strip trailing whitespace and newline
            source_line = source_line.rstrip()

            # skip comments and empty lines
            if source_line.startswith('#') or source_line == '':
                continue

            if source_line.lower().startswith('dn:'):
                # Starting new dn
                if dn is not None:
                    # Emit previous dn
                    emit_item(logical_line)
                    logical_line = ''
                    emit_update(update)
                    update = {}

                dn = source_line[3:].strip()
                dn = DN(self._template_str(dn))
                update['dn'] = dn
            else:
                # Process items belonging to dn
                if dn is None:
                    raise BadSyntax, "dn is not defined in the update, data source=%s" % (data_source_name)

                # If continuation line, append to existing logical line & continue,
                # otherwise flush the previous item.
                if source_line.startswith(' '):
                    logical_line += source_line[1:]
                    continue
                else:
                    emit_item(logical_line)
                    logical_line = ''
                    logical_line = source_line

        if dn is not None:
            emit_item(logical_line)
            logical_line = ''
            emit_update(update)
            update = {}

        return all_updates

    def create_index_task(self, attribute):
        """Create a task to update an index for an attribute"""

        # Sleep a bit to ensure previous operations are complete
        if self.live_run:
            time.sleep(5)

        cn_uuid = uuid.uuid1()
        # cn_uuid.time is in nanoseconds, but other users of LDAPUpdate expect
        # seconds in 'TIME' so scale the value down
        self.sub_dict['TIME'] = int(cn_uuid.time/1e9)
        cn = "indextask_%s_%s_%s" % (attribute, cn_uuid.time, cn_uuid.clock_seq)
        dn = DN(('cn', cn), ('cn', 'index'), ('cn', 'tasks'), ('cn', 'config'))

        e = ipaldap.Entry(dn)

        e.setValues('objectClass', ['top', 'extensibleObject'])
        e.setValue('cn', cn)
        e.setValue('nsInstance', 'userRoot')
        e.setValues('nsIndexAttribute', attribute)

        self.info("Creating task to index attribute: %s", attribute)
        self.debug("Task id: %s", dn)

        if self.live_run:
            self.conn.addEntry(e)

        return dn

    def monitor_index_task(self, dn):
        """Give a task DN monitor it and wait until it has completed (or failed)
        """

        assert isinstance(dn, DN)

        if not self.live_run:
            # If not doing this live there is nothing to monitor
            return

        # Pause for a moment to give the task time to be created
        time.sleep(1)

        attrlist = ['nstaskstatus', 'nstaskexitcode']
        entry = None

        while True:
            try:
                entry = self.conn.getEntry(dn, ldap.SCOPE_BASE, "(objectclass=*)", attrlist)
            except errors.NotFound, e:
                self.error("Task not found: %s", dn)
                return
            except errors.DatabaseError, e:
                self.error("Task lookup failure %s", e)
                return

            status = entry.getValue('nstaskstatus')
            if status is None:
                # task doesn't have a status yet
                time.sleep(1)
                continue

            if status.lower().find("finished") > -1:
                self.info("Indexing finished")
                break

            self.debug("Indexing in progress")
            time.sleep(1)

        return

    def _create_default_entry(self, dn, default):
        """Create the default entry from the values provided.

           The return type is entity.Entity
        """
        assert isinstance(dn, DN)
        entry = ipaldap.Entry(dn)

        if not default:
            # This means that the entire entry needs to be created with add
            return self._entry_to_entity(entry)

        for item in default:
            # We already do syntax-parsing so this is safe
            (attr, value) = item.split(':',1)
            e = entry.getValues(attr)
            if e:
                # multi-valued attribute
                e = list(e)
                e.append(value)
            else:
                e = value
            entry.setValues(attr, e)

        return self._entry_to_entity(entry)

    def _get_entry(self, dn):
        """Retrieve an object from LDAP.

           The return type is ipaldap.Entry
        """
        assert isinstance(dn, DN)
        searchfilter="objectclass=*"
        sattrs = ["*", "aci", "attributeTypes", "objectClasses"]
        scope = ldap.SCOPE_BASE

        return self.conn.getList(dn, scope, searchfilter, sattrs)

    def _apply_update_disposition(self, updates, entry):
        """
        updates is a list of changes to apply
        entry is the thing to apply them to

        Returns the modified entry
        """
        if not updates:
            return entry

        only = {}
        for update in updates:
            # We already do syntax-parsing so this is safe
            (action, attr, update_values) = update.split(':',2)
            update_values = self._parse_values(update_values)

            # If the attribute is known to be a DN convert it to a DN object.
            # This has to be done after _parse_values() due to quoting and comma separated lists.
            if self.conn.has_dn_syntax(attr):
                update_values = [DN(x) for x in update_values]

            entry_values = entry.getValues(attr)
            if not isinstance(entry_values, list):
                if entry_values is None:
                    entry_values = []
                else:
                    entry_values = [entry_values]

            # Replacing objectClassess needs a special handling and
            # normalization of OC definitions to avoid update failures for
            # example when X-ORIGIN is the only difference
            schema_update = False
            schema_elem_class = None
            schema_elem_name = None
            if action == "replace" and entry.dn == DN(('cn', 'schema')):
                if attr.lower() == "objectclasses":
                    schema_elem_class = ObjectClass
                    schema_elem_name = "ObjectClass"
                elif attr.lower() == "attributetypes":
                    schema_elem_class = AttributeType
                    schema_elem_name = "AttributeType"

                if schema_elem_class is not None:
                    schema_update = True
                    oid_index = {}
                    # build the OID index for replacing
                    for schema_elem in entry_values:
                        try:
                            schema_elem_object = schema_elem_class(str(schema_elem))
                        except Exception, e:
                            self.error('replace: cannot parse %s "%s": %s',
                                            schema_elem_name, schema_elem, e)
                            continue
                        # In a corner case, there may be more representations of
                        # the same objectclass/attributetype due to the previous updates
                        # We want to replace them all
                        oid_index.setdefault(schema_elem_object.oid, []).append(schema_elem)

            for update_value in update_values:
                if action == 'remove':
                    self.debug("remove: '%s' from %s, current value %s", update_value, attr, entry_values)
                    try:
                        entry_values.remove(update_value)
                    except ValueError:
                        self.warning("remove: '%s' not in %s", update_value, attr)
                        pass
                    entry.setValues(attr, entry_values)
                    self.debug('remove: updated value %s', entry_values)
                elif action == 'add':
                    self.debug("add: '%s' to %s, current value %s", update_value, attr, entry_values)
                    # Remove it, ignoring errors so we can blindly add it later
                    try:
                        entry_values.remove(update_value)
                    except ValueError:
                        pass
                    entry_values.append(update_value)
                    self.debug('add: updated value %s', entry_values)
                    entry.setValues(attr, entry_values)
                elif action == 'addifnew':
                    self.debug("addifnew: '%s' to %s, current value %s", update_value, attr, entry_values)
                    # Only add the attribute if it doesn't exist. Only works
                    # with single-value attributes.
                    if len(entry_values) == 0:
                        entry_values.append(update_value)
                        self.debug('addifnew: set %s to %s', attr, entry_values)
                        entry.setValues(attr, entry_values)
                elif action == 'addifexist':
                    self.debug("addifexist: '%s' to %s, current value %s", update_value, attr, entry_values)
                    # Only add the attribute if the entry doesn't exist. We
                    # determine this based on whether it has an objectclass
                    if entry.getValues('objectclass'):
                        entry_values.append(update_value)
                        self.debug('addifexist: set %s to %s', attr, entry_values)
                        entry.setValues(attr, entry_values)
                elif action == 'only':
                    self.debug("only: set %s to '%s', current value %s", attr, update_value, entry_values)
                    if only.get(attr):
                        entry_values.append(update_value)
                    else:
                        entry_values = [update_value]
                        only[attr] = True
                    entry.setValues(attr, entry_values)
                    self.debug('only: updated value %s', entry_values)
                elif action == 'deleteentry':
                    # skip this update type, it occurs in  __delete_entries()
                    return None
                elif action == 'replace':
                    # value has the format "old::new"
                    try:
                        (old, new) = update_value.split('::', 1)
                    except ValueError:
                        raise BadSyntax, "bad syntax in replace, needs to be in the format old::new in %s" % update_value
                    try:
                        if schema_update:
                            try:
                                schema_elem_old = schema_elem_class(str(old))
                            except Exception, e:
                                self.error('replace: cannot parse replaced %s "%s": %s',
                                        schema_elem_name, old, e)
                                continue
                            replaced_values = []
                            for schema_elem in oid_index.get(schema_elem_old.oid, []):
                                schema_elem_object = schema_elem_class(str(schema_elem))
                                if str(schema_elem_old).lower() == str(schema_elem_object).lower():
                                    # compare normalized values
                                    replaced_values.append(schema_elem)
                                    self.debug('replace: replace %s "%s" with "%s"',
                                            schema_elem_name, old, new)
                            if not replaced_values:
                                self.debug('replace: no match for replaced %s "%s"',
                                        schema_elem_name, old)
                                continue
                            for value in replaced_values:
                                entry_values.remove(value)
                        else:
                            entry_values.remove(old)
                        entry_values.append(new)
                        self.debug('replace: updated value %s', entry_values)
                        entry.setValues(attr, entry_values)
                    except ValueError:
                        self.debug('replace: %s not found, skipping', old)

        return entry

    def print_entity(self, e, message=None):
        """The entity object currently lacks a str() method"""
        self.debug("---------------------------------------------")
        if message:
            self.debug("%s", message)
        self.debug("dn: %s", e.dn)
        attr = e.attrList()
        for a in attr:
            value = e.getValues(a)
            if isinstance(value, (list, tuple)):
                self.debug('%s:', a)
                for l in value:
                    self.debug("\t%s", l)
            else:
                self.debug('%s: %s', a, value)

    def is_schema_updated(self, s):
        """Compare the schema in 's' with the current schema in the DS to
           see if anything has changed. This should account for syntax
           differences (like added parens that make no difference but are
           detected as a change by generateModList()).

           This doesn't handle re-ordering of attributes. They are still
           detected as changes, so foo $ bar != bar $ foo.

           return True if the schema has changed
           return False if it has not
        """
        signature = inspect.getargspec(ldap.schema.SubSchema.__init__)
        if 'check_uniqueness' in signature.args:
            s = ldap.schema.SubSchema(s, check_uniqueness=0)
        else:
            s = ldap.schema.SubSchema(s)
        s = s.ldap_entry()

        # Get a fresh copy and convert into a SubSchema
        n = self._get_entry(DN(('cn', 'schema')))[0]

        # Convert IPA data types back to strings
        d = dict()
        for k,v in n.data.items():
            d[k] = [str(x) for x in v]

        # Convert to subschema dict
        n = ldap.schema.SubSchema(d)
        n = n.ldap_entry()

        # Are they equal?
        if s == n:
            return False
        else:
            return True

    def _update_record(self, update):
        found = False

        # If the entry is going to be deleted no point in processing it.
        if update.has_key('deleteentry'):
            return

        new_entry = self._create_default_entry(update.get('dn'),
                                               update.get('default'))

        try:
            e = self._get_entry(new_entry.dn)
            if len(e) > 1:
                # we should only ever get back one entry
                raise BadSyntax, "More than 1 entry returned on a dn search!? %s" % new_entry.dn
            entry = self._entry_to_entity(e[0])
            found = True
            self.info("Updating existing entry: %s", entry.dn)
        except errors.NotFound:
            # Doesn't exist, start with the default entry
            entry = new_entry
            self.info("New entry: %s", entry.dn)
        except errors.DatabaseError:
            # Doesn't exist, start with the default entry
            entry = new_entry
            self.info("New entry, using default value: %s", entry.dn)

        self.print_entity(entry, "Initial value")

        # Bring this entry up to date
        entry = self._apply_update_disposition(update.get('updates'), entry)
        if entry is None:
            # It might be None if it is just deleting an entry
            return

        self.print_entity(entry, "Final value after applying updates")

        added = False
        updated = False
        if not found:
            # New entries get their orig_data set to the entry itself. We want to
            # empty that so that everything appears new when generating the
            # modlist
            # entry.orig_data = {}
            try:
                if self.live_run:
                    if len(entry.toTupleList()) > 0:
                        # addifexist may result in an entry with only a
                        # dn defined. In that case there is nothing to do.
                        # It means the entry doesn't exist, so skip it.
                        try:
                            self.conn.addEntry(entry)
                        except errors.NotFound:
                            # parent entry of the added entry does not exist
                            # this may not be an error (e.g. entries in NIS container)
                            self.info("Parent DN of %s may not exist, cannot create the entry",
                                    entry.dn)
                            return
                added = True
                self.modified = True
            except Exception, e:
                self.error("Add failure %s", e)
        else:
            # Update LDAP
            try:
                changes = self.conn.generateModList(entry.origDataDict(), entry.toDict())
                if (entry.dn == DN(('cn', 'schema'))):
                    d = dict()
                    e = entry.toDict()
                    for k,v in e.items():
                        d[k] = [str(x) for x in v]
                    updated = self.is_schema_updated(d)
                else:
                    if len(changes) >= 1:
                        updated = True
                self.debug("%s" % changes)
                self.debug("Live %d, updated %d" % (self.live_run, updated))
                if self.live_run and updated:
                    self.conn.updateEntry(entry.dn, entry.origDataDict(), entry.toDict())
                self.info("Done")
            except errors.EmptyModlist:
                self.info("Entry already up-to-date")
                updated = False
            except errors.DatabaseError, e:
                self.error("Update failed: %s", e)
                updated = False
            except errors.ACIError, e:
                self.error("Update failed: %s", e)
                updated = False

            if updated:
                self.modified = True

        if entry.dn.endswith(DN(('cn', 'index'), ('cn', 'userRoot'),
                                ('cn', 'ldbm database'), ('cn', 'plugins'),
                                ('cn', 'config'))) and (added or updated):
            taskid = self.create_index_task(entry.getValue('cn'))
            self.monitor_index_task(taskid)
        return

    def _delete_record(self, updates):
        """
        Run through all the updates again looking for any that should be
        deleted.

        This must use a reversed list so that the longest entries are
        considered first so we don't end up trying to delete a parent
        and child in the wrong order.
        """

        if not updates.has_key('deleteentry'):
            return

        dn = updates['dn']
        try:
            self.info("Deleting entry %s", dn)
            if self.live_run:
                self.conn.deleteEntry(dn)
            self.modified = True
        except errors.NotFound, e:
            self.info("%s did not exist:%s", dn, e)
            self.modified = True
        except errors.DatabaseError, e:
            self.error("Delete failed: %s", e)

    def get_all_files(self, root, recursive=False):
        """Get all update files"""
        f = []
        for path, subdirs, files in os.walk(root):
            for name in files:
                if fnmatch.fnmatch(name, "*.update"):
                    f.append(os.path.join(path, name))
            if not recursive:
                break
        f.sort()
        return f

    def create_connection(self):
        if self.online:
            if self.ldapi:
                self.conn = ipaldap.IPAdmin(ldapi=True, realm=self.realm)
            else:
                self.conn = ipaldap.IPAdmin(self.sub_dict['FQDN'],
                                            ldapi=False,
                                            realm=self.realm)
            try:
                if self.dm_password:
                    self.conn.do_simple_bind(binddn=DN(('cn', 'directory manager')), bindpw=self.dm_password)
                elif os.getegid() == 0:
                    try:
                        # autobind
                        self.conn.do_external_bind(self.pw_name)
                    except errors.NotFound:
                        # Fall back
                        self.conn.do_sasl_gssapi_bind()
                else:
                    self.conn.do_sasl_gssapi_bind()
            except ldap.LOCAL_ERROR, e:
                raise RuntimeError('%s' % e.args[0].get('info', '').strip())
        else:
            raise RuntimeError("Offline updates are not supported.")

    def _run_updates(self, all_updates):
        # For adds and updates we want to apply updates from shortest
        # to greatest length of the DN. For deletes we want the reverse.

        dn_by_rdn_count = {}
        for dn in all_updates.keys():
            assert isinstance(dn, DN)
            rdn_count = len(dn)
            rdn_count_list = dn_by_rdn_count.setdefault(rdn_count, [])
            if dn not in rdn_count_list:
                rdn_count_list.append(dn)

        sortedkeys = dn_by_rdn_count.keys()
        sortedkeys.sort()
        for rdn_count in sortedkeys:
            for dn in dn_by_rdn_count[rdn_count]:
                self._update_record(all_updates[dn])

        sortedkeys.reverse()
        for rdn_count in sortedkeys:
            for dn in dn_by_rdn_count[rdn_count]:
                self._delete_record(all_updates[dn])

    def update(self, files):
        """Execute the update. files is a list of the update files to use.

           returns True if anything was changed, otherwise False
        """

        all_updates = {}
        if self.plugins:
            self.info('PRE_UPDATE')
            updates = api.Backend.updateclient.update(PRE_UPDATE, self.dm_password, self.ldapi, self.live_run)
            self.merge_updates(all_updates, updates)
        try:
            self.create_connection()

            for f in files:
                try:
                    self.info("Parsing update file '%s'" % f)
                    data = self.read_file(f)
                except Exception, e:
                    self.error("error reading update file '%s'", f)
                    sys.exit(e)

                self.parse_update_file(f, data, all_updates)

            self._run_updates(all_updates)
        finally:
            if self.conn: self.conn.unbind()

        if self.plugins:
            self.info('POST_UPDATE')
            all_updates = {}
            updates = api.Backend.updateclient.update(POST_UPDATE, self.dm_password, self.ldapi, self.live_run)
            self.merge_updates(all_updates, updates)
            self._run_updates(all_updates)

        return self.modified


    def update_from_dict(self, updates):
        """
        Apply updates internally as opposed to from a file.
        updates is a dictionary containing the updates
        """
        if not self.conn:
            self.create_connection()

        self._run_updates(updates)

        return self.modified
