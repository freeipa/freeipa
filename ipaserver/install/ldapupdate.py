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
from __future__ import absolute_import

import base64
import logging
import sys
import uuid
import time
import os
import fnmatch
import warnings

from pysss_murmur import murmurhash3
import six

from ipapython import ipautil, ipaldap
from ipalib import errors
from ipalib import api, create_api
from ipalib import constants
from ipaplatform.constants import constants as platformconstants
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks
from ipapython.dn import DN
from ipaserver.install import installutils, replication

if six.PY3:
    unicode = str

logger = logging.getLogger(__name__)

UPDATES_DIR=paths.UPDATES_DIR
UPDATE_SEARCH_TIME_LIMIT = 30  # seconds


def get_sub_dict(realm, domain, suffix, fqdn, idstart=None, idmax=None):
    """LDAP template substitution dict for installer and updater
    """
    if idstart is None:
        idrange_size = None
        subid_base_rid = None
    else:
        idrange_size = idmax - idstart + 1
        subid_base_rid = constants.SUBID_RANGE_START - idrange_size

    # uid / gid for autobind
    # user is only defined when ipa-server-dns and bind are installed
    try:
        named_uid = platformconstants.NAMED_USER.uid
        named_gid = platformconstants.NAMED_GROUP.gid
    except ValueError:
        named_uid = None
        named_gid = None

    return dict(
        REALM=realm,
        DOMAIN=domain,
        SUFFIX=suffix,
        ESCAPED_SUFFIX=str(suffix),
        FQDN=fqdn,
        HOST=fqdn,
        LIBARCH=paths.LIBARCH,
        TIME=int(time.time()),
        FIPS="#" if tasks.is_fips_enabled() else "",
        # idstart, idmax, and idrange_size may be None
        IDSTART=idstart,
        IDMAX=idmax,
        IDRANGE_SIZE=idrange_size,
        SUBID_COUNT=constants.SUBID_COUNT,
        SUBID_RANGE_START=constants.SUBID_RANGE_START,
        SUBID_RANGE_SIZE=constants.SUBID_RANGE_SIZE,
        SUBID_RANGE_MAX=constants.SUBID_RANGE_MAX,
        SUBID_DNA_THRESHOLD=constants.SUBID_DNA_THRESHOLD,
        SUBID_BASE_RID=subid_base_rid,
        DOMAIN_HASH=murmurhash3(domain, len(domain), 0xdeadbeef),
        MAX_DOMAIN_LEVEL=constants.MAX_DOMAIN_LEVEL,
        MIN_DOMAIN_LEVEL=constants.MIN_DOMAIN_LEVEL,
        STRIP_ATTRS=" ".join(replication.STRIP_ATTRS),
        EXCLUDES=(
            '(objectclass=*) $ EXCLUDE ' + ' '.join(replication.EXCLUDES)
        ),
        TOTAL_EXCLUDES=(
            '(objectclass=*) $ EXCLUDE '
            + ' '.join(replication.TOTAL_EXCLUDES)
        ),
        DEFAULT_SHELL=platformconstants.DEFAULT_SHELL,
        DEFAULT_ADMIN_SHELL=platformconstants.DEFAULT_ADMIN_SHELL,
        SELINUX_USERMAP_DEFAULT=platformconstants.SELINUX_USERMAP_DEFAULT,
        SELINUX_USERMAP_ORDER=platformconstants.SELINUX_USERMAP_ORDER,
        NAMED_UID=named_uid,
        NAMED_GID=named_gid,
    )


def connect(ldapi=False, realm=None, fqdn=None):
    """Create a connection for updates"""
    if ldapi:
        conn = ipaldap.LDAPClient.from_realm(realm, decode_attrs=False)
    else:
        conn = ipaldap.LDAPClient.from_hostname_secure(
            fqdn, decode_attrs=False
        )
    try:
        if os.getegid() == 0:
            try:
                # autobind
                conn.external_bind()
            except errors.NotFound:
                # Fall back
                conn.gssapi_bind()
        else:
            conn.gssapi_bind()
    except (errors.DatabaseError, errors.NetworkError) as e:
        raise RuntimeError("Unable to connect to LDAP server: %s" % e)
    except errors.ACIError as e:
        raise RuntimeError(
            "The password provided is incorrect for LDAP server %s: %s" %
            (fqdn, e))
    return conn


class BadSyntax(installutils.ScriptError):
    def __init__(self, value):
        self.value = value
        super(BadSyntax, self).__init__(
            msg="LDAPUpdate: syntax error: \n  %s" % value, rval=1)

    def __str__(self):
        return repr(self.value)

def safe_output(attr, values):
    """
    Sanitizes values we do not want logged, like passwords.

    This should be called in all debug statements that output values.

    This list does not necessarily need to be exhaustive given the limited
    scope of types of values that the updater manages.

    This only supports lists, tuples and strings. If you pass a dict you may
    get a string back.
    """
    sensitive_attributes = ['krbmkey', 'userpassword', 'passwordhistory', 'krbprincipalkey', 'sambalmpassword', 'sambantpassword', 'ipanthash']

    if attr.lower() in sensitive_attributes:
        if type(values) in (tuple, list):
            # try to still look a little like what is in LDAP
            return ['XXXXXXX'] * len(values)
        else:
            return 'XXXXXXXX'

    if values is None:
        return None

    is_list = type(values) in (tuple, list)

    if is_list and None in values:
        return values

    if not is_list:
        values = [values]

    try:
        values = [v.decode('ascii') for v in values]
    except UnicodeDecodeError:
        try:
            values = [base64.b64encode(v).decode('ascii') for v in values]
        except TypeError:
            pass

    if not is_list:
        values = values[0]
    return values


_sentinel = object()


def run_ldapi_reload_task(conn):
    """Create and wait for reload ldapi mappings task

    :param conn: ldap2 connection
    :return: exitcode
    """
    task_cn = "reload_{}".format(int(time.time()))
    task_dn = DN(
        ('cn', task_cn), ('cn', 'reload ldapi mappings'),
        ('cn', 'tasks'), ('cn', 'config')
    )
    entry = conn.make_entry(
        task_dn,
        objectClass=['top', 'extensibleObject'],
        cn=[task_cn],
        ttl=[10],
    )
    logger.debug('Creating reload task %s', task_dn)
    conn.add_entry(entry)
    # task usually finishes in a few ms, avoid 1 sec delay in wait_for_task
    time.sleep(0.1)
    exitcode = replication.wait_for_task(api.Backend.ldap2, task_dn)
    logger.debug(
        'Task %s has finished with exit code %i',
        task_dn, exitcode
    )
    return exitcode


class LDAPUpdate:
    action_keywords = {
        "default", "add", "remove", "only", "onlyifexist", "deleteentry",
        "replace", "addifnew", "addifexist"
    }
    index_suffix = DN(
        ('cn', 'index'), ('cn', 'userRoot'), ('cn', 'ldbm database'),
        ('cn', 'plugins'), ('cn', 'config')
    )
    ldapi_autobind_suffix = DN(('cn', 'auto_bind'), ('cn', 'config'))

    def __init__(self, dm_password=_sentinel, sub_dict=None,
                 online=_sentinel, ldapi=_sentinel, api=api):
        '''
        :parameters:
            dm_password
                deprecated and no longer used
            sub_dict
                substitution dictionary
            online
                deprecated and no longer used
            ldapi
                deprecated and no longer used
            api
                bootstrapped API object (for configuration)

        Data Structure Example:
        -----------------------

        dn_by_rdn_count = {
            3: 'cn=config,dc=example,dc=com':
            4: 'cn=bob,ou=people,dc=example,dc=com',
        }

        all_updates = [
            {
                'dn': 'cn=config,dc=example,dc=com',
                'default': [
                    dict(attr='attr1', value='default1'),
                ],
                'updates': [
                    dict(action='action', attr='attr1', value='value1'),
                    dict(action='replace', attr='attr2', value=['old', 'new']),
                ]
            },
            {
                'dn': 'cn=bob,ou=people,dc=example,dc=com',
                'default': [
                    dict(attr='attr3', value='default3'),
                ],
                'updates': [
                    dict(action='action', attr='attr3', value='value3'),
                    dict(action='action', attr='attr4', value='value4'),
                }
            }
        ]

        Please notice the replace action requires two values in list

        The default and update lists are "dispositions"

        Plugins:

        Plugins has to be specified in update file to be executed, using
        'plugin' directive

        Example:
        plugin: update_uniqueness_plugins_to_new_syntax

        Each plugin returns two values:

        1. restart: dirsrv will be restarted AFTER this update is
                     applied.
        2. updates: A list of updates to be applied.

        The value of an update is a dictionary with the following possible
        values:
          - dn: DN, equal to the dn attribute
          - updates: list of updates against the dn
          - default: list of the default entry to be added if it doesn't
                     exist
          - deleteentry: list of dn's to be deleted (typically single dn)

        For example, this update file:

          dn: cn=global_policy,cn=$REALM,cn=kerberos,$SUFFIX
          replace:krbPwdLockoutDuration:10::600
          replace: krbPwdMaxFailure:3::6

        Generates this list which contain the update dictionary:

        [
          {
            'dn': 'cn=global_policy,cn=EXAMPLE.COM,cn=kerberos,dc=example,dc=com',
            'updates': [
              dict(action='replace', attr='krbPwdLockoutDuration',
                   value=['10','600']),
              dict(action='replace', attr='krbPwdMaxFailure',
                   value=['3','6']),
            ]
          }
        ]

        Here is another example showing how a default entry is configured:

          dn: cn=Managed Entries,cn=etc,$SUFFIX
          default: objectClass: nsContainer
          default: objectClass: top
          default: cn: Managed Entries

        This generates:

        [
          {
            'dn': 'cn=Managed Entries,cn=etc,dc=example,dc=com',
            'default': [
              dict(attr='objectClass', value='nsContainer'),
              dict(attr='objectClass', value='top'),
              dict(attr='cn', value='Managed Entries'),
            ]
          }
        ]

        Note that the variable substitution in both examples has been completed.

        Either may make changes directly in LDAP or can return updates in
        update format.

        '''
        if any(arg is not _sentinel for arg in (dm_password, online, ldapi)):
            warnings.warn(
                "dm_password, online, and ldapi arguments are deprecated",
                DeprecationWarning,
                stacklevel=2
            )
        self.sub_dict = sub_dict if sub_dict is not None else {}
        self.conn = None
        self.modified = False
        self.ldapuri = ipaldap.realm_to_ldapi_uri(api.env.realm)

        self.api = create_api(mode=None)
        self.api.bootstrap(
            in_server=True,
            context='updates',
            confdir=paths.ETC_IPA,
            ldap_uri=self.ldapuri
        )
        self.api.finalize()
        self.create_connection()

        # get ipa-local domain idrange settings
        domain_range = f"{self.api.env.realm}_id_range"
        try:
            result = self.api.Command.idrange_show(domain_range)["result"]
        except errors.NotFound:
            idstart = None
            idmax = None
        else:
            idstart = int(result['ipabaseid'][0])
            idrange_size = int(result['ipaidrangesize'][0])
            idmax = idstart + idrange_size - 1

        default_sub = get_sub_dict(
            realm=api.env.realm,
            domain=api.env.domain,
            suffix=api.env.basedn,
            fqdn=api.env.host,
            idstart=idstart,
            idmax=idmax,
        )
        replication_plugin = (
            installutils.get_replication_plugin_name(self.conn.get_entry)
        )
        default_sub["REPLICATION_PLUGIN"] = replication_plugin

        for k, v in default_sub.items():
            self.sub_dict.setdefault(k, v)

    def _template_str(self, s):
        try:
            return ipautil.template_str(s, self.sub_dict)
        except KeyError as e:
            raise BadSyntax("Unknown template keyword %s" % e)

    def read_file(self, filename):
        if filename == '-':
            fd = sys.stdin
        else:
            fd = open(filename)
        text = fd.readlines()
        if fd != sys.stdin: fd.close()
        return text

    def parse_update_file(self, data_source_name, source_data, all_updates):
        """Parse the update file into a dictonary of lists and apply the update
           for each DN in the file."""
        update = {}
        logical_line = ""
        dn = None
        lcount = 0

        def emit_item(logical_line):
            '''
            Given a logical line containing an item to process perform the following:

            * Strip leading & trailing whitespace
            * Substitute any variables
            * Strip again and skip empty/commented lines after substitution
            * Get the action, attribute, and value
            * Each update has one list per disposition, append to specified disposition list
            '''

            logical_line = logical_line.strip()
            if logical_line == '':
                return

            # Perform variable substitution on constructued line
            logical_line = self._template_str(logical_line)

            # skip line if substitution has added a comment. FIPS mode
            # disables some lines that way.
            logical_line = logical_line.strip()
            if not logical_line or logical_line.startswith('#'):
                return

            items = logical_line.split(':', 2)

            if len(items) == 0:
                raise BadSyntax("Bad formatting on line %s:%d: %s" % (data_source_name, lcount, logical_line))

            action = items[0].strip().lower()

            if action not in self.action_keywords:
                raise BadSyntax("Unknown update action '%s', data source=%s" % (action, data_source_name))

            if action == 'deleteentry':
                new_value = None
                disposition = "deleteentry"
            else:
                if len(items) != 3:
                    raise BadSyntax("Bad formatting on line %s:%d: %s" % (data_source_name, lcount, logical_line))

                attr = items[1].strip()
                # do not strip here, we need detect '::' due to base64 encoded
                # values, strip may result into fake detection
                value = items[2]

                # detect base64 encoding
                # value which start with ':' are base64 encoded
                # decode it as a binary value
                if value.startswith(':'):
                    value = value[1:]
                    binary = True
                else:
                    binary = False
                value = value.strip()

                if action == 'replace':
                    try:
                        value = value.split('::', 1)
                    except ValueError:
                        raise BadSyntax(
                            "Bad syntax in replace on line %s:%d: %s, needs to "
                            "be in the format old::new in %s" % (
                                data_source_name, lcount, logical_line, value)
                        )
                else:
                    value = [value]

                if binary:
                    for i, v in enumerate(value):
                        try:
                            value[i] = base64.b64decode(v)
                        except (TypeError, ValueError) as e:
                            raise BadSyntax(
                                "Base64 encoded value %s on line %s:%d: %s is "
                                "incorrect (%s)" % (v, data_source_name,
                                                    lcount, logical_line, e)
                            )
                else:
                    for i, v in enumerate(value):
                        if isinstance(v, unicode):
                            value[i] = v.encode('utf-8')

                if action != 'replace':
                    value = value[0]

                if action == "default":
                    new_value = {'attr': attr, 'value': value}
                    disposition = "default"
                else:
                    new_value = {'action': action, "attr": attr,
                                 'value': value}
                    disposition = "updates"

            disposition_list = update.setdefault(disposition, [])
            disposition_list.append(new_value)

        def emit_update(update):
            '''
            When processing a dn is completed emit the update by appending it
            into list of all updates
            '''
            dn = update.get('dn')
            assert isinstance(dn, DN)
            all_updates.append(update)

        def emit_plugin_update(update):
            '''
            When processing a plugin is complete emit the plugin update by
            appending it into list of all updates
            '''
            all_updates.append(update)

        # Iterate over source input lines
        for source_line in source_data:
            lcount += 1

            # strip trailing whitespace and newline
            source_line = source_line.rstrip()

            # skip comments and empty lines
            if source_line.startswith('#') or source_line == '':
                continue

            state = None
            emit_previous_dn = False

            # parse special keywords
            if source_line.lower().startswith('dn:'):
                state = 'dn'
                emit_previous_dn = True
            elif source_line.lower().startswith('plugin:'):
                state = 'plugin'
                emit_previous_dn = True

            if emit_previous_dn and dn is not None:
                # Emit previous dn
                emit_item(logical_line)
                logical_line = ''
                emit_update(update)
                update = {}
                dn = None

            if state == 'dn':
                # Starting new dn
                dn = source_line[3:].strip()
                dn = DN(self._template_str(dn))
                update['dn'] = dn
            elif state == 'plugin':
                # plugin specification is online only
                plugin_name = source_line[7:].strip()
                if not plugin_name:
                    raise BadSyntax("plugin name is not defined")
                update['plugin'] = plugin_name
                emit_plugin_update(update)
                update = {}
            else:
                # Process items belonging to dn
                if dn is None:
                    raise BadSyntax("dn is not defined in the update, data source=%s" % (data_source_name))

                # If continuation line, append to existing logical line & continue,
                # otherwise flush the previous item.
                if source_line.startswith(' '):
                    logical_line += source_line[1:]
                    continue
                emit_item(logical_line)
                logical_line = source_line

        if dn is not None:
            emit_item(logical_line)
            logical_line = ''
            emit_update(update)
            update = {}

        return all_updates

    def create_index_task(self, *attributes):
        """Create a task to update an index for attributes"""
        cn_uuid = uuid.uuid1()
        # cn_uuid.time is in nanoseconds, but other users of LDAPUpdate expect
        # seconds in 'TIME' so scale the value down
        self.sub_dict['TIME'] = int(cn_uuid.time/1e9)
        cn = "indextask_%s_%s" % (cn_uuid.time, cn_uuid.clock_seq)
        dn = DN(('cn', cn), ('cn', 'index'), ('cn', 'tasks'), ('cn', 'config'))

        e = self.conn.make_entry(
            dn,
            objectClass=['top', 'extensibleObject'],
            cn=[cn],
            nsInstance=['userRoot'],
            nsIndexAttribute=list(attributes),
        )

        logger.debug(
            "Creating task %s to index attributes: %s",
            dn, ', '.join(attributes)
        )

        self.conn.add_entry(e)

        return dn

    def monitor_index_task(self, dn):
        """Give a task DN monitor it and wait until it has completed (or failed)
        """

        assert isinstance(dn, DN)

        # Pause for a moment to give the task time to be created
        time.sleep(1)

        attrlist = ['nstaskstatus', 'nstaskexitcode']
        entry = None

        while True:
            try:
                entry = self.conn.get_entry(dn, attrlist)
            except errors.NotFound:
                logger.error("Task not found: %s", dn)
                return
            except errors.DatabaseError as e:
                logger.error("Task lookup failure %s", e)
                return

            status = entry.single_value.get('nstaskstatus')
            if status is None:
                # task doesn't have a status yet
                time.sleep(1)
                continue

            if "finished" in status.lower():
                logger.debug("Indexing finished")
                break

            logger.debug("Indexing in progress")
            time.sleep(1)

        return

    def _create_default_entry(self, dn, default):
        """Create the default entry from the values provided.

           The return type is ipaldap.LDAPEntry
        """
        assert isinstance(dn, DN)
        entry = self.conn.make_entry(dn)

        if not default:
            # This means that the entire entry needs to be created with add
            return entry

        for item in default:
            # We already do syntax-parsing so this is safe
            attr = item['attr']
            value = item['value']

            e = entry.raw.get(attr)
            if e:
                # multi-valued attribute
                e = list(e)
                e.append(value)
            else:
                e = [value]

            entry.raw[attr] = e
        entry.reset_modlist()

        return entry

    def _get_entry(self, dn):
        """Retrieve an object from LDAP.

           The return type is ipaldap.LDAPEntry
        """
        assert isinstance(dn, DN)
        searchfilter="objectclass=*"
        sattrs = ["*", "aci", "attributeTypes", "objectClasses"]
        scope = self.conn.SCOPE_BASE

        return self.conn.get_entries(dn, scope, searchfilter, sattrs)

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
            action = update['action']
            attr = update['attr']
            update_value = update['value']

            # do not mix comparison of bytes and unicode, everything in this
            # function should be compared as bytes
            if isinstance(update_value, (list, tuple)):
                update_value = [
                    v.encode('utf-8') if isinstance(v, unicode) else v
                    for v in update_value
                ]
            elif isinstance(update_value, unicode):
                update_value = update_value.encode('utf-8')

            entry_values = entry.raw.get(attr, [])
            if action == 'remove':
                logger.debug("remove: '%s' from %s, current value %s",
                             safe_output(attr, update_value),
                             attr,
                             safe_output(attr, entry_values))
                try:
                    entry_values.remove(update_value)
                except ValueError:
                    logger.debug(
                        "remove: '%s' not in %s",
                        safe_output(attr, update_value), attr)
                else:
                    entry.raw[attr] = entry_values
                    logger.debug('remove: updated value %s', safe_output(
                        attr, entry_values))
            elif action == 'add':
                logger.debug("add: '%s' to %s, current value %s",
                             safe_output(attr, update_value),
                             attr,
                             safe_output(attr, entry_values))
                # Remove it, ignoring errors so we can blindly add it later
                try:
                    entry_values.remove(update_value)
                except ValueError:
                    pass
                entry_values.append(update_value)
                logger.debug('add: updated value %s',
                             safe_output(attr, entry_values))
                entry.raw[attr] = entry_values
            elif action == 'addifnew':
                logger.debug("addifnew: '%s' to %s, current value %s",
                             safe_output(attr, update_value),
                             attr,
                             safe_output(attr, entry_values))
                # Only add the attribute if it doesn't exist. Only works
                # with single-value attributes. Entry must exist.
                if entry.get('objectclass') and len(entry_values) == 0:
                    entry_values.append(update_value)
                    logger.debug('addifnew: set %s to %s',
                                 attr, safe_output(attr, entry_values))
                    entry.raw[attr] = entry_values
            elif action == 'addifexist':
                logger.debug("addifexist: '%s' to %s, current value %s",
                             safe_output(attr, update_value),
                             attr,
                             safe_output(attr, entry_values))
                # Only add the attribute if the entry doesn't exist. We
                # determine this based on whether it has an objectclass
                if entry.get('objectclass'):
                    entry_values.append(update_value)
                    logger.debug('addifexist: set %s to %s',
                                 attr, safe_output(attr, entry_values))
                    entry.raw[attr] = entry_values
            elif action == 'only':
                logger.debug("only: set %s to '%s', current value %s",
                             attr,
                             safe_output(attr, update_value),
                             safe_output(attr, entry_values))
                if only.get(attr):
                    entry_values.append(update_value)
                else:
                    entry_values = [update_value]
                    only[attr] = True
                entry.raw[attr] = entry_values
                logger.debug('only: updated value %s',
                             safe_output(attr, entry_values))
            elif action == 'onlyifexist':
                logger.debug("onlyifexist: '%s' to %s, current value %s",
                             safe_output(attr, update_value),
                             attr,
                             safe_output(attr, entry_values))
                # Only set the attribute if the entry exist's. We
                # determine this based on whether it has an objectclass
                if entry.get('objectclass'):
                    if only.get(attr):
                        entry_values.append(update_value)
                    else:
                        entry_values = [update_value]
                        only[attr] = True
                    logger.debug('onlyifexist: set %s to %s',
                                 attr, safe_output(attr, entry_values))
                    entry.raw[attr] = entry_values
            elif action == 'deleteentry':
                # skip this update type, it occurs in  __delete_entries()
                return None
            elif action == 'replace':
                # replace values were store as list
                old, new = update_value

                try:
                    entry_values.remove(old)
                except ValueError:
                    logger.debug('replace: %s not found, skipping',
                                 safe_output(attr, old))
                else:
                    entry_values.append(new)
                    logger.debug('replace: updated value %s',
                                 safe_output(attr, entry_values))
                    entry.raw[attr] = entry_values

        return entry

    def print_entity(self, e, message=None):
        """The entity object currently lacks a str() method"""
        logger.debug("---------------------------------------------")
        if message:
            logger.debug("%s", message)
        logger.debug("dn: %s", e.dn)
        for a, value in e.raw.items():
            logger.debug('%s:', a)
            for l in value:
                logger.debug("\t%s", safe_output(a, l))

    def _update_record(self, update):
        found = False

        new_entry = self._create_default_entry(update.get('dn'),
                                               update.get('default'))

        try:
            e = self._get_entry(new_entry.dn)
            if len(e) > 1:
                # we should only ever get back one entry
                raise BadSyntax("More than 1 entry returned on a dn search!? %s" % new_entry.dn)
            entry = e[0]
            found = True
            logger.debug("Updating existing entry: %s", entry.dn)
        except errors.NotFound:
            # Doesn't exist, start with the default entry
            entry = new_entry
            logger.debug("New entry: %s", entry.dn)
        except errors.DatabaseError:
            # Doesn't exist, start with the default entry
            entry = new_entry
            logger.debug("New entry, using default value: %s", entry.dn)

        self.print_entity(entry, "Initial value")

        # Bring this entry up to date
        entry = self._apply_update_disposition(update.get('updates'), entry)
        if entry is None:
            # It might be None if it is just deleting an entry
            return None, False

        self.print_entity(entry, "Final value after applying updates")

        added = False
        updated = False
        if not found:
            try:
                if len(entry):
                    # addifexist may result in an entry with only a
                    # dn defined. In that case there is nothing to do.
                    # It means the entry doesn't exist, so skip it.
                    try:
                        self.conn.add_entry(entry)
                    except errors.NotFound:
                        # parent entry of the added entry does not exist
                        # this may not be an error (e.g. entries in NIS container)
                        logger.error("Parent DN of %s may not exist, cannot "
                                     "create the entry", entry.dn)
                        return entry, False
                added = True
                self.modified = True
            except Exception as e:
                logger.error("Add failure %s", e)
        else:
            # Update LDAP
            try:
                changes = entry.generate_modlist()
                if len(changes) >= 1:
                    updated = True
                safe_changes = []
                for (type, attr, values) in changes:
                    safe_changes.append((type, attr, safe_output(attr, values)))
                logger.debug("%s", safe_changes)
                logger.debug("Updated %d", updated)
                if updated:
                    self.conn.update_entry(entry)
                logger.debug("Done")
            except errors.EmptyModlist:
                logger.debug("Entry already up-to-date")
                updated = False
            except errors.DatabaseError as e:
                logger.error("Update failed: %s", e)
                updated = False
            except errors.DuplicateEntry as e:
                logger.debug("Update already exists, skip it: %s", e)
                updated = False
            except errors.ACIError as e:
                logger.error("Update failed: %s", e)
                updated = False

            if updated:
                self.modified = True

        return entry, added or updated

    def _delete_record(self, updates):
        """
        Delete record
        """

        dn = updates['dn']
        try:
            logger.debug("Deleting entry %s", dn)
            self.conn.delete_entry(dn)
            self.modified = True
        except errors.NotFound as e:
            logger.debug("%s did not exist:%s", dn, e)
            self.modified = True
        except errors.DatabaseError as e:
            logger.error("Delete failed: %s", e)

    def get_all_files(self, root, recursive=False):
        """Get all update files"""
        f = []
        for path, _subdirs, files in os.walk(root):
            for name in files:
                if fnmatch.fnmatch(name, "*.update"):
                    f.append(os.path.join(path, name))
            if not recursive:
                break
        f.sort()
        return f

    def _run_update_plugin(self, plugin_name):
        logger.debug("Executing upgrade plugin: %s", plugin_name)
        restart_ds, updates = self.api.Updater[plugin_name]()
        if updates:
            self._run_updates(updates)
        # restart may be required even if no updates were returned
        # from plugin, plugin may change LDAP data directly
        if restart_ds:
            self.close_connection()
            self.restart_ds()
            self.create_connection()

    def create_connection(self):
        if self.conn is None:
            self.api.Backend.ldap2.connect(
                time_limit=UPDATE_SEARCH_TIME_LIMIT,
                size_limit=0)
            self.conn = self.api.Backend.ldap2

    def _run_updates(self, all_updates):
        index_attributes = set()
        update_ldapi_mappings = False
        for update in all_updates:
            if 'deleteentry' in update:
                self._delete_record(update)
            elif 'plugin' in update:
                self._run_update_plugin(update['plugin'])
            else:
                entry, modified = self._update_record(update)
                if modified:
                    if entry.dn.endswith(self.index_suffix):
                        index_attributes.add(entry.single_value['cn'])
                    if (
                        entry.dn.endswith(self.ldapi_autobind_suffix)
                        and "nsLDAPIFixedAuthMap" in entry.get(
                            "objectClass", ()
                        )
                    ):
                        update_ldapi_mappings = True

        if index_attributes:
            # The LDAPUpdate framework now keeps record of all changed/added
            # indices and batches all changed attribute in a single index
            # task. This makes updates much faster when multiple indices are
            # added or modified.
            task_dn = self.create_index_task(*sorted(index_attributes))
            self.monitor_index_task(task_dn)

        if update_ldapi_mappings:
            # update mappings when any autobind entry is added or modified
            run_ldapi_reload_task(self.conn)

    def update(self, files, ordered=True):
        """Execute the update. files is a list of the update files to use.
        :param ordered: Update files are executed in alphabetical order

        returns True if anything was changed, otherwise False
        """
        self.modified = False
        try:
            upgrade_files = files
            if ordered:
                upgrade_files = sorted(files)

            for f in upgrade_files:
                start = time.time()
                try:
                    logger.debug("Parsing update file '%s'", f)
                    data = self.read_file(f)
                except Exception as e:
                    logger.error("error reading update file '%s'", f)
                    raise RuntimeError(e)

                all_updates = []
                self.parse_update_file(f, data, all_updates)
                self._run_updates(all_updates)
                dur = time.time() - start
                logger.debug(
                    "LDAP update duration: %s %.03f sec", f, dur,
                    extra={'timing': ('ldapupdate', f, None, dur)}
                )
        finally:
            self.close_connection()

        return self.modified

    def close_connection(self):
        """Close ldap connection"""
        if self.conn:
            self.api.Backend.ldap2.disconnect()
            self.conn = None

    def restart_ds(self):
        logger.debug('Restarting directory server to apply updates')
        installutils.restart_dirsrv()
