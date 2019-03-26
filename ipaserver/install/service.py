# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#
# Copyright (C) 2007  Red Hat
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

from __future__ import absolute_import

import logging
import sys
import os
import pwd
import socket
import datetime
import traceback
import tempfile
import warnings

import six

from ipalib.install import certstore, sysrestore
from ipapython import ipautil
from ipapython.dn import DN
from ipapython import kerberos
from ipalib import api, errors
from ipaplatform import services
from ipaplatform.paths import paths
from ipaserver.masters import (
    CONFIGURED_SERVICE, ENABLED_SERVICE, HIDDEN_SERVICE, SERVICE_LIST
)
from ipaserver.servroles import HIDDEN

logger = logging.getLogger(__name__)

if six.PY3:
    unicode = str


def print_msg(message, output_fd=sys.stdout):
    logger.debug("%s", message)
    output_fd.write(message)
    output_fd.write("\n")
    output_fd.flush()


def format_seconds(seconds):
    """Format a number of seconds as an English minutes+seconds message"""
    parts = []
    minutes, seconds = divmod(seconds, 60)
    if minutes:
        parts.append('%d minute' % minutes)
        if minutes != 1:
            parts[-1] += 's'
    if seconds or not minutes:
        parts.append('%d second' % seconds)
        if seconds != 1:
            parts[-1] += 's'
    return ' '.join(parts)

def add_principals_to_group(admin_conn, group, member_attr, principals):
    """Add principals to a GroupOfNames LDAP group
    admin_conn  -- LDAP connection with admin rights
    group       -- DN of the group
    member_attr -- attribute to represent members
    principals  -- list of DNs to add as members
    """
    try:
        current = admin_conn.get_entry(group)
        members = current.get(member_attr, [])
        if len(members) == 0:
            current[member_attr] = []
        for amember in principals:
            if not(amember in members):
                current[member_attr].extend([amember])
        admin_conn.update_entry(current)
    except errors.NotFound:
        entry = admin_conn.make_entry(
                group,
                objectclass=["top", "GroupOfNames"],
                cn=[group['cn']],
                member=principals,
        )
        admin_conn.add_entry(entry)
    except errors.EmptyModlist:
        # If there are no changes just pass
        pass



def case_insensitive_attr_has_value(attr, value):
    """
    Helper function to find value in an attribute having case-insensitive
    matching rules

    :param attr: attribute values
    :param value: value to find

    :returns: True if the case-insensitive match succeeds, false otherwise

    """
    if any(value.lower() == val.lower()
           for val in attr):
        return True

    return False


def set_service_entry_config(name, fqdn, config_values,
                             ldap_suffix='',
                             post_add_config=()):
    """
    Sets the 'ipaConfigString' values on the entry. If the entry is not present
    already, create a new one with desired 'ipaConfigString'

    :param name: service entry name
    :param config_values: configuration values to store
    :param fqdn: master fqdn
    :param ldap_suffix: LDAP backend suffix
    :param post_add_config: additional configuration to add when adding a
        non-existent entry
    """
    assert isinstance(ldap_suffix, DN)

    entry_name = DN(
        ('cn', name), ('cn', fqdn), api.env.container_masters, ldap_suffix)

    # enable disabled service
    try:
        entry = api.Backend.ldap2.get_entry(
            entry_name, ['ipaConfigString'])
    except errors.NotFound:
        pass
    else:
        existing_values = entry.get('ipaConfigString', [])
        for value in config_values:
            if case_insensitive_attr_has_value(existing_values, value):
                logger.debug(
                    "service %s: config string %s already set", name, value)

            entry.setdefault('ipaConfigString', []).append(value)

        try:
            api.Backend.ldap2.update_entry(entry)
        except errors.EmptyModlist:
            logger.debug(
                "service %s has already enabled config values %s", name,
                config_values)
            return
        except:
            logger.debug("failed to set service %s config values", name)
            raise

        logger.debug("service %s has all config values set", name)
        return

    entry = api.Backend.ldap2.make_entry(
        entry_name,
        objectclass=["nsContainer", "ipaConfigObject"],
        cn=[name],
        ipaconfigstring=config_values + list(post_add_config),
    )

    try:
        api.Backend.ldap2.add_entry(entry)
    except (errors.DuplicateEntry) as e:
        logger.debug("failed to add service entry %s", name)
        raise e


def enable_services(fqdn):
    """Change all services to enabled state

    Server.ldap_configure() only marks a service as configured. Services
    are enabled at the very end of installation.

    Note: DNS records must be updated with dns_update_system_records, too.

    :param fqdn: hostname of server
    """
    _set_services_state(fqdn, ENABLED_SERVICE)


def hide_services(fqdn):
    """Change all services to hidden state

    Note: DNS records must be updated with dns_update_system_records, too.

    :param fqdn: hostname of server
    """
    _set_services_state(fqdn, HIDDEN_SERVICE)


def sync_services_state(fqdn):
    """Synchronize services state from IPA master role state

    Hide all services if the IPA master role state is in hidden state.
    Otherwise enable all services.

    :param fqdn: hostname of server
    """
    result = api.Command.server_role_find(
        server_server=fqdn,
        role_servrole='IPA master',
        status=HIDDEN
    )
    if result['count']:
        # one hidden server role
        hide_services(fqdn)
    else:
        # IPA master is either enabled or configured, enable all
        enable_services(fqdn)


def _set_services_state(fqdn, dest_state):
    """Change all services of a host

    :param fqdn: hostname of server
    :param dest_state: destination state
    """
    ldap2 = api.Backend.ldap2
    search_base = DN(('cn', fqdn), api.env.container_masters, api.env.basedn)

    source_states = {
        CONFIGURED_SERVICE.lower(),
        ENABLED_SERVICE.lower(),
        HIDDEN_SERVICE.lower()
    }
    source_states.remove(dest_state.lower())

    search_filter = ldap2.combine_filters(
        [
            ldap2.make_filter({'objectClass': 'ipaConfigObject'}),
            ldap2.make_filter(
                {'ipaConfigString': list(source_states)},
                rules=ldap2.MATCH_ANY
            ),
        ],
        rules=ldap2.MATCH_ALL
    )

    entries = ldap2.get_entries(
        search_base,
        filter=search_filter,
        scope=api.Backend.ldap2.SCOPE_ONELEVEL,
        attrs_list=['cn', 'ipaConfigString']
    )
    for entry in entries:
        name = entry['cn']
        cfgstrings = entry.setdefault('ipaConfigString', [])
        for value in list(cfgstrings):
            if value.lower() in source_states:
                cfgstrings.remove(value)
        if not case_insensitive_attr_has_value(cfgstrings, dest_state):
            cfgstrings.append(dest_state)

        try:
            ldap2.update_entry(entry)
        except errors.EmptyModlist:
            logger.debug("Nothing to do for service %s", name)
        except Exception:
            logger.exception("failed to set service %s config values", name)
            raise
        else:
            logger.debug(
                "Set service %s for %s to %s", name, fqdn, dest_state
            )


class Service(object):
    def __init__(self, service_name, service_desc=None, sstore=None,
                 fstore=None, api=api, realm_name=None,
                 service_user=None, service_prefix=None,
                 keytab=None):
        self.service_name = service_name
        self.service_desc = service_desc
        self.service = services.service(service_name, api)
        self.steps = []
        self.output_fd = sys.stdout

        self.fqdn = socket.gethostname()

        if sstore:
            self.sstore = sstore
        else:
            self.sstore = sysrestore.StateFile(paths.SYSRESTORE)

        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore(paths.SYSRESTORE)

        self.realm = realm_name
        self.suffix = DN()
        self.service_prefix = service_prefix
        self.keytab = keytab
        self.cert = None
        self.api = api
        self.service_user = service_user
        self.keytab_user = service_user
        self.dm_password = None  # silence pylint
        self.promote = False

    @property
    def principal(self):
        if any(attr is None for attr in (self.realm, self.fqdn,
                                         self.service_prefix)):
            return None

        return unicode(
            kerberos.Principal(
                (self.service_prefix, self.fqdn), realm=self.realm))

    def _ldap_mod(self, ldif, sub_dict=None, raise_on_err=True,
                  ldap_uri=None, dm_password=None):
        pw_name = None
        fd = None
        path = os.path.join(paths.USR_SHARE_IPA_DIR, ldif)
        nologlist = []

        if sub_dict is not None:
            txt = ipautil.template_file(path, sub_dict)
            fd = ipautil.write_tmp_file(txt)
            path = fd.name

            # do not log passwords
            if 'PASSWORD' in sub_dict:
                nologlist.append(sub_dict['PASSWORD'])
            if 'RANDOM_PASSWORD' in sub_dict:
                nologlist.append(sub_dict['RANDOM_PASSWORD'])

        args = [paths.LDAPMODIFY, "-v", "-f", path]

        # As we always connect to the local host,
        # use URI of admin connection
        if not ldap_uri:
            ldap_uri = api.Backend.ldap2.ldap_uri

        args += ["-H", ldap_uri]

        if dm_password:
            with tempfile.NamedTemporaryFile(
                    mode='w', delete=False) as pw_file:
                pw_file.write(dm_password)
                pw_name = pw_file.name
            auth_parms = ["-x", "-D", "cn=Directory Manager", "-y", pw_name]
        # Use GSSAPI auth when not using DM password or not being root
        elif os.getegid() != 0:
            auth_parms = ["-Y", "GSSAPI"]
        # Default to EXTERNAL auth mechanism
        else:
            auth_parms = ["-Y", "EXTERNAL"]

        args += auth_parms

        try:
            try:
                ipautil.run(args, nolog=nologlist)
            except ipautil.CalledProcessError as e:
                logger.critical("Failed to load %s: %s", ldif, str(e))
                if raise_on_err:
                    raise
        finally:
            if pw_name:
                os.remove(pw_name)

    def move_service(self, principal):
        """
        Used to move a principal entry created by kadmin.local from
        cn=kerberos to cn=services
        """

        dn = DN(('krbprincipalname', principal), ('cn', self.realm), ('cn', 'kerberos'), self.suffix)
        try:
            entry = api.Backend.ldap2.get_entry(dn)
        except errors.NotFound:
            # There is no service in the wrong location, nothing to do.
            # This can happen when installing a replica
            return None
        entry.pop('krbpwdpolicyreference', None)  # don't copy virtual attr
        newdn = DN(('krbprincipalname', principal), ('cn', 'services'), ('cn', 'accounts'), self.suffix)
        hostdn = DN(('fqdn', self.fqdn), ('cn', 'computers'), ('cn', 'accounts'), self.suffix)
        api.Backend.ldap2.delete_entry(entry)
        entry.dn = newdn
        classes = entry.get("objectclass")
        classes = classes + ["ipaobject", "ipaservice", "pkiuser"]
        entry["objectclass"] = list(set(classes))
        entry["ipauniqueid"] = ['autogenerate']
        entry["managedby"] = [hostdn]
        api.Backend.ldap2.add_entry(entry)
        return newdn

    def add_simple_service(self, principal):
        """
        Add a very basic IPA service.

        The principal needs to be fully-formed: service/host@REALM
        """
        dn = DN(('krbprincipalname', principal), ('cn', 'services'), ('cn', 'accounts'), self.suffix)
        hostdn = DN(('fqdn', self.fqdn), ('cn', 'computers'), ('cn', 'accounts'), self.suffix)
        entry = api.Backend.ldap2.make_entry(
            dn,
            objectclass=[
                "krbprincipal", "krbprincipalaux", "krbticketpolicyaux",
                "ipaobject", "ipaservice", "pkiuser"],
            krbprincipalname=[principal],
            ipauniqueid=['autogenerate'],
            managedby=[hostdn],
        )
        api.Backend.ldap2.add_entry(entry)
        return dn

    def add_cert_to_service(self):
        """
        Add a certificate to a service

        This server cert should be in DER format.
        """
        dn = DN(('krbprincipalname', self.principal), ('cn', 'services'),
                ('cn', 'accounts'), self.suffix)
        entry = api.Backend.ldap2.get_entry(dn)
        entry.setdefault('userCertificate', []).append(self.cert)
        try:
            api.Backend.ldap2.update_entry(entry)
        except Exception as e:
            logger.critical("Could not add certificate to service %s entry: "
                            "%s", self.principal, str(e))

    def import_ca_certs(self, db, ca_is_configured, conn=None):
        if conn is None:
            conn = api.Backend.ldap2

        try:
            ca_certs = certstore.get_ca_certs_nss(
                conn, self.suffix, self.realm, ca_is_configured)
        except errors.NotFound:
            pass
        else:
            for cert, nickname, trust_flags in ca_certs:
                db.add_cert(cert, nickname, trust_flags)

    def is_configured(self):
        return self.sstore.has_state(self.service_name)

    def set_output(self, fd):
        self.output_fd = fd

    def stop(self, instance_name="", capture_output=True):
        self.service.stop(instance_name, capture_output=capture_output)

    def start(self, instance_name="", capture_output=True, wait=True):
        self.service.start(instance_name, capture_output=capture_output, wait=wait)

    def restart(self, instance_name="", capture_output=True, wait=True):
        self.service.restart(instance_name, capture_output=capture_output, wait=wait)

    def is_running(self, instance_name="", wait=True):
        return self.service.is_running(instance_name, wait)

    def install(self):
        self.service.install()

    def remove(self):
        self.service.remove()

    def enable(self):
        self.service.enable()

    def disable(self):
        self.service.disable()

    def is_enabled(self):
        return self.service.is_enabled()

    def mask(self):
        return self.service.mask()

    def unmask(self):
        return self.service.unmask()

    def is_masked(self):
        return self.service.is_masked()

    def backup_state(self, key, value):
        self.sstore.backup_state(self.service_name, key, value)

    def restore_state(self, key):
        return self.sstore.restore_state(self.service_name, key)

    def get_state(self, key):
        return self.sstore.get_state(self.service_name, key)

    def print_msg(self, message):
        print_msg(message, self.output_fd)

    def step(self, message, method, run_after_failure=False):
        self.steps.append((message, method, run_after_failure))

    def start_creation(self, start_message=None, end_message=None,
                       show_service_name=True, runtime=None):
        """
        Starts creation of the service.

        Use start_message and end_message for explicit messages
        at the beggining / end of the process. Otherwise they are generated
        using the service description (or service name, if the description has
        not been provided).

        Use show_service_name to include service name in generated descriptions.
        """

        if start_message is None:
            # no other info than mandatory service_name provided, use that
            if self.service_desc is None:
                start_message = "Configuring %s" % self.service_name

            # description should be more accurate than service name
            else:
                start_message = "Configuring %s" % self.service_desc
                if show_service_name:
                    start_message = "%s (%s)" % (start_message, self.service_name)

        if end_message is None:
            if self.service_desc is None:
                if show_service_name:
                    end_message = "Done configuring %s." % self.service_name
                else:
                    end_message = "Done."
            else:
                if show_service_name:
                    end_message = "Done configuring %s (%s)." % (
                        self.service_desc, self.service_name)
                else:
                    end_message = "Done configuring %s." % self.service_desc

        if runtime is not None and runtime > 0:
            self.print_msg('%s. Estimated time: %s' % (start_message,
                                                      format_seconds(runtime)))
        else:
            self.print_msg(start_message)

        def run_step(message, method):
            self.print_msg(message)
            s = datetime.datetime.now()
            method()
            e = datetime.datetime.now()
            d = e - s
            logger.debug("  duration: %d seconds", d.seconds)

        step = 0
        steps_iter = iter(self.steps)
        try:
            for message, method, run_after_failure in steps_iter:
                full_msg = "  [%d/%d]: %s" % (step+1, len(self.steps), message)
                run_step(full_msg, method)
                step += 1
        except BaseException as e:
            if not (isinstance(e, SystemExit) and
                    e.code == 0):  # pylint: disable=no-member
                # show the traceback, so it's not lost if cleanup method fails
                logger.debug("%s", traceback.format_exc())
                self.print_msg('  [error] %s: %s' % (type(e).__name__, e))

                # run through remaining methods marked run_after_failure
                for message, method, run_after_failure in steps_iter:
                    if run_after_failure:
                        run_step("  [cleanup]: %s" % message, method)

            raise

        self.print_msg(end_message)

        self.steps = []

    def ldap_enable(self, name, fqdn, dm_password=None, ldap_suffix='',
                    config=()):
        """Legacy function, all services should use ldap_configure()
        """
        warnings.warn(
            "ldap_enable is deprecated, use ldap_configure instead.",
            DeprecationWarning,
            stacklevel=2
        )
        self._ldap_enable(ENABLED_SERVICE, name, fqdn, ldap_suffix, config)

    def ldap_configure(self, name, fqdn, dm_password=None, ldap_suffix='',
                       config=()):
        """Create or modify service entry in cn=masters,cn=ipa,cn=etc

        Contrary to ldap_enable(), the method only sets
        ipaConfigString=configuredService. ipaConfigString=enabledService
        is set at the very end of the installation process, to ensure that
        other machines see this master/replica after it is fully installed.

        To switch all configured services to enabled, use::

            ipaserver.install.service.enable_services(api.env.host)
            api.Command.dns_update_system_records()
        """
        self._ldap_enable(
            CONFIGURED_SERVICE, name, fqdn, ldap_suffix, config
        )

    def _ldap_enable(self, value, name, fqdn, ldap_suffix, config):
        extra_config_opts = [
            u'startOrder {}'.format(SERVICE_LIST[name].startorder),
        ]
        extra_config_opts.extend(config)

        self.disable()

        set_service_entry_config(
            name,
            fqdn,
            [value],
            ldap_suffix=ldap_suffix,
            post_add_config=extra_config_opts)

    def ldap_disable(self, name, fqdn, ldap_suffix):
        assert isinstance(ldap_suffix, DN)

        entry_dn = DN(('cn', name), ('cn', fqdn), api.env.container_masters,
                      ldap_suffix)
        search_kw = {'ipaConfigString': ENABLED_SERVICE}
        filter = api.Backend.ldap2.make_filter(search_kw)
        try:
            entries, _truncated = api.Backend.ldap2.find_entries(
                filter=filter,
                attrs_list=['ipaConfigString'],
                base_dn=entry_dn,
                scope=api.Backend.ldap2.SCOPE_BASE)
        except errors.NotFound:
            logger.debug("service %s startup entry already disabled", name)
            return

        assert len(entries) == 1  # only one entry is expected
        entry = entries[0]

        # case insensitive
        for value in entry.get('ipaConfigString', []):
            if value.lower() == ENABLED_SERVICE:
                entry['ipaConfigString'].remove(value)
                break

        try:
            api.Backend.ldap2.update_entry(entry)
        except errors.EmptyModlist:
            pass
        except:
            logger.debug("failed to disable service %s startup entry", name)
            raise

        logger.debug("service %s startup entry disabled", name)

    def ldap_remove_service_container(self, name, fqdn, ldap_suffix):
        entry_dn = DN(('cn', name), ('cn', fqdn),
                      self.api.env.container_masters, ldap_suffix)
        try:
            api.Backend.ldap2.delete_entry(entry_dn)
        except errors.NotFound:
            logger.debug("service %s container already removed", name)
        else:
            logger.debug("service %s container sucessfully removed", name)

    def _add_service_principal(self):
        try:
            self.api.Command.service_add(self.principal, force=True)
        except errors.DuplicateEntry:
            pass

    def clean_previous_keytab(self, keytab=None):
        if keytab is None:
            keytab = self.keytab

        self.fstore.backup_file(keytab)
        try:
            os.unlink(keytab)
        except OSError:
            pass

    def set_keytab_owner(self, keytab=None, owner=None):
        if keytab is None:
            keytab = self.keytab
        if owner is None:
            owner = self.service_user

        pent = pwd.getpwnam(owner)
        os.chown(keytab, pent.pw_uid, pent.pw_gid)

    def run_getkeytab(self, ldap_uri, keytab, principal, retrieve=False):
        """
        retrieve service keytab using ipa-getkeytab. This assumes that the
        service principal is already created in LDAP. By default GSSAPI
        authentication is used unless:
            * LDAPI socket is used and effective process UID is 0, then
              autobind is used by EXTERNAL SASL mech
            * self.dm_password is not none, then DM credentials are used to
              fetch keytab
        """
        args = [paths.IPA_GETKEYTAB,
                '-k', keytab,
                '-p', principal,
                '-H', ldap_uri]
        nolog = tuple()

        if ldap_uri.startswith("ldapi://") and os.geteuid() == 0:
            args.extend(["-Y", "EXTERNAL"])
        elif self.dm_password is not None and not self.promote:
            args.extend(
                ['-D', 'cn=Directory Manager',
                 '-w', self.dm_password])
            nolog += (self.dm_password,)

        if retrieve:
            args.extend(['-r'])

        ipautil.run(args, nolog=nolog)

    def request_service_keytab(self):
        if any(attr is None for attr in (self.principal, self.keytab)):
            raise NotImplementedError(
                "service must have defined principal "
                "name and keytab")

        self._add_service_principal()
        self.clean_previous_keytab()
        self.run_getkeytab(self.api.env.ldap_uri, self.keytab, self.principal)
        self.set_keytab_owner()


class SimpleServiceInstance(Service):
    def create_instance(self, gensvc_name=None, fqdn=None, ldap_suffix=None,
                        realm=None):
        self.gensvc_name = gensvc_name
        self.fqdn = fqdn
        self.suffix = ldap_suffix
        self.realm = realm

        self.step("starting %s " % self.service_name, self.__start)
        self.step("configuring %s to start on boot" % self.service_name, self.__enable)
        self.start_creation("Configuring %s" % self.service_name)

    suffix = ipautil.dn_attribute_property('_ldap_suffix')

    def __start(self):
        self.backup_state("running", self.is_running())
        self.restart()

    def __enable(self):
        self.backup_state("enabled", self.is_enabled())
        if self.gensvc_name == None:
            self.enable()
        else:
            self.ldap_configure(self.gensvc_name, self.fqdn, None, self.suffix)

    def is_installed(self):
        return self.service.is_installed()

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring %s" % self.service_name)

        running = self.restore_state("running")
        enabled = self.restore_state("enabled")

        if self.is_installed():
            self.stop()
            self.disable()

            if running:
                self.start()
            if enabled:
                self.enable()
