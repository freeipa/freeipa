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

import sys
import os, socket
import tempfile
import time
import datetime
import traceback

from ipapython import sysrestore, ipautil, ipaldap
from ipapython.dn import DN
from ipapython.ipa_log_manager import *
from ipalib import api, errors, certstore
from ipaplatform import services
from ipaplatform.paths import paths


# The service name as stored in cn=masters,cn=ipa,cn=etc. In the tuple
# the first value is the *nix service name, the second the start order.
SERVICE_LIST = {
    'KDC': ('krb5kdc', 10),
    'KPASSWD': ('kadmin', 20),
    'DNS': ('named', 30),
    'MEMCACHE': ('ipa_memcached', 39),
    'HTTP': ('httpd', 40),
    'KEYS': ('ipa-custodia', 41),
    'CA': ('pki-tomcatd', 50),
    'KRA': ('pki-tomcatd', 51),
    'ADTRUST': ('smb', 60),
    'EXTID': ('winbind', 70),
    'OTPD': ('ipa-otpd', 80),
    'DNSKeyExporter': ('ipa-ods-exporter', 90),
    'DNSSEC': ('ods-enforcerd', 100),
    'DNSKeySync': ('ipa-dnskeysyncd', 110),
}

def print_msg(message, output_fd=sys.stdout):
    root_logger.debug(message)
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


def find_providing_server(svcname, conn, host_name=None, api=api):
    """
    :param svcname: The service to find
    :param conn: a connection to the LDAP server
    :param host_name: the preferred server
    :return: the selected host name

    Find a server that is a CA.
    """
    dn = DN(('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'), api.env.basedn)
    query_filter = conn.make_filter({'objectClass': 'ipaConfigObject',
                                     'ipaConfigString': 'enabledService',
                                     'cn': svcname}, rules='&')
    try:
        entries, trunc = conn.find_entries(filter=query_filter, base_dn=dn)
    except errors.NotFound:
        return None
    if len(entries):
        if host_name is not None:
            for entry in entries:
                if entry.dn[1].value == host_name:
                    return host_name
        # if the preferred is not found, return the first in the list
        return entries[0].dn[1].value
    return None


class Service(object):
    def __init__(self, service_name, service_desc=None, sstore=None,
                 dm_password=None, ldapi=True, autobind=ipaldap.AUTOBIND_AUTO,
                 start_tls=False):
        self.service_name = service_name
        self.service_desc = service_desc
        self.service = services.service(service_name)
        self.steps = []
        self.output_fd = sys.stdout
        self.dm_password = dm_password
        self.ldapi = ldapi
        self.autobind = autobind
        self.start_tls = start_tls

        self.fqdn = socket.gethostname()
        self.admin_conn = None

        if sstore:
            self.sstore = sstore
        else:
            self.sstore = sysrestore.StateFile(paths.SYSRESTORE)

        self.realm = None
        self.suffix = DN()
        self.principal = None
        self.dercert = None

    def ldap_connect(self):
        # If DM password is provided, we use it
        # If autobind was requested, attempt autobind when root and ldapi
        # If autobind was disabled or not succeeded, go with GSSAPI
        # LDAPI can be used with either autobind or GSSAPI
        # LDAPI requires realm to be set
        try:
            if self.ldapi:
                if not self.realm:
                    raise errors.NotFound(reason="realm is missing for %s" % (self))
                conn = ipaldap.IPAdmin(ldapi=self.ldapi, realm=self.realm)
            elif self.start_tls:
                conn = ipaldap.IPAdmin(self.fqdn, port=389, protocol='ldap',
                                       cacert=paths.IPA_CA_CRT,
                                       start_tls=self.start_tls)
            else:
                conn = ipaldap.IPAdmin(self.fqdn, port=389)

            conn.do_bind(self.dm_password, autobind=self.autobind)
        except Exception as e:
            root_logger.debug("Could not connect to the Directory Server on %s: %s" % (self.fqdn, str(e)))
            raise

        self.admin_conn = conn

    def ldap_disconnect(self):
        self.admin_conn.unbind()
        self.admin_conn = None

    def _ldap_mod(self, ldif, sub_dict=None, raise_on_err=False):
        pw_name = None
        fd = None
        path = ipautil.SHARE_DIR + ldif
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
        if not self.admin_conn:
            self.ldap_connect()
        args += ["-H", self.admin_conn.ldap_uri]

        # If DM password is available, use it
        if self.dm_password:
            [pw_fd, pw_name] = tempfile.mkstemp()
            os.write(pw_fd, self.dm_password)
            os.close(pw_fd)
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
                if raise_on_err:
                    raise
                root_logger.critical("Failed to load %s: %s" % (ldif, str(e)))
        finally:
            if pw_name:
                os.remove(pw_name)

        if fd is not None:
            fd.close()

    def move_service(self, principal):
        """
        Used to move a principal entry created by kadmin.local from
        cn=kerberos to cn=services
        """

        dn = DN(('krbprincipalname', principal), ('cn', self.realm), ('cn', 'kerberos'), self.suffix)
        try:
            entry = self.admin_conn.get_entry(dn)
        except errors.NotFound:
            # There is no service in the wrong location, nothing to do.
            # This can happen when installing a replica
            return None
        entry.pop('krbpwdpolicyreference', None)  # don't copy virtual attr
        newdn = DN(('krbprincipalname', principal), ('cn', 'services'), ('cn', 'accounts'), self.suffix)
        hostdn = DN(('fqdn', self.fqdn), ('cn', 'computers'), ('cn', 'accounts'), self.suffix)
        self.admin_conn.delete_entry(entry)
        entry.dn = newdn
        classes = entry.get("objectclass")
        classes = classes + ["ipaobject", "ipaservice", "pkiuser"]
        entry["objectclass"] = list(set(classes))
        entry["ipauniqueid"] = ['autogenerate']
        entry["managedby"] = [hostdn]
        self.admin_conn.add_entry(entry)
        return newdn

    def add_simple_service(self, principal):
        """
        Add a very basic IPA service.

        The principal needs to be fully-formed: service/host@REALM
        """
        if not self.admin_conn:
            self.ldap_connect()

        dn = DN(('krbprincipalname', principal), ('cn', 'services'), ('cn', 'accounts'), self.suffix)
        hostdn = DN(('fqdn', self.fqdn), ('cn', 'computers'), ('cn', 'accounts'), self.suffix)
        entry = self.admin_conn.make_entry(
            dn,
            objectclass=[
                "krbprincipal", "krbprincipalaux", "krbticketpolicyaux",
                "ipaobject", "ipaservice", "pkiuser"],
            krbprincipalname=[principal],
            ipauniqueid=['autogenerate'],
            managedby=[hostdn],
        )
        self.admin_conn.add_entry(entry)
        return dn

    def add_cert_to_service(self):
        """
        Add a certificate to a service

        This server cert should be in DER format.
        """

        # add_cert_to_service() is relatively rare operation
        # we actually call it twice during ipa-server-install, for different
        # instances: ds and cs. Unfortunately, it may happen that admin
        # connection was created well before add_cert_to_service() is called
        # If there are other operations in between, it will become stale and
        # since we are using SimpleLDAPObject, not ReconnectLDAPObject, the
        # action will fail. Thus, explicitly disconnect and connect again.
        # Using ReconnectLDAPObject instead of SimpleLDAPObject was considered
        # but consequences for other parts of the framework are largely
        # unknown.
        if self.admin_conn:
            self.ldap_disconnect()
        self.ldap_connect()

        dn = DN(('krbprincipalname', self.principal), ('cn', 'services'),
                ('cn', 'accounts'), self.suffix)
        entry = self.admin_conn.get_entry(dn)
        entry.setdefault('userCertificate', []).append(self.dercert)
        try:
            self.admin_conn.update_entry(entry)
        except Exception as e:
            root_logger.critical("Could not add certificate to service %s entry: %s" % (self.principal, str(e)))

    def import_ca_certs(self, db, ca_is_configured, conn=None):
        if conn is None:
            if not self.admin_conn:
                self.ldap_connect()
            conn = self.admin_conn

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

    def is_running(self):
        return self.service.is_running()

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
        show_service_name=True, runtime=-1):
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

        if runtime > 0:
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
            root_logger.debug("  duration: %d seconds" % d.seconds)

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
                root_logger.debug("%s" % traceback.format_exc())
                self.print_msg('  [error] %s: %s' % (type(e).__name__, e))

                # run through remaining methods marked run_after_failure
                for message, method, run_after_failure in steps_iter:
                    if run_after_failure:
                        run_step("  [cleanup]: %s" % message, method)

            raise

        self.print_msg(end_message)

        self.steps = []

    def ldap_enable(self, name, fqdn, dm_password, ldap_suffix, config=[]):
        assert isinstance(ldap_suffix, DN)
        self.disable()
        if not self.admin_conn:
            self.ldap_connect()

        entry_name = DN(('cn', name), ('cn', fqdn), ('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'), ldap_suffix)

        # enable disabled service
        try:
            entry = self.admin_conn.get_entry(entry_name, ['ipaConfigString'])
        except errors.NotFound:
            pass
        else:
            if any(u'enabledservice' == val.lower()
                   for val in entry.get('ipaConfigString', [])):
                root_logger.debug("service %s startup entry already enabled", name)
                return

            entry.setdefault('ipaConfigString', []).append(u'enabledService')

            try:
                self.admin_conn.update_entry(entry)
            except errors.EmptyModlist:
                root_logger.debug("service %s startup entry already enabled", name)
                return
            except:
                root_logger.debug("failed to enable service %s startup entry", name)
                raise

            root_logger.debug("service %s startup entry enabled", name)
            return

        order = SERVICE_LIST[name][1]
        entry = self.admin_conn.make_entry(
            entry_name,
            objectclass=["nsContainer", "ipaConfigObject"],
            cn=[name],
            ipaconfigstring=[
                "enabledService", "startOrder " + str(order)] + config,
        )

        try:
            self.admin_conn.add_entry(entry)
        except (errors.DuplicateEntry) as e:
            root_logger.debug("failed to add service %s startup entry", name)
            raise e

    def ldap_disable(self, name, fqdn, ldap_suffix):
        assert isinstance(ldap_suffix, DN)
        if not self.admin_conn:
            self.ldap_connect()

        entry_dn = DN(('cn', name), ('cn', fqdn), ('cn', 'masters'),
                        ('cn', 'ipa'), ('cn', 'etc'), ldap_suffix)
        search_kw = {'ipaConfigString': u'enabledService'}
        filter = self.admin_conn.make_filter(search_kw)
        try:
            entries, truncated = self.admin_conn.find_entries(
                filter=filter,
                attrs_list=['ipaConfigString'],
                base_dn=entry_dn,
                scope=self.admin_conn.SCOPE_BASE)
        except errors.NotFound:
            root_logger.debug("service %s startup entry already disabled", name)
            return

        assert len(entries) == 1  # only one entry is expected
        entry = entries[0]

        # case insensitive
        for value in entry.get('ipaConfigString', []):
            if value.lower() == u'enabledservice':
                entry['ipaConfigString'].remove(value)
                break

        try:
            self.admin_conn.update_entry(entry)
        except errors.EmptyModlist:
            pass
        except:
            root_logger.debug("failed to disable service %s startup entry", name)
            raise

        root_logger.debug("service %s startup entry disabled", name)

    def ldap_remove_service_container(self, name, fqdn, ldap_suffix):
        if not self.admin_conn:
            self.ldap_connect()

        entry_dn = DN(('cn', name), ('cn', fqdn), ('cn', 'masters'),
                        ('cn', 'ipa'), ('cn', 'etc'), ldap_suffix)
        try:
            self.admin_conn.delete_entry(entry_dn)
        except errors.NotFound:
            root_logger.debug("service %s container already removed", name)
        else:
            root_logger.debug("service %s container sucessfully removed", name)


class SimpleServiceInstance(Service):
    def create_instance(self, gensvc_name=None, fqdn=None, dm_password=None, ldap_suffix=None, realm=None):
        self.gensvc_name = gensvc_name
        self.fqdn = fqdn
        self.dm_password = dm_password
        self.suffix = ldap_suffix
        self.realm = realm
        if not realm:
            self.ldapi = False

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
            self.ldap_enable(self.gensvc_name, self.fqdn,
                             self.dm_password, self.suffix)

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring %s" % self.service_name)

        self.stop()
        self.disable()

        running = self.restore_state("running")
        enabled = self.restore_state("enabled")

        # restore the original state of service
        if running:
            self.start()
        if enabled:
            self.enable()
