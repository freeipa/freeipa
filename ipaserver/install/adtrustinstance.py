# Authors: Sumit Bose <sbose@redhat.com>
#
# Copyright (C) 2011  Red Hat
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

from __future__ import print_function, absolute_import

import logging
import os
import errno
import ldap
import tempfile
import uuid
import string
import struct
import re
import socket

import six

from ipaserver.dns_data_management import IPASystemRecords
from ipaserver.install import service
from ipaserver.install import installutils
from ipaserver.install.bindinstance import dns_zone_exists
from ipaserver.install.replication import wait_for_task
from ipalib import errors, api
from ipalib.util import normalize_zone
from ipapython.dn import DN
from ipapython import ipautil
import ipapython.errors

import ipaclient.install.ipachangeconf
from ipaplatform import services
from ipaplatform.constants import constants
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks

if six.PY3:
    unicode = str

logger = logging.getLogger(__name__)

ALLOWED_NETBIOS_CHARS = string.ascii_uppercase + string.digits + '-'

UPGRADE_ERROR = """
Entry %(dn)s does not exist.
This means upgrade from IPA 2.x to 3.x did not went well and required S4U2Proxy
configuration was not set up properly. Please run ipa-ldap-updater manually
and re-run ipa-adtrust-instal again afterwards.
"""


def check_inst():
    for smbfile in [paths.SMBD, paths.NET]:
        if not os.path.exists(smbfile):
            print("%s was not found on this system" % smbfile)
            print("Please install the 'samba' packages and " \
                  "start the installation again")
            return False

    # Check that ipa-server-trust-ad package is installed,
    # by looking for the file /usr/share/ipa/smb.conf.empty
    if not os.path.exists(os.path.join(paths.USR_SHARE_IPA_DIR,
                                       "smb.conf.empty")):
        print("AD Trust requires the '%s' package" %
              constants.IPA_ADTRUST_PACKAGE_NAME)
        print("Please install the package and start the installation again")
        return False

    #TODO: Add check for needed samba4 libraries

    return True

def ipa_smb_conf_exists():
    try:
        conf_fd = open(paths.SMB_CONF, 'r')
    except IOError as err:
        if err.errno == errno.ENOENT:
            return False
        else:
            raise

    lines = conf_fd.readlines()
    conf_fd.close()
    for line in lines:
        if line.startswith('### Added by IPA Installer ###'):
            return True
    return False


def check_netbios_name(name):
    # Empty NetBIOS name is not allowed
    if not name:
        return False

    # NetBIOS names may not be longer than 15 allowed characters
    invalid_netbios_name = any([
        len(name) > 15,
        ''.join([c for c in name if c not in ALLOWED_NETBIOS_CHARS])
    ])

    return not invalid_netbios_name


def make_netbios_name(s):
    return ''.join([c for c in s.split('.')[0].upper() \
                    if c in ALLOWED_NETBIOS_CHARS])[:15]


def map_Guests_to_nobody():
    env = {'LC_ALL': 'C'}
    args = [paths.NET, '-s', '/dev/null', 'groupmap', 'add',
            'sid=S-1-5-32-546', 'unixgroup=nobody', 'type=builtin']

    logger.debug("Map BUILTIN\\Guests to a group 'nobody'")
    ipautil.run(args, env=env, raiseonerr=False, capture_error=True)

class ADTRUSTInstance(service.Service):

    ATTR_SID = "ipaNTSecurityIdentifier"
    ATTR_FLAT_NAME = "ipaNTFlatName"
    ATTR_GUID = "ipaNTDomainGUID"
    ATTR_FALLBACK_GROUP = "ipaNTFallbackPrimaryGroup"
    OBJC_USER = "ipaNTUserAttrs"
    OBJC_GROUP = "ipaNTGroupAttrs"
    OBJC_DOMAIN = "ipaNTDomainAttrs"
    FALLBACK_GROUP_NAME = u'Default SMB Group'

    def __init__(self, fstore=None):
        self.netbios_name = None
        self.reset_netbios_name = None
        self.add_sids = None
        self.smbd_user = None
        self.smb_dn_pwd = None
        self.trust_dn = None
        self.smb_dom_dn = None
        self.sub_dict = None
        self.rid_base = None
        self.secondary_rid_base = None

        self.fqdn = None
        self.host_netbios_name = None

        super(ADTRUSTInstance, self).__init__(
            "smb", service_desc="CIFS", fstore=fstore, service_prefix=u'cifs',
            keytab=paths.SAMBA_KEYTAB)

        self.__setup_default_attributes()

    def __setup_default_attributes(self):
        """
        This method setups default attributes that are either constants, or
        based on api.env attributes, such as realm, hostname or domain name.
        """

        # Constants
        self.smb_conf = paths.SMB_CONF
        self.cifs_hosts = []

        # Values obtained from API.env
        self.fqdn = self.fqdn or api.env.host
        self.host_netbios_name = make_netbios_name(self.fqdn)
        self.realm = self.realm or api.env.realm

        self.suffix = ipautil.realm_to_suffix(self.realm)
        self.ldapi_socket = "%%2fvar%%2frun%%2fslapd-%s.socket" % \
                            installutils.realm_to_serverid(self.realm)

        # DN definitions
        self.trust_dn = DN(api.env.container_trusts, self.suffix)

        self.smb_dn = DN(('cn', 'adtrust agents'),
                         ('cn', 'sysaccounts'),
                         ('cn', 'etc'),
                         self.suffix)

        self.smb_dom_dn = DN(('cn', api.env.domain),
                             api.env.container_cifsdomains,
                             self.suffix)

        self.cifs_agent = DN(('krbprincipalname', self.principal.lower()),
                             api.env.container_service,
                             self.suffix)
        self.host_princ = DN(('fqdn', self.fqdn),
                             api.env.container_host,
                             self.suffix)


    def __gen_sid_string(self):
        sub_ids = struct.unpack("<LLL", os.urandom(12))
        return "S-1-5-21-%d-%d-%d" % (sub_ids[0], sub_ids[1], sub_ids[2])

    def __add_admin_sids(self):
        """
        The IPA admin and the IPA admins group with get the well knows SIDs
        used by AD for the administrator and the administrator group.

        By default new users belong only to a user private group (UPG) and no
        other Posix group since ipausers is not a Posix group anymore. To be
        able to add a RID to the primary RID attribute in a PAC a fallback
        group is added.
        """

        admin_dn = DN(('uid', 'admin'), api.env.container_user,
                      self.suffix)
        admin_group_dn = DN(('cn', 'admins'), api.env.container_group,
                            self.suffix)
        try:
            dom_entry = api.Backend.ldap2.get_entry(self.smb_dom_dn)
        except errors.NotFound:
            self.print_msg("Samba domain object not found")
            return

        dom_sid = dom_entry.single_value.get(self.ATTR_SID)
        if not dom_sid:
            self.print_msg("Samba domain object does not have a SID")
            return

        try:
            admin_entry = api.Backend.ldap2.get_entry(admin_dn)
        except errors.NotFound:
            self.print_msg("IPA admin object not found")
            return

        try:
            admin_group_entry = api.Backend.ldap2.get_entry(admin_group_dn)
        except errors.NotFound:
            self.print_msg("IPA admin group object not found")
            return

        if admin_entry.single_value.get(self.ATTR_SID):
            self.print_msg("Admin SID already set, nothing to do")
        else:
            try:
                api.Backend.ldap2.modify_s(
                    admin_dn,
                    [(ldap.MOD_ADD, "objectclass", self.OBJC_USER),
                     (ldap.MOD_ADD, self.ATTR_SID, dom_sid + "-500")])
            except Exception:
                self.print_msg("Failed to modify IPA admin object")

        if admin_group_entry.single_value.get(self.ATTR_SID):
            self.print_msg("Admin group SID already set, nothing to do")
        else:
            try:
                api.Backend.ldap2.modify_s(
                    admin_group_dn,
                    [(ldap.MOD_ADD, "objectclass", self.OBJC_GROUP),
                     (ldap.MOD_ADD, self.ATTR_SID, dom_sid + "-512")])
            except Exception:
                self.print_msg("Failed to modify IPA admin group object")

    def __add_default_trust_view(self):
        default_view_dn = DN(('cn', 'Default Trust View'),
                             api.env.container_views, self.suffix)

        try:
            api.Backend.ldap2.get_entry(default_view_dn)
        except errors.NotFound:
            try:
                self._ldap_mod('default-trust-view.ldif', self.sub_dict)
            except Exception as e:
                self.print_msg("Failed to add default trust view.")
                raise e
        else:
            self.print_msg("Default Trust View already exists.")

        # _ldap_mod does not return useful error codes, so we must check again
        # if the default trust view was created properly.
        try:
            api.Backend.ldap2.get_entry(default_view_dn)
        except errors.NotFound:
            self.print_msg("Failed to add Default Trust View.")

    def __add_fallback_group(self):
        """
        By default new users belong only to a user private group (UPG) and no
        other Posix group since ipausers is not a Posix group anymore. To be
        able to add a RID to the primary RID attribute in a PAC a fallback
        group is added.

        Since this method must be run after a restart of the directory server
        to enable the sidgen plugin we have to reconnect to the directory
        server.
        """
        try:
            dom_entry = api.Backend.ldap2.get_entry(self.smb_dom_dn)
        except errors.NotFound:
            self.print_msg("Samba domain object not found")
            return

        if dom_entry.single_value.get(self.ATTR_FALLBACK_GROUP):
            self.print_msg("Fallback group already set, nothing to do")
            return

        fb_group_dn = DN(('cn', self.FALLBACK_GROUP_NAME),
                         api.env.container_group, self.suffix)
        try:
            api.Backend.ldap2.get_entry(fb_group_dn)
        except errors.NotFound:
            try:
                self._ldap_mod('default-smb-group.ldif', self.sub_dict)
            except Exception as e:
                self.print_msg("Failed to add fallback group.")
                raise e

        # _ldap_mod does not return useful error codes, so we must check again
        # if the fallback group was created properly.
        try:
            api.Backend.ldap2.get_entry(fb_group_dn)
        except errors.NotFound:
            self.print_msg("Failed to add fallback group.")
            return

        try:
            mod = [(ldap.MOD_ADD, self.ATTR_FALLBACK_GROUP, fb_group_dn)]
            api.Backend.ldap2.modify_s(self.smb_dom_dn, mod)
        except Exception:
            self.print_msg("Failed to add fallback group to domain object")

    def __add_rid_bases(self):
        """
        Add RID bases to the range object for the local ID range.

        TODO: handle missing or multiple ranges more gracefully.
        """

        try:
            # Get the ranges
            ranges = api.Backend.ldap2.get_entries(
                DN(api.env.container_ranges, self.suffix),
                ldap.SCOPE_ONELEVEL, "(objectclass=ipaDomainIDRange)")

            # Filter out ranges where RID base is already set
            no_rid_base_set = lambda r: not any((
                                  r.single_value.get('ipaBaseRID'),
                                  r.single_value.get('ipaSecondaryBaseRID')))

            ranges_with_no_rid_base = [r for r in ranges if no_rid_base_set(r)]

            # Return if no range is without RID base
            if len(ranges_with_no_rid_base) == 0:
                self.print_msg("RID bases already set, nothing to do")
                return

            # Abort if RID base needs to be added to more than one range
            if len(ranges_with_no_rid_base) != 1:
                logger.critical("Found more than one local domain ID "
                                "range with no RID base set.")
                raise RuntimeError("Too many ID ranges\n")

            # Abort if RID bases are too close
            local_range = ranges_with_no_rid_base[0]
            try:
                size = int(local_range.single_value.get('ipaIDRangeSize'))
            except ValueError:
                raise RuntimeError('ipaIDRangeSize is set to a non-integer '
                                   'value or is not set at all (got {val})'
                                   .format(val=size))

            if abs(self.rid_base - self.secondary_rid_base) < size:
                self.print_msg("Primary and secondary RID base are too close. "
                               "They have to differ at least by %d." % size)
                raise RuntimeError("RID bases too close.\n")

            # Modify the range
            # If the RID bases would cause overlap with some other range,
            # this will be detected by ipa-range-check DS plugin
            try:
                api.Backend.ldap2.modify_s(local_range.dn,
                                         [(ldap.MOD_ADD, "ipaBaseRID",
                                                 str(self.rid_base)),
                                         (ldap.MOD_ADD, "ipaSecondaryBaseRID",
                                                 str(self.secondary_rid_base))])
            except ldap.CONSTRAINT_VIOLATION as e:
                self.print_msg("Failed to add RID bases to the local range "
                               "object:\n  %s" % e[0]['info'])
                raise RuntimeError("Constraint violation.\n")

        except errors.NotFound as e:
            logger.critical("ID range of the local domain not found, "
                            "define it and run again.")
            raise e

    def __reset_netbios_name(self):
        """
        Set the NetBIOS domain name to a new value.
        """
        self.print_msg("Reset NetBIOS domain name")

        try:
            api.Backend.ldap2.modify_s(self.smb_dom_dn,
                                     [(ldap.MOD_REPLACE, self.ATTR_FLAT_NAME,
                                       self.netbios_name)])
        except ldap.LDAPError:
            self.print_msg("Failed to reset the NetBIOS domain name")

    def __create_samba_domain_object(self):

        try:
            api.Backend.ldap2.get_entry(self.smb_dom_dn)
            if self.reset_netbios_name:
                self.__reset_netbios_name()
            else :
                self.print_msg("Samba domain object already exists")
            return
        except errors.NotFound:
            pass

        for new_dn in (self.trust_dn, \
                       DN(('cn', 'ad'), self.trust_dn), \
                       DN(api.env.container_cifsdomains, self.suffix)):
            try:
                api.Backend.ldap2.get_entry(new_dn)
            except errors.NotFound:
                try:
                    name = new_dn[1].attr
                except Exception as e:
                    self.print_msg('Cannot extract RDN attribute value from "%s": %s' % \
                          (new_dn, e))
                    return
                entry = api.Backend.ldap2.make_entry(
                    new_dn, objectclass=['nsContainer'], cn=[name])
                api.Backend.ldap2.add_entry(entry)

        entry = api.Backend.ldap2.make_entry(
            self.smb_dom_dn,
            {
                'objectclass': [self.OBJC_DOMAIN, "nsContainer"],
                'cn': [api.env.domain],
                self.ATTR_FLAT_NAME: [self.netbios_name],
                self.ATTR_SID: [self.__gen_sid_string()],
                self.ATTR_GUID: [str(uuid.uuid4())],
            }
        )
        #TODO: which MAY attributes do we want to set ?
        api.Backend.ldap2.add_entry(entry)

    def __write_smb_conf(self):
        conf_fd = open(self.smb_conf, "w")
        conf_fd.write('### Added by IPA Installer ###\n')
        conf_fd.write('[global]\n')
        conf_fd.write('debug pid = yes\n')
        conf_fd.write('config backend = registry\n')
        conf_fd.close()

    def __add_plugin_conf(self, name, plugin_cn, ldif_file):
        """
        Add directory server plugin configuration if it not already
        exists.
        """
        try:
            plugin_dn = DN(('cn', plugin_cn), ('cn', 'plugins'),
                           ('cn', 'config'))
            api.Backend.ldap2.get_entry(plugin_dn)
            self.print_msg('%s plugin already configured, nothing to do' % name)
        except errors.NotFound:
            try:
                self._ldap_mod(ldif_file, self.sub_dict)
            except Exception:
                pass

    def __add_cldap_module(self):
        """
        Add cldap directory server plugin configuration if it not already
        exists.
        """
        self.__add_plugin_conf('CLDAP', 'ipa_cldap', 'ipa-cldap-conf.ldif')

    def __add_sidgen_task(self):
        """
        Add sidgen directory server plugin configuration and the related task
        if they not already exist.
        """
        self.__add_plugin_conf('Sidgen task', 'ipa-sidgen-task',
                               'ipa-sidgen-task-conf.ldif')

    def __add_sids(self):
        """
        Add SIDs for existing users and groups. Make sure the task is finished
        before continuing.
        """

        try:
            # Start the sidgen task
            self._ldap_mod("ipa-sidgen-task-run.ldif", self.sub_dict)

            # Notify the user about the possible delay
            self.print_msg("This step may take considerable amount of time, please wait..")

            # Wait for the task to complete
            task_dn = DN('cn=sidgen,cn=ipa-sidgen-task,cn=tasks,cn=config')
            wait_for_task(api.Backend.ldap2, task_dn)

        except Exception as e:
            logger.warning("Exception occured during SID generation: %s",
                           str(e))

    def __add_s4u2proxy_target(self):
        """
        Add CIFS principal to S4U2Proxy target
        """

        targets_dn = DN(('cn', 'ipa-cifs-delegation-targets'), ('cn', 's4u2proxy'),
                        ('cn', 'etc'), self.suffix)
        try:
            current = api.Backend.ldap2.get_entry(targets_dn)
            members = current.get('memberPrincipal', [])
            if not(self.principal in members):
                current["memberPrincipal"] = members + [self.principal]
                api.Backend.ldap2.update_entry(current)
            else:
                self.print_msg('cifs principal already targeted, nothing to do.')
        except errors.NotFound:
            self.print_msg(UPGRADE_ERROR % dict(dn=targets_dn))

    def __write_smb_registry(self):
        # Workaround for: https://fedorahosted.org/freeipa/ticket/5687
        # We make sure that paths.SMB_CONF file exists, hence touch it
        with open(paths.SMB_CONF, 'a'):
            os.utime(paths.SMB_CONF, None)

        template = os.path.join(paths.USR_SHARE_IPA_DIR, "smb.conf.template")
        conf = ipautil.template_file(template, self.sub_dict)
        with tempfile.NamedTemporaryFile(mode='w') as tmp_conf:
            tmp_conf.write(conf)
            tmp_conf.flush()
            ipautil.run([paths.NET, "conf", "import", tmp_conf.name])

    def __map_Guests_to_nobody(self):
        map_Guests_to_nobody()

    def __setup_group_membership(self):
        # Add the CIFS and host principals to the 'adtrust agents' group
        # as 389-ds only operates with GroupOfNames, we have to use
        # the principal's proper dn as defined in self.cifs_agent
        service.add_principals_to_group(
            api.Backend.ldap2, self.smb_dn, "member",
            [self.cifs_agent, self.host_princ])

    def clean_previous_keytab(self, keytab=None):
        """
        Purge old CIFS keys from samba and clean up samba ccache
        """
        self.clean_samba_keytab()
        installutils.remove_ccache(paths.KRB5CC_SAMBA)

    def set_keytab_owner(self, keytab=None, owner=None):
        """
        Do not re-set ownership of samba keytab
        """

    def clean_samba_keytab(self):
        if os.path.exists(self.keytab):
            try:
                ipautil.run([
                    paths.IPA_RMKEYTAB, "--principal", self.principal,
                    "-k", self.keytab
                ])
            except ipautil.CalledProcessError as e:
                if e.returncode != 5:
                    logger.critical("Failed to remove old key for %s",
                                    self.principal)

    def srv_rec(self, host, port, prio):
        return "%(prio)d 100 %(port)d %(host)s" % dict(host=host,prio=prio,port=port)

    def __add_dns_service_records(self):
        """
        Add DNS service records for Windows if DNS is enabled and the DNS zone
        is managed. If there are already service records for LDAP and Kerberos
        their values are used. Otherwise default values are used.
        """

        zone = api.env.domain

        err_msg = None

        ret = api.Command['dns_is_enabled']()
        if not ret['result']:
            err_msg = "DNS management was not enabled at install time."
        else:
            if not dns_zone_exists(zone):
                err_msg = (
                    "DNS zone %s cannot be managed as it is not defined in "
                    "IPA" % zone)

        if err_msg:
            self.print_msg(err_msg)
            self.print_msg("Add the following service records to your DNS " \
                           "server for DNS zone %s: " % zone)
            system_records = IPASystemRecords(api, all_servers=True)
            adtrust_records = system_records.get_base_records(
                [self.fqdn], ["AD trust controller"],
                include_master_role=False, include_kerberos_realm=False)
            for r_name, node in adtrust_records.items():
                for rec in IPASystemRecords.records_list_from_node(r_name, node):
                    self.print_msg(rec)
        else:
            api.Command.dns_update_system_records()

    def __configure_selinux_for_smbd(self):
        try:
            tasks.set_selinux_booleans(constants.SELINUX_BOOLEAN_ADTRUST,
                                       self.backup_state)
        except ipapython.errors.SetseboolError as e:
            self.print_msg(e.format_service_warning('adtrust service'))

    def __mod_krb5_conf(self):
        """
        Set dns_lookup_kdc to true and master_kdc in /etc/krb5.conf
        """

        if not self.fqdn or not self.realm:
            self.print_msg("Cannot modify /etc/krb5.conf")

        krbconf = (
            ipaclient.install.ipachangeconf.IPAChangeConf("IPA Installer"))
        krbconf.setOptionAssignment((" = ", " "))
        krbconf.setSectionNameDelimiters(("[", "]"))
        krbconf.setSubSectionDelimiters(("{", "}"))
        krbconf.setIndent(("", "  ", "    "))

        libopts = [{'name':'dns_lookup_kdc', 'type':'option', 'action':'set',
                    'value':'true'}]

        master_kdc = self.fqdn + ":88"
        kropts = [{'name':'master_kdc', 'type':'option', 'action':'set',
                   'value':master_kdc}]

        ropts = [{'name':self.realm, 'type':'subsection', 'action':'set',
                  'value':kropts}]

        opts = [{'name':'libdefaults', 'type':'section', 'action':'set',
                 'value':libopts},
                {'name':'realms', 'type':'section', 'action':'set',
                 'value':ropts}]

        krbconf.changeConf(paths.KRB5_CONF, opts)

    def __update_krb5_conf(self):
        """
        Update /etc/krb5.conf if needed
        """

        try:
            krb5conf = open(paths.KRB5_CONF, 'r')
        except IOError as e:
            self.print_msg("Cannot open /etc/krb5.conf (%s)\n" % str(e))
            return

        has_dns_lookup_kdc_true = False
        for line in krb5conf:
            if re.match("^\s*dns_lookup_kdc\s*=\s*[Tt][Rr][Uu][Ee]\s*$", line):
                has_dns_lookup_kdc_true = True
                break
        krb5conf.close()

        if not has_dns_lookup_kdc_true:
            self.__mod_krb5_conf()
        else:
            self.print_msg("'dns_lookup_kdc' already set to 'true', "
                           "nothing to do.")

    def __check_replica(self):
        try:
            cifs_services = DN(api.env.container_service, self.suffix)
            # Search for cifs services which also belong to adtrust agents, these are our DCs
            res = api.Backend.ldap2.get_entries(cifs_services,
                ldap.SCOPE_ONELEVEL,
                "(&(krbprincipalname=cifs/*@%s)(memberof=%s))" % (self.realm, str(self.smb_dn)))
            if len(res) > 1:
                # there are other CIFS services defined, we are not alone
                for entry in res:
                    managedBy = entry.single_value.get('managedBy')
                    if managedBy:
                        fqdn = DN(managedBy)['fqdn']
                        if fqdn != unicode(self.fqdn):
                            # this is CIFS service of a different host in our
                            # REALM, we need to remember it to announce via
                            # SRV records for _msdcs
                            self.cifs_hosts.append(normalize_zone(fqdn))

        except Exception as e:
            logger.critical("Checking replicas for cifs principals failed "
                            "with error '%s'", e)

    def __enable_compat_tree(self):
        try:
            compat_plugin_dn = DN("cn=Schema Compatibility,cn=plugins,cn=config")
            lookup_nsswitch_name = "schema-compat-lookup-nsswitch"
            for config in (("cn=users", "user"), ("cn=groups", "group")):
                entry_dn = DN(config[0], compat_plugin_dn)
                current = api.Backend.ldap2.get_entry(entry_dn)
                lookup_nsswitch = current.get(lookup_nsswitch_name, [])
                if not(config[1] in lookup_nsswitch):
                    current[lookup_nsswitch_name] = [config[1]]
                    api.Backend.ldap2.update_entry(current)
        except Exception as e:
            logger.critical("Enabling nsswitch support in slapi-nis failed "
                            "with error '%s'", e)

    def __validate_server_hostname(self):
        hostname = socket.gethostname()
        if hostname != self.fqdn:
            raise ValueError("Host reports different name than configured: "
                             "'%s' versus '%s'. Samba requires to have "
                             "the same hostname or Kerberos principal "
                             "'cifs/%s' will not be found in Samba keytab." %
                             (hostname, self.fqdn, self.fqdn))

    def __start(self):
        try:
            self.start()
            services.service('winbind', api).start()
        except Exception:
            logger.critical("CIFS services failed to start")

    def __stop(self):
        self.backup_state("running", self.is_running())
        try:
            services.service('winbind', api).stop()
            self.stop()
        except Exception:
            pass

    def __restart_dirsrv(self):
        try:
            installutils.restart_dirsrv()
        except Exception:
            pass

    def __restart_smb(self):
        try:
            services.knownservices.smb.restart()
        except Exception:
            pass

    def __enable(self):
        self.backup_state("enabled", self.is_enabled())
        # We do not let the system start IPA components on its own,
        # Instead we reply on the IPA init script to start only enabled
        # components as found in our LDAP configuration tree
        # Note that self.dm_password is None for ADTrustInstance because
        # we ensure to be called as root and using ldapi to use autobind
        try:
            self.ldap_configure('ADTRUST', self.fqdn, None, self.suffix)
        except (ldap.ALREADY_EXISTS, errors.DuplicateEntry):
            logger.info("ADTRUST Service startup entry already exists.")

        try:
            self.ldap_configure('EXTID', self.fqdn, None, self.suffix)
        except (ldap.ALREADY_EXISTS, errors.DuplicateEntry):
            logger.info("EXTID Service startup entry already exists.")

    def __setup_sub_dict(self):
        self.sub_dict = dict(REALM = self.realm,
                             SUFFIX = self.suffix,
                             NETBIOS_NAME = self.netbios_name,
                             HOST_NETBIOS_NAME = self.host_netbios_name,
                             SMB_DN = self.smb_dn,
                             LDAPI_SOCKET = self.ldapi_socket,
                             FQDN = self.fqdn)

    def setup(self, fqdn, realm_name, netbios_name,
              reset_netbios_name, rid_base, secondary_rid_base,
              add_sids=False, smbd_user="samba",
              enable_compat=False):
        self.fqdn = fqdn
        self.realm = realm_name
        self.netbios_name = netbios_name
        self.reset_netbios_name = reset_netbios_name
        self.rid_base = rid_base
        self.secondary_rid_base = secondary_rid_base
        self.add_sids = add_sids
        self.enable_compat = enable_compat
        self.smbd_user = smbd_user

        # Setup constants and attributes derived from the values above
        self.__setup_default_attributes()

        self.__setup_sub_dict()

    def find_local_id_range(self):
        if api.Backend.ldap2.get_entries(
                DN(api.env.container_ranges, self.suffix),
                ldap.SCOPE_ONELEVEL,
                "(objectclass=ipaDomainIDRange)"):
            return

        try:
            entry = api.Backend.ldap2.get_entry(
                DN(('cn', 'admins'), api.env.container_group, self.suffix))
        except errors.NotFound:
            raise ValueError("No local ID range and no admins group found.\n" \
                             "Add local ID range manually and try again!")

        base_id = int(entry.single_value['gidNumber'])
        id_range_size = 200000

        id_filter = "(&" \
                      "(|(objectclass=posixAccount)" \
                        "(objectclass=posixGroup)" \
                        "(objectclass=ipaIDObject))" \
                      "(|(uidNumber<=%d)(uidNumber>=%d)" \
                        "(gidNumber<=%d)(gidNumner>=%d)))" % \
                     ((base_id - 1), (base_id + id_range_size),
                      (base_id - 1), (base_id + id_range_size))
        if api.Backend.ldap2.get_entries(DN(('cn', 'accounts'), self.suffix),
                                       ldap.SCOPE_SUBTREE, id_filter):
            raise ValueError("There are objects with IDs out of the expected" \
                             "range.\nAdd local ID range manually and try " \
                             "again!")

        entry = api.Backend.ldap2.make_entry(
            DN(
                ('cn', ('%s_id_range' % self.realm)),
                api.env.container_ranges, self.suffix),
            objectclass=['ipaDomainIDRange'],
            cn=['%s_id_range' % self.realm],
            ipaBaseID=[str(base_id)],
            ipaIDRangeSize=[str(id_range_size)],
        )
        api.Backend.ldap2.add_entry(entry)

    def create_instance(self):
        self.step("validate server hostname",
                  self.__validate_server_hostname)
        self.step("stopping smbd", self.__stop)
        self.step("creating samba domain object", \
                  self.__create_samba_domain_object)
        self.step("creating samba config registry", self.__write_smb_registry)
        self.step("writing samba config file", self.__write_smb_conf)
        self.step("adding cifs Kerberos principal",
                  self.request_service_keytab)
        self.step("adding cifs and host Kerberos principals to the adtrust agents group", \
                  self.__setup_group_membership)
        self.step("check for cifs services defined on other replicas", self.__check_replica)
        self.step("adding cifs principal to S4U2Proxy targets", self.__add_s4u2proxy_target)
        self.step("adding admin(group) SIDs", self.__add_admin_sids)
        self.step("adding RID bases", self.__add_rid_bases)
        self.step("updating Kerberos config", self.__update_krb5_conf)
        self.step("activating CLDAP plugin", self.__add_cldap_module)
        self.step("activating sidgen task", self.__add_sidgen_task)
        self.step("map BUILTIN\\Guests to nobody group",
                  self.__map_Guests_to_nobody)
        self.step("configuring smbd to start on boot", self.__enable)
        self.step("adding special DNS service records", \
                  self.__add_dns_service_records)

        if self.enable_compat:
            self.step("enabling trusted domains support for older clients via Schema Compatibility plugin",
                      self.__enable_compat_tree)

        self.step("restarting Directory Server to take MS PAC and LDAP plugins changes into account", \
                  self.__restart_dirsrv)
        self.step("adding fallback group", self.__add_fallback_group)
        self.step("adding Default Trust View", self.__add_default_trust_view)
        self.step("setting SELinux booleans", \
                  self.__configure_selinux_for_smbd)
        self.step("starting CIFS services", self.__start)

        if self.add_sids:
            self.step("adding SIDs to existing users and groups",
                      self.__add_sids)
        self.step("restarting smbd", self.__restart_smb)

        self.start_creation(show_service_name=False)

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring %s" % self.service_name)

        # Call restore_state so that we do not leave mess in the statestore
        # Otherwise this does nothing
        self.restore_state("running")
        self.restore_state("enabled")

        winbind = services.service("winbind", api)
        # Always try to stop and disable smb service, since we do not leave
        # working configuration after uninstall
        try:
            self.stop()
            self.disable()
            winbind.stop()
            winbind.disable()
        except Exception:
            pass

        # Since we do not guarantee restoring back to working samba state,
        # we should not restore smb.conf

        # Restore the state of affected selinux booleans
        boolean_states = {name: self.restore_state(name)
                          for name in constants.SELINUX_BOOLEAN_ADTRUST}
        try:
            tasks.set_selinux_booleans(boolean_states)
        except ipapython.errors.SetseboolError as e:
            self.print_msg('WARNING: ' + str(e))

        # Remove samba's credentials cache
        installutils.remove_ccache(ccache_path=paths.KRB5CC_SAMBA)

        # Remove samba's configuration file
        installutils.remove_file(self.smb_conf)

        # Remove samba's persistent and temporary tdb files
        tdb_files = [tdb_file for tdb_file in os.listdir(paths.SAMBA_DIR)
                                           if tdb_file.endswith(".tdb")]
        for tdb_file in tdb_files:
            installutils.remove_file(tdb_file)

        # Remove our keys from samba's keytab
        self.clean_samba_keytab()
