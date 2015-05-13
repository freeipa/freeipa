# Authors: Simo Sorce <ssorce@redhat.com>
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

import shutil
import fileinput
import re
import sys
import os
import pwd
import socket
import dns.name

from ipaserver.install import service
from ipaserver.install import installutils
from ipapython import sysrestore
from ipapython import ipautil
from ipapython import kernel_keyring
from ipalib import errors
from ipalib.constants import CACERT
from ipapython.ipa_log_manager import *
from ipapython.dn import DN

from ipaserver.install import replication
from ipaserver.install import dsinstance

import pyasn1.codec.ber.decoder
import struct

from ipaserver.install import certs
from distutils import version
from ipaplatform.tasks import tasks
from ipaplatform.paths import paths

def update_key_val_in_file(filename, key, val):
    if os.path.exists(filename):
        pattern = "^[\s#]*%s\s*=\s*%s\s*" % (re.escape(key), re.escape(val))
        p = re.compile(pattern)
        for line in fileinput.input(filename):
            if p.search(line):
                fileinput.close()
                return
        fileinput.close()

        pattern = "^[\s#]*%s\s*=" % re.escape(key)
        p = re.compile(pattern)
        for line in fileinput.input(filename, inplace=1):
            if not p.search(line):
                sys.stdout.write(line)
        fileinput.close()
    f = open(filename, "a")
    f.write("%s=%s\n" % (key, val))
    f.close()

class KpasswdInstance(service.SimpleServiceInstance):
    def __init__(self):
        service.SimpleServiceInstance.__init__(self, "kadmin")

class KrbInstance(service.Service):
    def __init__(self, fstore=None):
        service.Service.__init__(self, "krb5kdc", service_desc="Kerberos KDC")
        self.fqdn = None
        self.realm = None
        self.domain = None
        self.host = None
        self.admin_password = None
        self.master_password = None
        self.suffix = None
        self.subject_base = None
        self.kdc_password = None
        self.sub_dict = None
        self.pkcs12_info = None

        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore(paths.SYSRESTORE)

    suffix = ipautil.dn_attribute_property('_suffix')
    subject_base = ipautil.dn_attribute_property('_subject_base')

    def get_realm_suffix(self):
        return DN(('cn', self.realm), ('cn', 'kerberos'), self.suffix)

    def move_service_to_host(self, principal):
        """
        Used to move a host/ service principal created by kadmin.local from
        cn=kerberos to reside under the host entry.
        """

        service_dn = DN(('krbprincipalname', principal), self.get_realm_suffix())
        service_entry = self.admin_conn.get_entry(service_dn)
        self.admin_conn.delete_entry(service_entry)

        # Create a host entry for this master
        host_dn = DN(
            ('fqdn', self.fqdn), ('cn', 'computers'), ('cn', 'accounts'),
            self.suffix)
        host_entry = self.admin_conn.make_entry(
            host_dn,
            objectclass=[
               'top', 'ipaobject', 'nshost', 'ipahost', 'ipaservice',
               'pkiuser', 'krbprincipalaux', 'krbprincipal',
               'krbticketpolicyaux', 'ipasshhost'],
            krbextradata=service_entry['krbextradata'],
            krblastpwdchange=service_entry['krblastpwdchange'],
            krbprincipalname=service_entry['krbprincipalname'],
            krbprincipalkey=service_entry['krbprincipalkey'],
            serverhostname=[self.fqdn.split('.',1)[0]],
            cn=[self.fqdn],
            fqdn=[self.fqdn],
            ipauniqueid=['autogenerate'],
            managedby=[host_dn],
        )
        if 'krbpasswordexpiration' in service_entry:
            host_entry['krbpasswordexpiration'] = service_entry[
                'krbpasswordexpiration']
        if 'krbticketflags' in service_entry:
            host_entry['krbticketflags'] = service_entry['krbticketflags']
        self.admin_conn.add_entry(host_entry)

    def __common_setup(self, realm_name, host_name, domain_name, admin_password):
        self.fqdn = host_name
        self.realm = realm_name.upper()
        self.host = host_name.split(".")[0]
        self.ip = socket.getaddrinfo(host_name, None, socket.AF_UNSPEC, socket.SOCK_STREAM)[0][4][0]
        self.domain = domain_name
        self.suffix = ipautil.realm_to_suffix(self.realm)
        self.kdc_password = ipautil.ipa_generate_password()
        self.admin_password = admin_password
        self.dm_password = admin_password

        self.__setup_sub_dict()

        # get a connection to the DS
        self.ldap_connect()

        self.backup_state("running", self.is_running())
        try:
            self.stop()
        except:
            # It could have been not running
            pass

    def __common_post_setup(self):
        self.step("starting the KDC", self.__start_instance)
        self.step("configuring KDC to start on boot", self.__enable)

    def create_instance(self, realm_name, host_name, domain_name, admin_password, master_password, setup_pkinit=False, pkcs12_info=None, subject_base=None):
        self.master_password = master_password
        self.pkcs12_info = pkcs12_info
        self.subject_base = subject_base

        self.__common_setup(realm_name, host_name, domain_name, admin_password)

        self.step("adding sasl mappings to the directory", self.__configure_sasl_mappings)
        self.step("adding kerberos container to the directory", self.__add_krb_container)
        self.step("configuring KDC", self.__configure_instance)
        self.step("initialize kerberos container", self.__init_ipa_kdb)
        self.step("adding default ACIs", self.__add_default_acis)
        self.step("creating a keytab for the directory", self.__create_ds_keytab)
        self.step("creating a keytab for the machine", self.__create_host_keytab)
        self.step("adding the password extension to the directory", self.__add_pwd_extop_module)
        if setup_pkinit:
            self.step("creating X509 Certificate for PKINIT", self.__setup_pkinit)
            self.step("creating principal for anonymous PKINIT", self.__add_anonymous_pkinit_principal)

        self.__common_post_setup()

        self.start_creation(runtime=30)

        self.kpasswd = KpasswdInstance()
        self.kpasswd.create_instance('KPASSWD', self.fqdn, self.admin_password, self.suffix, realm=self.realm)

    def create_replica(self, realm_name,
                       master_fqdn, host_name,
                       domain_name, admin_password,
                       setup_pkinit=False, pkcs12_info=None,
                       subject_base=None):
        self.pkcs12_info = pkcs12_info
        self.subject_base = subject_base
        self.master_fqdn = master_fqdn

        self.__common_setup(realm_name, host_name, domain_name, admin_password)

        self.step("adding sasl mappings to the directory", self.__configure_sasl_mappings)
        self.step("configuring KDC", self.__configure_instance)
        self.step("creating a keytab for the directory", self.__create_ds_keytab)
        self.step("creating a keytab for the machine", self.__create_host_keytab)
        self.step("adding the password extension to the directory", self.__add_pwd_extop_module)
        if setup_pkinit:
            self.step("installing X509 Certificate for PKINIT", self.__setup_pkinit)
        self.step("enable GSSAPI for replication", self.__convert_to_gssapi_replication)

        self.__common_post_setup()

        self.start_creation(runtime=30)

        self.kpasswd = KpasswdInstance()
        self.kpasswd.create_instance('KPASSWD', self.fqdn, self.admin_password, self.suffix)


    def __enable(self):
        self.backup_state("enabled", self.is_enabled())
        # We do not let the system start IPA components on its own,
        # Instead we reply on the IPA init script to start only enabled
        # components as found in our LDAP configuration tree
        self.ldap_enable('KDC', self.fqdn, self.admin_password, self.suffix)

    def __start_instance(self):
        try:
            self.start()
        except:
            root_logger.critical("krb5kdc service failed to start")

    def __setup_sub_dict(self):
        self.sub_dict = dict(FQDN=self.fqdn,
                             IP=self.ip,
                             PASSWORD=self.kdc_password,
                             SUFFIX=self.suffix,
                             DOMAIN=self.domain,
                             HOST=self.host,
                             SERVER_ID=installutils.realm_to_serverid(self.realm),
                             REALM=self.realm)

        # IPA server/KDC is not a subdomain of default domain
        # Proper domain-realm mapping needs to be specified
        domain = dns.name.from_text(self.domain)
        fqdn = dns.name.from_text(self.fqdn)
        if not fqdn.is_subdomain(domain):
            root_logger.debug("IPA FQDN '%s' is not located in default domain '%s'",
                    fqdn, domain)
            server_domain = fqdn.parent().to_unicode(omit_final_dot=True)
            root_logger.debug("Domain '%s' needs additional mapping in krb5.conf",
                server_domain)
            dr_map = " .%(domain)s = %(realm)s\n %(domain)s = %(realm)s\n" \
                        % dict(domain=server_domain, realm=self.realm)
        else:
            dr_map = ""
        self.sub_dict['OTHER_DOMAIN_REALM_MAPS'] = dr_map

        # Configure KEYRING CCACHE if supported
        if kernel_keyring.is_persistent_keyring_supported():
            root_logger.debug("Enabling persistent keyring CCACHE")
            self.sub_dict['OTHER_LIBDEFAULTS'] = \
                " default_ccache_name = KEYRING:persistent:%{uid}\n"
        else:
            root_logger.debug("Persistent keyring CCACHE is not enabled")
            self.sub_dict['OTHER_LIBDEFAULTS'] = ''

    def __configure_sasl_mappings(self):
        # we need to remove any existing SASL mappings in the directory as otherwise they
        # they may conflict.

        try:
            res = self.admin_conn.get_entries(
                DN(('cn', 'mapping'), ('cn', 'sasl'), ('cn', 'config')),
                self.admin_conn.SCOPE_ONELEVEL,
                "(objectclass=nsSaslMapping)")
            for r in res:
                try:
                    self.admin_conn.delete_entry(r)
                except Exception, e:
                    root_logger.critical(
                        "Error during SASL mapping removal: %s", e)
                    raise
        except Exception, e:
            root_logger.critical("Error while enumerating SASL mappings %s", e)
            raise

        entry = self.admin_conn.make_entry(
            DN(
                ('cn', 'Full Principal'), ('cn', 'mapping'), ('cn', 'sasl'),
                ('cn', 'config')),
            objectclass=["top", "nsSaslMapping"],
            cn=["Full Principal"],
            nsSaslMapRegexString=['\(.*\)@\(.*\)'],
            nsSaslMapBaseDNTemplate=[self.suffix],
            nsSaslMapFilterTemplate=['(krbPrincipalName=\\1@\\2)'],
            nsSaslMapPriority=['10'],
        )
        self.admin_conn.add_entry(entry)

        entry = self.admin_conn.make_entry(
            DN(
                ('cn', 'Name Only'), ('cn', 'mapping'), ('cn', 'sasl'),
                ('cn', 'config')),
            objectclass=["top", "nsSaslMapping"],
            cn=["Name Only"],
            nsSaslMapRegexString=['^[^:@]+$'],
            nsSaslMapBaseDNTemplate=[self.suffix],
            nsSaslMapFilterTemplate=['(krbPrincipalName=&@%s)' % self.realm],
            nsSaslMapPriority=['10'],
        )
        self.admin_conn.add_entry(entry)

    def __add_krb_container(self):
        self._ldap_mod("kerberos.ldif", self.sub_dict)

    def __add_default_acis(self):
        self._ldap_mod("default-aci.ldif", self.sub_dict)

    def __template_file(self, path, chmod=0644):
        template = os.path.join(ipautil.SHARE_DIR, os.path.basename(path) + ".template")
        conf = ipautil.template_file(template, self.sub_dict)
        self.fstore.backup_file(path)
        fd = open(path, "w+")
        fd.write(conf)
        fd.close()
        if chmod is not None:
            os.chmod(path, chmod)

    def __init_ipa_kdb(self):
        # kdb5_util may take a very long time when entropy is low
        installutils.check_entropy()

        #populate the directory with the realm structure
        args = ["kdb5_util", "create", "-s",
                                       "-r", self.realm,
                                       "-x", "ipa-setup-override-restrictions"]
        dialogue = (
            # Enter KDC database master key:
            self.master_password + '\n',
            # Re-enter KDC database master key to verify:
            self.master_password + '\n',
        )
        try:
            ipautil.run(args, nolog=(self.master_password,), stdin=''.join(dialogue))
        except ipautil.CalledProcessError, e:
            print "Failed to initialize the realm container"

    def __configure_instance(self):
        self.__template_file(paths.KRB5KDC_KDC_CONF, chmod=None)
        self.__template_file(paths.KRB5_CONF)
        self.__template_file(paths.HTML_KRB5_INI)
        self.__template_file(paths.KRB_CON)
        self.__template_file(paths.HTML_KRBREALM_CON)

        MIN_KRB5KDC_WITH_WORKERS = "1.9"
        cpus = os.sysconf('SC_NPROCESSORS_ONLN')
        workers = False
        (stdout, stderr, rc) = ipautil.run(['klist', '-V'], raiseonerr=False)
        if rc == 0:
            verstr = stdout.split()[-1]
            ver = version.LooseVersion(verstr)
            min = version.LooseVersion(MIN_KRB5KDC_WITH_WORKERS)
            if ver >= min:
                workers = True
        # Write down config file
        # We write realm and also number of workers (for multi-CPU systems)
        replacevars = {'KRB5REALM':self.realm}
        appendvars = {}
        if workers and cpus > 1:
            appendvars = {'KRB5KDC_ARGS': "'-w %s'" % str(cpus)}
        ipautil.backup_config_and_replace_variables(self.fstore, paths.SYSCONFIG_KRB5KDC_DIR,
                                                    replacevars=replacevars,
                                                    appendvars=appendvars)
        tasks.restore_context(paths.SYSCONFIG_KRB5KDC_DIR)

    #add the password extop module
    def __add_pwd_extop_module(self):
        self._ldap_mod("pwd-extop-conf.ldif", self.sub_dict)

    def __create_ds_keytab(self):
        ldap_principal = "ldap/" + self.fqdn + "@" + self.realm
        installutils.kadmin_addprinc(ldap_principal)
        self.move_service(ldap_principal)

        self.fstore.backup_file(paths.DS_KEYTAB)
        installutils.create_keytab(paths.DS_KEYTAB, ldap_principal)

        update_key_val_in_file(paths.SYSCONFIG_DIRSRV, "KRB5_KTNAME", paths.DS_KEYTAB)
        pent = pwd.getpwnam(dsinstance.DS_USER)
        os.chown(paths.DS_KEYTAB, pent.pw_uid, pent.pw_gid)

    def __create_host_keytab(self):
        host_principal = "host/" + self.fqdn + "@" + self.realm
        installutils.kadmin_addprinc(host_principal)

        self.fstore.backup_file(paths.KRB5_KEYTAB)
        installutils.create_keytab(paths.KRB5_KEYTAB, host_principal)

        # Make sure access is strictly reserved to root only for now
        os.chown(paths.KRB5_KEYTAB, 0, 0)
        os.chmod(paths.KRB5_KEYTAB, 0600)

        self.move_service_to_host(host_principal)

    def __setup_pkinit(self):
        ca_db = certs.CertDB(self.realm, host_name=self.fqdn,
                                subject_base=self.subject_base)

        if self.pkcs12_info:
            ca_db.install_pem_from_p12(self.pkcs12_info[0],
                                       self.pkcs12_info[1],
                                       paths.KDC_PEM)
        else:
            raise RuntimeError("PKI not supported yet\n")

        # Finally copy the cacert in the krb directory so we don't
        # have any selinux issues with the file context
        shutil.copyfile(CACERT, paths.CACERT_PEM)

    def __add_anonymous_pkinit_principal(self):
        princ = "WELLKNOWN/ANONYMOUS"
        princ_realm = "%s@%s" % (princ, self.realm)

        # Create the special anonymous principal
        installutils.kadmin_addprinc(princ_realm)
        dn = DN(('krbprincipalname', princ_realm), self.get_realm_suffix())
        entry = self.admin_conn.get_entry(dn)
        entry['nsAccountlock'] = ['TRUE']
        self.admin_conn.update_entry(entry)

    def __convert_to_gssapi_replication(self):
        repl = replication.ReplicationManager(self.realm,
                                              self.fqdn,
                                              self.dm_password)
        repl.convert_to_gssapi_replication(self.master_fqdn,
                                           r_binddn=DN(('cn', 'Directory Manager')),
                                           r_bindpw=self.dm_password)

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring %s" % self.service_name)

        running = self.restore_state("running")
        enabled = self.restore_state("enabled")

        try:
            self.stop()
        except:
            pass

        for f in [paths.KRB5KDC_KDC_CONF, paths.KRB5_CONF]:
            try:
                self.fstore.restore_file(f)
            except ValueError, error:
                root_logger.debug(error)
                pass

        # disabled by default, by ldap_enable()
        if enabled:
            self.enable()

        if running:
            self.restart()

        self.kpasswd = KpasswdInstance()
        self.kpasswd.uninstall()
