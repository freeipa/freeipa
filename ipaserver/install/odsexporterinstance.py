#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import logging
import os
import pwd
import grp

import ldap

from ipaserver.install import service
from ipaserver.install import installutils
from ipapython.dn import DN
from ipapython import directivesetter
from ipapython import ipautil
from ipaplatform.constants import constants
from ipaplatform.paths import paths
from ipaplatform import services
from ipalib import errors, api

logger = logging.getLogger(__name__)


class ODSExporterInstance(service.Service):
    def __init__(self, fstore=None):
        super(ODSExporterInstance, self).__init__(
            "ipa-ods-exporter",
            service_desc="IPA OpenDNSSEC exporter daemon",
            fstore=fstore,
            keytab=paths.IPA_ODS_EXPORTER_KEYTAB,
            service_prefix=u'ipa-ods-exporter'
        )
        self.ods_uid = None
        self.ods_gid = None
        self.enable_if_exists = False

    suffix = ipautil.dn_attribute_property('_suffix')

    def create_instance(self, fqdn, realm_name):
        self.backup_state("enabled", self.is_enabled())
        self.backup_state("running", self.is_running())
        self.fqdn = fqdn
        self.realm = realm_name
        self.suffix = ipautil.realm_to_suffix(self.realm)

        try:
            self.stop()
        except Exception:
            pass

        # checking status step must be first
        self.step("checking status", self.__check_dnssec_status)
        self.step("setting up DNS Key Exporter", self.__setup_key_exporter)
        self.step("setting up kerberos principal", self.__setup_principal)
        self.step("disabling default signer daemon", self.__disable_signerd)
        self.step("starting DNS Key Exporter", self.__start)
        self.step("configuring DNS Key Exporter to start on boot", self.__enable)
        self.start_creation()

    def __check_dnssec_status(self):
        try:
            self.ods_uid = pwd.getpwnam(constants.ODS_USER).pw_uid
        except KeyError:
            raise RuntimeError("OpenDNSSEC UID not found")

        try:
            self.ods_gid = grp.getgrnam(constants.ODS_GROUP).gr_gid
        except KeyError:
            raise RuntimeError("OpenDNSSEC GID not found")

    def __enable(self):

        try:
            self.ldap_configure('DNSKeyExporter', self.fqdn, None,
                                self.suffix)
        except errors.DuplicateEntry:
            logger.error("DNSKeyExporter service already exists")

    def __setup_key_exporter(self):
        directivesetter.set_directive(paths.SYSCONFIG_IPA_ODS_EXPORTER,
                                   'SOFTHSM2_CONF',
                                   paths.DNSSEC_SOFTHSM2_CONF,
                                   quotes=False, separator='=')

    def __setup_principal(self):
        assert self.ods_uid is not None

        for f in [paths.IPA_ODS_EXPORTER_CCACHE, self.keytab]:
            try:
                os.remove(f)
            except OSError:
                pass

        installutils.kadmin_addprinc(self.principal)

        # Store the keytab on disk
        installutils.create_keytab(paths.IPA_ODS_EXPORTER_KEYTAB,
                                   self.principal)
        p = self.move_service(self.principal)
        if p is None:
            # the service has already been moved, perhaps we're doing a DNS reinstall
            dns_exporter_principal_dn = DN(
                ('krbprincipalname', self.principal),
                ('cn', 'services'), ('cn', 'accounts'), self.suffix)
        else:
            dns_exporter_principal_dn = p

        # Make sure access is strictly reserved to the ods user
        os.chmod(self.keytab, 0o440)
        os.chown(self.keytab, 0, self.ods_gid)

        dns_group = DN(('cn', 'DNS Servers'), ('cn', 'privileges'),
                       ('cn', 'pbac'), self.suffix)
        mod = [(ldap.MOD_ADD, 'member', dns_exporter_principal_dn)]

        try:
            api.Backend.ldap2.modify_s(dns_group, mod)
        except ldap.TYPE_OR_VALUE_EXISTS:
            pass
        except Exception as e:
            logger.critical("Could not modify principal's %s entry: %s",
                            dns_exporter_principal_dn, str(e))
            raise

        # limit-free connection

        mod = [(ldap.MOD_REPLACE, 'nsTimeLimit', '-1'),
               (ldap.MOD_REPLACE, 'nsSizeLimit', '-1'),
               (ldap.MOD_REPLACE, 'nsIdleTimeout', '-1'),
               (ldap.MOD_REPLACE, 'nsLookThroughLimit', '-1')]
        try:
            api.Backend.ldap2.modify_s(dns_exporter_principal_dn, mod)
        except Exception as e:
            logger.critical("Could not set principal's %s LDAP limits: %s",
                            dns_exporter_principal_dn, str(e))
            raise

    def __disable_signerd(self):
        signerd_service = services.knownservices.ods_signerd
        if self.get_state("singerd_running") is None:
            self.backup_state("singerd_running", signerd_service.is_running())
        if self.get_state("singerd_enabled") is None:
            self.backup_state("singerd_enabled", signerd_service.is_enabled())

        # disable default opendnssec signer daemon
        signerd_service.stop()
        signerd_service.mask()

    def __start(self):
        self.start()

    def remove_service(self):
        try:
            api.Command.service_del(self.principal)
        except errors.NotFound:
            pass

    def uninstall(self):
        if not self.is_configured():
            return

        self.print_msg("Unconfiguring %s" % self.service_name)

        # just eat states
        self.restore_state("running")
        self.restore_state("enabled")

        # stop and disable service (IPA service, we do not need it anymore)
        self.disable()
        self.stop()

        # restore state of dnssec default signer daemon
        signerd_enabled = self.restore_state("singerd_enabled")
        signerd_running = self.restore_state("singerd_running")
        signerd_service = services.knownservices.ods_signerd

        signerd_service.unmask()

        # service was stopped and disabled by setup
        if signerd_enabled:
            signerd_service.enable()

        if signerd_running:
            signerd_service.start()

        installutils.remove_keytab(self.keytab)
        installutils.remove_ccache(ccache_path=paths.IPA_ODS_EXPORTER_CCACHE)
