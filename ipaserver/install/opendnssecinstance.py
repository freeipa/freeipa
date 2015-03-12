#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

import random

import service
import os
import pwd
import grp
import stat

import _ipap11helper

import installutils
from ipapython.ipa_log_manager import *
from ipapython.dn import DN
from ipapython import sysrestore, ipautil, ipaldap, p11helper
from ipaplatform import services
from ipaplatform.paths import paths
from ipalib import errors, api
from ipaserver.install import dnskeysyncinstance

KEYMASTER = u'dnssecKeyMaster'
softhsm_slot = 0


def get_dnssec_key_masters(conn):
    """
    :return: list of active dnssec key masters
    """
    assert conn is not None

    dn = DN(('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'), api.env.basedn)

    filter_attrs = {
        u'cn': u'DNSSEC',
        u'objectclass': u'ipaConfigObject',
        u'ipaConfigString': [KEYMASTER, u'enabledService'],
    }
    only_masters_f = conn.make_filter(filter_attrs, rules=conn.MATCH_ALL)

    try:
        entries = conn.find_entries(filter=only_masters_f, base_dn=dn)
    except errors.NotFound:
        return []

    keymasters_list = []
    for entry in entries[0]:
        keymasters_list.append(str(entry.dn[1].value))

    return keymasters_list


def check_inst():
    if not os.path.exists(paths.ODS_KSMUTIL):
        print ("Please install the 'opendnssec' package and start "
               "the installation again")
        return False
    return True


class OpenDNSSECInstance(service.Service):
    def __init__(self, fstore=None, dm_password=None, ldapi=False,
                 start_tls=False, autobind=ipaldap.AUTOBIND_DISABLED):
        service.Service.__init__(
            self, "ods-enforcerd",
            service_desc="OpenDNSSEC enforcer daemon",
            dm_password=dm_password,
            ldapi=ldapi,
            autobind=autobind,
            start_tls=start_tls
        )
        self.dm_password = dm_password
        self.ods_uid = None
        self.ods_gid = None
        self.conf_file_dict = {
            'SOFTHSM_LIB': paths.LIBSOFTHSM2_SO,
            'TOKEN_LABEL': dnskeysyncinstance.softhsm_token_label,
            'KASP_DB': paths.OPENDNSSEC_KASP_DB,
        }
        self.kasp_file_dict = {}
        self.extra_config = [KEYMASTER]

        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore(paths.SYSRESTORE)

    suffix = ipautil.dn_attribute_property('_suffix')

    def get_masters(self):
        if not self.admin_conn:
            self.ldap_connect()
        return get_dnssec_key_masters(self.admin_conn)

    def create_instance(self, fqdn, realm_name, generate_master_key=True):
        self.backup_state("enabled", self.is_enabled())
        self.backup_state("running", self.is_running())
        self.fqdn = fqdn
        self.realm = realm_name
        self.suffix = ipautil.realm_to_suffix(self.realm)

        try:
            self.stop()
        except Exception:
            pass

        # get a connection to the DS
        if not self.admin_conn:
            self.ldap_connect()
        # checking status must be first
        self.step("checking status", self.__check_dnssec_status)
        self.step("setting up configuration files", self.__setup_conf_files)
        self.step("setting up ownership and file mode bits", self.__setup_ownership_file_modes)
        if generate_master_key:
            self.step("generating master key", self.__generate_master_key)
        self.step("setting up OpenDNSSEC", self.__setup_dnssec)
        self.step("setting up ipa-dnskeysyncd", self.__setup_dnskeysyncd)
        self.step("starting OpenDNSSEC enforcer", self.__start)
        self.step("configuring OpenDNSSEC enforcer to start on boot", self.__enable)
        self.start_creation()

    def __check_dnssec_status(self):
        named = services.knownservices.named
        ods_enforcerd = services.knownservices.ods_enforcerd

        try:
            self.named_uid = pwd.getpwnam(named.get_user_name()).pw_uid
        except KeyError:
            raise RuntimeError("Named UID not found")

        try:
            self.named_gid = grp.getgrnam(named.get_group_name()).gr_gid
        except KeyError:
            raise RuntimeError("Named GID not found")

        try:
            self.ods_uid = pwd.getpwnam(ods_enforcerd.get_user_name()).pw_uid
        except KeyError:
            raise RuntimeError("OpenDNSSEC UID not found")

        try:
            self.ods_gid = grp.getgrnam(ods_enforcerd.get_group_name()).gr_gid
        except KeyError:
            raise RuntimeError("OpenDNSSEC GID not found")

    def __enable(self):
        try:
            self.ldap_enable('DNSSEC', self.fqdn, self.dm_password,
                             self.suffix, self.extra_config)
        except errors.DuplicateEntry:
            root_logger.error("DNSSEC service already exists")

    def __setup_conf_files(self):
        if not self.fstore.has_file(paths.OPENDNSSEC_CONF_FILE):
            self.fstore.backup_file(paths.OPENDNSSEC_CONF_FILE)

        if not self.fstore.has_file(paths.OPENDNSSEC_KASP_FILE):
            self.fstore.backup_file(paths.OPENDNSSEC_KASP_FILE)

        pin_fd = open(paths.DNSSEC_SOFTHSM_PIN, "r")
        pin = pin_fd.read()
        pin_fd.close()

        # add pin to template
        sub_conf_dict = self.conf_file_dict
        sub_conf_dict['PIN'] = pin

        ods_conf_txt = ipautil.template_file(
            ipautil.SHARE_DIR + "opendnssec_conf.template", sub_conf_dict)
        ods_conf_fd = open(paths.OPENDNSSEC_CONF_FILE, 'w')
        ods_conf_fd.seek(0)
        ods_conf_fd.truncate(0)
        ods_conf_fd.write(ods_conf_txt)
        ods_conf_fd.close()

        ods_kasp_txt = ipautil.template_file(
            ipautil.SHARE_DIR + "opendnssec_kasp.template", self.kasp_file_dict)
        ods_kasp_fd = open(paths.OPENDNSSEC_KASP_FILE, 'w')
        ods_kasp_fd.seek(0)
        ods_kasp_fd.truncate(0)
        ods_kasp_fd.write(ods_kasp_txt)
        ods_kasp_fd.close()

        if not self.fstore.has_file(paths.SYSCONFIG_ODS):
            self.fstore.backup_file(paths.SYSCONFIG_ODS)

        installutils.set_directive(paths.SYSCONFIG_ODS,
                                   'SOFTHSM2_CONF',
                                    paths.DNSSEC_SOFTHSM2_CONF,
                                    quotes=False, separator='=')

    def __setup_ownership_file_modes(self):
        assert self.ods_uid is not None
        assert self.ods_gid is not None

        # workarounds for packaging bugs in opendnssec-1.4.5-2.fc20.x86_64
        # https://bugzilla.redhat.com/show_bug.cgi?id=1098188
        for (root, dirs, files) in os.walk(paths.ETC_OPENDNSSEC_DIR):
            for directory in dirs:
                dir_path = os.path.join(root, directory)
                os.chmod(dir_path, 0770)
                # chown to root:ods
                os.chown(dir_path, 0, self.ods_gid)
            for filename in files:
                file_path = os.path.join(root, filename)
                os.chmod(file_path, 0660)
                # chown to root:ods
                os.chown(file_path, 0, self.ods_gid)

        for (root, dirs, files) in os.walk(paths.VAR_OPENDNSSEC_DIR):
            for directory in dirs:
                dir_path = os.path.join(root, directory)
                os.chmod(dir_path, 0770)
                # chown to ods:ods
                os.chown(dir_path, self.ods_uid, self.ods_gid)
            for filename in files:
                file_path = os.path.join(root, filename)
                os.chmod(file_path, 0660)
                # chown to ods:ods
                os.chown(file_path, self.ods_uid, self.ods_gid)

    def __generate_master_key(self):

        with open(paths.DNSSEC_SOFTHSM_PIN, "r") as f:
            pin = f.read()

        os.environ["SOFTHSM2_CONF"] = paths.DNSSEC_SOFTHSM2_CONF
        p11 = _ipap11helper.P11_Helper(softhsm_slot, pin, paths.LIBSOFTHSM2_SO)
        try:
            # generate master key
            root_logger.debug("Creating master key")
            p11helper.generate_master_key(p11)

            # change tokens mod/owner
            root_logger.debug("Changing ownership of token files")
            for (root, dirs, files) in os.walk(paths.DNSSEC_TOKENS_DIR):
                for directory in dirs:
                    dir_path = os.path.join(root, directory)
                    os.chmod(dir_path, 0770 | stat.S_ISGID)
                    os.chown(dir_path, self.ods_uid, self.named_gid)  # chown to ods:named
                for filename in files:
                    file_path = os.path.join(root, filename)
                    os.chmod(file_path, 0770 | stat.S_ISGID)
                    os.chown(file_path, self.ods_uid, self.named_gid)  # chown to ods:named

        finally:
            p11.finalize()

    def __setup_dnssec(self):
        # run once only
        if self.get_state("KASP_DB_configured"):
            root_logger.debug("Already configured, skipping step")

        self.backup_state("KASP_DB_configured", True)

        if not self.fstore.has_file(paths.OPENDNSSEC_KASP_DB):
            self.fstore.backup_file(paths.OPENDNSSEC_KASP_DB)

        command = [
            paths.ODS_KSMUTIL,
            'setup'
        ]

        ods_enforcerd = services.knownservices.ods_enforcerd
        ipautil.run(command, stdin="y", runas=ods_enforcerd.get_user_name())

    def __setup_dnskeysyncd(self):
        # set up dnskeysyncd this is DNSSEC master
        installutils.set_directive(paths.SYSCONFIG_IPA_DNSKEYSYNCD,
                                   'ISMASTER',
                                   '1',
                                   quotes=False, separator='=')

    def __start(self):
        self.restart()  # needed to reload conf files

    def uninstall(self):
        if not self.is_configured():
            return

        self.print_msg("Unconfiguring %s" % self.service_name)

        running = self.restore_state("running")
        enabled = self.restore_state("enabled")

        for f in [paths.OPENDNSSEC_CONF_FILE, paths.OPENDNSSEC_KASP_FILE,
                  paths.OPENDNSSEC_KASP_DB, paths.SYSCONFIG_ODS]:
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
