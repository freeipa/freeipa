#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import logging
import os
import pwd
import grp
import stat
import shutil
from subprocess import CalledProcessError

from ipalib.install import sysrestore
from ipaserver.install import service
from ipaserver.masters import ENABLED_SERVICE
from ipapython.dn import DN
from ipapython import directivesetter
from ipapython import ipautil
from ipaplatform import services
from ipaplatform.constants import constants
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks
from ipalib import errors, api
from ipaserver import p11helper
from ipalib.constants import SOFTHSM_DNSSEC_TOKEN_LABEL

logger = logging.getLogger(__name__)

KEYMASTER = u'dnssecKeyMaster'


def get_dnssec_key_masters(conn):
    """
    This method can be used only for admin connections, common users do not
    have permission to access content of service containers.
    :return: list of active dnssec key masters
    """
    assert conn is not None

    # please check ipalib/dns.py:dnssec_installed() method too, if you do
    # any modifications here

    dn = DN(api.env.container_masters, api.env.basedn)

    filter_attrs = {
        u'cn': u'DNSSEC',
        u'objectclass': u'ipaConfigObject',
        u'ipaConfigString': [KEYMASTER, ENABLED_SERVICE],
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


class OpenDNSSECInstance(service.Service):
    def __init__(self, fstore=None):
        service.Service.__init__(
            self, "ods-enforcerd",
            service_desc="OpenDNSSEC enforcer daemon",
        )
        self.ods_uid = None
        self.ods_gid = None
        self.conf_file_dict = {
            'SOFTHSM_LIB': paths.LIBSOFTHSM2_SO,
            'TOKEN_LABEL': SOFTHSM_DNSSEC_TOKEN_LABEL,
            'KASP_DB': paths.OPENDNSSEC_KASP_DB,
            'ODS_USER': constants.ODS_USER,
            'ODS_GROUP': constants.ODS_GROUP,
        }
        self.kasp_file_dict = {}
        self.extra_config = [KEYMASTER]

        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore()

    suffix = ipautil.dn_attribute_property('_suffix')

    def get_masters(self):
        return get_dnssec_key_masters(api.Backend.ldap2)

    def create_instance(self, fqdn, realm_name, generate_master_key=True,
                        kasp_db_file=None):
        if self.get_state("enabled") is None:
            self.backup_state("enabled", self.is_enabled())
        if self.get_state("running") is None:
            self.backup_state("running", self.is_running())
        self.fqdn = fqdn
        self.realm = realm_name
        self.suffix = ipautil.realm_to_suffix(self.realm)
        self.kasp_db_file = kasp_db_file

        try:
            self.stop()
        except Exception:
            pass

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
        try:
            self.named_uid = pwd.getpwnam(constants.NAMED_USER).pw_uid
        except KeyError:
            raise RuntimeError("Named UID not found")

        try:
            self.named_gid = grp.getgrnam(constants.NAMED_GROUP).gr_gid
        except KeyError:
            raise RuntimeError("Named GID not found")

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
            self.ldap_configure('DNSSEC', self.fqdn, None,
                                self.suffix, self.extra_config)
        except errors.DuplicateEntry:
            logger.error("DNSSEC service already exists")

        # add the KEYMASTER identifier into ipaConfigString
        # this is needed for the re-enabled DNSSEC master
        dn = DN(('cn', 'DNSSEC'), ('cn', self.fqdn), api.env.container_masters,
                api.env.basedn)
        try:
            entry = api.Backend.ldap2.get_entry(dn, ['ipaConfigString'])
        except errors.NotFound as e:
            logger.error(
                "DNSSEC service entry not found in the LDAP (%s)", e)
        else:
            config = entry.setdefault('ipaConfigString', [])
            if KEYMASTER not in config:
                config.append(KEYMASTER)
                api.Backend.ldap2.update_entry(entry)

    def __setup_conf_files(self):
        if not self.fstore.has_file(paths.OPENDNSSEC_CONF_FILE):
            self.fstore.backup_file(paths.OPENDNSSEC_CONF_FILE)

        if not self.fstore.has_file(paths.OPENDNSSEC_KASP_FILE):
            self.fstore.backup_file(paths.OPENDNSSEC_KASP_FILE)

        if not self.fstore.has_file(paths.OPENDNSSEC_ZONELIST_FILE):
            self.fstore.backup_file(paths.OPENDNSSEC_ZONELIST_FILE)

        pin_fd = open(paths.DNSSEC_SOFTHSM_PIN, "r")
        pin = pin_fd.read()
        pin_fd.close()

        # add pin to template
        sub_conf_dict = self.conf_file_dict
        sub_conf_dict['PIN'] = pin

        ods_conf_txt = ipautil.template_file(
            os.path.join(paths.USR_SHARE_IPA_DIR, "opendnssec_conf.template"),
            sub_conf_dict)
        ods_conf_fd = open(paths.OPENDNSSEC_CONF_FILE, 'w')
        ods_conf_fd.seek(0)
        ods_conf_fd.truncate(0)
        ods_conf_fd.write(ods_conf_txt)
        ods_conf_fd.close()

        ods_kasp_txt = ipautil.template_file(
            os.path.join(paths.USR_SHARE_IPA_DIR, "opendnssec_kasp.template"),
            self.kasp_file_dict)
        ods_kasp_fd = open(paths.OPENDNSSEC_KASP_FILE, 'w')
        ods_kasp_fd.seek(0)
        ods_kasp_fd.truncate(0)
        ods_kasp_fd.write(ods_kasp_txt)
        ods_kasp_fd.close()

        if not self.fstore.has_file(paths.SYSCONFIG_ODS):
            self.fstore.backup_file(paths.SYSCONFIG_ODS)

        if not os.path.isfile(paths.SYSCONFIG_ODS):
            # create file, it's not shipped on Debian
            with open(paths.SYSCONFIG_ODS, 'a') as f:
                os.fchmod(f.fileno(), 0o644)

        directivesetter.set_directive(paths.SYSCONFIG_ODS,
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
                os.chmod(dir_path, 0o770)
                # chown to root:ods
                os.chown(dir_path, 0, self.ods_gid)
            for filename in files:
                file_path = os.path.join(root, filename)
                os.chmod(file_path, 0o660)
                # chown to root:ods
                os.chown(file_path, 0, self.ods_gid)

        for (root, dirs, files) in os.walk(paths.VAR_OPENDNSSEC_DIR):
            for directory in dirs:
                dir_path = os.path.join(root, directory)
                os.chmod(dir_path, 0o770)
                # chown to ods:ods
                os.chown(dir_path, self.ods_uid, self.ods_gid)
            for filename in files:
                file_path = os.path.join(root, filename)
                os.chmod(file_path, 0o660)
                # chown to ods:ods
                os.chown(file_path, self.ods_uid, self.ods_gid)

    def __generate_master_key(self):

        with open(paths.DNSSEC_SOFTHSM_PIN, "r") as f:
            pin = f.read()

        os.environ["SOFTHSM2_CONF"] = paths.DNSSEC_SOFTHSM2_CONF
        p11 = p11helper.P11_Helper(
            SOFTHSM_DNSSEC_TOKEN_LABEL, pin, paths.LIBSOFTHSM2_SO)
        try:
            # generate master key
            logger.debug("Creating master key")
            p11helper.generate_master_key(p11)

            # change tokens mod/owner
            logger.debug("Changing ownership of token files")
            for (root, dirs, files) in os.walk(paths.DNSSEC_TOKENS_DIR):
                for directory in dirs:
                    dir_path = os.path.join(root, directory)
                    os.chmod(dir_path, 0o770 | stat.S_ISGID)
                    os.chown(dir_path, self.ods_uid, self.named_gid)  # chown to ods:named
                for filename in files:
                    file_path = os.path.join(root, filename)
                    os.chmod(file_path, 0o770 | stat.S_ISGID)
                    os.chown(file_path, self.ods_uid, self.named_gid)  # chown to ods:named

        finally:
            p11.finalize()

    def __setup_dnssec(self):
        # run once only
        if self.get_state("kasp_db_configured") and not self.kasp_db_file:
            logger.debug("Already configured, skipping step")
            return

        self.backup_state("kasp_db_configured", True)

        if not self.fstore.has_file(paths.OPENDNSSEC_KASP_DB):
            self.fstore.backup_file(paths.OPENDNSSEC_KASP_DB)

        if self.kasp_db_file:
            # copy user specified kasp.db to proper location and set proper
            # privileges
            shutil.copy(self.kasp_db_file, paths.OPENDNSSEC_KASP_DB)
            os.chown(paths.OPENDNSSEC_KASP_DB, self.ods_uid, self.ods_gid)
            os.chmod(paths.OPENDNSSEC_KASP_DB, 0o660)

            # regenerate zonelist.xml
            result = tasks.run_ods_manager(
                ['zonelist', 'export'], capture_output=True
            )
            with open(paths.OPENDNSSEC_ZONELIST_FILE, 'w') as f:
                f.write(result.output)
                os.fchown(f.fileno(), self.ods_uid, self.ods_gid)
                os.fchmod(f.fileno(), 0o660)
        else:
            # initialize new kasp.db
            tasks.run_ods_setup()

    def __setup_dnskeysyncd(self):
        # set up dnskeysyncd this is DNSSEC master
        directivesetter.set_directive(paths.SYSCONFIG_IPA_DNSKEYSYNCD,
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

        # stop DNSSEC services before backing up kasp.db
        try:
            self.stop()
        except Exception:
            pass

        ods_exporter = services.service('ipa-ods-exporter', api)
        try:
            ods_exporter.stop()
        except Exception:
            pass

        # remove directive from ipa-dnskeysyncd, this server is not DNSSEC
        # master anymore
        directivesetter.set_directive(paths.SYSCONFIG_IPA_DNSKEYSYNCD,
                                      'ISMASTER', None,
                                      quotes=False, separator='=')

        restore_list = [paths.OPENDNSSEC_CONF_FILE, paths.OPENDNSSEC_KASP_FILE,
                        paths.SYSCONFIG_ODS, paths.OPENDNSSEC_ZONELIST_FILE]

        if os.path.isfile(paths.OPENDNSSEC_KASP_DB):

            # force to export data
            cmd = [paths.IPA_ODS_EXPORTER, 'ipa-full-update']
            try:
                self.print_msg("Exporting DNSSEC data before uninstallation")
                ipautil.run(cmd, runas=constants.ODS_USER)
            except CalledProcessError:
                logger.error("DNSSEC data export failed")

            try:
                shutil.copy(paths.OPENDNSSEC_KASP_DB,
                            paths.IPA_KASP_DB_BACKUP)
            except IOError as e:
                logger.error(
                    "Unable to backup OpenDNSSEC database %s, "
                    "restore will be skipped: %s", paths.OPENDNSSEC_KASP_DB, e)
            else:
                logger.info("OpenDNSSEC database backed up in %s",
                            paths.IPA_KASP_DB_BACKUP)
                # restore OpenDNSSEC's KASP DB only if backup succeeded
                # removing the file without backup could totally break DNSSEC
                restore_list.append(paths.OPENDNSSEC_KASP_DB)

        for f in restore_list:
            try:
                self.fstore.restore_file(f)
            except ValueError as error:
                logger.debug("%s", error)

        self.restore_state("kasp_db_configured")  # just eat state

        # disabled by default, by ldap_configure()
        if enabled:
            self.enable()

        if running:
            self.restart()
