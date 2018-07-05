#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function, absolute_import

import logging
import errno
import os
import pwd
import grp
import shutil
import stat

import ldap

from ipaserver import p11helper as _ipap11helper
from ipapython.dnsutil import DNSName
from ipaserver.install import service
from ipaserver.install import installutils
from ipapython.dn import DN
from ipapython import directivesetter
from ipapython import ipautil
from ipaplatform.constants import constants
from ipaplatform.paths import paths
from ipalib import errors, api
from ipalib.constants import SOFTHSM_DNSSEC_TOKEN_LABEL
from ipaserver.install.bindinstance import dns_container_exists

logger = logging.getLogger(__name__)

replica_keylabel_template = u"dnssec-replica:%s"


def dnssec_container_exists(suffix):
    """
    Test whether the dns container exists.
    """
    assert isinstance(suffix, DN)
    return api.Backend.ldap2.entry_exists(
        DN(('cn', 'sec'), ('cn', 'dns'), suffix))


def remove_replica_public_keys(hostname):
    keysyncd = DNSKeySyncInstance()
    keysyncd.remove_replica_public_keys(hostname)


class DNSKeySyncInstance(service.Service):
    def __init__(self, fstore=None, logger=logger):
        super(DNSKeySyncInstance, self).__init__(
            "ipa-dnskeysyncd",
            service_desc="DNS key synchronization service",
            fstore=fstore,
            service_prefix=u'ipa-dnskeysyncd',
            keytab=paths.IPA_DNSKEYSYNCD_KEYTAB
        )
        self.extra_config = [u'dnssecVersion 1', ]  # DNSSEC enabled
        self.named_uid = None
        self.named_gid = None
        self.ods_uid = None
        self.ods_gid = None

    suffix = ipautil.dn_attribute_property('_suffix')

    def set_dyndb_ldap_workdir_permissions(self):
        """
        Setting up correct permissions to allow write/read access for daemons
        """
        if self.named_uid is None:
            self.named_uid = self.__get_named_uid()

        if self.named_gid is None:
            self.named_gid = self.__get_named_gid()

        if not os.path.exists(paths.BIND_LDAP_DNS_IPA_WORKDIR):
            os.mkdir(paths.BIND_LDAP_DNS_IPA_WORKDIR, 0o770)
        # dnssec daemons require to have access into the directory
        os.chmod(paths.BIND_LDAP_DNS_IPA_WORKDIR, 0o770)
        os.chown(paths.BIND_LDAP_DNS_IPA_WORKDIR, self.named_uid,
                 self.named_gid)

    def remove_replica_public_keys(self, replica_fqdn):
        ldap = api.Backend.ldap2
        dn_base = DN(('cn', 'keys'), ('cn', 'sec'), ('cn', 'dns'), api.env.basedn)
        keylabel = replica_keylabel_template % DNSName(replica_fqdn).\
            make_absolute().canonicalize().ToASCII()
        # get old keys from LDAP
        search_kw = {
            'objectclass': u"ipaPublicKeyObject",
            'ipk11Label': keylabel,
            'ipk11Wrap': True,
        }
        filter = ldap.make_filter(search_kw, rules=ldap.MATCH_ALL)
        entries, _truncated = ldap.find_entries(filter=filter, base_dn=dn_base)
        for entry in entries:
            ldap.delete_entry(entry)

    def start_dnskeysyncd(self):
        print("Restarting ipa-dnskeysyncd")
        self.__start()

    def create_instance(self, fqdn, realm_name):
        self.fqdn = fqdn
        self.realm = realm_name
        self.suffix = ipautil.realm_to_suffix(self.realm)
        try:
            self.stop()
        except Exception:
            pass

        # checking status step must be first
        self.step("checking status", self.__check_dnssec_status)
        self.step("setting up bind-dyndb-ldap working directory",
                  self.set_dyndb_ldap_workdir_permissions)
        self.step("setting up kerberos principal", self.__setup_principal)
        self.step("setting up SoftHSM", self.__setup_softhsm)
        self.step("adding DNSSEC containers", self.__setup_dnssec_containers)
        self.step("creating replica keys", self.__setup_replica_keys)
        self.step("configuring ipa-dnskeysyncd to start on boot", self.__enable)
        # we need restart named after setting up this service
        self.start_creation()

    def __get_named_uid(self):
        try:
            return pwd.getpwnam(constants.NAMED_USER).pw_uid
        except KeyError:
            raise RuntimeError("Named UID not found")

    def __get_named_gid(self):
        try:
            return grp.getgrnam(constants.NAMED_GROUP).gr_gid
        except KeyError:
            raise RuntimeError("Named GID not found")

    def __check_dnssec_status(self):
        self.named_uid = self.__get_named_uid()
        self.named_gid = self.__get_named_gid()

        try:
            self.ods_uid = pwd.getpwnam(constants.ODS_USER).pw_uid
        except KeyError:
            raise RuntimeError("OpenDNSSEC UID not found")

        try:
            self.ods_gid = grp.getgrnam(constants.ODS_GROUP).gr_gid
        except KeyError:
            raise RuntimeError("OpenDNSSEC GID not found")

        if not dns_container_exists(self.suffix):
            raise RuntimeError("DNS container does not exist")

        # ready to be installed, storing a state is required to run uninstall
        self.backup_state("configured", True)

    def __setup_dnssec_containers(self):
        """
        Setup LDAP containers for DNSSEC
        """
        if dnssec_container_exists(self.suffix):

            logger.info("DNSSEC container exists (step skipped)")
            return

        self._ldap_mod("dnssec.ldif", {'SUFFIX': self.suffix, })

    def __setup_softhsm(self):
        assert self.ods_uid is not None
        assert self.named_gid is not None

        token_dir_exists = os.path.exists(paths.DNSSEC_TOKENS_DIR)

        # create dnssec directory
        if not os.path.exists(paths.IPA_DNSSEC_DIR):
            logger.debug("Creating %s directory", paths.IPA_DNSSEC_DIR)
            os.mkdir(paths.IPA_DNSSEC_DIR)
            os.chmod(paths.IPA_DNSSEC_DIR, 0o770)
            # chown ods:named
            os.chown(paths.IPA_DNSSEC_DIR, self.ods_uid, self.named_gid)

        # setup softhsm2 config file
        softhsm_conf_txt = ("# SoftHSM v2 configuration file \n"
                            "# File generated by IPA instalation\n"
                            "directories.tokendir = %(tokens_dir)s\n"
                            "objectstore.backend = file") % {
                               'tokens_dir': paths.DNSSEC_TOKENS_DIR
                            }
        logger.debug("Creating new softhsm config file")
        named_fd = open(paths.DNSSEC_SOFTHSM2_CONF, 'w')
        named_fd.seek(0)
        named_fd.truncate(0)
        named_fd.write(softhsm_conf_txt)
        named_fd.close()
        os.chmod(paths.DNSSEC_SOFTHSM2_CONF, 0o644)

        # setting up named to use softhsm2
        if not self.fstore.has_file(paths.SYSCONFIG_NAMED):
            self.fstore.backup_file(paths.SYSCONFIG_NAMED)

        # setting up named and ipa-dnskeysyncd to use our softhsm2 config
        for sysconfig in [paths.SYSCONFIG_NAMED,
                          paths.SYSCONFIG_IPA_DNSKEYSYNCD]:
            directivesetter.set_directive(sysconfig, 'SOFTHSM2_CONF',
                                          paths.DNSSEC_SOFTHSM2_CONF,
                                          quotes=False, separator='=')

        if (token_dir_exists and os.path.exists(paths.DNSSEC_SOFTHSM_PIN) and
                os.path.exists(paths.DNSSEC_SOFTHSM_PIN_SO)):
            # there is initialized softhsm
            return

        # remove old tokens
        if token_dir_exists:
            logger.debug('Removing old tokens directory %s',
                         paths.DNSSEC_TOKENS_DIR)
            shutil.rmtree(paths.DNSSEC_TOKENS_DIR)

        # create tokens subdirectory
        logger.debug('Creating tokens %s directory', paths.DNSSEC_TOKENS_DIR)
        # sticky bit is required by daemon
        os.mkdir(paths.DNSSEC_TOKENS_DIR)
        os.chmod(paths.DNSSEC_TOKENS_DIR, 0o770 | stat.S_ISGID)
        # chown to ods:named
        os.chown(paths.DNSSEC_TOKENS_DIR, self.ods_uid, self.named_gid)

        # generate PINs for softhsm
        pin_length = 30  # Bind allows max 32 bytes including ending '\0'
        pin = ipautil.ipa_generate_password(
            entropy_bits=0, special=None, min_len=pin_length)
        pin_so = ipautil.ipa_generate_password(
            entropy_bits=0, special=None, min_len=pin_length)

        logger.debug("Saving user PIN to %s", paths.DNSSEC_SOFTHSM_PIN)
        named_fd = open(paths.DNSSEC_SOFTHSM_PIN, 'w')
        named_fd.seek(0)
        named_fd.truncate(0)
        named_fd.write(pin)
        named_fd.close()
        os.chmod(paths.DNSSEC_SOFTHSM_PIN, 0o770)
        # chown to ods:named
        os.chown(paths.DNSSEC_SOFTHSM_PIN, self.ods_uid, self.named_gid)

        logger.debug("Saving SO PIN to %s", paths.DNSSEC_SOFTHSM_PIN_SO)
        named_fd = open(paths.DNSSEC_SOFTHSM_PIN_SO, 'w')
        named_fd.seek(0)
        named_fd.truncate(0)
        named_fd.write(pin_so)
        named_fd.close()
        # owner must be root
        os.chmod(paths.DNSSEC_SOFTHSM_PIN_SO, 0o400)

        # initialize SoftHSM

        command = [
            paths.SOFTHSM2_UTIL,
            '--init-token',
            '--free',  # use random free slot
            '--label', SOFTHSM_DNSSEC_TOKEN_LABEL,
            '--pin', pin,
            '--so-pin', pin_so,
        ]
        logger.debug("Initializing tokens")
        os.environ["SOFTHSM2_CONF"] = paths.DNSSEC_SOFTHSM2_CONF
        ipautil.run(command, nolog=(pin, pin_so,))

    def __setup_replica_keys(self):
        keylabel = replica_keylabel_template % DNSName(self.fqdn).\
            make_absolute().canonicalize().ToASCII()

        ldap = api.Backend.ldap2
        dn_base = DN(('cn', 'keys'), ('cn', 'sec'), ('cn', 'dns'), api.env.basedn)

        with open(paths.DNSSEC_SOFTHSM_PIN, "r") as f:
                pin = f.read()

        os.environ["SOFTHSM2_CONF"] = paths.DNSSEC_SOFTHSM2_CONF
        p11 = _ipap11helper.P11_Helper(
            SOFTHSM_DNSSEC_TOKEN_LABEL, pin, paths.LIBSOFTHSM2_SO)

        try:
            # generate replica keypair
            logger.debug("Creating replica's key pair")
            key_id = None
            while True:
                # check if key with this ID exist in softHSM
                key_id = _ipap11helper.gen_key_id()
                replica_pubkey_dn = DN(('ipk11UniqueId', 'autogenerate'), dn_base)


                pub_keys = p11.find_keys(_ipap11helper.KEY_CLASS_PUBLIC_KEY,
                                        label=keylabel,
                                        id=key_id)
                if pub_keys:
                    # key with id exists
                    continue

                priv_keys = p11.find_keys(_ipap11helper.KEY_CLASS_PRIVATE_KEY,
                                        label=keylabel,
                                        id=key_id)
                if not priv_keys:
                    break  # we found unique id

            public_key_handle, _privkey_handle = p11.generate_replica_key_pair(
                    keylabel, key_id,
                    pub_cka_verify=False,
                    pub_cka_verify_recover=False,
                    pub_cka_wrap=True,
                    priv_cka_unwrap=True,
                    priv_cka_sensitive=True,
                    priv_cka_extractable=False)

            # export public key
            public_key_blob = p11.export_public_key(public_key_handle)

            # save key to LDAP
            replica_pubkey_objectclass = [
                'ipk11Object', 'ipk11PublicKey', 'ipaPublicKeyObject', 'top'
            ]
            kw = {
                'objectclass': replica_pubkey_objectclass,
                'ipk11UniqueId': [u'autogenerate'],
                'ipk11Label': [keylabel],
                'ipaPublicKey': [public_key_blob],
                'ipk11Id': [key_id],
                'ipk11Wrap': [True],
                'ipk11Verify': [False],
                'ipk11VerifyRecover': [False],
            }

            logger.debug("Storing replica public key to LDAP, %s",
                         replica_pubkey_dn)

            entry = ldap.make_entry(replica_pubkey_dn, **kw)
            ldap.add_entry(entry)
            logger.debug("Replica public key stored")

            logger.debug("Setting CKA_WRAP=False for old replica keys")
            # first create new keys, we don't want disable keys before, we
            # have new keys in softhsm and LDAP

            # get replica pub keys with CKA_WRAP=True
            replica_pub_keys = p11.find_keys(_ipap11helper.KEY_CLASS_PUBLIC_KEY,
                                             label=keylabel,
                                             cka_wrap=True)
            # old keys in softHSM
            for handle in replica_pub_keys:
                # don't disable wrapping for new key
                # compare IDs not handle
                if key_id != p11.get_attribute(handle, _ipap11helper.CKA_ID):
                    p11.set_attribute(handle, _ipap11helper.CKA_WRAP, False)

            # get old keys from LDAP
            search_kw = {
                'objectclass': u"ipaPublicKeyObject",
                'ipk11Label': keylabel,
                'ipk11Wrap': True,
            }
            filter = ldap.make_filter(search_kw, rules=ldap.MATCH_ALL)
            entries, _truncated = ldap.find_entries(filter=filter,
                                                   base_dn=dn_base)
            for entry in entries:
                # don't disable wrapping for new key
                if entry.single_value['ipk11Id'] != key_id:
                    entry['ipk11Wrap'] = [False]
                    ldap.update_entry(entry)

        finally:
            p11.finalize()

        # change tokens mod/owner
        logger.debug("Changing ownership of token files")
        for (root, dirs, files) in os.walk(paths.DNSSEC_TOKENS_DIR):
            for directory in dirs:
                dir_path = os.path.join(root, directory)
                os.chmod(dir_path, 0o770 | stat.S_ISGID)
                # chown to ods:named
                os.chown(dir_path, self.ods_uid, self.named_gid)
            for filename in files:
                file_path = os.path.join(root, filename)
                os.chmod(file_path, 0o770 | stat.S_ISGID)
                # chown to ods:named
                os.chown(file_path, self.ods_uid, self.named_gid)

    def __enable(self):
        try:
            self.ldap_configure('DNSKeySync', self.fqdn, None,
                                self.suffix, self.extra_config)
        except errors.DuplicateEntry:
            logger.error("DNSKeySync service already exists")

    def __setup_principal(self):
        assert self.ods_gid is not None
        installutils.remove_keytab(self.keytab)
        installutils.kadmin_addprinc(self.principal)

        # Store the keytab on disk
        installutils.create_keytab(self.keytab, self.principal)
        p = self.move_service(self.principal)
        if p is None:
            # the service has already been moved, perhaps we're doing a DNS reinstall
            dnssynckey_principal_dn = DN(
                ('krbprincipalname', self.principal),
                ('cn', 'services'), ('cn', 'accounts'), self.suffix)
        else:
            dnssynckey_principal_dn = p

        # Make sure access is strictly reserved to the named user
        os.chown(self.keytab, 0, self.ods_gid)
        os.chmod(self.keytab, 0o440)

        dns_group = DN(('cn', 'DNS Servers'), ('cn', 'privileges'),
                       ('cn', 'pbac'), self.suffix)
        mod = [(ldap.MOD_ADD, 'member', dnssynckey_principal_dn)]

        try:
            api.Backend.ldap2.modify_s(dns_group, mod)
        except ldap.TYPE_OR_VALUE_EXISTS:
            pass
        except Exception as e:
            logger.critical("Could not modify principal's %s entry: %s",
                            dnssynckey_principal_dn, str(e))
            raise

        # bind-dyndb-ldap persistent search feature requires both size and time
        # limit-free connection

        mod = [(ldap.MOD_REPLACE, 'nsTimeLimit', '-1'),
               (ldap.MOD_REPLACE, 'nsSizeLimit', '-1'),
               (ldap.MOD_REPLACE, 'nsIdleTimeout', '-1'),
               (ldap.MOD_REPLACE, 'nsLookThroughLimit', '-1')]
        try:
            api.Backend.ldap2.modify_s(dnssynckey_principal_dn, mod)
        except Exception as e:
            logger.critical("Could not set principal's %s LDAP limits: %s",
                            dnssynckey_principal_dn, str(e))
            raise

    def __start(self):
        try:
            self.restart()
        except Exception as e:
            print("Failed to start ipa-dnskeysyncd")
            logger.debug("Failed to start ipa-dnskeysyncd: %s", e)


    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring %s" % self.service_name)

        # Just eat states
        self.restore_state("running")
        self.restore_state("enabled")
        self.restore_state("configured")

        # stop and disable service (IPA service, we do not need it anymore)
        self.stop()
        self.disable()

        for f in [paths.SYSCONFIG_NAMED]:
            try:
                self.fstore.restore_file(f)
            except ValueError as error:
                logger.debug('%s', error)

        # remove softhsm pin, to make sure new installation will generate
        # new token database
        # do not delete *so pin*, user can need it to get token data
        installutils.remove_file(paths.DNSSEC_SOFTHSM_PIN)
        installutils.remove_file(paths.DNSSEC_SOFTHSM2_CONF)

        try:
            shutil.rmtree(paths.DNSSEC_TOKENS_DIR)
        except OSError as e:
            if e.errno != errno.ENOENT:
                logger.exception(
                    "Failed to remove %s", paths.DNSSEC_TOKENS_DIR
                )

        installutils.remove_keytab(self.keytab)
