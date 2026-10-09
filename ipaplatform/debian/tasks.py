#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

"""
This module contains default Debian-specific implementations of system tasks.
"""

from __future__ import absolute_import

import logging
import os
import shutil
from pathlib import Path

from ipaplatform.base.tasks import BaseTaskNamespace
from ipaplatform.redhat.tasks import RedHatTaskNamespace
from ipaplatform.paths import paths

from ipapython import directivesetter
from ipapython import ipautil
from ipapython.dn import DN

logger = logging.getLogger(__name__)


class HttpdState:
    _prefix = ""
    _enable = ""
    _disable = ""
    _query = ""

    def __init__(self, key, found, enabled, by_maintainer):
        self.key = key
        self.found = found
        self.enabled = enabled
        self.by_maintainer = by_maintainer

    @classmethod
    def prefix(cls):
        return cls._prefix

    @classmethod
    def from_store(cls, sstore, key):
        if not sstore.has_state(cls.prefix() + key):
            return None

        found = sstore.get_state(cls.prefix() + key, "found")
        enabled = sstore.get_state(cls.prefix() + key, "enabled")
        by_maintainer = sstore.get_state(cls.prefix() + key, "by_maintainer")

        return cls(key, found, enabled, by_maintainer)

    @classmethod
    def has_state(cls, sstore, key):
        return sstore.has_state(cls.prefix() + key)

    @classmethod
    def get_state(cls, key):
        result = ipautil.run([paths.A2QUERY, "-" + cls._query, key],
                             raiseonerr=False, capture_output=True)

        found = False
        enabled = False
        by_maintainer = False
        if result.returncode == 0:
            enabled = True
            found = True
        elif result.returncode == 1:
            # not found, so we'll leave everything as is
            pass
        else:
            found = True

        if "by maintainer script" in result.output:
            by_maintainer = True

        return cls(key, found, enabled, by_maintainer)

    def backup_state(self, sstore):
        sstore.backup_state(self.prefix() + self.key, "found", self.found)
        sstore.backup_state(self.prefix() + self.key, "enabled", self.enabled)
        sstore.backup_state(self.prefix() + self.key, "by_maintainer", self.by_maintainer)

    @classmethod
    def configure(cls, sstore, key):
        if cls.has_state(sstore, key):
            # already configured
            return False

        state = cls.get_state(key)
        state.backup_state(sstore)

        if not state.enabled:
            ipautil.run([cls._enable, key])
            return True

        return False

    @classmethod
    def configure_all(cls, sstore, keys):
        changed = False
        for key in keys:
            if cls.configure(sstore, key):
                changed = True

        return changed

    @classmethod
    def restore(cls, sstore, key):
        state = cls.from_store(sstore, key)
        if state is None:
            # if we don't know about the state it's safest not to touch it
            return False

        if state.enabled:
            # leave it as is
            return False

        command = [cls._disable]
        if not state.found:
            command.append("--purge")
        elif state.by_maintainer:
            command.append("--maintmode")

        command.append(key)

        ipautil.run(command, raiseonerr=False, capture_output=True)
        return True

    @classmethod
    def restore_all(cls, sstore, keys):
        changed = False
        for key in keys:
            if cls.restore(sstore, key):
                changed = True

        return changed


class HttpdModuleState(HttpdState):
    _prefix = "httpd_mod_"
    _enable = paths.A2ENMOD
    _disable = paths.A2DISMOD
    _query = "m"


class HttpdConfState(HttpdState):
    _prefix = "httpd_conf_"
    _enable = paths.A2ENCONF
    _disable = paths.A2DISCONF
    _query = "c"


class HttpdSiteState(HttpdState):
    _prefix = "httpd_site_"
    _enable = paths.A2ENSITE
    _disable = paths.A2DISSITE
    _query = "s"


class DebianTaskNamespace(RedHatTaskNamespace):
    def restore_pre_ipa_client_configuration(self, fstore, statestore,
                                             was_sssd_installed,
                                             was_sssd_configured):
        try:
            ipautil.run(["pam-auth-update",
                         "--package", "--remove", "mkhomedir"])
        except ipautil.CalledProcessError:
            return False
        return True

    def set_nisdomain(self, nisdomain):
        # Debian doesn't use authconfig, nothing to set
        return True

    def modify_nsswitch_pam_stack(self, sssd, mkhomedir, statestore, sudo=True,
                                  subid=False):
        if mkhomedir:
            try:
                ipautil.run(["pam-auth-update",
                             "--package", "--enable", "mkhomedir"])
            except ipautil.CalledProcessError:
                return False
            return True
        else:
            return True

    def modify_pam_to_use_krb5(self, statestore):
        # Debian doesn't use authconfig, this is handled by pam-auth-update
        return True

    def backup_auth_configuration(self, path):
        # Debian doesn't use authconfig, nothing to backup
        return True

    def restore_auth_configuration(self, path):
        # Debian doesn't use authconfig, nothing to restore
        return True

    def migrate_auth_configuration(self, statestore):
        # Debian doesn't have authselect
        return True

    def configure_httpd_modules(self, sstore, modules):
        HttpdModuleState.configure_all(sstore, modules)

    def restore_httpd_modules(self, sstore, modules):
        HttpdModuleState.restore_all(sstore, modules)

    def configure_httpd_confs(self, sstore, confs):
        HttpdConfState.configure_all(sstore, confs)

    def restore_httpd_confs(self, sstore, confs):
        HttpdConfState.restore_all(sstore, confs)

    def configure_httpd_sites(self, sstore, sites):
        HttpdSiteState.configure_all(sstore, sites)

    def restore_httpd_sites(self, sstore, sites):
        HttpdSiteState.restore_all(sstore, sites)

    def configure_httpd_wsgi_conf(self):
        # Debian doesn't require special mod_wsgi configuration
        pass

    def configure_httpd_protocol(self):
        # TLS 1.3 is not yet supported
        directivesetter.set_directive(paths.HTTPD_SSL_CONF,
                                      'SSLProtocol',
                                      'TLSv1.2', False)

    def setup_httpd_logging(self):
        # Debian handles httpd logging differently
        pass

    def configure_pkcs11_modules(self, fstore):
        # Debian doesn't use p11-kit
        pass

    def restore_pkcs11_modules(self, fstore):
        pass

    def platform_insert_ca_certs(self, ca_certs):
        # ca-certificates does not use this file, so it doesn't matter if we
        # fail to create it.
        try:
            self.write_p11kit_certs(paths.IPA_P11_KIT, ca_certs),
        except Exception:
            logger.exception("""\
Could not create p11-kit anchor trust file. On Debian this file is not
used by ca-certificates and is provided for information only.\
""")

        return any([
            self.write_ca_certificates_dir(
                paths.CA_CERTIFICATES_DIR, ca_certs
            ),
            self.remove_ca_certificates_bundle(
                paths.CA_CERTIFICATES_BUNDLE_PEM
            ),
        ])

    @staticmethod
    def write_ca_certificates_dir(directory, ca_certs):
        # pylint: disable=ipa-forbidden-import
        from ipalib import x509  # FixMe: break import cycle
        # pylint: enable=ipa-forbidden-import

        path = Path(directory)
        try:
            path.mkdir(mode=0o755, exist_ok=True)
        except Exception:
            logger.error("Could not create %s", path)
            raise

        for cert, nickname, trusted, _ext_key_usage, _serial in ca_certs:
            if not trusted:
                continue

            # I'm not handling errors here because they have already
            # been checked by the time we get here
            subject = DN(cert.subject)
            issuer = DN(cert.issuer)

            # Construct the certificate filename using the Subject DN so that
            # the user can see which CA a particular file is for, and include
            # the serial number to disambiguate clashes where a subordinate CA
            # had a new certificate issued.
            #
            # Strictly speaking, certificates are uniquely identified by (Issuer
            # DN, Serial Number). Do we care about the possibility of a clash
            # where a subordinate CA had two certificates issued by different
            # CAs who used the same serial number?)
            filename = f'{subject.ldap_text()} {cert.serial_number}.crt'

            # Some CAs have DNs with a / or NUL character, which are not legal
            # in paths. Also escape some other annoying characters for good
            # measure.
            bad_chars = {'\0', '/', ':'}
            safe_filename = ''.join(
                ('-' if c in bad_chars else c for c in filename)
            )

            cert_path = os.path.join(path, safe_filename)
            try:
                f = open(cert_path, 'w')
            except Exception:
                logger.error("Could not create %s", cert_path)
                raise

            with f:
                try:
                    os.fchmod(f.fileno(), 0o644)
                except Exception:
                    logger.error("Could not set mode of %s", cert_path)
                    raise

                try:
                    f.write(f"""\
This file was created by IPA. Do not edit.

Description: {nickname}
Subject: {subject.ldap_text()}
Issuer: {issuer.ldap_text()}
Serial Number (dec): {cert.serial_number}
Serial Number (hex): {cert.serial_number:#x}

""")
                    pem = cert.public_bytes(x509.Encoding.PEM).decode('ascii')
                    f.write(pem)
                except Exception:
                    logger.error("Could not write to %s", cert_path)
                    raise

        return True

    def platform_remove_ca_certs(self):
        return any([
            self.remove_ca_certificates_dir(paths.CA_CERTIFICATES_DIR),
            self.remove_ca_certificates_bundle(paths.IPA_P11_KIT),
            self.remove_ca_certificates_bundle(
                paths.CA_CERTIFICATES_BUNDLE_PEM
            ),
        ])

    @staticmethod
    def remove_ca_certificates_dir(directory):
        path = Path(directory)
        if not path.exists():
            return False

        try:
            shutil.rmtree(path)
        except Exception:
            logger.error("Could not remove %s", path)
            raise

        return True

    # Debian doesn't use authselect, so call disable_ldap_automount
    def disable_ldap_automount(self, statestore):
        return BaseTaskNamespace.disable_ldap_automount(self, statestore)

tasks = DebianTaskNamespace()
