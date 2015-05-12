#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import re
import os
import shutil
import pwd
import fileinput
import ConfigParser
import sys
import krbV

from ipalib import api
import SSSDConfig
import ipalib.util
import ipalib.errors
from ipaplatform import services
from ipaplatform.tasks import tasks
from ipapython import ipautil, sysrestore, version, certdb
from ipapython import ipaldap
from ipapython.ipa_log_manager import *
from ipapython import certmonger
from ipapython import dogtag
from ipaplatform.paths import paths
from ipaserver.install import installutils
from ipaserver.install import dsinstance
from ipaserver.install import httpinstance
from ipaserver.install import memcacheinstance
from ipaserver.install import bindinstance
from ipaserver.install import service
from ipaserver.install import cainstance
from ipaserver.install import certs
from ipaserver.install import otpdinstance
from ipaserver.install import schemaupdate
from ipaserver.install import sysupgrade
from ipaserver.install import dnskeysyncinstance
from ipaserver.install.upgradeinstance import IPAUpgrade
from ipaserver.install.ldapupdate import BadSyntax


class KpasswdInstance(service.SimpleServiceInstance):
    def __init__(self):
        service.SimpleServiceInstance.__init__(self, "ipa_kpasswd")

def uninstall_ipa_kpasswd():
    """
    We can't use the full service uninstaller because that will attempt
    to stop and disable the service which by now doesn't exist. We just
    want to clean up sysrestore.state to remove all references to
    ipa_kpasswd.
    """
    ipa_kpasswd = KpasswdInstance()

    running = ipa_kpasswd.restore_state("running")
    enabled = not ipa_kpasswd.restore_state("enabled")

    if enabled is not None and not enabled:
        ipa_kpasswd.remove()

def backup_file(filename, ext):
    """Make a backup of filename using ext as the extension. Do not overwrite
       previous backups."""
    if not os.path.isabs(filename):
        raise ValueError("Absolute path required")

    backupfile = filename + ".bak"
    (reldir, file) = os.path.split(filename)

    while os.path.exists(backupfile):
        backupfile = backupfile + "." + str(ext)

    try:
        shutil.copy2(filename, backupfile)
    except IOError as e:
        if e.errno == 2: # No such file or directory
            pass
        else:
            raise e

def update_conf(sub_dict, filename, template_filename):
    template = ipautil.template_file(template_filename, sub_dict)
    fd = open(filename, "w")
    fd.write(template)
    fd.close()

def find_hostname():
    """Find the hostname currently configured in ipa-rewrite.conf"""
    filename=paths.HTTPD_IPA_REWRITE_CONF

    if not ipautil.file_exists(filename):
        return None

    pattern = "^[\s#]*.*https:\/\/([A-Za-z0-9\.\-]*)\/.*"
    p = re.compile(pattern)
    for line in fileinput.input(filename):
        if p.search(line):
            fileinput.close()
            return p.search(line).group(1)
    fileinput.close()

    raise RuntimeError("Unable to determine the fully qualified hostname from %s" % filename)

def find_autoredirect(fqdn):
    """
    When upgrading ipa-rewrite.conf we need to see if the automatic redirect
    was disabled during install time (or afterward). So sift through the
    configuration file and see if we can determine the status.

    Returns True if autoredirect is enabled, False otherwise
    """
    filename = paths.HTTPD_IPA_REWRITE_CONF
    if os.path.exists(filename):
        pattern = "^RewriteRule \^/\$ https://%s/ipa/ui \[L,NC,R=301\]" % fqdn
        p = re.compile(pattern)
        for line in fileinput.input(filename):
            if p.search(line):
                fileinput.close()
                return True
        fileinput.close()
        return False
    return True

def find_version(filename):
    """Find the version of a configuration file

    If no VERSION entry exists in the file, returns 0.
    If the file does not exist, returns -1.
    """
    if os.path.exists(filename):
        pattern = "^[\s#]*VERSION\s+([0-9]+)\s+.*"
        p = re.compile(pattern)
        for line in fileinput.input(filename):
            if p.search(line):
                fileinput.close()
                return p.search(line).group(1)
        fileinput.close()

        # no VERSION found
        return 0
    else:
        return -1

def upgrade_file(sub_dict, filename, template, add=False):
    """
    Get the version from the current and template files and update the
    installed configuration file if there is a new template.

    If add is True then create a new configuration file.
    """
    old = int(find_version(filename))
    new = int(find_version(template))

    if old < 0 and not add:
        root_logger.error("%s not found." % filename)
        raise RuntimeError("%s not found." % filename)

    if new < 0:
        root_logger.error("%s not found." % template)

    if old == 0:
        # The original file does not have a VERSION entry. This means it's now
        # managed by IPA, but previously was not.
        root_logger.warning("%s is now managed by IPA. It will be "
            "overwritten. A backup of the original will be made.", filename)

    if old < new or (add and old == 0):
        backup_file(filename, new)
        update_conf(sub_dict, filename, template)
        root_logger.info("Upgraded %s to version %d", filename, new)

def check_certs():
    """Check ca.crt is in the right place, and try to fix if not"""
    root_logger.info('[Verifying that root certificate is published]')
    if not os.path.exists(paths.CA_CRT):
        ca_file = paths.ALIAS_CACERT_ASC
        if os.path.exists(ca_file):
            old_umask = os.umask(022)   # make sure its readable by httpd
            try:
                shutil.copyfile(ca_file, paths.CA_CRT)
            finally:
                os.umask(old_umask)
        else:
            root_logger.error("Missing Certification Authority file.")
            root_logger.error("You should place a copy of the CA certificate in /usr/share/ipa/html/ca.crt")
    else:
        root_logger.debug('Certificate file exists')

def upgrade_pki(ca, fstore):
    """
    Update/add the dogtag proxy configuration. The IPA side of this is
    handled in ipa-pki-proxy.conf.

    This requires enabling SSL renegotiation.
    """
    configured_constants = dogtag.configured_constants()
    root_logger.info('[Verifying that CA proxy configuration is correct]')
    if not ca.is_configured():
        root_logger.info('CA is not configured')
        return

    http = httpinstance.HTTPInstance(fstore)
    http.enable_mod_nss_renegotiate()
    if not installutils.get_directive(configured_constants.CS_CFG_PATH,
                                      'proxy.securePort', '=') and \
            os.path.exists(paths.PKI_SETUP_PROXY):
        # update proxy configuration with stopped dogtag to prevent corruption
        # of CS.cfg
        ipautil.run([paths.PKI_SETUP_PROXY, '-pki_instance_root=/var/lib',
                     '-pki_instance_name=pki-ca','-subsystem_type=ca'])
        root_logger.debug('Proxy configuration updated')
    else:
        root_logger.debug('Proxy configuration up-to-date')

def update_dbmodules(realm, filename=paths.KRB5_CONF):
    newfile = []
    found_dbrealm = False
    found_realm = False
    prefix = ''

    root_logger.info('[Verifying that KDC configuration is using ipa-kdb backend]')
    st = os.stat(filename)
    fd = open(filename)

    lines = fd.readlines()
    fd.close()

    if '    db_library = ipadb.so\n' in lines:
        root_logger.debug('dbmodules already updated in %s', filename)
        return

    for line in lines:
        if line.startswith('[dbmodules]'):
            found_dbrealm = True
        if found_dbrealm and line.find(realm) > -1:
            found_realm = True
            prefix = '#'
        if found_dbrealm and line.find('}') > -1 and found_realm:
            found_realm = False
            newfile.append('#%s' % line)
            prefix = ''
            continue

        newfile.append('%s%s' % (prefix, line))

    # Append updated dbmodules information
    newfile.append('  %s = {\n' % realm)
    newfile.append('    db_library = ipadb.so\n')
    newfile.append('  }\n')

    # Write out new file
    fd = open(filename, 'w')
    fd.write("".join(newfile))
    fd.close()
    root_logger.debug('%s updated', filename)

def cleanup_kdc(fstore):
    """
    Clean up old KDC files if they exist. We need to remove the actual
    file and any references in the uninstall configuration.
    """
    root_logger.info('[Checking for deprecated KDC configuration files]')
    for file in ['kpasswd.keytab', 'ldappwd']:
        filename = os.path.join(paths.VAR_KERBEROS_KRB5KDC_DIR, file)
        installutils.remove_file(filename)
        if fstore.has_file(filename):
            fstore.untrack_file(filename)
            root_logger.debug('Uninstalling %s', filename)

def cleanup_adtrust(fstore):
    """
    Clean up any old Samba backup files that were deprecated.
    """

    root_logger.info('[Checking for deprecated backups of Samba '
                     'configuration files]')

    for backed_up_file in [paths.SMB_CONF]:
        if fstore.has_file(backed_up_file):
            fstore.untrack_file(backed_up_file)
            root_logger.debug('Removing %s from backup', backed_up_file)


def setup_firefox_extension(fstore):
    """Set up the Firefox configuration extension, if it's not set up yet
    """
    root_logger.info('[Setting up Firefox extension]')
    http = httpinstance.HTTPInstance(fstore)
    realm = api.env.realm
    domain = api.env.domain
    http.setup_firefox_extension(realm, domain)


def ca_configure_profiles_acl(ca):
    root_logger.info('[Authorizing RA Agent to modify profiles]')

    if not ca.is_configured():
        root_logger.info('CA is not configured')
        return False

    return cainstance.configure_profiles_acl()


def ca_enable_ldap_profile_subsystem(ca):
    root_logger.info('[Ensuring CA is using LDAPProfileSubsystem]')
    if not ca.is_configured():
        root_logger.info('CA is not configured')
        return False

    caconfig = dogtag.configured_constants()

    needs_update = False
    directive = None
    try:
        for i in range(15):
            directive = "subsystem.{}.class".format(i)
            value = installutils.get_directive(
                caconfig.CS_CFG_PATH,
                directive,
                separator='=')
            if value == 'com.netscape.cmscore.profile.ProfileSubsystem':
                needs_update = True
                break
    except OSError, e:
        root_logger.error('Cannot read CA configuration file "%s": %s',
                caconfig.CS_CFG_PATH, e)
        return False

    if needs_update:
        installutils.set_directive(
            caconfig.CS_CFG_PATH,
            directive,
            'com.netscape.cmscore.profile.LDAPProfileSubsystem',
            quotes=False,
            separator='=')

        ca.restart(dogtag.configured_constants().PKI_INSTANCE_NAME)
        cainstance.migrate_profiles_to_ldap()

    return needs_update


def ca_import_included_profiles(ca):
    root_logger.info('[Ensuring presence of included profiles]')

    if not ca.is_configured():
        root_logger.info('CA is not configured')
        return False

    return cainstance.import_included_profiles()


def upgrade_ca_audit_cert_validity(ca):
    """
    Update the Dogtag audit signing certificate.

    Returns True if restart is needed, False otherwise.
    """
    root_logger.info('[Verifying that CA audit signing cert has 2 year validity]')
    if ca.is_configured():
        return ca.set_audit_renewal()
    else:
        root_logger.info('CA is not configured')
        return False


def named_remove_deprecated_options():
    """
    From IPA 3.3, persistent search is a default mechanism for new DNS zone
    detection.

    Remove psearch, zone_refresh and cache_ttl options, as they have been
    deprecated in bind-dyndb-ldap configuration file.

    When some change in named.conf is done, this functions returns True.
    """

    root_logger.info('[Removing deprecated DNS configuration options]')

    if not bindinstance.named_conf_exists():
        # DNS service may not be configured
        root_logger.info('DNS is not configured')
        return False

    deprecated_options = ['zone_refresh', 'psearch', 'cache_ttl']
    removed_options = []

    try:
        # Remove all the deprecated options
        for option in deprecated_options:
            value = bindinstance.named_conf_get_directive(option)

            if value is not None:
                bindinstance.named_conf_set_directive(option, None)
                removed_options.append(option)

    except IOError as e:
        root_logger.error('Cannot modify DNS configuration in %s: %s',
                          bindinstance.NAMED_CONF, e)

    # Log only the changed options
    if not removed_options:
        root_logger.debug('No changes made')
        return False

    root_logger.debug('The following configuration options have been removed: '
                      '{options}'.format(options = ', '.join(removed_options)))
    return True


def named_set_minimum_connections():
    """
    Sets the minimal number of connections.

    When some change in named.conf is done, this functions returns True.
    """

    changed = False

    root_logger.info('[Ensuring minimal number of connections]')

    if not bindinstance.named_conf_exists():
        # DNS service may not be configured
        root_logger.info('DNS is not configured')
        return changed

    # make sure number of connections is right
    minimum_connections = 4

    try:
        connections = bindinstance.named_conf_get_directive('connections')
    except IOError as e:
        root_logger.debug('Cannot retrieve connections option from %s: %s',
                bindinstance.NAMED_CONF, e)
        return changed

    try:
        if connections is not None:
            connections = int(connections)
    except ValueError:
        # this should not happend, but there is some bad value in
        # "connections" option, bail out
        pass
    else:
        if connections is not None and connections < minimum_connections:
            try:
                bindinstance.named_conf_set_directive('connections',
                                                       minimum_connections)
                root_logger.debug('Connections set to %d', minimum_connections)
            except IOError, e:
                root_logger.error('Cannot update connections in %s: %s',
                        bindinstance.NAMED_CONF, e)
            else:
                changed = True

    if not changed:
        root_logger.debug('No changes made')

    return changed


def named_enable_serial_autoincrement():
    """
    Serial autoincrement is a requirement for zone transfers or DNSSEC. It
    should be enabled both for new installs and upgraded servers.

    When some change in named.conf is done, this functions returns True
    """
    changed = False

    root_logger.info('[Enabling serial autoincrement in DNS]')

    if not bindinstance.named_conf_exists():
        # DNS service may not be configured
        root_logger.info('DNS is not configured')
        return changed

    try:
        serial_autoincrement = bindinstance.named_conf_get_directive(
                                    'serial_autoincrement')
    except IOError as e:
        root_logger.debug('Cannot retrieve psearch option from %s: %s',
                          bindinstance.NAMED_CONF, e)
        return changed
    else:
        serial_autoincrement = None if serial_autoincrement is None \
                else serial_autoincrement.lower()

    # enable SOA serial autoincrement
    if not sysupgrade.get_upgrade_state('named.conf', 'autoincrement_enabled'):
        if serial_autoincrement != 'yes':
            try:
                bindinstance.named_conf_set_directive('serial_autoincrement',
                                                      'yes')
            except IOError, e:
                root_logger.error('Cannot enable serial_autoincrement in %s: %s',
                        bindinstance.NAMED_CONF, e)
                return changed
            else:
                root_logger.debug('Serial autoincrement enabled')
                changed = True
        else:
            root_logger.debug('Serial autoincrement is alredy enabled')
        sysupgrade.set_upgrade_state('named.conf', 'autoincrement_enabled', True)
    else:
        root_logger.debug('Skip serial autoincrement check')

    return changed

def named_update_gssapi_configuration():
    """
    Update GSSAPI configuration in named.conf to a recent API.
    tkey-gssapi-credential and tkey-domain is replaced with tkey-gssapi-keytab.
    Details can be found in https://fedorahosted.org/freeipa/ticket/3429.

    When some change in named.conf is done, this functions returns True
    """

    root_logger.info('[Updating GSSAPI configuration in DNS]')

    if not bindinstance.named_conf_exists():
        # DNS service may not be configured
        root_logger.info('DNS is not configured')
        return False

    if sysupgrade.get_upgrade_state('named.conf', 'gssapi_updated'):
        root_logger.debug('Skip GSSAPI configuration check')
        return False

    try:
        gssapi_keytab = bindinstance.named_conf_get_directive('tkey-gssapi-keytab',
                bindinstance.NAMED_SECTION_OPTIONS)
    except IOError, e:
        root_logger.error('Cannot retrieve tkey-gssapi-keytab option from %s: %s',
                bindinstance.NAMED_CONF, e)
        return False
    else:
        if gssapi_keytab:
            root_logger.debug('GSSAPI configuration already updated')
            sysupgrade.set_upgrade_state('named.conf', 'gssapi_updated', True)
            return False

    try:
        tkey_credential = bindinstance.named_conf_get_directive('tkey-gssapi-credential',
                bindinstance.NAMED_SECTION_OPTIONS)
        tkey_domain = bindinstance.named_conf_get_directive('tkey-domain',
                bindinstance.NAMED_SECTION_OPTIONS)
    except IOError, e:
        root_logger.error('Cannot retrieve tkey-gssapi-credential option from %s: %s',
                bindinstance.NAMED_CONF, e)
        return False

    if not tkey_credential or not tkey_domain:
        root_logger.error('Either tkey-gssapi-credential or tkey-domain is missing in %s. '
            'Skip update.', bindinstance.NAMED_CONF)
        return False

    try:
        bindinstance.named_conf_set_directive(
            'tkey-gssapi-credential', None,
            bindinstance.NAMED_SECTION_OPTIONS)
        bindinstance.named_conf_set_directive(
            'tkey-domain', None,
            bindinstance.NAMED_SECTION_OPTIONS)
        bindinstance.named_conf_set_directive(
            'tkey-gssapi-keytab', paths.NAMED_KEYTAB,
            bindinstance.NAMED_SECTION_OPTIONS)
    except IOError, e:
        root_logger.error('Cannot update GSSAPI configuration in %s: %s',
                bindinstance.NAMED_CONF, e)
        return False
    else:
        root_logger.debug('GSSAPI configuration updated')

    sysupgrade.set_upgrade_state('named.conf', 'gssapi_updated', True)
    return True


def named_update_pid_file():
    """
    Make sure that named reads the pid file from the right file
    """
    root_logger.info('[Updating pid-file configuration in DNS]')

    if not bindinstance.named_conf_exists():
        # DNS service may not be configured
        root_logger.info('DNS is not configured')
        return False

    if sysupgrade.get_upgrade_state('named.conf', 'pid-file_updated'):
        root_logger.debug('Skip pid-file configuration check')
        return False

    try:
        pid_file = bindinstance.named_conf_get_directive('pid-file',
                bindinstance.NAMED_SECTION_OPTIONS)
    except IOError, e:
        root_logger.error('Cannot retrieve pid-file option from %s: %s',
                bindinstance.NAMED_CONF, e)
        return False
    else:
        if pid_file:
            root_logger.debug('pid-file configuration already updated')
            sysupgrade.set_upgrade_state('named.conf', 'pid-file_updated', True)
            return False

    try:
        bindinstance.named_conf_set_directive('pid-file', paths.NAMED_PID,
                                              bindinstance.NAMED_SECTION_OPTIONS)
    except IOError, e:
        root_logger.error('Cannot update pid-file configuration in %s: %s',
                bindinstance.NAMED_CONF, e)
        return False
    else:
        root_logger.debug('pid-file configuration updated')

    sysupgrade.set_upgrade_state('named.conf', 'pid-file_updated', True)
    return True

def named_enable_dnssec():
    """
    Enable dnssec in named.conf
    """
    if not bindinstance.named_conf_exists():
        # DNS service may not be configured
        root_logger.info('DNS is not configured')
        return False

    if not sysupgrade.get_upgrade_state('named.conf', 'dnssec_enabled'):
        root_logger.info('[Enabling "dnssec-enable" configuration in DNS]')
        try:
            bindinstance.named_conf_set_directive('dnssec-enable', 'yes',
                                                  bindinstance.NAMED_SECTION_OPTIONS,
                                                  str_val=False)
        except IOError, e:
            root_logger.error('Cannot update dnssec-enable configuration in %s: %s',
                    bindinstance.NAMED_CONF, e)
            return False
    else:
        root_logger.debug('dnssec-enabled in %s' % bindinstance.NAMED_CONF)

    sysupgrade.set_upgrade_state('named.conf', 'dnssec_enabled', True)
    return True

def named_validate_dnssec():
    """
    Disable dnssec validation in named.conf

    We can't let enable it by default, there can be non-valid dns forwarders
    which breaks DNSSEC validation
    """
    if not bindinstance.named_conf_exists():
        # DNS service may not be configured
        root_logger.info('DNS is not configured')
        return False

    if (not sysupgrade.get_upgrade_state('named.conf', 'dnssec_validation_upgraded')
        and bindinstance.named_conf_get_directive(
                'dnssec-validation', bindinstance.NAMED_SECTION_OPTIONS,
                str_val=False) is None):
        # dnssec-validation is not configured, disable it
        root_logger.info('[Disabling "dnssec-validate" configuration in DNS]')
        try:
            bindinstance.named_conf_set_directive('dnssec-validation', 'no',
                                                  bindinstance.NAMED_SECTION_OPTIONS,
                                                  str_val=False)
        except IOError, e:
            root_logger.error('Cannot update dnssec-validate configuration in %s: %s',
                    bindinstance.NAMED_CONF, e)
            return False
    else:
        root_logger.debug('dnssec-validate already configured in %s' % bindinstance.NAMED_CONF)

    sysupgrade.set_upgrade_state('named.conf', 'dnssec_validation_upgraded', True)
    return True

def named_bindkey_file_option():
    """
    Add options bindkey_file to named.conf
    """
    if not bindinstance.named_conf_exists():
        # DNS service may not be configured
        root_logger.info('DNS is not configured')
        return False

    if sysupgrade.get_upgrade_state('named.conf', 'bindkey-file_updated'):
        root_logger.debug('Skip bindkey-file configuration check')
        return False

    try:
        bindkey_file = bindinstance.named_conf_get_directive('bindkey-file',
                bindinstance.NAMED_SECTION_OPTIONS)
    except IOError, e:
        root_logger.error('Cannot retrieve bindkey-file option from %s: %s',
                bindinstance.NAMED_CONF, e)
        return False
    else:
        if bindkey_file:
            root_logger.debug('bindkey-file configuration already updated')
            sysupgrade.set_upgrade_state('named.conf', 'bindkey-file_updated', True)
            return False

    root_logger.info('[Setting "bindkeys-file" option in named.conf]')
    try:
        bindinstance.named_conf_set_directive('bindkeys-file',
                                              paths.NAMED_BINDKEYS_FILE,
                                              bindinstance.NAMED_SECTION_OPTIONS)
    except IOError, e:
        root_logger.error('Cannot update bindkeys-file configuration in %s: %s',
                bindinstance.NAMED_CONF, e)
        return False


    sysupgrade.set_upgrade_state('named.conf', 'bindkey-file_updated', True)
    return True

def named_managed_keys_dir_option():
    """
    Add options managed_keys_directory to named.conf
    """
    if not bindinstance.named_conf_exists():
        # DNS service may not be configured
        root_logger.info('DNS is not configured')
        return False

    if sysupgrade.get_upgrade_state('named.conf', 'managed-keys-directory_updated'):
        root_logger.debug('Skip managed-keys-directory configuration check')
        return False

    try:
        managed_keys = bindinstance.named_conf_get_directive('managed-keys-directory',
                bindinstance.NAMED_SECTION_OPTIONS)
    except IOError, e:
        root_logger.error('Cannot retrieve managed-keys-directory option from %s: %s',
                bindinstance.NAMED_CONF, e)
        return False
    else:
        if managed_keys:
            root_logger.debug('managed_keys_directory configuration already updated')
            sysupgrade.set_upgrade_state('named.conf', 'managed-keys-directory_updated', True)
            return False

    root_logger.info('[Setting "managed-keys-directory" option in named.conf]')
    try:
        bindinstance.named_conf_set_directive('managed-keys-directory',
                                              paths.NAMED_MANAGED_KEYS_DIR,
                                              bindinstance.NAMED_SECTION_OPTIONS)
    except IOError, e:
        root_logger.error('Cannot update managed-keys-directory configuration in %s: %s',
                bindinstance.NAMED_CONF, e)
        return False


    sysupgrade.set_upgrade_state('named.conf', 'managed-keys-directory_updated', True)
    return True

def named_root_key_include():
    """
    Add options managed_keys_directory to named.conf
    """
    if not bindinstance.named_conf_exists():
        # DNS service may not be configured
        root_logger.info('DNS is not configured')
        return False

    if sysupgrade.get_upgrade_state('named.conf', 'root_key_updated'):
        root_logger.debug('Skip root key configuration check')
        return False

    try:
        root_key = bindinstance.named_conf_include_exists(paths.NAMED_ROOT_KEY)
    except IOError, e:
        root_logger.error('Cannot check root key include in %s: %s',
                bindinstance.NAMED_CONF, e)
        return False
    else:
        if root_key:
            root_logger.debug('root keys configuration already updated')
            sysupgrade.set_upgrade_state('named.conf', 'root_key_updated', True)
            return False

    root_logger.info('[Including named root key in named.conf]')
    try:
        bindinstance.named_conf_add_include(paths.NAMED_ROOT_KEY)
    except IOError, e:
        root_logger.error('Cannot update named root key include in %s: %s',
                bindinstance.NAMED_CONF, e)
        return False


    sysupgrade.set_upgrade_state('named.conf', 'root_key_updated', True)
    return True

def certificate_renewal_update(ca):
    """
    Update certmonger certificate renewal configuration.
    """
    dogtag_constants = dogtag.configured_constants()

    # bump version when requests is changed
    version = 3
    requests = (
        (
            dogtag_constants.ALIAS_DIR,
            'auditSigningCert cert-pki-ca',
            'dogtag-ipa-ca-renew-agent',
            'stop_pkicad',
            'renew_ca_cert',
            None,
        ),
        (
            dogtag_constants.ALIAS_DIR,
            'ocspSigningCert cert-pki-ca',
            'dogtag-ipa-ca-renew-agent',
            'stop_pkicad',
            'renew_ca_cert',
            None,
        ),
        (
            dogtag_constants.ALIAS_DIR,
            'subsystemCert cert-pki-ca',
            'dogtag-ipa-ca-renew-agent',
            'stop_pkicad',
            'renew_ca_cert',
            None,
        ),
        (
            dogtag_constants.ALIAS_DIR,
            'caSigningCert cert-pki-ca',
            'dogtag-ipa-ca-renew-agent',
            'stop_pkicad',
            'renew_ca_cert',
            'ipaCACertRenewal',
        ),
        (
            paths.HTTPD_ALIAS_DIR,
            'ipaCert',
            'dogtag-ipa-ca-renew-agent',
            None,
            'renew_ra_cert',
            None,
        ),
        (
            dogtag_constants.ALIAS_DIR,
            'Server-Cert cert-pki-ca',
            'dogtag-ipa-renew-agent',
            'stop_pkicad',
            'renew_ca_cert',
            None,
        ),
    )

    root_logger.info("[Update certmonger certificate renewal configuration to "
                     "version %d]" % version)
    if not ca.is_configured():
        root_logger.info('CA is not configured')
        return False

    state = 'certificate_renewal_update_%d' % version
    if sysupgrade.get_upgrade_state('dogtag', state):
        return False

    # State not set, lets see if we are already configured
    for request in requests:
        nss_dir, nickname, ca_name, pre_command, post_command, profile = request
        criteria = {
            'cert-database': nss_dir,
            'cert-nickname': nickname,
            'ca-name': ca_name,
            'template-profile': profile,
        }
        request_id = certmonger.get_request_id(criteria)
        if request_id is None:
            break

        val = certmonger.get_request_value(request_id, 'cert-presave-command')
        if val is not None:
            val = val.split(' ', 1)[0]
            val = os.path.basename(val)
        if pre_command != val:
            break

        val = certmonger.get_request_value(request_id, 'cert-postsave-command')
        if val is not None:
            val = val.split(' ', 1)[0]
            val = os.path.basename(val)
        if post_command != val:
            break
    else:
        sysupgrade.set_upgrade_state('dogtag', state, True)
        root_logger.info("Certmonger certificate renewal configuration is "
                         "already at version %d" % version)
        return False

    # Ok, now we need to stop tracking, then we can start tracking them
    # again with new configuration:
    ca.stop_tracking_certificates()

    if not sysupgrade.get_upgrade_state('dogtag',
                                        'certificate_renewal_update_1'):
        filename = paths.CERTMONGER_CAS_CA_RENEWAL
        if os.path.exists(filename):
            with installutils.stopped_service('certmonger'):
                root_logger.info("Removing %s" % filename)
                installutils.remove_file(filename)

    ca.configure_certmonger_renewal()
    ca.configure_renewal()
    ca.configure_agent_renewal()
    ca.track_servercert()

    sysupgrade.set_upgrade_state('dogtag', state, True)
    root_logger.info("Certmonger certificate renewal configuration updated to "
                     "version %d" % version)
    return True

def copy_crl_file(old_path, new_path=None):
    """
    Copy CRL to new location, update permissions and SELinux context
    """
    if new_path is None:
        filename = os.path.basename(old_path)
        new_path = os.path.join(dogtag.configured_constants().CRL_PUBLISH_PATH,
                                filename)
    root_logger.debug('copy_crl_file: %s -> %s', old_path, new_path)

    if os.path.islink(old_path):
        # update symlink to the most most recent CRL file
        filename = os.path.basename(os.readlink(old_path))
        realpath = os.path.join(dogtag.configured_constants().CRL_PUBLISH_PATH,
                                filename)
        root_logger.debug('copy_crl_file: Create symlink %s -> %s',
            new_path, realpath)
        os.symlink(realpath, new_path)
    else:
        shutil.copy2(old_path, new_path)
        pent = pwd.getpwnam(cainstance.PKI_USER)
        os.chown(new_path, pent.pw_uid, pent.pw_gid)

    tasks.restore_context(new_path)

def migrate_crl_publish_dir(ca):
    """
    Move CRL publish dir from /var/lib/pki-ca/publish to IPA controlled tree:
    /var/lib/ipa/pki-ca/publish
    """
    root_logger.info('[Migrate CRL publish directory]')
    if sysupgrade.get_upgrade_state('dogtag', 'moved_crl_publish_dir'):
        root_logger.info('CRL tree already moved')
        return False

    if not ca.is_configured():
        root_logger.info('CA is not configured')
        return False

    caconfig = dogtag.configured_constants()

    try:
        old_publish_dir = installutils.get_directive(caconfig.CS_CFG_PATH,
            'ca.publish.publisher.instance.FileBaseCRLPublisher.directory',
            separator='=')
    except OSError, e:
        root_logger.error('Cannot read CA configuration file "%s": %s',
                caconfig.CS_CFG_PATH, e)
        return False

    # Prepare target publish dir (creation, permissions, SELinux context)
    # Run this every update to ensure proper values
    publishdir = ca.prepare_crl_publish_dir()

    if old_publish_dir == caconfig.CRL_PUBLISH_PATH:
        # publish dir is already updated
        root_logger.info('Publish directory already set to new location')
        sysupgrade.set_upgrade_state('dogtag', 'moved_crl_publish_dir', True)
        return False

    # Copy all CRLs to new directory
    root_logger.info('Copy all CRLs to new publish directory')
    try:
        crl_files_unsorted = cainstance.get_crl_files(old_publish_dir)
    except OSError, e:
        root_logger.error('Cannot move CRL files to new directory: %s', e)
    else:
        # Move CRL files at the end of the list to make sure that the actual
        # CRL files are copied first
        crl_files = sorted(crl_files_unsorted,
                           key=lambda f: os.path.islink(f))
        for f in crl_files:
            try:
                copy_crl_file(f)
            except Exception as e:
                root_logger.error('Cannot move CRL file to new directory: %s', e)

    try:
        installutils.set_directive(caconfig.CS_CFG_PATH,
            'ca.publish.publisher.instance.FileBaseCRLPublisher.directory',
            publishdir, quotes=False, separator='=')
    except OSError as e:
        root_logger.error('Cannot update CA configuration file "%s": %s',
                caconfig.CS_CFG_PATH, e)
        return False
    sysupgrade.set_upgrade_state('dogtag', 'moved_crl_publish_dir', True)
    root_logger.info('CRL publish directory has been migrated, '
                     'request pki-ca restart')
    return True


def ca_enable_pkix(ca):
    root_logger.info('[Enable PKIX certificate path discovery and validation]')
    if sysupgrade.get_upgrade_state('dogtag', 'pkix_enabled'):
        root_logger.info('PKIX already enabled')
        return False

    if not ca.is_configured():
        root_logger.info('CA is not configured')
        return False

    ca.enable_pkix()
    sysupgrade.set_upgrade_state('dogtag', 'pkix_enabled', True)

    return True


def add_ca_dns_records():
    root_logger.info('[Add missing CA DNS records]')

    if sysupgrade.get_upgrade_state('dns', 'ipa_ca_records'):
        root_logger.info('IPA CA DNS records already processed')
        return

    if not api.Backend.ldap2.isconnected():
        try:
            api.Backend.ldap2.connect(autobind=True)
        except ipalib.errors.PublicError, e:
            root_logger.error(
                "Cannot connect to LDAP to add DNS records: %s", e)
            return

    ret = api.Command['dns_is_enabled']()
    if not ret['result']:
        root_logger.info('DNS is not configured')
        sysupgrade.set_upgrade_state('dns', 'ipa_ca_records', True)
        return

    bind = bindinstance.BindInstance()

    bind.convert_ipa_ca_cnames(api.env.domain)

    # DNS is enabled, so let bindinstance find out if CA is enabled
    # and let it add the record in that case
    bind.add_ipa_ca_dns_records(api.env.host, api.env.domain,
                                ca_configured=None)

    sysupgrade.set_upgrade_state('dns', 'ipa_ca_records', True)


def find_subject_base():
    """
    Try to find the current value of certificate subject base.
    See the docstring in dsinstance.DsInstance for details.
    """
    subject_base =  dsinstance.DsInstance().find_subject_base()

    if subject_base:
        sysupgrade.set_upgrade_state(
            'certmap.conf',
            'subject_base',
            subject_base
        )
        return subject_base

    root_logger.error('Unable to determine certificate subject base. '
                      'certmap.conf will not be updated.')


def uninstall_selfsign(ds, http):
    root_logger.info('[Removing self-signed CA]')
    """Replace self-signed CA by a CA-less install"""
    if api.env.ra_plugin != 'selfsign':
        root_logger.debug('Self-signed CA is not installed')
        return

    root_logger.warning(
        'Removing self-signed CA. Certificates will need to managed manually.')
    p = ConfigParser.SafeConfigParser()
    p.read(paths.IPA_DEFAULT_CONF)
    p.set('global', 'enable_ra', 'False')
    p.set('global', 'ra_plugin', 'none')
    with open(paths.IPA_DEFAULT_CONF, 'w') as f:
        p.write(f)

    ds.stop_tracking_certificates()
    http.stop_tracking_certificates()


def mask_named_regular():
    """Disable named, we need to run only named-pkcs11, running both named and
    named-pkcs can cause unexpected errors"""
    if sysupgrade.get_upgrade_state('dns', 'regular_named_masked'):
        return False

    sysupgrade.set_upgrade_state('dns', 'regular_named_masked', True)

    if bindinstance.named_conf_exists():
        root_logger.info('[Masking named]')
        named = services.service('named-regular')
        try:
            named.stop()
        except Exception as e:
            root_logger.warning('Unable to stop named service (%s)', e)

        try:
            named.mask()
        except Exception as e:
            root_logger.warning('Unable to mask named service (%s)', e)

        return True

    return False


def fix_dyndb_ldap_workdir_permissions():
    """Fix dyndb-ldap working dir permissions. DNSSEC daemons requires it"""
    if sysupgrade.get_upgrade_state('dns', 'dyndb_ipa_workdir_perm'):
        return

    if bindinstance.named_conf_exists():
        root_logger.info('[Fix bind-dyndb-ldap IPA working directory]')
        dnskeysync = dnskeysyncinstance.DNSKeySyncInstance()
        dnskeysync.set_dyndb_ldap_workdir_permissions()

    sysupgrade.set_upgrade_state('dns', 'dyndb_ipa_workdir_perm', True)


def fix_schema_file_syntax():
    """Fix syntax errors in schema files

    https://fedorahosted.org/freeipa/ticket/3578
    """
    root_logger.info('[Fix DS schema file syntax]')

    # This is not handled by normal schema updates, because pre-1.3.2 DS will
    # ignore (auto-fix) these syntax errors, and 1.3.2 and above will choke on
    # them before checking dynamic schema updates.

    if sysupgrade.get_upgrade_state('ds', 'fix_schema_syntax'):
        root_logger.info('Syntax already fixed')
        return

    serverid = installutils.realm_to_serverid(api.env.realm)
    ds_dir = dsinstance.config_dirname(serverid)

    # 1. 60ipadns.ldif: Add parenthesis to idnsRecord

    filename = os.path.join(ds_dir, 'schema', '60ipadns.ldif')
    result_lines = []
    with open(filename) as file:
        for line in file:
            line = line.strip('\n')
            if (line.startswith('objectClasses:') and
                    "NAME 'idnsRecord'" in line and
                    line.count('(') == 2 and
                    line.count(')') == 1):
                root_logger.debug('Add closing parenthesis in idnsRecord')
                line += ' )'
            result_lines.append(line)

    with open(filename, 'w') as file:
        file.write('\n'.join(result_lines))

    # 2. 65ipasudo.ldif: Remove extra dollar from ipaSudoRule

    filename = os.path.join(ds_dir, 'schema', '65ipasudo.ldif')
    result_lines = []
    with open(filename) as file:
        for line in file:
            line = line.strip('\n')
            if (line.startswith('objectClasses:') and
                    "NAME 'ipaSudoRule'" in line):
                root_logger.debug('Remove extra dollar sign in ipaSudoRule')
                line = line.replace('$$', '$')
            result_lines.append(line)

    with open(filename, 'w') as file:
        file.write('\n'.join(result_lines))

    # Done

    sysupgrade.set_upgrade_state('ds', 'fix_schema_syntax', True)


def set_sssd_domain_option(option, value):
    sssdconfig = SSSDConfig.SSSDConfig()
    sssdconfig.import_config()
    domain = sssdconfig.get_domain(str(api.env.domain))
    domain.set_option(option, value)
    sssdconfig.save_domain(domain)
    sssdconfig.write(paths.SSSD_CONF)


def remove_ds_ra_cert(subject_base):
    root_logger.info('[Removing RA cert from DS NSS database]')

    if sysupgrade.get_upgrade_state('ds', 'remove_ra_cert'):
        root_logger.info('RA cert already removed')
        return

    dbdir = dsinstance.config_dirname(
        installutils.realm_to_serverid(api.env.realm))
    dsdb = certs.CertDB(api.env.realm, nssdir=dbdir, subject_base=subject_base)

    nickname = 'CN=IPA RA,%s' % subject_base
    cert = dsdb.get_cert_from_db(nickname)
    if cert:
        dsdb.delete_cert(nickname)

    sysupgrade.set_upgrade_state('ds', 'remove_ra_cert', True)


def fix_trust_flags():
    root_logger.info('[Fixing trust flags in %s]' % paths.HTTPD_ALIAS_DIR)

    if sysupgrade.get_upgrade_state('http', 'fix_trust_flags'):
        root_logger.info("Trust flags already processed")
        return

    if not api.Backend.ldap2.isconnected():
        try:
            api.Backend.ldap2.connect(autobind=True)
        except ipalib.errors.PublicError, e:
            root_logger.error("Cannot connect to LDAP: %s", e)
            return

    if not api.Command.ca_is_enabled()['result']:
        root_logger.info("CA is not enabled")
        return

    db = certs.CertDB(api.env.realm)
    nickname = certdb.get_ca_nickname(api.env.realm)
    cert = db.get_cert_from_db(nickname)
    if cert:
        db.trust_root_cert(nickname, 'CT,C,C')

    sysupgrade.set_upgrade_state('http', 'fix_trust_flags', True)


def update_mod_nss_protocol(http):
    root_logger.info('[Updating mod_nss protocol versions]')

    if sysupgrade.get_upgrade_state('nss.conf', 'protocol_updated_tls12'):
        root_logger.info("Protocol versions already updated")
        return

    http.set_mod_nss_protocol()

    sysupgrade.set_upgrade_state('nss.conf', 'protocol_updated_tls12', True)

def ds_enable_sidgen_extdom_plugins(ds):
    """For AD trust agents, make sure we enable sidgen and extdom plugins
    """
    root_logger.info('[Enable sidgen and extdom plugins by default]')

    if sysupgrade.get_upgrade_state('ds', 'enable_ds_sidgen_extdom_plugins'):
        root_logger.info('sidgen and extdom plugins are enabled already')
        return

    ds._add_sidgen_plugin()
    ds._add_extdom_plugin()
    sysupgrade.set_upgrade_state('ds', 'enable_ds_sidgen_extdom_plugins', True)

def ca_upgrade_schema(ca):
    root_logger.info('[Upgrading CA schema]')
    if not ca.is_configured():
        root_logger.info('CA is not configured')
        return False

    schema_files=['/usr/share/pki/server/conf/schema-certProfile.ldif']
    try:
        modified = schemaupdate.update_schema(schema_files, ldapi=True)
    except Exception as e:
        root_logger.error("%s", e)
        raise RuntimeError('CA schema upgrade failed.', 1)
    else:
        if modified:
            root_logger.info('CA schema update complete')
            return True
        else:
            root_logger.info('CA schema update complete (no changes)')
            return False


def add_default_caacl(ca):
    root_logger.info('[Add default CA ACL]')

    if sysupgrade.get_upgrade_state('caacl', 'add_default_caacl'):
        root_logger.info('Default CA ACL already added')
        return

    if ca.is_configured():
        if not api.Backend.ldap2.isconnected():
            try:
                api.Backend.ldap2.connect(autobind=True)
            except ipalib.errors.PublicError as e:
                root_logger.error("Cannot connect to LDAP to add CA ACLs: %s", e)
                return

        if not api.Command.caacl_find()['result']:
            api.Command.caacl_add(u'hosts_services_caIPAserviceCert',
                hostcategory=u'all', usercategory=u'all')
            api.Command.caacl_add_profile(u'hosts_services_caIPAserviceCert',
                certprofile=(u'caIPAserviceCert',))

    sysupgrade.set_upgrade_state('caacl', 'add_default_caacl', True)


def upgrade_configuration():
    """
    Execute configuration upgrade of the IPA services
    """

    root_logger.debug('IPA version %s' % version.VENDOR_VERSION)

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    fqdn = find_hostname()
    if fqdn is None:
        # ipa-rewrite.conf doesn't exist, nothing to do
        raise RuntimeError("ipa-rewrite.conf doesn't exists (is this server?)")

    # Ok, we are an IPA server, do the additional tests

    check_certs()

    auto_redirect = find_autoredirect(fqdn)
    configured_constants = dogtag.configured_constants()
    sub_dict = dict(
        REALM=api.env.realm,
        FQDN=fqdn,
        AUTOREDIR='' if auto_redirect else '#',
        CRL_PUBLISH_PATH=configured_constants.CRL_PUBLISH_PATH,
        DOGTAG_PORT=configured_constants.AJP_PORT,
        CLONE='#'
    )

    subject_base = find_subject_base()
    if subject_base:
        sub_dict['SUBJECT_BASE'] = subject_base

    ca = cainstance.CAInstance(api.env.realm, certs.NSS_DIR)
    ca.backup_config()

    with installutils.stopped_service(configured_constants.SERVICE_NAME,
            configured_constants.PKI_INSTANCE_NAME):
        # migrate CRL publish dir before the location in ipa.conf is updated
        ca_restart = migrate_crl_publish_dir(ca)

        if ca.is_configured():
            crl = installutils.get_directive(configured_constants.CS_CFG_PATH,
                    'ca.crl.MasterCRL.enableCRLUpdates', '=')
            sub_dict['CLONE']='#' if crl.lower() == 'true' else ''

        ds_serverid = installutils.realm_to_serverid(api.env.realm)
        ds_dirname = dsinstance.config_dirname(ds_serverid)

        upgrade_file(sub_dict, paths.HTTPD_IPA_CONF,
                     ipautil.SHARE_DIR + "ipa.conf")
        upgrade_file(sub_dict, paths.HTTPD_IPA_REWRITE_CONF,
                     ipautil.SHARE_DIR + "ipa-rewrite.conf")
        if ca.is_configured():
            upgrade_file(sub_dict, paths.HTTPD_IPA_PKI_PROXY_CONF,
                         ipautil.SHARE_DIR + "ipa-pki-proxy.conf", add=True)
        else:
            if ipautil.file_exists(paths.HTTPD_IPA_PKI_PROXY_CONF):
                os.remove(paths.HTTPD_IPA_PKI_PROXY_CONF)
        if subject_base:
            upgrade_file(
                sub_dict,
                os.path.join(ds_dirname, "certmap.conf"),
                os.path.join(ipautil.SHARE_DIR, "certmap.conf.template")
            )
        upgrade_pki(ca, fstore)

    ca.configure_certmonger_renewal_guard()

    update_dbmodules(api.env.realm)
    uninstall_ipa_kpasswd()

    removed_sysconfig_file = paths.SYSCONFIG_HTTPD
    if fstore.has_file(removed_sysconfig_file):
        root_logger.info('Restoring %s as it is no longer required',
                         removed_sysconfig_file)
        fstore.restore_file(removed_sysconfig_file)

    http = httpinstance.HTTPInstance(fstore)
    http.configure_selinux_for_httpd()
    http.change_mod_nss_port_from_http()
    http.configure_certmonger_renewal_guard()

    if not http.is_kdcproxy_configured():
        root_logger.info('[Enabling KDC Proxy]')
        if http.admin_conn is None:
            http.ldapi = True
            http.fqdn = fqdn
            http.realm = api.env.realm
            http.suffix = ipautil.realm_to_suffix(api.env.realm)
            http.ldap_connect()
        http.create_kdcproxy_conf()
        http.enable_kdcproxy()

    http.stop()
    update_mod_nss_protocol(http)
    fix_trust_flags()
    http.start()

    ds = dsinstance.DsInstance()
    ds.configure_dirsrv_ccache()

    # ldap2 connection is not valid after DS restart, close connection otherwise
    # it will cause network errors
    if api.Backend.ldap2.isconnected():
        api.Backend.ldap2.disconnect()

    ds.stop(ds_serverid)
    fix_schema_file_syntax()
    remove_ds_ra_cert(subject_base)
    ds.start(ds_serverid)

    # Force enabling plugins via LDAPI and external bind
    ds.ldapi = True
    ds.autobind = ipaldap.AUTOBIND_ENABLED
    ds.fqdn = fqdn
    ds.realm = api.env.realm
    ds.suffix = ipautil.realm_to_suffix(api.env.realm)
    ds_enable_sidgen_extdom_plugins(ds)

    uninstall_selfsign(ds, http)

    simple_service_list = (
        (memcacheinstance.MemcacheInstance(), 'MEMCACHE'),
        (otpdinstance.OtpdInstance(), 'OTPD'),
    )

    for service, ldap_name in simple_service_list:
        service.ldapi = True
        try:
            if not service.is_configured():
                # 389-ds needs to be running to create the memcache instance
                # because we record the new service in cn=masters.
                ds.start()
                service.create_instance(ldap_name, fqdn, None,
                                        ipautil.realm_to_suffix(api.env.realm),
                                        realm=api.env.realm)
        except ipalib.errors.DuplicateEntry:
            pass

    # install DNSKeySync service only if DNS is configured on server
    if bindinstance.named_conf_exists():
            dnskeysyncd = dnskeysyncinstance.DNSKeySyncInstance(fstore,
                                                                ldapi=True)
            if not dnskeysyncd.is_configured():
                ds.start()
                dnskeysyncd.create_instance(fqdn, api.env.realm)
                dnskeysyncd.start_dnskeysyncd()

    cleanup_kdc(fstore)
    cleanup_adtrust(fstore)
    setup_firefox_extension(fstore)
    add_ca_dns_records()

    # Any of the following functions returns True iff the named.conf file
    # has been altered
    named_conf_changes = (
                          named_remove_deprecated_options(),
                          named_set_minimum_connections(),
                          named_enable_serial_autoincrement(),
                          named_update_gssapi_configuration(),
                          named_update_pid_file(),
                          named_enable_dnssec(),
                          named_validate_dnssec(),
                          named_bindkey_file_option(),
                          named_managed_keys_dir_option(),
                          named_root_key_include(),
                          mask_named_regular(),
                          fix_dyndb_ldap_workdir_permissions(),
                         )

    if any(named_conf_changes):
        # configuration has changed, restart the name server
        root_logger.info('Changes to named.conf have been made, restart named')
        bind = bindinstance.BindInstance(fstore)
        try:
            bind.restart()
        except ipautil.CalledProcessError as e:
            root_logger.error("Failed to restart %s: %s", bind.service_name, e)

    ca_restart = any([
        ca_restart,
        ca_upgrade_schema(ca),
        upgrade_ca_audit_cert_validity(ca),
        certificate_renewal_update(ca),
        ca_enable_pkix(ca),
        ca_configure_profiles_acl(ca),
    ])

    if ca_restart:
        root_logger.info('pki-ca configuration changed, restart pki-ca')
        try:
            ca.restart(dogtag.configured_constants().PKI_INSTANCE_NAME)
        except ipautil.CalledProcessError as e:
            root_logger.error("Failed to restart %s: %s", ca.service_name, e)

    ca_enable_ldap_profile_subsystem(ca)

    # This step MUST be done after ca_enable_ldap_profile_subsystem and
    # ca_configure_profiles_acl, and the consequent restart, but does not
    # itself require a restart.
    #
    ca_import_included_profiles(ca)
    add_default_caacl(ca)

    set_sssd_domain_option('ipa_server_mode', 'True')


def upgrade_check(options):
    try:
        installutils.check_server_configuration()
    except RuntimeError as e:
        print unicode(e)
        sys.exit(1)

    if not services.knownservices.certmonger.is_running():
        raise RuntimeError('Certmonger is not running. Start certmonger and run upgrade again.')

    if not options.skip_version_check:
        # check IPA version and data version
        try:
            installutils.check_version()
        except (installutils.UpgradePlatformError,
                installutils.UpgradeDataNewerVersionError) as e:
            raise RuntimeError(
                'Unable to execute IPA upgrade: %s' % e, 1)
        except installutils.UpgradeMissingVersionError as e:
            root_logger.info("Missing version: %s", e)
        except installutils.UpgradeVersionError:
            # Ignore other errors
            pass
    else:
        root_logger.info("Skipping version check")
        root_logger.warning("Upgrade without version check may break your "
                         "system")


def upgrade():
    realm = krbV.default_context().default_realm
    schema_files = [os.path.join(ipautil.SHARE_DIR, f) for f
                    in dsinstance.ALL_SCHEMA_FILES]
    data_upgrade = IPAUpgrade(realm, schema_files=schema_files)

    try:
        data_upgrade.create_instance()
    except BadSyntax:
        raise RuntimeError(
            'Bad syntax detected in upgrade file(s).', 1)
    except RuntimeError:
        raise RuntimeError('IPA upgrade failed.', 1)
    else:
        if data_upgrade.modified:
            root_logger.info('Update complete')
        else:
            root_logger.info('Update complete, no data were modified')

    # store new data version after upgrade
    installutils.store_version()

    print 'Upgrading IPA services'
    root_logger.info('Upgrading the configuration of the IPA services')
    upgrade_configuration()
    root_logger.info('The IPA services were upgraded')
