#
# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2012, 2019 Red Hat
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
# Configure the automount client for ldap.

from __future__ import print_function

import logging
import sys
import os
import shutil
import time
import tempfile
import gssapi
import warnings

try:
    from xml.etree import cElementTree as etree
except ImportError:
    from xml.etree import ElementTree as etree
import SSSDConfig

# pylint: disable=import-error
from six.moves.urllib.parse import urlsplit

# pylint: enable=import-error
from optparse import OptionParser  # pylint: disable=deprecated-module
from ipapython import ipachangeconf
from ipaclient.install import ipadiscovery
from ipaclient.install.client import (
    CLIENT_NOT_CONFIGURED,
    CLIENT_ALREADY_CONFIGURED,
)
from ipalib import api, errors
from ipalib.install import sysrestore
from ipalib.install.kinit import kinit_keytab
from ipalib.util import check_client_configuration
from ipapython import ipautil
from ipapython.ipa_log_manager import standard_logging_setup
from ipapython.dn import DN
from ipaplatform.constants import constants
from ipaplatform.tasks import tasks
from ipaplatform import services
from ipaplatform.paths import paths
from ipapython.admintool import ScriptError


logger = logging.getLogger(os.path.basename(__file__))


def parse_options():
    usage = "%prog [options]\n"
    parser = OptionParser(usage=usage)
    parser.add_option("--server", dest="server", help="FQDN of IPA server")
    parser.add_option(
        "--location",
        dest="location",
        default="default",
        help="Automount location",
    )
    parser.add_option(
        "-S",
        "--no-sssd",
        dest="sssd",
        action="store_false",
        default=True,
        help="Do not configure the client to use SSSD for automount",
    )
    parser.add_option(
        "--idmap-domain",
        dest="idmapdomain",
        default=None,
        help="nfs domain for idmapd.conf",
    )
    parser.add_option(
        "--debug",
        dest="debug",
        action="store_true",
        default=False,
        help="enable debugging",
    )
    parser.add_option(
        "-U",
        "--unattended",
        dest="unattended",
        action="store_true",
        default=False,
        help="unattended installation never prompts the user",
    )
    parser.add_option(
        "--uninstall",
        dest="uninstall",
        action="store_true",
        default=False,
        help="Unconfigure automount",
    )

    options, args = parser.parse_args()
    return options, args


def wait_for_sssd():
    """
    It takes a bit for sssd to get going, lets loop until it is
    serving data.

    This function returns nothing.
    """
    n = 0
    found = False
    time.sleep(1)
    while n < 10 and not found:
        try:
            ipautil.run([paths.GETENT, "passwd", "admin@%s" % api.env.realm])
            found = True
        except Exception:
            time.sleep(1)
            n = n + 1

    # This should never happen but if it does, may as well warn the user
    if not found:
        err_msg = (
            "Unable to find 'admin' user with "
            "'getent passwd admin@%s'!" % api.env.realm
        )
        logger.debug('%s', err_msg)
        print(err_msg)
        print(
            "This may mean that sssd didn't re-start properly after "
            "the configuration changes."
        )


def configure_xml(fstore):
    authconf = paths.AUTOFS_LDAP_AUTH_CONF
    fstore.backup_file(authconf)

    try:
        tree = etree.parse(authconf)
    except IOError as e:
        logger.debug('Unable to open file %s', e)
        logger.debug('Creating new from template')
        tree = etree.ElementTree(
            element=etree.Element('autofs_ldap_sasl_conf')
        )

    element = tree.getroot()
    if element.tag != 'autofs_ldap_sasl_conf':
        raise RuntimeError('Invalid XML root in file %s' % authconf)

    element.set('usetls', 'no')
    element.set('tlsrequired', 'no')
    element.set('authrequired', 'yes')
    element.set('authtype', 'GSSAPI')
    element.set('clientprinc', 'host/%s@%s' % (api.env.host, api.env.realm))

    try:
        tree.write(authconf, xml_declaration=True, encoding='UTF-8')
    except IOError as e:
        print("Unable to write %s: %s" % (authconf, e))
    else:
        print("Configured %s" % authconf)


def configure_nsswitch(statestore, options):
    """
    This function was deprecated. Use ipaplatform.tasks.

    Point automount to ldap in nsswitch.conf.
    This function is for non-SSSD setups only.
    """
    warnings.warn(
        "Use ipaplatform.tasks.tasks.enable_ldap_automount",
        DeprecationWarning,
        stacklevel=2
    )
    return tasks.enable_ldap_automount(statestore)


def configure_autofs_sssd(fstore, statestore, autodiscover, options):
    try:
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.import_config()
        domains = sssdconfig.list_active_domains()
    except Exception as e:
        sys.exit(e)

    try:
        sssdconfig.new_service('autofs')
    except SSSDConfig.ServiceAlreadyExists:
        pass
    except SSSDConfig.ServiceNotRecognizedError:
        logger.error("Unable to activate the Autofs service in SSSD config.")
        logger.info(
            "Please make sure you have SSSD built with autofs support "
            "installed."
        )
        logger.info(
            "Configure autofs support manually in /etc/sssd/sssd.conf."
        )
        sys.exit("Cannot create the autofs service in sssd.conf")

    sssdconfig.activate_service('autofs')

    domain = None
    for name in domains:
        domain = sssdconfig.get_domain(name)
        try:
            provider = domain.get_option('id_provider')
        except SSSDConfig.NoOptionError:
            continue
        if provider == "ipa":
            domain.add_provider('ipa', 'autofs')
            try:
                domain.get_option('ipa_automount_location')
                print('An automount location is already configured')
                sys.exit(CLIENT_ALREADY_CONFIGURED)
            except SSSDConfig.NoOptionError:
                domain.set_option('ipa_automount_location', options.location)
                break

    if domain is None:
        sys.exit('SSSD is not configured.')

    sssdconfig.save_domain(domain)
    sssdconfig.write(paths.SSSD_CONF)
    statestore.backup_state('autofs', 'sssd', True)

    sssd = services.service('sssd', api)
    sssd.restart()
    print("Restarting sssd, waiting for it to become available.")
    wait_for_sssd()


def configure_autofs(fstore, statestore, autodiscover, server, options):
    """
    fstore: the FileStore to back up files in
    options.server: the IPA server to use
    options.location: the Automount location to use
    """
    if not autodiscover:
        ldap_uri = "ldap://%s" % server
    else:
        ldap_uri = "ldap:///%s" % api.env.basedn

    search_base = str(
        DN(
            ('cn', options.location),
            api.env.container_automount,
            api.env.basedn,
        )
    )
    replacevars = {
        'MAP_OBJECT_CLASS': 'automountMap',
        'ENTRY_OBJECT_CLASS': 'automount',
        'MAP_ATTRIBUTE': 'automountMapName',
        'ENTRY_ATTRIBUTE': 'automountKey',
        'VALUE_ATTRIBUTE': 'automountInformation',
        'SEARCH_BASE': search_base,
        'LDAP_URI': ldap_uri,
    }

    ipautil.backup_config_and_replace_variables(
        fstore, paths.SYSCONFIG_AUTOFS, replacevars=replacevars
    )
    tasks.restore_context(paths.SYSCONFIG_AUTOFS)
    statestore.backup_state('autofs', 'sssd', False)

    print("Configured %s" % paths.SYSCONFIG_AUTOFS)


def configure_autofs_common(fstore, statestore, options):
    autofs = services.knownservices.autofs
    statestore.backup_state('autofs', 'enabled', autofs.is_enabled())
    statestore.backup_state('autofs', 'running', autofs.is_running())
    try:
        autofs.restart()
        print("Started %s" % autofs.service_name)
    except Exception as e:
        logger.error("%s failed to restart: %s", autofs.service_name, e)
    try:
        autofs.enable()
    except Exception as e:
        print(
            "Failed to configure automatic startup of the %s daemon"
            % (autofs.service_name)
        )
        logger.error(
            "Failed to enable automatic startup of the %s daemon: %s",
            autofs.service_name,
            str(e),
        )


def uninstall(fstore, statestore):
    RESTORE_FILES = [
        paths.SYSCONFIG_AUTOFS,
        paths.AUTOFS_LDAP_AUTH_CONF,
        paths.SYSCONFIG_NFS,
        paths.IDMAPD_CONF,
    ]
    STATES = ['autofs', 'rpcidmapd', 'rpcgssd']

    if not statestore.get_state('autofs', 'sssd'):
        tasks.disable_ldap_automount(statestore)

    if not any(fstore.has_file(f) for f in RESTORE_FILES) or not any(
        statestore.has_state(s) for s in STATES
    ):
        print("IPA automount is not configured on this system")
        return CLIENT_NOT_CONFIGURED

    print("Restoring configuration")

    for filepath in RESTORE_FILES:
        if fstore.has_file(filepath):
            fstore.restore_file(filepath)
    if statestore.has_state('autofs'):
        enabled = statestore.restore_state('autofs', 'enabled')
        running = statestore.restore_state('autofs', 'running')
        sssd = statestore.restore_state('autofs', 'sssd')
        autofs = services.knownservices.autofs
        if not enabled:
            autofs.disable()
        if not running:
            autofs.stop()
        if sssd:
            try:
                sssdconfig = SSSDConfig.SSSDConfig()
                sssdconfig.import_config()
                sssdconfig.deactivate_service('autofs')
                domains = sssdconfig.list_active_domains()
                for name in domains:
                    domain = sssdconfig.get_domain(name)
                    try:
                        provider = domain.get_option('id_provider')
                    except SSSDConfig.NoOptionError:
                        continue
                    if provider == "ipa":
                        domain.remove_option('ipa_automount_location')
                        sssdconfig.save_domain(domain)
                        domain.remove_provider('autofs')
                        sssdconfig.save_domain(domain)
                        break
                sssdconfig.write(paths.SSSD_CONF)
                sssd = services.service('sssd', api)
                sssd.restart()
                wait_for_sssd()
            except Exception as e:
                print('Unable to restore SSSD configuration: %s' % str(e))
                logger.debug(
                    'Unable to restore SSSD configuration: %s', str(e)
                )

    # rpcidmapd and rpcgssd are static units now
    if statestore.has_state('rpcidmapd'):
        statestore.delete_state('rpcidmapd', 'enabled')
        statestore.delete_state('rpcidmapd', 'running')
    if statestore.has_state('rpcgssd'):
        statestore.delete_state('rpcgssd', 'enabled')
        statestore.delete_state('rpcgssd', 'running')

    nfsutils = services.knownservices['nfs-utils']
    try:
        nfsutils.restart()
    except Exception as e:
        logger.error("Failed to restart nfs client services (%s)", str(e))
        return 1
    return 0


def configure_nfs(fstore, statestore, options):
    """
    Configure secure NFS
    """
    # Newer Fedora releases ship /etc/nfs.conf instead of /etc/sysconfig/nfs
    # and do not require changes there. On these, SECURE_NFS_VAR == None
    if constants.SECURE_NFS_VAR:
        replacevars = {constants.SECURE_NFS_VAR: 'yes'}
        ipautil.backup_config_and_replace_variables(
            fstore, paths.SYSCONFIG_NFS, replacevars=replacevars
        )
        tasks.restore_context(paths.SYSCONFIG_NFS)
        print("Configured %s" % paths.SYSCONFIG_NFS)

    # Prepare the changes
    # We need to use IPAChangeConf as simple regexp substitution
    # does not cut it here
    conf = ipachangeconf.IPAChangeConf("IPA automount installer")
    conf.case_insensitive_sections = False
    conf.setOptionAssignment(" = ")
    conf.setSectionNameDelimiters(("[", "]"))

    if options.idmapdomain is None:
        # Set NFSv4 domain to the IPA domain
        changes = [conf.setOption('Domain', api.env.domain)]
    elif options.idmapdomain == 'DNS':
        # Rely on idmapd auto-detection (DNS)
        changes = [conf.rmOption('Domain')]
    else:
        # Set NFSv4 domain to what was provided
        changes = [conf.setOption('Domain', options.idmapdomain)]

    if changes is not None:
        section_with_changes = [conf.setSection('General', changes)]
        # Backup the file and apply the changes
        fstore.backup_file(paths.IDMAPD_CONF)
        conf.changeConf(paths.IDMAPD_CONF, section_with_changes)
        tasks.restore_context(paths.IDMAPD_CONF)
        print("Configured %s" % paths.IDMAPD_CONF)

    rpcgssd = services.knownservices.rpcgssd
    try:
        rpcgssd.restart()
    except Exception as e:
        logger.error("Failed to restart rpc-gssd (%s)", str(e))
    nfsutils = services.knownservices['nfs-utils']
    try:
        nfsutils.restart()
    except Exception as e:
        logger.error("Failed to restart nfs client services (%s)", str(e))


def configure_automount():
    try:
        check_client_configuration()
    except ScriptError as e:
        print(e.msg)
        sys.exit(e.rval)

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    statestore = sysrestore.StateFile(paths.IPA_CLIENT_SYSRESTORE)

    options, _args = parse_options()

    standard_logging_setup(
        paths.IPACLIENT_INSTALL_LOG,
        verbose=False,
        debug=options.debug,
        filemode='a',
        console_format='%(message)s',
    )

    cfg = dict(
        context='cli_installer',
        confdir=paths.ETC_IPA,
        in_server=False,
        debug=options.debug,
        verbose=0,
    )

    # Bootstrap API early so that env object is available
    api.bootstrap(**cfg)

    if options.uninstall:
        return uninstall(fstore, statestore)

    ca_cert_path = None
    if os.path.exists(paths.IPA_CA_CRT):
        ca_cert_path = paths.IPA_CA_CRT

    if statestore.has_state('autofs'):
        print('An automount location is already configured')
        sys.exit(CLIENT_ALREADY_CONFIGURED)

    autodiscover = False
    ds = ipadiscovery.IPADiscovery()
    if not options.server:
        print("Searching for IPA server...")
        ret = ds.search(ca_cert_path=ca_cert_path)
        logger.debug('Executing DNS discovery')
        if ret == ipadiscovery.NO_LDAP_SERVER:
            logger.debug('Autodiscovery did not find LDAP server')
            s = urlsplit(api.env.xmlrpc_uri)
            server = [s.netloc]
            logger.debug('Setting server to %s', s.netloc)
        else:
            autodiscover = True
            if not ds.servers:
                sys.exit(
                    'Autodiscovery was successful but didn\'t return a server'
                )
            logger.debug(
                'Autodiscovery success, possible servers %s',
                ','.join(ds.servers),
            )
            server = ds.servers[0]
    else:
        server = options.server
        logger.debug("Verifying that %s is an IPA server", server)
        ldapret = ds.ipacheckldap(server, api.env.realm, ca_cert_path)
        if ldapret[0] == ipadiscovery.NO_ACCESS_TO_LDAP:
            print("Anonymous access to the LDAP server is disabled.")
            print("Proceeding without strict verification.")
            print(
                "Note: This is not an error if anonymous access has been "
                "explicitly restricted."
            )
        elif ldapret[0] == ipadiscovery.NO_TLS_LDAP:
            logger.warning("Unencrypted access to LDAP is not supported.")
        elif ldapret[0] != 0:
            sys.exit('Unable to confirm that %s is an IPA server' % server)

    if not autodiscover:
        print("IPA server: %s" % server)
        logger.debug('Using fixed server %s', server)
    else:
        print("IPA server: DNS discovery")
        logger.debug('Configuring to use DNS discovery')

    print("Location: %s" % options.location)
    logger.debug('Using automount location %s', options.location)

    ccache_dir = tempfile.mkdtemp()
    ccache_name = os.path.join(ccache_dir, 'ccache')
    try:
        try:
            host_princ = str('host/%s@%s' % (api.env.host, api.env.realm))
            kinit_keytab(host_princ, paths.KRB5_KEYTAB, ccache_name)
            os.environ['KRB5CCNAME'] = ccache_name
        except gssapi.exceptions.GSSError as e:
            sys.exit("Failed to obtain host TGT: %s" % e)

        # Finalize API when TGT obtained using host keytab exists
        api.finalize()

        # Now we have a TGT, connect to IPA
        try:
            api.Backend.rpcclient.connect()
        except errors.KerberosError as e:
            sys.exit('Cannot connect to the server due to ' + str(e))
        try:
            # Use the RPC directly so older servers are supported
            api.Backend.rpcclient.forward(
                'automountlocation_show',
                ipautil.fsdecode(options.location),
                version=u'2.0',
            )
        except errors.VersionError as e:
            sys.exit('This client is incompatible: ' + str(e))
        except errors.NotFound:
            sys.exit(
                "Automount location '%s' does not exist" % options.location
            )
        except errors.PublicError as e:
            sys.exit(
                "Cannot connect to the server due to generic error: %s"
                % str(e)
            )
    finally:
        shutil.rmtree(ccache_dir)

    if not options.unattended and not ipautil.user_input(
        "Continue to configure the system with these values?", False
    ):
        sys.exit("Installation aborted")

    try:
        if not options.sssd:
            tasks.enable_ldap_automount(statestore)
        configure_nfs(fstore, statestore, options)
        if options.sssd:
            configure_autofs_sssd(fstore, statestore, autodiscover, options)
        else:
            configure_xml(fstore)
            configure_autofs(
                fstore, statestore, autodiscover, server, options
            )
        configure_autofs_common(fstore, statestore, options)
    except Exception as e:
        logger.debug('Raised exception %s', e)
        print("Installation failed. Rolling back changes.")
        uninstall(fstore, statestore)
        return 1

    return 0


def main():
    try:
        if not os.geteuid() == 0:
            sys.exit("\nMust be run as root\n")
        configure_automount()
    except SystemExit as e:
        sys.exit(e)
    except RuntimeError as e:
        sys.exit(e)
    except (KeyboardInterrupt, EOFError):
        sys.exit(1)
