#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#
# Configure the Samba suite to operate as domain member in IPA domain

from __future__ import print_function

import logging
import os
import gssapi
from urllib.parse import urlsplit
from optparse import OptionParser  # pylint: disable=deprecated-module
from contextlib import contextmanager

from ipaclient import discovery
from ipaclient.install.client import (
    CLIENT_NOT_CONFIGURED,
    CLIENT_ALREADY_CONFIGURED,
)
from ipalib import api, errors
from ipalib.install import sysrestore
from ipalib.util import check_client_configuration
from ipalib.request import context
from ipapython import ipautil
from ipapython.errors import SetseboolError
from ipapython.ipa_log_manager import standard_logging_setup
from ipapython.dnsutil import DNSName
from ipaplatform.tasks import tasks
from ipaplatform.paths import paths
from ipaplatform.constants import constants
from ipaplatform import services
from ipapython.admintool import ScriptError
from samba import generate_random_password

logger = logging.getLogger(os.path.basename(__file__))
logger.setLevel(logging.DEBUG)


@contextmanager
def use_api_as_principal(principal, keytab):
    with ipautil.private_ccache() as ccache_file:
        try:
            old_principal = getattr(context, "principal", None)
            name = gssapi.Name(principal, gssapi.NameType.kerberos_principal)
            store = {"ccache": ccache_file, "client_keytab": keytab}
            gssapi.Credentials(name=name, usage="initiate", store=store)
            # Finalize API when TGT obtained using host keytab exists
            if not api.isdone("finalize"):
                api.finalize()

            # Now we have a TGT, connect to IPA
            try:
                if api.Backend.rpcclient.isconnected():
                    api.Backend.rpcclient.disconnect()
                api.Backend.rpcclient.connect()

                yield
            except gssapi.exceptions.GSSError as e:
                raise Exception(
                    "Unable to bind to IPA server. Error initializing "
                    "principal %s in %s: %s" % (principal, keytab, str(e))
                )
        finally:
            if api.Backend.rpcclient.isconnected():
                api.Backend.rpcclient.disconnect()
            setattr(context, "principal", old_principal)


def parse_options():
    usage = "%prog [options]\n"
    parser = OptionParser(usage=usage)
    parser.add_option(
        "--server",
        dest="server",
        help="FQDN of IPA server to connect to",
    )
    parser.add_option(
        "--netbios-name",
        dest="netbiosname",
        help="NetBIOS name of this machine",
        default=None,
    )
    parser.add_option(
        "--no-homes",
        dest="no_homes",
        action="store_true",
        default=False,
        help="Do not add [homes] share to the generated Samba configuration",
    )
    parser.add_option(
        "--no-nfs",
        dest="no_nfs",
        action="store_true",
        default=False,
        help="Do not allow NFS integration (SELinux booleans)",
    )
    parser.add_option(
        "--force",
        dest="force",
        action="store_true",
        default=False,
        help="force installation by redoing all steps",
    )
    parser.add_option(
        "--debug",
        dest="debug",
        action="store_true",
        default=False,
        help="print debugging information",
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
        help="Revert configuration and remove SMB service",
    )

    options, args = parser.parse_args()
    return options, args


domain_information_template = """
 Domain name: {domain_name}
NetBIOS name: {netbios_name}
         SID: {domain_sid}
    ID range: {range_id_min} - {range_id_max}
"""


def pretty_print_domain_information(info):
    result = []
    for domain in info:
        result.append(domain_information_template.format(**domain))
    return "\n".join(result)


trust_keymap = {
    "netbios_name": "ipantflatname",
    "domain_sid": "ipantsecurityidentifier",
    "domain_name": "cn",
}


trust_keymap_trustdomain = {
    "netbios_name": "ipantflatname",
    "domain_sid": "ipanttrusteddomainsid",
    "domain_name": "cn",
}


def retrieve_domain_information(api):
    # Pull down default domain configuration
    # IPA master might be missing freeipa-server-trust-ad package
    # or `ipa-adtrust-install` was never run. In such case return
    # empty list to report an error
    try:
        tc_command = api.Command.trustconfig_show
    except AttributeError:
        return []
    try:
        result = tc_command()["result"]
    except errors.PublicError:
        return []

    l_domain = dict()
    for key in trust_keymap:
        l_domain[key] = result.get(trust_keymap[key], [None])[0]

    # Pull down ID range and other details of our domain
    #
    # TODO: make clear how to handle multiple ID ranges for ipa-local range
    # In Samba only one range can belong to the same idmap domain,
    # otherwise winbindd's _wbint_Sids2UnixIDs function will not be able
    # to accept that a mapped Unix ID belongs to the specified domain
    idrange_local = "{realm}_id_range".format(realm=api.env.realm)
    result = api.Command.idrange_show(idrange_local)["result"]
    l_domain["range_id_min"] = int(result["ipabaseid"][0])
    l_domain["range_id_max"] = (
        int(result["ipabaseid"][0]) + int(result["ipaidrangesize"][0]) - 1
    )

    domains = [l_domain]

    # Retrieve list of trusted domains, if they exist
    #
    # We flatten the whole trust list because it should be non-overlapping
    result = api.Command.trust_find()["result"]
    for forest in result:
        r = api.Command.trustdomain_find(forest["cn"][0], all=True, raw=True)[
            "result"
        ]
        # We don't need to process forest root info separately
        # as trustdomain_find() returns it as well
        for dom in r:
            r_dom = dict()
            for key in trust_keymap:
                r_dom[key] = dom.get(trust_keymap_trustdomain[key], [None])[0]

            r_idrange_name = "{realm}_id_range".format(
                realm=r_dom["domain_name"].upper()
            )

            # TODO: support ipa-ad-trust-posix range as well
            r_idrange = api.Command.idrange_show(r_idrange_name)["result"]
            r_dom["range_id_min"] = int(r_idrange["ipabaseid"][0])
            r_dom["range_id_max"] = (
                int(r_idrange["ipabaseid"][0]) +
                int(r_idrange["ipaidrangesize"][0]) - 1
            )
            domains.append(r_dom)
    return domains


smb_conf_template = """
[global]
    # Limit number of forked processes to avoid SMBLoris attack
    max smbd processes = 1000
    # Use dedicated Samba keytab. The key there must be synchronized
    # with Samba tdb databases or nothing will work
    dedicated keytab file = FILE:${samba_keytab}
    kerberos method = dedicated keytab
    # Set up logging per machine and Samba process
    log file = /var/log/samba/log.%m
    log level = 1
    # We force 'member server' role to allow winbind automatically
    # discover what is supported by the domain controller side
    server role = member server
    realm = ${realm}
    netbios name = ${machine_name}
    workgroup = ${netbios_name}
    # Local writable range for IDs not coming from IPA or trusted domains
    idmap config * : range = 0 - 0
    idmap config * : backend = tdb
"""

idmap_conf_domain_snippet = """
    idmap config ${netbios_name} : range = ${range_id_min} - ${range_id_max}
    idmap config ${netbios_name} : backend = sss
"""

homes_conf_snippet = """
# Default homes share
[homes]
    read only = no
"""


def configure_smb_conf(fstore, statestore, options, domains):
    sub_dict = {
        "samba_keytab": paths.SAMBA_KEYTAB,
        "realm": api.env.realm,
        "machine_name": options.netbiosname,
    }

    # First domain in the list is ours, pull our domain name from there
    sub_dict["netbios_name"] = domains[0]["netbios_name"]

    # Construct elements of smb.conf by pre-rendering idmap configuration
    template = [smb_conf_template]
    for dom in domains:
        template.extend([ipautil.template_str(idmap_conf_domain_snippet, dom)])

    # Add default homes share so that users can log into Samba
    if not options.no_homes:
        template.extend([homes_conf_snippet])

    fstore.backup_file(paths.SMB_CONF)
    with open(paths.SMB_CONF, "w") as f:
        f.write(ipautil.template_str("\n".join(template), sub_dict))
    tasks.restore_context(paths.SMB_CONF)


def generate_smb_machine_account(fstore, statestore, options, domain):
    # Ideally, we should be using generate_random_machine_password()
    # from samba but it uses munged UTF-16 which is not decodable
    # by the code called from 'net changesecretpw -f'. Thus, we'd limit
    # password to ASCII only.
    return generate_random_password(128, 255)


def retrieve_service_principal(
    fstore, statestore, options, domain, principal, password
):
    # Use explicit encryption types. SMB service must have arcfour-hmac
    # generated to allow domain member to authenticate to the domain controller
    args = [
        paths.IPA_GETKEYTAB,
        "-p",
        principal,
        "-k",
        paths.SAMBA_KEYTAB,
        "-P",
        "-e",
        "aes128-cts-hmac-sha1-96,aes256-cts-hmac-sha1-96,arcfour-hmac",
    ]
    try:
        ipautil.run(args, stdin=password + "\n" + password, encoding="utf-8")
    except ipautil.CalledProcessError as e:
        logger.error(
            "Cannot set machine account password at IPA DC. Error: %s",
            e,
        )
        raise

    # Once we fetched the keytab, we also need to set ipaNTHash attribute
    # Use ipa-pwd-extop plugin to regenerate it from the Kerberos key
    value = "ipaNTHash=MagicRegen"
    try:
        api.Command.service_mod(principal, addattr=value)
    except errors.PublicError as e:
        logger.error(
            "Cannot update %s principal NT hash value due to an error: %s",
            principal,
            e,
        )
        raise


def populate_samba_databases(fstore, statestore, options, domain, password):
    # First, set domain SID in Samba
    args = [paths.NET, "setdomainsid", domain["domain_sid"]]
    try:
        ipautil.run(args)
    except ipautil.CalledProcessError as e:
        logger.error("Cannot set domain SID in Samba. Error: %s", e)
        raise

    # Next, make sure we can set machine account credentials
    # the workaround with tdbtool is temporary until 'net' utility
    # will not provide us a way to perform 'offline join' procedure
    secrets_key = "SECRETS/MACHINE_LAST_CHANGE_TIME/{}".format(
        domain["netbios_name"]
    )
    args = [paths.TDBTOOL, paths.SECRETS_TDB, "store", secrets_key, "2\\00"]
    try:
        ipautil.run(args)
    except ipautil.CalledProcessError as e:
        logger.error(
            "Cannot prepare machine account creds in Samba. Error: %s", e,
        )
        raise

    secrets_key = "SECRETS/MACHINE_PASSWORD/{}".format(domain["netbios_name"])
    args = [paths.TDBTOOL, paths.SECRETS_TDB, "store", secrets_key, "2\\00"]
    try:
        ipautil.run(args)
    except ipautil.CalledProcessError as e:
        logger.error(
            "Cannot prepare machine account creds in Samba. Error: %s", e,
        )
        raise

    # Finally, set actual machine account's password
    args = [paths.NET, "changesecretpw", "-f"]
    try:
        ipautil.run(args, stdin=password, encoding="utf-8")
    except ipautil.CalledProcessError as e:
        logger.error(
            "Cannot set machine account creds in Samba. Error: %s", e,
        )
        raise


def configure_default_groupmap(fstore, statestore, options, domain):
    args = [
        paths.NET,
        "groupmap",
        "add",
        "sid=S-1-5-32-546",
        "unixgroup=nobody",
        "type=builtin",
    ]

    logger.info("Map BUILTIN\\Guests to a group 'nobody'")
    try:
        ipautil.run(args)
    except ipautil.CalledProcessError as e:
        if "already mapped to SID S-1-5-32-546" not in e.stdout:
            logger.error(
                'Cannot map BUILTIN\\Guests to a group "nobody". Error: %s',
                e
            )
            raise


def set_selinux_booleans(booleans, statestore, backup=True):
    def default_backup_func(name, value):
        statestore.backup_state("selinux", name, value)

    backup_func = default_backup_func if backup else None
    try:
        tasks.set_selinux_booleans(booleans, backup_func=backup_func)
    except SetseboolError as e:
        print("WARNING: " + str(e))
        logger.info("WARNING: %s", e)


def harden_configuration(fstore, statestore, options, domain):
    # Add default homes share so that users can log into Samba
    if not options.no_homes:
        set_selinux_booleans(
            constants.SELINUX_BOOLEAN_SMBSERVICE["share_home_dirs"], statestore
        )
    # Allow Samba to access NFS-shared content
    if not options.no_nfs:
        set_selinux_booleans(
            constants.SELINUX_BOOLEAN_SMBSERVICE["reshare_nfs_with_samba"],
            statestore,
        )


def uninstall(fstore, statestore, options):
    # Shut down Samba services and disable them
    smb = services.service("smb", api)
    winbind = services.service("winbind", api)
    for svc in (smb, winbind):
        if svc.is_running():
            svc.stop()
        svc.disable()

    # Restore the state of affected selinux booleans
    boolean_states = {}
    for usecase in constants.SELINUX_BOOLEAN_SMBSERVICE:
        for name in usecase:
            boolean_states[name] = statestore.restore_state("selinux", name)

    if boolean_states:
        set_selinux_booleans(boolean_states, statestore, backup=False)

    # Remove samba's credentials cache
    ipautil.remove_ccache(ccache_path=paths.KRB5CC_SAMBA)

    # Remove samba's configuration file
    if fstore.has_file(paths.SMB_CONF):
        ipautil.remove_file(paths.SMB_CONF)
        fstore.restore_file(paths.SMB_CONF)

    # Remove samba's persistent and temporary tdb files
    tdb_files = [
        tdb_file
        for tdb_file in os.listdir(paths.SAMBA_DIR)
        if tdb_file.endswith(".tdb")
    ]
    for tdb_file in tdb_files:
        ipautil.remove_file(tdb_file)

    # Remove our keys from samba's keytab
    if os.path.exists(paths.SAMBA_KEYTAB):
        try:
            ipautil.run(
                [
                    paths.IPA_RMKEYTAB,
                    "--principal",
                    api.env.smb_princ,
                    "-k",
                    paths.SAMBA_KEYTAB,
                ]
            )
        except ipautil.CalledProcessError as e:
            if e.returncode != 5:
                logger.critical("Failed to remove old key for %s",
                                api.env.smb_princ)

    with use_api_as_principal(api.env.host_princ, paths.KRB5_KEYTAB):
        try:
            api.Command.service_del(api.env.smb_princ)
        except errors.VersionError as e:
            print("This client is incompatible: " + str(e))
        except errors.NotFound:
            logger.debug("No SMB service principal exists, OK to proceed")
        except errors.PublicError as e:
            logger.error(
                "Cannot connect to the server due to "
                "a generic error: %s", e,
            )


def run():
    try:
        check_client_configuration()
    except ScriptError as e:
        print(e.msg)
        return e.rval

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    statestore = sysrestore.StateFile(paths.IPA_CLIENT_SYSRESTORE)

    options, _args = parse_options()

    logfile = paths.IPACLIENTSAMBA_INSTALL_LOG
    if options.uninstall:
        logfile = paths.IPACLIENTSAMBA_UNINSTALL_LOG

    standard_logging_setup(
        logfile,
        verbose=False,
        debug=options.debug,
        filemode="a",
        console_format="%(message)s",
    )

    cfg = dict(
        context="cli_installer",
        confdir=paths.ETC_IPA,
        in_server=False,
        debug=options.debug,
        verbose=0,
    )

    # Bootstrap API early so that env object is available
    api.bootstrap(**cfg)

    local_config = dict(
        host_princ=str("host/%s@%s" % (api.env.host, api.env.realm)),
        smb_princ=str("cifs/%s@%s" % (api.env.host, api.env.realm)),
    )

    # Until api.finalize() is called, we can add our own configuration
    api.env._merge(**local_config)

    if options.uninstall:
        if statestore.has_state("domain_member"):
            uninstall(fstore, statestore, options)
            try:
                keys = (
                    "configured", "hardening", "groupmap", "tdb",
                    "service.principal", "smb.conf"
                )
                for key in keys:
                    statestore.delete_state("domain_member", key)
            except Exception as e:
                print(
                    "Error: Failed to remove the domain_member statestores: "
                    "%s" % e
                )
                return 1
            else:
                print(
                    "Samba configuration is reverted. "
                    "However, Samba databases were fully cleaned and "
                    "old configuration file will not be usable anymore."
                )
        else:
            print("Samba domain member is not configured yet")
        return 0

    ca_cert_path = None
    if os.path.exists(paths.IPA_CA_CRT):
        ca_cert_path = paths.IPA_CA_CRT

    if statestore.has_state("domain_member") and not options.force:
        print("Samba domain member is already configured")
        return CLIENT_ALREADY_CONFIGURED

    if not os.path.exists(paths.SMBD):
        print("Samba suite is not installed")
        return CLIENT_NOT_CONFIGURED

    autodiscover = False
    ds = discovery.IPADiscovery()
    if not options.server:
        print("Searching for IPA server...")
        ret = ds.search(ca_cert_path=ca_cert_path)
        logger.debug("Executing DNS discovery")
        if ret == discovery.NO_LDAP_SERVER:
            logger.debug("Autodiscovery did not find LDAP server")
            s = urlsplit(api.env.xmlrpc_uri)
            server = [s.netloc]
            logger.debug("Setting server to %s", s.netloc)
        else:
            autodiscover = True
            if not ds.servers:
                print(
                    "Autodiscovery was successful but didn't return a server"
                )
                return 1
            logger.debug(
                "Autodiscovery success, possible servers %s",
                ",".join(ds.servers),
            )
            server = ds.servers[0]
    else:
        server = options.server
        logger.debug("Verifying that %s is an IPA server", server)
        ldapret = ds.ipacheckldap(server, api.env.realm, ca_cert_path)
        if ldapret[0] == discovery.NO_ACCESS_TO_LDAP:
            print("Anonymous access to the LDAP server is disabled.")
            print("Proceeding without strict verification.")
            print(
                "Note: This is not an error if anonymous access has been "
                "explicitly restricted."
            )
        elif ldapret[0] == discovery.NO_TLS_LDAP:
            logger.warning("Unencrypted access to LDAP is not supported.")
        elif ldapret[0] != 0:
            print("Unable to confirm that %s is an IPA server" % server)
            return 1

    if not autodiscover:
        print("IPA server: %s" % server)
        logger.debug("Using fixed server %s", server)
    else:
        print("IPA server: DNS discovery")
        logger.info("Configured to use DNS discovery")

    if api.env.host == server:
        logger.error(
            "Cannot run on IPA master. "
            "Cannot configure Samba as a domain member on a domain "
            "controller. Please use ipa-adtrust-install for that!"
        )
        return 1

    if not options.netbiosname:
        options.netbiosname = DNSName.from_text(api.env.host)[0].decode()
    options.netbiosname = options.netbiosname.upper()

    with use_api_as_principal(api.env.host_princ, paths.KRB5_KEYTAB):
        try:
            # Try to access 'service_add_smb' command, if it throws
            # AttributeError exception, the IPA server doesn't support
            # setting up Samba as a domain member.
            service_add_smb = api.Command.service_add_smb

            # Now try to see if SMB principal already exists
            api.Command.service_show(api.env.smb_princ)

            # If no exception was raised, the object exists.
            # We cannot continue because we would break existing configuration
            print(
                "WARNING: SMB service principal %s already exists. "
                "Please remove it before proceeding." % (api.env.smb_princ)
            )
            if not options.force:
                return 1
            # For --force, we should then delete cifs/.. service object
            api.Command.service_del(api.env.smb_princ)
        except AttributeError:
            logger.error(
                "Chosen IPA master %s does not have support to "
                "set up Samba domain members", server,
            )
            return 1
        except errors.VersionError as e:
            print("This client is incompatible: " + str(e))
            return 1
        except errors.NotFound:
            logger.debug("No SMB service principal exists, OK to proceed")
        except errors.PublicError as e:
            logger.error(
                "Cannot connect to the server due to "
                "a generic error: %s", e,
            )
            return 1

        # At this point we have proper setup:
        # - we connected to IPA API end-point as a host principal
        # - no cifs/... principal exists so we can create it
        print("Chosen IPA master: %s" % server)
        print("SMB principal to be created: %s" % api.env.smb_princ)
        print("NetBIOS name to be used: %s" % options.netbiosname)
        logger.info("Chosen IPA master: %s", server)
        logger.info("SMB principal to be created: %s", api.env.smb_princ)
        logger.info("NetBIOS name to be used: %s", options.netbiosname)

        # 1. Pull down ID range and other details of known domains
        domains = retrieve_domain_information(api)
        if len(domains) == 0:
            # logger.error() produces both log file and stderr output
            logger.error("No configured trust controller detected "
                         "on IPA masters. Use ipa-adtrust-install on an IPA "
                         "master to configure trust controller role.")
            return 1

        str_info = pretty_print_domain_information(domains)
        logger.info("Discovered domains to use:\n%s", str_info)
        print("Discovered domains to use:\n%s" % str_info)

        if not options.unattended and not ipautil.user_input(
            "Continue to configure the system with these values?", False
        ):
            print("Installation aborted")
            return 1

        # 2. Create SMB service principal, if we are here, the command exists
        if (
            not statestore.get_state("domain_member", "service.principal") or
            options.force
        ):
            service_add_smb(api.env.host, options.netbiosname)
            statestore.backup_state(
                "domain_member", "service.principal", "configured"
            )

        # 3. Generate machine account password for reuse
        password = generate_smb_machine_account(
            fstore, statestore, options, domains[0]
        )

        # 4. Now that we have all domains retrieved, we can generate smb.conf
        if (
            not statestore.get_state("domain_member", "smb.conf") or
            options.force
        ):
            configure_smb_conf(fstore, statestore, options, domains)
            statestore.backup_state("domain_member", "smb.conf", "configured")

        # 5. Create SMB service
        if statestore.get_state("domain_member",
                                "service.principal") == "configured":
            retrieve_service_principal(
                fstore, statestore, options, domains[0],
                api.env.smb_princ, password
            )
            statestore.backup_state(
                "domain_member", "service.principal", "configured"
            )

        # 6. Configure databases to contain proper details
        if not statestore.get_state("domain_member", "tdb") or options.force:
            populate_samba_databases(
                fstore, statestore, options, domains[0], password
            )
            statestore.backup_state("domain_member", "tdb", "configured")

        # 7. Configure default group mapping
        if (
            not statestore.get_state("domain_member", "groupmap") or
            options.force
        ):
            configure_default_groupmap(fstore, statestore, options, domains[0])
            statestore.backup_state("domain_member", "groupmap", "configured")

        # 8. Enable SELinux policies
        if (
            not statestore.get_state("domain_member", "hardening") or
            options.force
        ):
            harden_configuration(fstore, statestore, options, domains[0])
            statestore.backup_state("domain_member", "hardening", "configured")

        # 9. Finally, store the state of upgrade
        statestore.backup_state("domain_member", "configured", True)

        # Suggest service start only after validating smb.conf
        print(
            "Samba domain member is configured. "
            "Please check configuration at %s and "
            "start smb and winbind services" % paths.SMB_CONF
        )
        logger.info(
            "Samba domain member is configured. "
            "Please check configuration at %s and "
            "start smb and winbind services",
            paths.SMB_CONF,
        )

    return 0
