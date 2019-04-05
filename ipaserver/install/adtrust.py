#
# Copyright (C) 2017 FreeIPA Contributors see COPYING for license
#

"""
AD trust installer module
"""

from __future__ import print_function, absolute_import

import logging
import os

import six

from ipalib.constants import MIN_DOMAIN_LEVEL
from ipalib import errors
from ipalib.install.service import ServiceAdminInstallInterface
from ipalib.install.service import replica_install_only
from ipaplatform.paths import paths
from ipapython.admintool import ScriptError
from ipapython import ipaldap, ipautil
from ipapython.dn import DN
from ipapython.install.core import group, knob
from ipaserver.install import installutils
from ipaserver.install import adtrustinstance
from ipaserver.install import service
from ipaserver.install.plugins.adtrust import update_host_cifs_keytabs


if six.PY3:
    unicode = str

logger = logging.getLogger(__name__)

netbios_name = None
reset_netbios_name = False


def netbios_name_error(name):
    logger.error("\nIllegal NetBIOS name [%s].\n", name)
    logger.error(
        "Up to 15 characters and only uppercase ASCII letters, digits "
        "and dashes are allowed. Empty string is not allowed.")


def read_netbios_name(netbios_default):
    netbios_name = ""

    print("Enter the NetBIOS name for the IPA domain.")
    print("Only up to 15 uppercase ASCII letters, digits "
          "and dashes are allowed.")
    print("Example: EXAMPLE.")
    print("")
    print("")
    if not netbios_default:
        netbios_default = "EXAMPLE"
    while True:
        netbios_name = ipautil.user_input(
            "NetBIOS domain name", netbios_default, allow_empty=False)
        print("")
        if adtrustinstance.check_netbios_name(netbios_name):
            break

        netbios_name_error(netbios_name)

    return netbios_name


def retrieve_netbios_name(api):
    flat_name_attr = 'ipantflatname'
    try:
        entry = api.Backend.ldap2.get_entry(
            DN(('cn', api.env.domain), api.env.container_cifsdomains,
               ipautil.realm_to_suffix(api.env.realm)),
            [flat_name_attr])
    except errors.NotFound:
        # trust not configured
        logger.debug("No previous trust configuration found")
        return None
    else:
        return entry.get(flat_name_attr)[0]


def set_and_check_netbios_name(netbios_name, unattended, api):
    """
    Depending on whether a trust is already configured or not, the passed
    NetBIOS domain name must be handled differently.

    If trust is not configured, the given NetBIOS is used. The NetBIOS is
    generated if none was given on the command line.

    If trust is already configured, the given NetBIOS name is used to reset
    the stored NetBIOS name in case it differs from the current one.
    """

    cur_netbios_name = None
    gen_netbios_name = None
    reset_netbios_name = False

    if api.Backend.ldap2.isconnected():
        cur_netbios_name = retrieve_netbios_name(api)
    else:
        logger.debug(
            "LDAP is not connected, can not retrieve NetBIOS name")

    if cur_netbios_name and not netbios_name:
        # keep the current NetBIOS name
        netbios_name = cur_netbios_name
        reset_netbios_name = False
    elif cur_netbios_name and cur_netbios_name != netbios_name:
        # change the NetBIOS name
        print("Current NetBIOS domain name is %s, new name is %s.\n"
              % (cur_netbios_name, netbios_name))
        print("Please note that changing the NetBIOS name might "
              "break existing trust relationships.")
        if unattended:
            reset_netbios_name = True
            print("NetBIOS domain name will be changed to %s.\n"
                  % netbios_name)
        else:
            print("Say 'yes' if the NetBIOS shall be changed and "
                  "'no' if the old one shall be kept.")
            reset_netbios_name = ipautil.user_input(
                            'Do you want to reset the NetBIOS domain name?',
                            default=False, allow_empty=False)
        if not reset_netbios_name:
            netbios_name = cur_netbios_name
    elif cur_netbios_name and cur_netbios_name == netbios_name:
        # keep the current NetBIOS name
        reset_netbios_name = False
    elif not cur_netbios_name:
        if not netbios_name:
            gen_netbios_name = adtrustinstance.make_netbios_name(
                api.env.domain)

        if gen_netbios_name is not None:
            # Fix existing trust configuration
            print("Trust is configured but no NetBIOS domain name found, "
                  "setting it now.")
            reset_netbios_name = True
        else:
            # initial trust configuration
            reset_netbios_name = False
    else:
        # all possible cases should be covered above
        raise Exception('Unexpected state while checking NetBIOS domain name')

    if unattended and netbios_name is None and gen_netbios_name:
        netbios_name = gen_netbios_name

    if not adtrustinstance.check_netbios_name(netbios_name):
        if unattended:
            netbios_name_error(netbios_name)
            raise ScriptError("Aborting installation.")
        else:
            if netbios_name:
                netbios_name_error(netbios_name)
                netbios_name = None

    if not unattended and not netbios_name:
        netbios_name = read_netbios_name(gen_netbios_name)

    return (netbios_name, reset_netbios_name)


def enable_compat_tree():
    print("Do you want to enable support for trusted domains in Schema "
          "Compatibility plugin?")
    print("This will allow clients older than SSSD 1.9 and non-Linux "
          "clients to work with trusted users.")
    print("")
    enable_compat = ipautil.user_input(
        "Enable trusted domains support in slapi-nis?",
        default=False,
        allow_empty=False)
    print("")
    return enable_compat


def check_for_installed_deps():
    # Check if samba packages are installed
    if not adtrustinstance.check_inst():
        raise ScriptError("Aborting installation.")


def retrieve_entries_without_sid(api):
    """
    Retrieve a list of entries without assigned SIDs.
    :returns: a list of entries or an empty list if an error occurs
    """
    # The filter corresponds to ipa_sidgen_task.c LDAP search filter
    filter = '(&(objectclass=ipaobject)(!(objectclass=mepmanagedentry))' \
             '(|(objectclass=posixaccount)(objectclass=posixgroup)' \
             '(objectclass=ipaidobject))(!(ipantsecurityidentifier=*)))'
    base_dn = api.env.basedn
    try:
        logger.debug(
            "Searching for objects with missing SID with "
            "filter=%s, base_dn=%s", filter, base_dn)
        entries, _truncated = api.Backend.ldap2.find_entries(
            filter=filter, base_dn=base_dn, attrs_list=[''])
        return entries
    except errors.NotFound:
        # All objects have SIDs assigned
        pass
    except (errors.DatabaseError, errors.NetworkError) as e:
        logger.error(
            "Could not retrieve a list of objects that need a SID "
            "identifier assigned: %s", e)

    return []


def retrieve_and_ask_about_sids(api, options):
    entries = []
    if api.Backend.ldap2.isconnected():
        entries = retrieve_entries_without_sid(api)
    else:
        logger.debug(
            "LDAP backend not connected, can not retrieve entries "
            "with missing SID")

    object_count = len(entries)
    if object_count > 0:
        print("")
        print("WARNING: %d existing users or groups do not have "
              "a SID identifier assigned." % len(entries))
        print("Installer can run a task to have ipa-sidgen "
              "Directory Server plugin generate")
        print("the SID identifier for all these users. Please note, "
              "in case of a high")
        print("number of users and groups, the operation might "
              "lead to high replication")
        print("traffic and performance degradation. Refer to "
              "ipa-adtrust-install(1) man page")
        print("for details.")
        print("")
        if options.unattended:
            print("Unattended mode was selected, installer will "
                  "NOT run ipa-sidgen task!")
        else:
            if ipautil.user_input(
                    "Do you want to run the ipa-sidgen task?",
                    default=False,
                    allow_empty=False):
                options.add_sids = True


def retrieve_potential_adtrust_agents(api):
    """
    Retrieve a sorted list of potential AD trust agents

    :param api: initialized API instance
    :returns: sorted list of FQDNs of masters which are not AD trust agents
    """
    try:
        # Search only masters which have support for domain levels
        # because only these masters will have SSSD recent enough
        # to support AD trust agents
        dl_enabled_masters = api.Command.server_find(
            ipamindomainlevel=MIN_DOMAIN_LEVEL, all=True)['result']
    except (errors.DatabaseError, errors.NetworkError) as e:
        logger.error(
            "Could not retrieve a list of existing IPA masters: %s", e)
        return None

    try:
        # search for existing AD trust agents
        adtrust_agents = api.Command.server_find(
            servrole=u'AD trust agent', all=True)['result']
    except (errors.DatabaseError, errors.NetworkError) as e:
        logger.error("Could not retrieve a list of adtrust agents: %s", e)
        return None

    dl_enabled_master_cns = {m['cn'][0] for m in dl_enabled_masters}
    adtrust_agents_cns = {m['cn'][0] for m in adtrust_agents}

    potential_agents_cns = dl_enabled_master_cns - adtrust_agents_cns

    # remove the local host from the potential agents since it will be set up
    # by adtrustinstance configuration code
    potential_agents_cns -= {api.env.host}
    return sorted(potential_agents_cns)


def add_hosts_to_adtrust_agents(api, host_list):
    """
    Add the CIFS and host principals to the 'adtrust agents'
    group as 389-ds only operates with GroupOfNames, we have to
    use the principal's proper dn as defined in self.cifs_agent

    :param api: API instance
    :param host_list: list of potential AD trust agent FQDNs
    """
    agents_dn = DN(
        ('cn', 'adtrust agents'), ('cn', 'sysaccounts'),
        ('cn', 'etc'), api.env.basedn)

    service.add_principals_to_group(
        api.Backend.ldap2,
        agents_dn,
        "member",
        [api.Object.host.get_dn(x) for x in host_list])


def add_new_adtrust_agents(api, options):
    """
    Find out IPA masters which are not part of the cn=adtrust agents
    and propose them to be added to the list
    :param api: API instance
    :param options: parsed CLI options
    """
    potential_agents_cns = retrieve_potential_adtrust_agents(api)

    if potential_agents_cns:
        print("")
        print("WARNING: %d IPA masters are not yet able to serve "
              "information about users from trusted forests."
              % len(potential_agents_cns))
        print("Installer can add them to the list of IPA masters "
              "allowed to access information about trusts.")
        print("If you choose to do so, you also need to restart "
              "LDAP service on those masters.")
        print("Refer to ipa-adtrust-install(1) man page for details.")
        print("")
        if options.unattended:
            print("Unattended mode was selected, installer will NOT "
                  "add other IPA masters to the list of allowed to")
            print("access information about trusted forests!")
            return

    new_agents = []

    for name in sorted(potential_agents_cns):
        if ipautil.user_input(
                "IPA master [%s]?" % (name),
                default=False,
                allow_empty=False):
            new_agents.append(name)

    if new_agents:
        add_hosts_to_adtrust_agents(api, new_agents)

        print("""
WARNING: you MUST restart (e.g. ipactl restart) the following IPA masters in
order to activate them to serve information about users from trusted forests:
""")
        for x in new_agents:
            print(x)


def install_check(standalone, options, api):
    global netbios_name
    global reset_netbios_name

    if not standalone:
        check_for_installed_deps()

    realm_not_matching_domain = (api.env.domain.upper() != api.env.realm)

    if realm_not_matching_domain:
        print("WARNING: Realm name does not match the domain name.\n"
              "You will not be able to establish trusts with Active "
              "Directory unless\nthe realm name of the IPA server matches its "
              "domain name.\n\n")
        if not options.unattended:
            if not ipautil.user_input("Do you wish to continue?",
                                      default=False,
                                      allow_empty=False):
                raise ScriptError("Aborting installation.")

    # Check if /etc/samba/smb.conf already exists. In case it was not generated
    # by IPA, print a warning that we will break existing configuration.

    if adtrustinstance.ipa_smb_conf_exists():
        if not options.unattended:
            print("IPA generated smb.conf detected.")
            if not ipautil.user_input("Overwrite smb.conf?",
                                      default=False,
                                      allow_empty=False):
                raise ScriptError("Aborting installation.")

    elif os.path.exists(paths.SMB_CONF):
        print("WARNING: The smb.conf already exists. Running "
              "ipa-adtrust-install will break your existing samba "
              "configuration.\n\n")
        if not options.unattended:
            if not ipautil.user_input("Do you wish to continue?",
                                      default=False,
                                      allow_empty=False):
                raise ScriptError("Aborting installation.")

    if not options.unattended and not options.enable_compat:
        options.enable_compat = enable_compat_tree()

    netbios_name, reset_netbios_name = set_and_check_netbios_name(
        options.netbios_name, options.unattended, api)

    if not options.add_sids:
        retrieve_and_ask_about_sids(api, options)


def install(standalone, options, fstore, api):
    if not options.unattended and standalone:
        print("")
        print("The following operations may take some minutes to complete.")
        print("Please wait until the prompt is returned.")
        print("")

    smb = adtrustinstance.ADTRUSTInstance(fstore)
    smb.realm = api.env.realm
    smb.autobind = ipaldap.AUTOBIND_ENABLED
    smb.setup(api.env.host, api.env.realm,
              netbios_name, reset_netbios_name,
              options.rid_base, options.secondary_rid_base,
              options.add_sids,
              enable_compat=options.enable_compat)
    smb.find_local_id_range()
    smb.create_instance()

    # Update Samba keytab with host keys
    ad_update = update_host_cifs_keytabs(api)
    if ad_update:
        result = ad_update()
        # this particular update does not require restarting DS but
        # the plugin might require that in future
        if result[0]:
            logger.debug('Restarting directory server to apply updates')
            installutils.restart_dirsrv()

    if options.add_agents:
        # Find out IPA masters which are not part of the cn=adtrust agents
        # and propose them to be added to the list
        add_new_adtrust_agents(api, options)


@group
class ADTrustInstallInterface(ServiceAdminInstallInterface):
    """
    Interface for the AD trust installer

    Knobs defined here will be available in:
    * ipa-server-install
    * ipa-replica-install
    * ipa-adtrust-install
    """
    description = "AD trust"

    # the following knobs are provided on top of those specified for
    # admin credentials
    add_sids = knob(
        None,
        description="Add SIDs for existing users and groups as the final step"
    )
    add_agents = knob(
        None,
        description="Add IPA masters to a list of hosts allowed to "
                    "serve information about users from trusted forests"
    )
    add_agents = replica_install_only(add_agents)
    enable_compat = knob(
        None,
        description="Enable support for trusted domains for old clients"
    )
    netbios_name = knob(
        str,
        None,
        description="NetBIOS name of the IPA domain"
    )
    no_msdcs = knob(
        None,
        description="Deprecated: has no effect",
        deprecated=True
    )
    rid_base = knob(
        int,
        1000,
        description="Start value for mapping UIDs and GIDs to RIDs"
    )
    secondary_rid_base = knob(
        int,
        100000000,
        description="Start value of the secondary range for mapping "
                    "UIDs and GIDs to RIDs"
    )
