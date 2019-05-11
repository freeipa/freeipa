# Copyright (C) 2012-2019  FreeIPA Contributors see COPYING for license

from __future__ import absolute_import
import logging

from ipalib import Registry, errors
from ipalib import Updater
from ipapython.dn import DN
from ipapython import ipautil
from ipaplatform.paths import paths
from ipaserver.install import sysupgrade
from ipaserver.install.adtrustinstance import (
    ADTRUSTInstance, map_Guests_to_nobody)
from ipaserver.dcerpc_common import TRUST_BIDIRECTIONAL

try:
    from samba.ndr import ndr_unpack
    from samba.dcerpc import lsa, drsblobs
except ImportError:
    # If samba.ndr is not available, this machine is not provisioned
    # for serving a trust to Active Directory. As result, it does
    # not matter what ndr_unpack does but we save on pylint checks
    def ndr_unpack(x):
        raise NotImplementedError

logger = logging.getLogger(__name__)

register = Registry()

DEFAULT_ID_RANGE_SIZE = 200000


@register()
class update_default_range(Updater):
    """
    Create default ID range for upgraded servers.
    """

    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        dn = DN(self.api.env.container_ranges, self.api.env.basedn)
        search_filter = "objectclass=ipaDomainIDRange"
        try:
            ldap.find_entries(search_filter, [], dn)
        except errors.NotFound:
            pass
        else:
            logger.debug("default_range: ipaDomainIDRange entry found, skip "
                         "plugin")
            return False, []

        dn = DN(('cn', 'admins'), self.api.env.container_group,
                self.api.env.basedn)
        try:
            admins_entry = ldap.get_entry(dn, ['gidnumber'])
        except errors.NotFound:
            logger.error("default_range: No local ID range and no admins "
                         "group found. Cannot create default ID range")
            return False, []

        id_range_base_id = admins_entry['gidnumber'][0]
        id_range_name = '%s_id_range' % self.api.env.realm
        id_range_size = DEFAULT_ID_RANGE_SIZE

        range_entry = [
            dict(attr='objectclass', value='top'),
            dict(attr='objectclass', value='ipaIDrange'),
            dict(attr='objectclass', value='ipaDomainIDRange'),
            dict(attr='cn', value=id_range_name),
            dict(attr='ipabaseid', value=id_range_base_id),
            dict(attr='ipaidrangesize', value=id_range_size),
            dict(attr='iparangetype', value='ipa-local'),
        ]

        dn = DN(('cn', '%s_id_range' % self.api.env.realm),
                self.api.env.container_ranges, self.api.env.basedn)

        update = {'dn': dn, 'default': range_entry}

        # Default range entry has a hard-coded range size to 200000 which is
        # a default range size in ipa-server-install. This could cause issues
        # if user did not use a default range, but rather defined an own,
        # bigger range (option --idmax).
        # We should make our best to check if this is the case and provide
        # user with an information how to fix it.
        dn = DN(self.api.env.container_dna_posix_ids, self.api.env.basedn)
        search_filter = "objectclass=dnaSharedConfig"
        attrs = ['dnaHostname', 'dnaRemainingValues']
        try:
            (entries, _truncated) = ldap.find_entries(search_filter, attrs, dn)
        except errors.NotFound:
            logger.warning("default_range: no dnaSharedConfig object found. "
                           "Cannot check default range size.")
        else:
            masters = set()
            remaining_values_sum = 0
            for entry in entries:
                hostname = entry.get('dnahostname', [None])[0]
                if hostname is None or hostname in masters:
                    continue
                remaining_values = entry.get('dnaremainingvalues', [''])[0]
                try:
                    remaining_values = int(remaining_values)
                except ValueError:
                    logger.warning("default_range: could not parse "
                                   "remaining values from '%s'",
                                   remaining_values)
                    continue
                else:
                    remaining_values_sum += remaining_values

                masters.add(hostname)

            if remaining_values_sum > DEFAULT_ID_RANGE_SIZE:
                msg = ['could not verify default ID range size',
                       'Please use the following command to set correct ID range size',
                       '  $ ipa range-mod %s --range-size=RANGE_SIZE' % id_range_name,
                       'RANGE_SIZE may be computed from --idstart and --idmax options '
                       'used during IPA server installation:',
                       '  RANGE_SIZE = (--idmax) - (--idstart) + 1'
                      ]

                logger.error("default_range: %s", "\n".join(msg))

        return False, [update]


@register()
class update_default_trust_view(Updater):
    """
    Create Default Trust View for upgraded servers.
    """

    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        default_trust_view_dn = DN(('cn', 'Default Trust View'),
                                   self.api.env.container_views,
                                   self.api.env.basedn)

        default_trust_view_entry = [
            dict(attr='objectclass', value='top'),
            dict(attr='objectclass', value='ipaIDView'),
            dict(attr='cn', value='Default Trust View'),
            dict(attr='description', value='Default Trust View for AD users. '
                 'Should not be deleted.'),
        ]

        # First, see if trusts are enabled on the server
        if not self.api.Command.adtrust_is_enabled()['result']:
            logger.debug('AD Trusts are not enabled on this server')
            return False, []

        # Second, make sure the Default Trust View does not exist yet
        try:
            ldap.get_entry(default_trust_view_dn)
        except errors.NotFound:
            pass
        else:
            logger.debug('Default Trust View already present on this server')
            return False, []

        # We have a server with AD trust support without Default Trust View.
        # Create the Default Trust View entry.

        update = {
            'dn': default_trust_view_dn,
            'default': default_trust_view_entry
        }

        return False, [update]


@register()
class update_sigden_extdom_broken_config(Updater):
    """Fix configuration of sidgen and extdom plugins

    Upgrade to IPA 4.2+ cause that sidgen and extdom plugins have improperly
    configured basedn.

    All trusts which have been added when config was broken must to be
    re-added manually.

    https://fedorahosted.org/freeipa/ticket/5665
    """

    sidgen_config_dn = DN("cn=IPA SIDGEN,cn=plugins,cn=config")
    extdom_config_dn = DN("cn=ipa_extdom_extop,cn=plugins,cn=config")

    def _fix_config(self):
        """Due upgrade error configuration of sidgen and extdom plugins may
        contain literally "$SUFFIX" value instead of real DN in nsslapd-basedn
        attribute

        :return: True if config was fixed, False if fix is not needed
        """
        ldap = self.api.Backend.ldap2
        basedn_attr = 'nsslapd-basedn'
        modified = False

        for dn in (self.sidgen_config_dn, self.extdom_config_dn):
            try:
                entry = ldap.get_entry(dn, attrs_list=[basedn_attr])
            except errors.NotFound:
                logger.debug("configuration for %s not found, skipping", dn)
            else:
                configured_suffix = entry.single_value.get(basedn_attr)
                if configured_suffix is None:
                    raise RuntimeError(
                        "Missing attribute {attr} in {dn}".format(
                            attr=basedn_attr, dn=dn
                        )
                    )
                elif configured_suffix == "$SUFFIX":
                    # configured value is wrong, fix it
                    entry.single_value[basedn_attr] = str(self.api.env.basedn)
                    logger.debug("updating attribute %s of %s to correct "
                                 "value %s",
                                 basedn_attr, dn, self.api.env.basedn)
                    ldap.update_entry(entry)
                    modified = True
                else:
                    logger.debug("configured basedn for %s is okay", dn)

        return modified

    def execute(self, **options):
        if sysupgrade.get_upgrade_state('sidgen', 'config_basedn_updated'):
            logger.debug("Already done, skipping")
            return False, ()

        restart = False
        if self._fix_config():
            sysupgrade.set_upgrade_state('sidgen', 'update_sids', True)
            restart = True  # DS has to be restarted to apply changes

        sysupgrade.set_upgrade_state('sidgen', 'config_basedn_updated', True)
        return restart, ()


@register()
class update_sids(Updater):
    """SIDs may be not created properly if bug with wrong configuration for
    sidgen and extdom plugins is effective

    This must be run after "update_sigden_extdom_broken_config"
    https://fedorahosted.org/freeipa/ticket/5665
    """
    sidgen_config_dn = DN("cn=IPA SIDGEN,cn=plugins,cn=config")

    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        if sysupgrade.get_upgrade_state('sidgen', 'update_sids') is not True:
            logger.debug("SIDs do not need to be generated")
            return False, ()

        # check if IPA domain for AD trust has been created, and if we need to
        # regenerate missing SIDs if attribute 'ipaNTSecurityIdentifier'
        domain_IPA_AD_dn = DN(
            ('cn', self.api.env.domain),
            self.api.env.container_cifsdomains,
            self.api.env.basedn)
        attr_name = 'ipaNTSecurityIdentifier'

        try:
            entry = ldap.get_entry(domain_IPA_AD_dn, attrs_list=[attr_name])
        except errors.NotFound:
            logger.debug("IPA domain object %s is not configured",
                         domain_IPA_AD_dn)
            sysupgrade.set_upgrade_state('sidgen', 'update_sids', False)
            return False, ()
        else:
            if not entry.single_value.get(attr_name):
                # we need to run sidgen task
                sidgen_task_dn = DN(
                    "cn=generate domain sid,cn=ipa-sidgen-task,cn=tasks,"
                    "cn=config")
                sidgen_tasks_attr = {
                    "objectclass": ["top", "extensibleObject"],
                    "cn": ["sidgen"],
                    "delay": [0],
                    "nsslapd-basedn": [self.api.env.basedn],
                }

                task_entry = ldap.make_entry(sidgen_task_dn,
                                             **sidgen_tasks_attr)
                try:
                    ldap.add_entry(task_entry)
                except errors.DuplicateEntry:
                    logger.debug("sidgen task already created")
                else:
                    logger.debug("sidgen task has been created")

        # we have to check all trusts domains which may been affected by the
        # bug. Symptom is missing 'ipaNTSecurityIdentifier' attribute

        base_dn = DN(self.api.env.container_adtrusts, self.api.env.basedn)
        try:
            trust_domain_entries, truncated = ldap.find_entries(
                base_dn=base_dn,
                scope=ldap.SCOPE_ONELEVEL,
                attrs_list=["cn"],
                # more types of trusts can be stored under cn=trusts, we need
                # the type with ipaNTTrustPartner attribute
                filter="(&(ipaNTTrustPartner=*)(!(%s=*)))" % attr_name
            )
        except errors.NotFound:
            pass
        else:
            if truncated:
                logger.warning("update_sids: Search results were truncated")

            for entry in trust_domain_entries:
                domain = entry.single_value["cn"]
                logger.error(
                    "Your trust to %s is broken. Please re-create it by "
                    "running 'ipa trust-add' again.", domain)

        sysupgrade.set_upgrade_state('sidgen', 'update_sids', False)
        return False, ()


def get_gidNumber(ldap, env):
    # Read the gidnumber of the fallback group and returns a list with it
    dn = DN(('cn', ADTRUSTInstance.FALLBACK_GROUP_NAME),
            env.container_group,
            env.basedn)

    try:
        entry = ldap.get_entry(dn, ['gidnumber'])
        gidNumber = entry.get('gidnumber')
    except errors.NotFound:
        logger.error("%s not found",
                     ADTRUSTInstance.FALLBACK_GROUP_NAME)
        return None

    if gidNumber is None:
        logger.error("%s does not have a gidnumber",
                     ADTRUSTInstance.FALLBACK_GROUP_NAME)
        return None

    return gidNumber


@register()
class update_tdo_gidnumber(Updater):
    """
    Create a gidNumber attribute for Trusted Domain Objects.

    The value is taken from the fallback group defined in cn=Default SMB Group.
    """
    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        # First, see if trusts are enabled on the server
        if not self.api.Command.adtrust_is_enabled()['result']:
            logger.debug('AD Trusts are not enabled on this server')
            return False, []

        gidNumber = get_gidNumber(ldap, self.api.env)
        if not gidNumber:
            logger.error("%s does not have a gidnumber",
                         ADTRUSTInstance.FALLBACK_GROUP_NAME)
            return False, ()

        # For each trusted domain object, add posix attributes
        # to allow use of a trusted domain account by AD DCs
        # to authenticate against our Samba instance
        try:
            tdos = ldap.get_entries(
                DN(self.api.env.container_adtrusts, self.api.env.basedn),
                scope=ldap.SCOPE_ONELEVEL,
                filter="(&(objectclass=ipaNTTrustedDomain)"
                       "(objectclass=ipaIDObject))",
                attrs_list=['gidnumber', 'uidnumber', 'objectclass',
                            'ipantsecurityidentifier',
                            'ipaNTTrustDirection'
                            'uid', 'cn', 'ipantflatname'])
            for tdo in tdos:
                # if the trusted domain object does not contain gidnumber,
                # add the default fallback group gidnumber
                if not tdo.get('gidnumber'):
                    tdo['gidnumber'] = gidNumber

                # Generate uidNumber and ipaNTSecurityIdentifier if
                # uidNumber is missing. We rely on sidgen plugin here
                # to generate ipaNTSecurityIdentifier.
                if not tdo.get('uidnumber'):
                    tdo['uidnumber'] = ['-1']

                if 'posixAccount' not in tdo.get('objectclass'):
                    tdo['objectclass'].extend(['posixAccount'])
                # Based on the flat name of a TDO,
                # add user name FLATNAME$ (note dollar sign)
                # to allow SSSD to map this TDO to a POSIX account
                if not tdo.get('uid'):
                    tdo['uid'] = ["{flatname}$".format(
                                  flatname=tdo.single_value['ipantflatname'])]
                if not tdo.get('homedirectory'):
                    tdo['homedirectory'] = ['/dev/null']

                # Store resulted entry
                try:
                    ldap.update_entry(tdo)
                except errors.ExecutionError as e:
                    logger.warning(
                        "Failed to update trusted domain object %s", tdo.dn)
                    logger.debug("Exception during TDO update: %s", str(e))

        except errors.NotFound:
            logger.debug("No trusted domain object to update")
            return False, ()

        return False, ()


@register()
class update_mapping_Guests_to_nobody(Updater):
    """
    Map BUILTIN\\Guests group to nobody

    Samba 4.9 became more strict on availability of builtin Guests group
    """
    def execute(self, **options):
        # First, see if trusts are enabled on the server
        if not self.api.Command.adtrust_is_enabled()['result']:
            logger.debug('AD Trusts are not enabled on this server')
            return False, []

        map_Guests_to_nobody()
        return False, []


@register()
class update_tdo_to_new_layout(Updater):
    """
    Transform trusted domain objects into a new layout

    There are now two Kerberos principals per direction of trust:

    INBOUND:
     - krbtgt/<OUR REALM>@<REMOTE REALM>, enabled by default

     - <OUR FLATNAME$>@<REMOTE REALM>, disabled by default on our side
       as it is only used by SSSD to retrieve TDO creds when operating
       as an AD Trust agent across IPA topology

    OUTBOUND:
     - krbtgt/<REMOTE REALM>@<OUR REALM>, enabled by default

     - <REMOTE FLATNAME$>@<OUR REALM>, enabled by default and
       used by remote trusted DCs to authenticate against us

       This principal also has krbtgt/<REMOTE FLATNAME>@<OUR REALM> defined
       as a Kerberos principal alias. This is due to how Kerberos
       key salt is derived for cross-realm principals on AD side

    Finally, Samba requires <REMOTE FLATNAME$> account to also possess POSIX
    and SMB identities. We ensure this by making the trusted domain object to
    be this account with 'uid' and 'cn' attributes being '<REMOTE FLATNAME$>'
    and uidNumber/gidNumber generated automatically. Also, we ensure the
    trusted domain object is given a SID.

    The update to <REMOTE FLATNAME$> POSIX/SMB identities is done through
    the update plugin update_tdo_gidnumber.
    """
    tgt_principal_template = "krbtgt/{remote}@{local}"
    nbt_principal_template = "{nbt}$@{realm}"
    trust_filter = \
        "(&(objectClass=ipaNTTrustedDomain)(objectClass=ipaIDObject))"
    trust_attrs = ("ipaNTFlatName", "ipaNTTrustPartner", "ipaNTTrustDirection",
                   "cn", "ipaNTTrustAttributes", "ipaNTAdditionalSuffixes",
                   "ipaNTTrustedDomainSID", "ipaNTTrustType",
                   "ipaNTTrustAuthIncoming", "ipaNTTrustAuthOutgoing")
    change_password_template = \
        "change_password -pw {password} " \
        "-e aes256-cts-hmac-sha1-96,aes128-cts-hmac-sha1-96 " \
        "{principal}"

    KRB_PRINC_CREATE_DEFAULT = 0x00000000
    KRB_PRINC_CREATE_DISABLED = 0x00000001
    KRB_PRINC_CREATE_AGENT_PERMISSION = 0x00000002
    KRB_PRINC_CREATE_IDENTITY = 0x00000004
    KRB_PRINC_MUST_EXIST = 0x00000008

    # This is a flag for krbTicketFlags attribute
    # to disallow creating any tickets using this principal
    KRB_DISALLOW_ALL_TIX = 0x00000040

    def retrieve_trust_password(self, packed):
        # The structure of the trust secret is described at
        # https://github.com/samba-team/samba/blob/master/
        # librpc/idl/drsblobs.idl#L516-L569
        # In our case in LDAP TDO object stores
        # `struct trustAuthInOutBlob` that has `count` and
        # the `current` of `AuthenticationInformationArray` struct
        # which has own `count` and `array` of `AuthenticationInformation`
        # structs that have `AuthType` field which should be equal to
        # `LSA_TRUST_AUTH_TYPE_CLEAR`.
        # Then AuthInfo field would contain a password as an array of bytes
        assert(packed.count != 0)
        assert(packed.current.count != 0)
        assert(packed.current.array[0].AuthType == lsa.TRUST_AUTH_TYPE_CLEAR)
        clear_value = packed.current.array[0].AuthInfo.password

        return ''.join(map(chr, clear_value))

    def set_krb_principal(self, principals, password, trustdn, flags=None):

        ldap = self.api.Backend.ldap2

        if isinstance(principals, (list, tuple)):
            trust_principal = principals[0]
            aliases = principals[1:]
        else:
            trust_principal = principals
            aliases = []

        try:
            entry = ldap.get_entry(
                DN(('krbprincipalname', trust_principal), trustdn))
            dn = entry.dn
            action = ldap.update_entry
            logger.debug("Updating Kerberos principal entry for %s",
                         trust_principal)
        except errors.NotFound:
            # For a principal that must exist, we re-raise the exception
            # to let the caller to handle this situation
            if flags & self.KRB_PRINC_MUST_EXIST:
                raise

            dn = DN(('krbprincipalname', trust_principal), trustdn)
            entry = ldap.make_entry(dn)
            logger.debug("Adding Kerberos principal entry for %s",
                         trust_principal)
            action = ldap.add_entry

        entry_data = {
            'objectclass':
                ['krbPrincipal', 'krbPrincipalAux',
                 'krbTicketPolicyAux', 'top'],
            'krbcanonicalname': [trust_principal],
            'krbprincipalname': [trust_principal],
        }

        entry_data['krbprincipalname'].extend(aliases)

        if flags & self.KRB_PRINC_CREATE_DISABLED:
            flg = int(entry.single_value.get('krbticketflags', 0))
            entry_data['krbticketflags'] = flg | self.KRB_DISALLOW_ALL_TIX

        if flags & self.KRB_PRINC_CREATE_AGENT_PERMISSION:
            entry_data['objectclass'].extend(['ipaAllowedOperations'])

        entry.update(entry_data)
        try:
            action(entry)
        except errors.EmptyModlist:
            logger.debug("No update was required for Kerberos principal %s",
                         trust_principal)

        # If entry existed, no need to set Kerberos keys on it
        if action == ldap.update_entry:
            logger.debug("No need to update Kerberos keys for "
                         "existing Kerberos principal %s",
                         trust_principal)
            return

        # Now that entry is updated, set its Kerberos keys.
        #
        # It would be a complication to use ipa-getkeytab LDAP extended control
        # here because we would need to encode the request in ASN.1 sequence
        # and we don't have the code to do so exposed in Python bindings.
        # Instead, as we run on IPA master, we can use kadmin.local for that
        # directly.
        # We pass the command as a stdin to both avoid shell interpolation
        # of the passwords and also to avoid its exposure to other processes
        # Since we don't want to record the output, make also a redacted log
        change_password = self.change_password_template.format(
            password=password,
            principal=trust_principal)

        redacted = self.change_password_template.format(
            password='<REDACTED OUT>',
            principal=trust_principal)
        logger.debug("Updating Kerberos keys for %s with the following "
                     "kadmin command:\n\t%s", trust_principal, redacted)

        ipautil.run([paths.KADMIN_LOCAL, "-x",
                    "ipa-setup-override-restrictions"],
                    stdin=change_password, skip_output=True)

    def execute(self, **options):
        # First, see if trusts are enabled on the server
        if not self.api.Command.adtrust_is_enabled()['result']:
            logger.debug('AD Trusts are not enabled on this server')
            return False, []

        ldap = self.api.Backend.ldap2
        gidNumber = get_gidNumber(ldap, self.api.env)
        if gidNumber is None:
            return False, []

        result = self.api.Command.trustconfig_show()['result']
        our_nbt_name = result.get('ipantflatname', [None])[0]
        if not our_nbt_name:
            return False, []

        trusts_dn = self.api.env.container_adtrusts + self.api.env.basedn

        # We might be in a situation when no trusts exist yet
        # In such case there is nothing to upgrade but we have to catch
        # an exception or it will abort the whole upgrade process
        try:
            trusts = ldap.get_entries(
                base_dn=trusts_dn,
                scope=ldap.SCOPE_ONELEVEL,
                filter=self.trust_filter,
                attrs_list=self.trust_attrs)
        except errors.EmptyResult:
            trusts = []

        # For every trust, retrieve its principals and convert
        for t_entry in trusts:
            t_dn = t_entry.dn
            logger.debug('Processing trust domain object %s', str(t_dn))
            t_realm = t_entry.single_value.get('ipaNTTrustPartner').upper()
            direction = int(t_entry.single_value.get('ipaNTTrustDirection'))
            passwd_incoming = self.retrieve_trust_password(
                ndr_unpack(drsblobs.trustAuthInOutBlob,
                           t_entry.single_value.get('ipaNTTrustAuthIncoming')))
            passwd_outgoing = self.retrieve_trust_password(
                ndr_unpack(drsblobs.trustAuthInOutBlob,
                           t_entry.single_value.get('ipaNTTrustAuthOutgoing')))
            # For outbound and inbound trusts, process four principals total
            if (direction & TRUST_BIDIRECTIONAL) == TRUST_BIDIRECTIONAL:
                # 1. OUTBOUND: krbtgt/<REMOTE REALM>@<OUR REALM> must exist
                trust_principal = self.tgt_principal_template.format(
                    remote=t_realm, local=self.api.env.realm)
                try:
                    self.set_krb_principal(trust_principal,
                                           passwd_outgoing,
                                           t_dn,
                                           flags=self.KRB_PRINC_CREATE_DEFAULT)
                except errors.NotFound:
                    # It makes no sense to convert this one, skip the trust
                    # completely, better to re-establish one
                    logger.error(
                        "Broken trust to AD: %s not found, "
                        "please re-establish the trust to %s",
                        trust_principal, t_realm)
                    continue

                # 2. Create <REMOTE FLATNAME$>@<OUR REALM>
                nbt_name = t_entry.single_value.get('ipaNTFlatName')
                nbt_principal = self.nbt_principal_template.format(
                    nbt=nbt_name, realm=self.api.env.realm)
                tgt_principal = self.tgt_principal_template.format(
                    remote=nbt_name, local=self.api.env.realm)
                self.set_krb_principal([nbt_principal, tgt_principal],
                                       passwd_incoming,
                                       t_dn,
                                       flags=self.KRB_PRINC_CREATE_DEFAULT)

            # 3. INBOUND: krbtgt/<OUR REALM>@<REMOTE REALM> must exist
            trust_principal = self.tgt_principal_template.format(
                remote=self.api.env.realm, local=t_realm)
            try:
                self.set_krb_principal(trust_principal, passwd_outgoing,
                                       t_dn,
                                       flags=self.KRB_PRINC_CREATE_DEFAULT)
            except errors.NotFound:
                # It makes no sense to convert this one, skip the trust
                # completely, better to re-establish one
                logger.error(
                    "Broken trust to AD: %s not found, "
                    "please re-establish the trust to %s",
                    trust_principal, t_realm)
                continue

            # 4. Create <OUR FLATNAME$>@<REMOTE REALM>, disabled
            nbt_principal = self.nbt_principal_template.format(
                nbt=our_nbt_name, realm=t_realm)
            tgt_principal = self.tgt_principal_template.format(
                remote=our_nbt_name, local=t_realm)
            self.set_krb_principal([nbt_principal, tgt_principal],
                                   passwd_incoming,
                                   t_dn,
                                   flags=self.KRB_PRINC_CREATE_DEFAULT |
                                   self.KRB_PRINC_CREATE_AGENT_PERMISSION |
                                   self.KRB_PRINC_CREATE_DISABLED)

        return False, []
