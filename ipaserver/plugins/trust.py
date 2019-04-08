# Authors:
#     Alexander Bokovoy <abokovoy@redhat.com>
#     Martin Kosek <mkosek@redhat.com>
#
# Copyright (C) 2011  Red Hat
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

import logging

import six

from ipalib.messages import (
    add_message,
    BrokenTrust)
from ipalib.plugable import Registry
from .baseldap import (
    pkey_to_value,
    entry_to_dict,
    LDAPCreate,
    LDAPDelete,
    LDAPUpdate,
    LDAPSearch,
    LDAPRetrieve,
    LDAPObject,
    LDAPQuery)
from .dns import dns_container_exists
from ipapython.dn import DN
from ipapython.ipautil import realm_to_suffix
from ipalib import api, Str, StrEnum, Password, Bool, _, ngettext, Int, Flag
from ipalib import Command
from ipalib import errors
from ipalib import output
from ldap import SCOPE_SUBTREE
from time import sleep
from ipaserver.dcerpc_common import (TRUST_ONEWAY,
                                     TRUST_BIDIRECTIONAL,
                                     TRUST_JOIN_EXTERNAL,
                                     LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE,
                                     trust_type_string,
                                     trust_direction_string,
                                     trust_status_string)

if six.PY3:
    unicode = str

try:
    import pysss_murmur
    _murmur_installed = True
except Exception as e:
    _murmur_installed = False

try:
    import pysss_nss_idmap
    _nss_idmap_installed = True
except Exception as e:
    _nss_idmap_installed = False

if api.env.in_server and api.env.context in ['lite', 'server']:
    try:
        import ipaserver.dcerpc
        import dbus
        import dbus.mainloop.glib
        _bindings_installed = True
    except ImportError:
        _bindings_installed = False

__doc__ = _("""
Cross-realm trusts

Manage trust relationship between IPA and Active Directory domains.

In order to allow users from a remote domain to access resources in IPA domain,
trust relationship needs to be established. Currently IPA supports only trusts
between IPA and Active Directory domains under control of Windows Server 2008
or later, with functional level 2008 or later.

Please note that DNS on both IPA and Active Directory domain sides should be
configured properly to discover each other. Trust relationship relies on
ability to discover special resources in the other domain via DNS records.

Examples:

1. Establish cross-realm trust with Active Directory using AD administrator
   credentials:

   ipa trust-add --type=ad <ad.domain> --admin <AD domain administrator> \
           --password

2. List all existing trust relationships:

   ipa trust-find

3. Show details of the specific trust relationship:

   ipa trust-show <ad.domain>

4. Delete existing trust relationship:

   ipa trust-del <ad.domain>

Once trust relationship is established, remote users will need to be mapped
to local POSIX groups in order to actually use IPA resources. The mapping
should be done via use of external membership of non-POSIX group and then
this group should be included into one of local POSIX groups.

Example:

1. Create group for the trusted domain admins' mapping and their local POSIX
group:

   ipa group-add --desc='<ad.domain> admins external map' \
           ad_admins_external --external
   ipa group-add --desc='<ad.domain> admins' ad_admins

2. Add security identifier of Domain Admins of the <ad.domain> to the
   ad_admins_external group:

   ipa group-add-member ad_admins_external --external 'AD\\Domain Admins'

3. Allow members of ad_admins_external group to be associated with
   ad_admins POSIX group:

   ipa group-add-member ad_admins --groups ad_admins_external

4. List members of external members of ad_admins_external group to see
   their SIDs:

   ipa group-show ad_admins_external


GLOBAL TRUST CONFIGURATION

When IPA AD trust subpackage is installed and ipa-adtrust-install is run, a
local domain configuration (SID, GUID, NetBIOS name) is generated. These
identifiers are then used when communicating with a trusted domain of the
particular type.

1. Show global trust configuration for Active Directory type of trusts:

   ipa trustconfig-show --type ad

2. Modify global configuration for all trusts of Active Directory type and set
   a different fallback primary group (fallback primary group GID is used as a
   primary user GID if user authenticating to IPA domain does not have any
   other primary GID already set):

   ipa trustconfig-mod --type ad --fallback-primary-group "another AD group"

3. Change primary fallback group back to default hidden group (any group with
   posixGroup object class is allowed):

   ipa trustconfig-mod --type ad --fallback-primary-group "Default SMB Group"
""")

logger = logging.getLogger(__name__)

register = Registry()

_trust_type_option = StrEnum(
         'trust_type',
         cli_name='type',
         label=_('Trust type (ad for Active Directory, default)'),
         values=(u'ad',),
         default=u'ad',
         autofill=True,
        )

DEFAULT_RANGE_SIZE = 200000

DBUS_IFACE_TRUST = 'com.redhat.idm.trust'

CRED_STYLE_SAMBA = 1
CRED_STYLE_KERBEROS = 2


def make_trust_dn(env, trust_type, dn):
    assert isinstance(dn, DN)
    if trust_type:
        container_dn = DN(('cn', trust_type), env.container_trusts, env.basedn)
        return DN(dn, container_dn)
    return dn


def find_adtrust_masters(ldap, api):
    """
    Returns a list of names of IPA servers with ADTRUST component configured.
    """

    try:
        entries, _truncated = ldap.find_entries(
                "cn=ADTRUST",
                base_dn=api.env.container_masters + api.env.basedn
        )
    except errors.NotFound:
        entries = []

    return [entry.dn[1].value for entry in entries]


def verify_samba_component_presence(ldap, api):
    """
    Verifies that Samba is installed and configured on this particular master.
    If Samba is not available, provide a heplful hint with the list of masters
    capable of running the commands.
    """

    adtrust_present = api.Command['adtrust_is_enabled']()['result']

    hint = _(
        ' Alternatively, following servers are capable of running this '
        'command: %(masters)s'
        )

    def raise_missing_component_error(message):
        masters_with_adtrust = find_adtrust_masters(ldap, api)

        # If there are any masters capable of running Samba requiring commands
        # let's advertise them directly
        if masters_with_adtrust:
            message += hint % dict(masters=', '.join(masters_with_adtrust))

        raise errors.NotFound(
            name=_('AD Trust setup'),
            reason=message,
        )

    # We're ok in this case, bail out
    if adtrust_present and _bindings_installed:
        return

    # First check for packages missing
    elif not _bindings_installed:
        error_message = _(
            'Cannot perform the selected command without Samba 4 support '
            'installed. Make sure you have installed server-trust-ad '
            'sub-package of IPA.'
        )

        raise_missing_component_error(error_message)

    # Packages present, but ADTRUST instance is not configured
    elif not adtrust_present:
        error_message = _(
            'Cannot perform the selected command without Samba 4 instance '
            'configured on this machine. Make sure you have run '
            'ipa-adtrust-install on this server.'
        )

        raise_missing_component_error(error_message)


def generate_creds(trustinstance, style, **options):
    """
    Generate string representing credentials using trust instance
    Input:
       trustinstance -- ipaserver.dcerpc.TrustInstance object
       style         -- style of credentials
                        CRED_STYLE_SAMBA -- for using with Samba bindings
                        CRED_STYLE_KERBEROS -- for obtaining Kerberos ticket
       **options     -- options with realm_admin and realm_passwd keys

    Result:
       a string representing credentials with first % separating
       username and password
       None is returned if realm_passwd key returns nothing from options
    """
    creds = None
    password = options.get('realm_passwd', None)
    if password:
        admin_name = options.get('realm_admin')
        sp = []
        sep = '@'
        if style == CRED_STYLE_SAMBA:
            sep = "\\"
            sp = admin_name.split(sep)
            if len(sp) == 1:
                sp.insert(0, trustinstance.remote_domain.info['name'])
        elif style == CRED_STYLE_KERBEROS:
            sp = admin_name.split('\\')
            if len(sp) > 1:
                sp = [sp[1]]
            else:
                sp = admin_name.split(sep)
            if len(sp) == 1:
                sp.append(
                    trustinstance.remote_domain.info['dns_domain'].upper()
                )
        creds = u"{name}%{password}".format(name=sep.join(sp),
                                            password=password)
    return creds


def add_range(myapi, trustinstance, range_name, dom_sid, *keys, **options):
    """
    First, we try to derive the parameters of the ID range based on the
    information contained in the Active Directory.

    If that was not successful, we go for our usual defaults (random base,
    range size 200 000, ipa-ad-trust range type).

    Any of these can be overridden by passing appropriate CLI options
    to the trust-add command.
    """

    range_size = None
    range_type = None
    base_id = None

    # First, get information about ID space from AD
    # However, we skip this step if other than ipa-ad-trust-posix
    # range type is enforced

    if options.get('range_type', None) in (None, u'ipa-ad-trust-posix'):

        # Get the base dn
        domain = keys[-1]
        basedn = realm_to_suffix(domain)

        # Search for information contained in
        # CN=ypservers,CN=ypServ30,CN=RpcServices,CN=System
        info_filter = '(objectClass=msSFU30DomainInfo)'
        info_dn = DN('CN=ypservers,CN=ypServ30,CN=RpcServices,CN=System')\
            + basedn

        # Get the domain validator
        domain_validator = ipaserver.dcerpc.DomainValidator(myapi)
        if not domain_validator.is_configured():
            raise errors.NotFound(
                reason=_('Cannot search in trusted domains without own '
                         'domain configured. Make sure you have run '
                         'ipa-adtrust-install on the IPA server first'))

        creds = None
        if trustinstance:
            # Re-use AD administrator credentials if they were provided
            creds = generate_creds(trustinstance,
                                   style=CRED_STYLE_KERBEROS, **options)
            if creds:
                domain_validator._admin_creds = creds
        # KDC might not get refreshed data at the first time,
        # retry several times
        for _retry in range(10):
            info_list = domain_validator.search_in_dc(domain,
                                                      info_filter,
                                                      None,
                                                      SCOPE_SUBTREE,
                                                      basedn=info_dn,
                                                      quiet=True)

            if info_list:
                info = info_list[0]
                break
            else:
                sleep(2)

        required_msSFU_attrs = ['msSFU30MaxUidNumber', 'msSFU30OrderNumber']

        if not info_list:
            # We were unable to gain UNIX specific info from the AD
            logger.debug("Unable to gain POSIX info from the AD")
        else:
            if all(attr in info for attr in required_msSFU_attrs):
                logger.debug("Able to gain POSIX info from the AD")
                range_type = u'ipa-ad-trust-posix'

                max_uid = info.get('msSFU30MaxUidNumber')
                max_gid = info.get('msSFU30MaxGidNumber', None)
                max_id = int(max(max_uid, max_gid)[0])

                base_id = int(info.get('msSFU30OrderNumber')[0])
                range_size = (1 + (max_id - base_id) // DEFAULT_RANGE_SIZE)\
                    * DEFAULT_RANGE_SIZE

    # Second, options given via the CLI options take precedence to discovery
    if options.get('range_type', None):
        range_type = options.get('range_type', None)
    elif not range_type:
        range_type = u'ipa-ad-trust'

    if options.get('range_size', None):
        range_size = options.get('range_size', None)
    elif not range_size:
        range_size = DEFAULT_RANGE_SIZE

    if options.get('base_id', None):
        base_id = options.get('base_id', None)
    elif not base_id:
        # Generate random base_id if not discovered nor given via CLI
        base_id = DEFAULT_RANGE_SIZE + (
            pysss_murmur.murmurhash3(
                dom_sid,
                len(dom_sid), 0xdeadbeef
            ) % 10000
        ) * DEFAULT_RANGE_SIZE

    # Finally, add new ID range
    myapi.Command['idrange_add'](range_name,
                                 ipabaseid=base_id,
                                 ipaidrangesize=range_size,
                                 ipabaserid=0,
                                 iparangetype=range_type,
                                 ipanttrusteddomainsid=dom_sid)

    # Return the values that were generated inside this function
    return range_type, range_size, base_id


def fetch_trusted_domains_over_dbus(myapi, *keys, **options):
    if not _bindings_installed:
        return

    forest_name = keys[0]
    method_options = []
    if 'realm_server' in options:
        method_options.extend(['--server', options['realm_server']])
    if 'realm_admin' in options:
        method_options.extend(['--admin', options['realm_admin']])
    if 'realm_passwd' in options:
        method_options.extend(['--password', options['realm_passwd']])

    # Calling oddjobd-activated service via DBus has some quirks:
    # - Oddjobd registers multiple canonical names on the same address
    # - python-dbus only follows name owner changes when mainloop is in use
    # See https://fedorahosted.org/oddjob/ticket/2 for details
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    try:
        _ret = 0
        _stdout = ''
        _stderr = ''
        bus = dbus.SystemBus()
        intf = bus.get_object(DBUS_IFACE_TRUST, "/",
                              follow_name_owner_changes=True)
        fetch_domains_method = intf.get_dbus_method(
                'fetch_domains',
                dbus_interface=DBUS_IFACE_TRUST)
        # Oddjobd D-BUS method definition only accepts fixed number
        # of arguments on the command line. Thus, we need to pass
        # remaining ones as ''. There are 30 slots to allow for extension
        # and the number comes from the 'arguments' definition in
        # install/oddjob/etc/oddjobd.conf.d/oddjobd-ipa-trust.conf
        method_arguments = [forest_name]
        method_arguments.extend(method_options)
        method_arguments.extend([''] * (30 - len(method_arguments)))
        (_ret, _stdout, _stderr) = fetch_domains_method(*method_arguments)
    except dbus.DBusException as e:
        logger.error('Failed to call %s.fetch_domains helper.'
                     'DBus exception is %s.', DBUS_IFACE_TRUST, str(e))
        if _ret != 0:
            logger.error('Helper was called for forest %s, return code is %d',
                         forest_name, _ret)
            logger.error('Standard output from the helper:\n%s---\n', _stdout)
            logger.error('Error output from the helper:\n%s--\n', _stderr)
        raise errors.ServerCommandError(
            server=myapi.env.host,
            error=_('Fetching domains from trusted forest failed. '
                    'See details in the error_log')
        )
    return


@register()
class trust(LDAPObject):
    """
    Trust object.
    """
    trust_types = ('ad', 'ipa')
    container_dn = api.env.container_trusts
    object_name = _('trust')
    object_name_plural = _('trusts')
    object_class = ['ipaNTTrustedDomain', 'ipaIDObject']
    default_attributes = ['cn', 'ipantflatname', 'ipanttrusteddomainsid',
                          'ipanttrusttype', 'ipanttrustattributes',
                          'ipanttrustdirection', 'ipanttrustpartner',
                          'ipanttrustforesttrustinfo',
                          'ipanttrustposixoffset',
                          'ipantsupportedencryptiontypes',
                          'ipantadditionalsuffixes']
    search_display_attributes = ['cn', 'ipantflatname',
                                 'ipanttrusteddomainsid', 'ipanttrusttype',
                                 'ipanttrustattributes',
                                 'ipantadditionalsuffixes']
    managed_permissions = {
        'System: Read Trust Information': {
            # Allow reading of attributes needed for SSSD subdomains support
            'non_object': True,
            'ipapermlocation': DN(container_dn, api.env.basedn),
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'objectclass',
                'ipantflatname', 'ipantsecurityidentifier',
                'ipanttrusteddomainsid', 'ipanttrustpartner',
                'ipantsidblacklistincoming', 'ipantsidblacklistoutgoing',
                'ipanttrustdirection', 'ipantadditionalsuffixes',
            },
        },

        'System: Read system trust accounts': {
            'non_object': True,
            'ipapermlocation': DN(container_dn, api.env.basedn),
            'replaces_global_anonymous_aci': True,
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'uidnumber', 'gidnumber', 'krbprincipalname'
            },
            'default_privileges': {'ADTrust Agents'},
        },
    }

    label = _('Trusts')
    label_singular = _('Trust')

    takes_params = (
        Str('cn',
            cli_name='realm',
            label=_('Realm name'),
            primary_key=True,
        ),
        Str('ipantflatname',
            cli_name='flat_name',
            label=_('Domain NetBIOS name'),
            flags=['no_create', 'no_update']),
        Str('ipanttrusteddomainsid',
            cli_name='sid',
            label=_('Domain Security Identifier'),
            flags=['no_create', 'no_update']),
        Str('ipantsidblacklistincoming*',
            cli_name='sid_blacklist_incoming',
            label=_('SID blacklist incoming'),
            flags=['no_create']),
        Str('ipantsidblacklistoutgoing*',
            cli_name='sid_blacklist_outgoing',
            label=_('SID blacklist outgoing'),
            flags=['no_create']),
        Str('trustdirection',
            label=_('Trust direction'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('trusttype',
            label=_('Trust type'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('truststatus',
            label=_('Trust status'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('ipantadditionalsuffixes*',
            cli_name='upn_suffixes',
            label=_('UPN suffixes'),
            flags={'no_create', 'no_search'},
        ),
    )

    def validate_sid_blacklists(self, entry_attrs):
        if not _bindings_installed:
            # SID validator is not available, return
            # Even if invalid SID gets in the trust entry, it won't crash
            # the validation process as it is translated to SID S-0-0
            return
        for attr in ('ipantsidblacklistincoming', 'ipantsidblacklistoutgoing'):
            values = entry_attrs.get(attr)
            if not values:
                continue
            for value in values:
                if not ipaserver.dcerpc.is_sid_valid(value):
                    err = unicode(_("invalid SID: {SID}")).format(SID=value)
                    raise errors.ValidationError(name=attr, error=err)

    def get_dn(self, *keys, **kwargs):
        trust_type = kwargs.get('trust_type')

        sdn = [('cn', x) for x in keys]
        sdn.reverse()

        if trust_type is None:
            ldap = self.backend
            trustfilter = ldap.make_filter({
                'objectclass': ['ipaNTTrustedDomain', 'ipaIDObject'],
                'cn': [keys[-1]]},
                rules=ldap.MATCH_ALL
            )

            # more type of objects can be located in subtree (for example
            # cross-realm principals). we need this attr do detect trust
            # entries
            trustfilter = ldap.combine_filters(
                (trustfilter, "ipaNTTrustPartner=*"),
                rules=ldap.MATCH_ALL
            )

            try:
                result = ldap.get_entries(
                    DN(self.container_dn, self.env.basedn),
                    ldap.SCOPE_SUBTREE, trustfilter, ['']
                )
            except errors.NotFound:
                raise self.handle_not_found(keys[-1])

            if len(result) > 1:
                raise errors.OnlyOneValueAllowed(attr='trust domain')

            return result[0].dn

        return make_trust_dn(self.env, trust_type, DN(*sdn))

    def warning_if_ad_trust_dom_have_missing_SID(self, result, **options):
        """Due bug https://fedorahosted.org/freeipa/ticket/5665 there might be
        AD trust domain without generated SID, warn user about it.
        """
        ldap = self.api.Backend.ldap2

        try:
            entries, _truncated = ldap.find_entries(
                base_dn=DN(self.api.env.container_adtrusts,
                           self.api.env.basedn),
                scope=ldap.SCOPE_ONELEVEL,
                attrs_list=['cn'],
                filter='(&(ipaNTTrustPartner=*)'
                       '(!(ipaNTSecurityIdentifier=*)))',
            )
        except errors.NotFound:
            pass
        else:
            for entry in entries:
                add_message(
                    options['version'],
                    result,
                    BrokenTrust(domain=entry.single_value['cn'])
                )


@register()
class trust_add(LDAPCreate):
    __doc__ = _('''
Add new trust to use.

This command establishes trust relationship to another domain
which becomes 'trusted'. As result, users of the trusted domain
may access resources of this domain.

Only trusts to Active Directory domains are supported right now.

The command can be safely run multiple times against the same domain,
this will cause change to trust relationship credentials on both
sides.

Note that if the command was previously run with a specific range type,
or with automatic detection of the range type, and you want to configure a
different range type, you may need to delete first the ID range using
ipa idrange-del before retrying the command with the desired range type.
    ''')

    range_types = {
        u'ipa-ad-trust': unicode(_('Active Directory domain range')),
        u'ipa-ad-trust-posix': unicode(_('Active Directory trust range with '
                                         'POSIX attributes')),
                  }

    takes_options = LDAPCreate.takes_options + (
        _trust_type_option,
        Str('realm_admin?',
            cli_name='admin',
            label=_("Active Directory domain administrator"),
            ),
        Password('realm_passwd?',
                 cli_name='password',
                 label=_("Active Directory domain administrator's password"),
                 confirm=False,
                 ),
        Str('realm_server?',
            cli_name='server',
            label=_('Domain controller for the Active Directory domain '
                    '(optional)'),
            ),
        Password('trust_secret?',
                 cli_name='trust_secret',
                 label=_('Shared secret for the trust'),
                 confirm=False,
                 ),
        Int('base_id?',
            cli_name='base_id',
            label=_('First Posix ID of the range reserved for the '
                    'trusted domain'),
            ),
        Int('range_size?',
            cli_name='range_size',
            label=_('Size of the ID range reserved for the trusted domain')
            ),
        StrEnum('range_type?',
                label=_('Range type'),
                cli_name='range_type',
                doc=(_('Type of trusted domain ID range, one of {vals}'
                     .format(vals=', '.join(sorted(range_types))))),
                values=sorted(range_types),
                ),
        Bool('bidirectional?',
             label=_('Two-way trust'),
             cli_name='two_way',
             doc=(_('Establish bi-directional trust. By default trust is '
                    'inbound one-way only.')),
             default=False,
             ),
        Bool('external?',
             label=_('External trust'),
             cli_name='external',
             doc=_('Establish external trust to a domain in another forest. '
                   'The trust is not transitive beyond the domain.'),
             default=False,
             ),
    )

    msg_summary = _('Added Active Directory trust for realm "%(value)s"')
    msg_summary_existing = _('Re-established trust to domain "%(value)s"')

    def _format_trust_attrs(self, result, **options):

        # Format the output into human-readable values
        attributes = int(result['result'].get('ipanttrustattributes', [0])[0])

        if not options.get('raw', False):
            result['result']['trusttype'] = [trust_type_string(
                result['result']['ipanttrusttype'][0], attributes)]
            result['result']['trustdirection'] = [trust_direction_string(
                result['result']['ipanttrustdirection'][0])]
            result['result']['truststatus'] = [trust_status_string(
                result['verified'])]

        if attributes:
            result['result'].pop('ipanttrustattributes', None)

        result['result'].pop('ipanttrustauthoutgoing', None)
        result['result'].pop('ipanttrustauthincoming', None)

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        verify_samba_component_presence(ldap, self.api)

        full_join = self.validate_options(*keys, **options)
        old_range, range_name, dom_sid = self.validate_range(*keys, **options)
        result = self.execute_ad(full_join, *keys, **options)

        if not old_range:
            # Store the created range type, since for POSIX trusts no
            # ranges for the subdomains should be added, POSIX attributes
            # provide a global mapping across all subdomains
            add_range(
                self.api, self.trustinstance, range_name, dom_sid,
                *keys, **options
            )

        attrs_list = self.obj.default_attributes
        if options.get('all', False):
            attrs_list.append('*')

        trust_filter = "cn=%s" % result['value']
        trusts, _truncated = ldap.find_entries(
            base_dn=DN(self.api.env.container_trusts, self.api.env.basedn),
            filter=trust_filter,
            attrs_list=attrs_list
        )

        result['result'] = entry_to_dict(trusts[0], **options)

        # Fetch topology of the trust forest -- we need always to do it
        # for AD trusts, regardless of the type of idranges associated with it
        # Note that add_new_domains_from_trust will add needed ranges for
        # the algorithmic ID mapping case.
        if (options.get('trust_type') == u'ad' and
                options.get('trust_secret') is None):

            if options.get('bidirectional') == True:
                # Bidirectional trust allows us to use cross-realm TGT,
                # so we can run the call under original user's credentials
                res = fetch_domains_from_trust(self.api, self.trustinstance,
                                               **options)
                add_new_domains_from_trust(
                    self.api, self.trustinstance, result['result'], res,
                    **options)
            else:
                # One-way trust is more complex. We don't have cross-realm TGT
                # and cannot use IPA principals to authenticate against AD.
                # Instead, we have to use our trusted domain object's (TDO)
                # account in AD. Access to the credentials is limited and IPA
                # framework cannot access it directly.  Instead, we call out to
                # oddjobd-activated higher privilege process that will use TDO
                # object credentials to authenticate to AD with Kerberos,
                # run DCE RPC calls to do discovery and will call
                # add_new_domains_from_trust() on its own.
                fetch_trusted_domains_over_dbus(self.api, result['value'])

        # Format the output into human-readable values unless `--raw` is given
        self._format_trust_attrs(result, **options)
        del result['verified']

        return result

    def validate_options(self, *keys, **options):
        trusted_realm_domain = keys[-1]

        if not _murmur_installed and 'base_id' not in options:
            raise errors.ValidationError(
                name=_('missing base_id'),
                error=_(
                    'pysss_murmur is not available on the server '
                    'and no base-id is given.'
                )
            )

        if 'trust_type' not in options:
            raise errors.RequirementError(name='trust_type')

        if options['trust_type'] != u'ad':
            raise errors.ValidationError(
                name=_('trust type'),
                error=_('only "ad" is supported')
            )

        # Detect IPA-AD domain clash
        if self.api.env.domain.lower() == trusted_realm_domain.lower():
            raise errors.ValidationError(
                name=_('domain'),
                error=_('Cannot establish a trust to AD deployed in the same '
                        'domain as IPA. Such setup is not supported.')
                )

        # If domain name and realm does not match, IPA server is not be able
        # to establish trust with Active Directory.

        realm_not_matching_domain = (
            self.api.env.domain.upper() != self.api.env.realm
        )

        if options['trust_type'] == u'ad' and realm_not_matching_domain:
            raise errors.ValidationError(
                name=_('Realm-domain mismatch'),
                error=_('To establish trust with Active Directory, the '
                        'domain name and the realm name of the IPA server '
                        'must match')
                )

        self.trustinstance = ipaserver.dcerpc.TrustDomainJoins(self.api)
        if not self.trustinstance.configured:
            raise errors.NotFound(
                name=_('AD Trust setup'),
                reason=_(
                    'Cannot perform join operation without own domain '
                    'configured. Make sure you have run ipa-adtrust-install '
                    'on the IPA server first'
                )
            )

        # Obtain a list of IPA realm domains
        result = self.api.Command.realmdomains_show()['result']
        realm_domains = result['associateddomain']

        # Do not allow the AD's trusted realm domain in the list
        # of our realm domains
        if trusted_realm_domain.lower() in realm_domains:
            raise errors.ValidationError(
                name=_('AD Trust setup'),
                error=_(
                    'Trusted domain %(domain)s is included among '
                    'IPA realm domains. It needs to be removed '
                    'prior to establishing the trust. See the '
                    '"ipa realmdomains-mod --del-domain" command.'
                ) % dict(domain=trusted_realm_domain)
            )

        self.realm_server = options.get('realm_server')
        self.realm_admin = options.get('realm_admin')
        self.realm_passwd = options.get('realm_passwd')

        if self.realm_admin:
            names = self.realm_admin.split('@')

            if len(names) > 1:
                # realm admin name is in UPN format, user@realm, check that
                # realm is the same as the one that we are attempting to trust
                if trusted_realm_domain.lower() != names[-1].lower():
                    raise errors.ValidationError(
                        name=_('AD Trust setup'),
                        error=_(
                            'Trusted domain and administrator account use '
                            'different realms'
                        )
                    )
                self.realm_admin = names[0]

            if not self.realm_passwd:
                raise errors.ValidationError(
                    name=_('AD Trust setup'),
                    error=_('Realm administrator password should be specified')
                )
            return True

        return False

    def validate_range(self, *keys, **options):
        # If a range for this trusted domain already exists,
        # '--base-id' or '--range-size' options should not be specified
        range_name = keys[-1].upper() + '_id_range'
        range_type = options.get('range_type')

        try:
            old_range = self.api.Command['idrange_show'](range_name, raw=True)
        except errors.NotFound:
            old_range = None

        if options.get('trust_type') == u'ad':
            if range_type and range_type not in (u'ipa-ad-trust',
                                                 u'ipa-ad-trust-posix'):
                raise errors.ValidationError(
                    name=_('id range type'),
                    error=_(
                        'Only the ipa-ad-trust and ipa-ad-trust-posix are '
                        'allowed values for --range-type when adding an AD '
                        'trust.'
                    ))

        base_id = options.get('base_id')
        range_size = options.get('range_size')

        if old_range and (base_id or range_size):
            raise errors.ValidationError(
                name=_('id range'),
                error=_(
                    'An id range already exists for this trust. '
                    'You should either delete the old range, or '
                    'exclude --base-id/--range-size options from the command.'
                )
            )

        # If a range for this trusted domain already exists,
        # domain SID must also match
        self.trustinstance.populate_remote_domain(
            keys[-1],
            self.realm_server,
            self.realm_admin,
            self.realm_passwd
        )
        dom_sid = self.trustinstance.remote_domain.info['sid']

        if old_range:
            old_dom_sid = old_range['result']['ipanttrusteddomainsid'][0]
            old_range_type = old_range['result']['iparangetype'][0]

            if old_dom_sid != dom_sid:
                raise errors.ValidationError(
                    name=_('range exists'),
                    error=_(
                        'ID range with the same name but different domain SID '
                        'already exists. The ID range for the new trusted '
                        'domain must be created manually.'
                    )
                )

            if range_type and range_type != old_range_type:
                raise errors.ValidationError(
                    name=_('range type change'),
                    error=_('ID range for the trusted domain already '
                            'exists, but it has a different type. Please '
                            'remove the old range manually, or do not '
                            'enforce type via --range-type option.'))

        return old_range, range_name, dom_sid

    def execute_ad(self, full_join, *keys, **options):
        # Join domain using full credentials and with random trustdom
        # secret (will be generated by the join method)

        # First see if the trust is already in place
        # Force retrieval of the trust object by not passing trust_type
        try:
            dn = self.obj.get_dn(keys[-1])
        except errors.NotFound:
            dn = None

        trust_type = TRUST_ONEWAY
        if options.get('bidirectional', False):
            trust_type = TRUST_BIDIRECTIONAL

        # If we are forced to establish external trust, allow it
        if options.get('external', False):
            self.trustinstance.allow_behavior(TRUST_JOIN_EXTERNAL)

        # 1. Full access to the remote domain. Use admin credentials and
        # generate random trustdom password to do work on both sides
        if full_join:
            try:
                result = self.trustinstance.join_ad_full_credentials(
                    keys[-1],
                    self.realm_server,
                    self.realm_admin,
                    self.realm_passwd,
                    trust_type
                )
            except errors.NotFound:
                _message = _("Unable to resolve domain controller for "
                             "{domain} domain. ")
                error_message = unicode(_message).format(domain=keys[-1])
                instructions = []

                if dns_container_exists(self.obj.backend):
                    try:
                        dns_zone = self.api.Command.dnszone_show(
                            keys[-1])['result']

                        if (('idnsforwardpolicy' in dns_zone) and
                                dns_zone['idnsforwardpolicy'][0] == u'only'):

                            instructions.append(
                                _("Forward policy is defined for it in "
                                  "IPA DNS, perhaps forwarder points to "
                                  "incorrect host?")
                            )
                    except (errors.NotFound, KeyError):
                        _instruction = _(
                            "IPA manages DNS, please verify your DNS "
                            "configuration and make sure that service "
                            "records of the '{domain}' domain can be "
                            "resolved. Examples how to configure DNS "
                            "with CLI commands or the Web UI can be "
                            "found in the documentation. "
                        )
                        instructions.append(
                            unicode(_instruction).format(domain=keys[-1])
                        )
                else:
                    _instruction = _(
                        "Since IPA does not manage DNS records, ensure "
                        "DNS is configured to resolve '{domain}' "
                        "domain from IPA hosts and back."
                    )
                    instructions.append(
                        unicode(_instruction).format(domain=keys[-1])
                    )
                raise errors.NotFound(
                    reason=error_message,
                    instructions=instructions
                )

            if result is None:
                raise errors.ValidationError(
                    name=_('AD Trust setup'),
                    error=_('Unable to verify write permissions to the AD')
                )

            ret = dict(
                value=pkey_to_value(
                    self.trustinstance.remote_domain.info['dns_domain'],
                    options),
                verified=result['verified']
            )
            if dn:
                ret['summary'] = self.msg_summary_existing % ret
            return ret

        # 2. We don't have access to the remote domain and trustdom password
        # is provided. Do the work on our side and inform what to do on remote
        # side.
        if options.get('trust_secret'):
            result = self.trustinstance.join_ad_ipa_half(
                keys[-1],
                self.realm_server,
                options['trust_secret'],
                trust_type
            )
            ret = dict(
                value=pkey_to_value(
                    self.trustinstance.remote_domain.info['dns_domain'],
                    options),
                verified=result['verified']
            )
            if dn:
                ret['summary'] = self.msg_summary_existing % ret
            return ret
        else:
            raise errors.ValidationError(
                name=_('AD Trust setup'),
                error=_('Not enough arguments specified to perform trust '
                        'setup'))


@register()
class trust_del(LDAPDelete):
    __doc__ = _('Delete a trust.')

    msg_summary = _('Deleted trust "%(value)s"')


@register()
class trust_mod(LDAPUpdate):
    __doc__ = _("""
    Modify a trust (for future use).

    Currently only the default option to modify the LDAP attributes is
    available. More specific options will be added in coming releases.
    """)

    msg_summary = _('Modified trust "%(value)s" '
                    '(change will be effective in 60 seconds)')

    def pre_callback(self, ldap, dn, e_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

        self.obj.validate_sid_blacklists(e_attrs)

        return dn


@register()
class trust_find(LDAPSearch):
    __doc__ = _('Search for trusts.')
    has_output_params = (LDAPSearch.has_output_params +
                         (Str('ipanttrusttype'), Str('ipanttrustattributes')))

    msg_summary = ngettext(
        '%(count)d trust matched', '%(count)d trusts matched', 0
    )

    # Since all trusts types are stored within separate containers
    # under 'cn=trusts', search needs to be done on a sub-tree scope
    def pre_callback(self, ldap, filters, attrs_list,
                     base_dn, scope, *args, **options):
        # list only trust, not trust domains
        return (filters, base_dn, ldap.SCOPE_SUBTREE)

    def execute(self, *args, **options):
        result = super(trust_find, self).execute(*args, **options)

        self.obj.warning_if_ad_trust_dom_have_missing_SID(result, **options)

        return result

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if options.get('pkey_only', False):
            return truncated

        for attrs in entries:
            # Translate ipanttrusttype to trusttype if --raw not used
            trust_type = attrs.single_value.get('ipanttrusttype', None)
            attributes = attrs.single_value.get('ipanttrustattributes', 0)
            if not options.get('raw', False) and trust_type is not None:
                attrs['trusttype'] = [
                    trust_type_string(trust_type, attributes)
                ]
                del attrs['ipanttrusttype']
                if attributes:
                    del attrs['ipanttrustattributes']

        return truncated


@register()
class trust_show(LDAPRetrieve):
    __doc__ = _('Display information about a trust.')
    has_output_params = (LDAPRetrieve.has_output_params +
                         (Str('ipanttrusttype'),
                          Str('ipanttrustdirection'),
                          Str('ipanttrustattributes')))

    def execute(self, *keys, **options):
        result = super(trust_show, self).execute(*keys, **options)

        self.obj.warning_if_ad_trust_dom_have_missing_SID(result, **options)

        return result

    def post_callback(self, ldap, dn, e_attrs, *keys, **options):

        assert isinstance(dn, DN)
        # Translate ipanttrusttype to trusttype
        # and ipanttrustdirection to trustdirection
        # if --raw not used

        if not options.get('raw', False):
            trust_type = e_attrs.single_value.get('ipanttrusttype', None)
            attributes = e_attrs.single_value.get('ipanttrustattributes', 0)
            if trust_type is not None:
                e_attrs['trusttype'] = [
                    trust_type_string(trust_type, attributes)
                ]
                del e_attrs['ipanttrusttype']

            dir_str = e_attrs.single_value.get('ipanttrustdirection', None)
            if dir_str is not None:
                e_attrs['trustdirection'] = [trust_direction_string(dir_str)]
                del e_attrs['ipanttrustdirection']

            if attributes:
                del e_attrs['ipanttrustattributes']

        return dn


_trustconfig_dn = {
    u'ad': DN(('cn', api.env.domain),
              api.env.container_cifsdomains, api.env.basedn),
}


@register()
class trustconfig(LDAPObject):
    """
    Trusts global configuration object
    """
    object_name = _('trust configuration')
    default_attributes = [
        'cn', 'ipantsecurityidentifier', 'ipantflatname', 'ipantdomainguid',
        'ipantfallbackprimarygroup',
    ]

    label = _('Global Trust Configuration')
    label_singular = _('Global Trust Configuration')

    takes_params = (
        Str('cn',
            label=_('Domain'),
            flags=['no_update'],
        ),
        Str('ipantsecurityidentifier',
            label=_('Security Identifier'),
            flags=['no_update'],
        ),
        Str('ipantflatname',
            label=_('NetBIOS name'),
            flags=['no_update'],
        ),
        Str('ipantdomainguid',
            label=_('Domain GUID'),
            flags=['no_update'],
        ),
        Str('ipantfallbackprimarygroup',
            cli_name='fallback_primary_group',
            label=_('Fallback primary group'),
        ),
        Str(
            'ad_trust_agent_server*',
            label=_('IPA AD trust agents'),
            doc=_('IPA servers configured as AD trust agents'),
            flags={'virtual_attribute', 'no_create', 'no_update'}
        ),
        Str(
            'ad_trust_controller_server*',
            label=_('IPA AD trust controllers'),
            doc=_('IPA servers configured as AD trust controllers'),
            flags={'virtual_attribute', 'no_create', 'no_update'}
        ),
    )

    def get_dn(self, *keys, **kwargs):
        trust_type = kwargs.get('trust_type')
        if trust_type is None:
            raise errors.RequirementError(name='trust_type')
        try:
            return _trustconfig_dn[kwargs['trust_type']]
        except KeyError:
            raise errors.ValidationError(
                name='trust_type',
                error=_("unsupported trust type")
            )

    def _normalize_groupdn(self, entry_attrs):
        """
        Checks that group with given name/DN exists and updates the entry_attrs
        """
        if 'ipantfallbackprimarygroup' not in entry_attrs:
            return

        group = entry_attrs['ipantfallbackprimarygroup']
        if isinstance(group, (list, tuple)):
            group = group[0]

        if group is None:
            return

        try:
            dn = DN(group)
            # group is in a form of a DN
            try:
                self.backend.get_entry(dn)
            except errors.NotFound:
                raise self.api.Object['group'].handle_not_found(group)
            # DN is valid, we can just return
            return
        except ValueError:
            # The search is performed for groups with "posixgroup" objectclass
            # and not "ipausergroup" so that it can also match groups like
            # "Default SMB Group" which does not have this objectclass.
            try:
                group_entry = self.backend.find_entry_by_attr(
                    self.api.Object['group'].primary_key.name,
                    group,
                    ['posixgroup'],
                    [''],
                    DN(self.api.env.container_group, self.api.env.basedn))
            except errors.NotFound:
                raise self.api.Object['group'].handle_not_found(group)
            else:
                entry_attrs['ipantfallbackprimarygroup'] = [group_entry.dn]

    def _convert_groupdn(self, entry_attrs, options):
        """
        Convert an group dn into a name. As we use CN as user RDN, its value
        can be extracted from the DN without further LDAP queries.
        """
        if options.get('raw', False):
            return

        try:
            groupdn = entry_attrs['ipantfallbackprimarygroup'][0]
        except (IndexError, KeyError):
            groupdn = None

        if groupdn is None:
            return
        assert isinstance(groupdn, DN)

        entry_attrs['ipantfallbackprimarygroup'] = [groupdn[0][0].value]


@register()
class trustconfig_mod(LDAPUpdate):
    __doc__ = _('Modify global trust configuration.')

    takes_options = LDAPUpdate.takes_options + (_trust_type_option,)
    msg_summary = _('Modified "%(value)s" trust configuration')
    has_output = output.simple_entry

    def pre_callback(self, ldap, dn, e_attrs, attrs_list, *keys, **options):
        self.obj._normalize_groupdn(e_attrs)
        return dn

    def execute(self, *keys, **options):
        result = super(trustconfig_mod, self).execute(*keys, **options)
        result['value'] = pkey_to_value(options['trust_type'], options)
        return result

    def post_callback(self, ldap, dn, e_attrs, *keys, **options):
        self.obj._convert_groupdn(e_attrs, options)
        self.api.Object.config.show_servroles_attributes(
            e_attrs, "AD trust agent", "AD trust controller", **options)
        return dn


@register()
class trustconfig_show(LDAPRetrieve):
    __doc__ = _('Show global trust configuration.')

    takes_options = LDAPRetrieve.takes_options + (_trust_type_option,)
    has_output = output.simple_entry

    def execute(self, *keys, **options):
        result = super(trustconfig_show, self).execute(*keys, **options)
        result['value'] = pkey_to_value(options['trust_type'], options)
        return result

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj._convert_groupdn(entry_attrs, options)
        self.api.Object.config.show_servroles_attributes(
            entry_attrs, "AD trust agent", "AD trust controller", **options)

        return dn


if _nss_idmap_installed:
    _idmap_type_dict = {
        pysss_nss_idmap.ID_USER: 'user',
        pysss_nss_idmap.ID_GROUP: 'group',
        pysss_nss_idmap.ID_BOTH: 'both',
    }

    def idmap_type_string(level):
        string = _idmap_type_dict.get(int(level), 'unknown')
        return unicode(string)


@register()
class trust_resolve(Command):
    NO_CLI = True
    __doc__ = _('Resolve security identifiers of users and groups '
                'in trusted domains')

    takes_options = (
        Str('sids+',
            label = _('Security Identifiers (SIDs)'),
        ),
    )

    has_output_params = (
        Str('name', label=_('Name')),
        Str('sid', label=_('SID')),
    )

    has_output = (
        output.ListOfEntries('result'),
    )

    def execute(self, *keys, **options):
        result = list()
        if not _nss_idmap_installed:
            return dict(result=result)
        try:
            NAME_KEY = pysss_nss_idmap.NAME_KEY
            TYPE_KEY = pysss_nss_idmap.TYPE_KEY
            sids = [str(x) for x in options['sids']]
            xlate = pysss_nss_idmap.getnamebysid(sids)
            for sid in xlate:
                entry = dict()
                entry['sid'] = [unicode(sid)]
                entry['name'] = [unicode(xlate[sid][NAME_KEY])]
                entry['type'] = [idmap_type_string(xlate[sid][TYPE_KEY])]
                result.append(entry)
        except ValueError:
            pass

        return dict(result=result)


@register()
class adtrust_is_enabled(Command):
    NO_CLI = True

    __doc__ = _('Determine whether ipa-adtrust-install has been run on this '
                'system')

    def execute(self, *keys, **options):
        ldap = self.api.Backend.ldap2
        adtrust_dn = DN(
            ('cn', 'ADTRUST'),
            ('cn', self.api.env.host),
            ('cn', 'masters'),
            ('cn', 'ipa'),
            ('cn', 'etc'),
            self.api.env.basedn
        )

        try:
            ldap.get_entry(adtrust_dn)
        except errors.NotFound:
            return dict(result=False)

        return dict(result=True)


@register()
class compat_is_enabled(Command):
    NO_CLI = True

    __doc__ = _('Determine whether Schema Compatibility plugin is configured '
                'to serve trusted domain users and groups')

    def execute(self, *keys, **options):
        ldap = self.api.Backend.ldap2
        users_dn = DN(
            ('cn', 'users'),
            ('cn', 'Schema Compatibility'),
            ('cn', 'plugins'),
            ('cn', 'config')
        )
        groups_dn = DN(
            ('cn', 'groups'),
            ('cn', 'Schema Compatibility'),
            ('cn', 'plugins'),
            ('cn', 'config')
        )

        try:
            users_entry = ldap.get_entry(users_dn)
        except errors.NotFound:
            return dict(result=False)

        attr = users_entry.get('schema-compat-lookup-nsswitch')
        if not attr or 'user' not in attr:
            return dict(result=False)

        try:
            groups_entry = ldap.get_entry(groups_dn)
        except errors.NotFound:
            return dict(result=False)

        attr = groups_entry.get('schema-compat-lookup-nsswitch')
        if not attr or 'group' not in attr:
            return dict(result=False)

        return dict(result=True)


@register()
class sidgen_was_run(Command):
    """
    This command tries to determine whether the sidgen task was run during
    ipa-adtrust-install. It does that by simply checking the "editors" group
    for the presence of the ipaNTSecurityIdentifier attribute - if the
    attribute is present, the sidgen task was run.

    Since this command relies on the existence of the "editors" group, it will
    fail loudly in case this group does not exist.
    """
    NO_CLI = True

    __doc__ = _('Determine whether ipa-adtrust-install has been run with '
                'sidgen task')

    def execute(self, *keys, **options):
        ldap = self.api.Backend.ldap2
        editors_dn = DN(
            ('cn', 'editors'),
            ('cn', 'groups'),
            ('cn', 'accounts'),
            api.env.basedn
        )

        try:
            editors_entry = ldap.get_entry(editors_dn)
        except errors.NotFound:
            raise errors.NotFound(
                name=_('sidgen_was_run'),
                reason=_(
                    'This command relies on the existence of the "editors" '
                    'group, but this group was not found.'
                )
            )

        attr = editors_entry.get('ipaNTSecurityIdentifier')
        if not attr:
            return dict(result=False)

        return dict(result=True)


@register()
class trustdomain(LDAPObject):
    """
    Object representing a domain of the AD trust.
    """
    parent_object = 'trust'
    trust_type_idx = {'2': u'ad'}
    object_name = _('trust domain')
    object_name_plural = _('trust domains')
    object_class = ['ipaNTTrustedDomain']
    default_attributes = ['cn', 'ipantflatname', 'ipanttrusteddomainsid',
                          'ipanttrustpartner', 'ipantadditionalsuffixes']
    search_display_attributes = ['cn', 'ipantflatname',
                                 'ipanttrusteddomainsid',
                                 'ipantadditionalsuffixes']

    label = _('Trusted domains')
    label_singular = _('Trusted domain')

    takes_params = (
        Str('cn',
            label=_('Domain name'),
            cli_name='domain',
            primary_key=True),
        Str('ipantflatname?',
            cli_name='flat_name',
            label=_('Domain NetBIOS name')),
        Str('ipanttrusteddomainsid?',
            cli_name='sid',
            label=_('Domain Security Identifier')),
        Flag('domain_enabled',
             label=_('Domain enabled'),
             flags={'virtual_attribute',
                    'no_create', 'no_update', 'no_search'}),
    )

    # LDAPObject.get_dn() only passes all but last element of keys and no
    # kwargs to the parent object's get_dn() no matter what you pass to it.
    # Make own get_dn() as we really need all elements to construct proper dn.
    def get_dn(self, *keys, **kwargs):
        sdn = [('cn', x) for x in keys]
        sdn.reverse()
        trust_type = kwargs.get('trust_type')
        if not trust_type:
            trust_type = u'ad'

        dn = make_trust_dn(self.env, trust_type, DN(*sdn))
        return dn


@register()
class trustdomain_find(LDAPSearch):
    __doc__ = _('Search domains of the trust')

    def pre_callback(self, ldap, filters, attrs_list, base_dn,
                     scope, *args, **options):
        return (filters, base_dn, ldap.SCOPE_SUBTREE)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if options.get('pkey_only', False):
            return truncated
        trust_dn = self.obj.get_dn(args[0], trust_type=u'ad')
        trust_entry = ldap.get_entry(trust_dn)
        blacklist = trust_entry.get('ipantsidblacklistincoming')
        for entry in entries:
            sid = entry.get('ipanttrusteddomainsid', [None])[0]
            if sid is None:
                continue

            if sid in blacklist:
                entry['domain_enabled'] = [False]
            else:
                entry['domain_enabled'] = [True]
        return truncated


@register()
class trustdomain_mod(LDAPUpdate):
    __doc__ = _('Modify trustdomain of the trust')

    NO_CLI = True
    takes_options = LDAPUpdate.takes_options + (_trust_type_option,)


@register()
class trustdomain_add(LDAPCreate):
    __doc__ = _('Allow access from the trusted domain')
    NO_CLI = True

    takes_options = LDAPCreate.takes_options + (_trust_type_option,)

    def pre_callback(self, ldap, dn, e_attrs, attrs_list, *keys, **options):
        # ipaNTTrustPartner must always be set to the name of the trusted
        # domain. See MS-ADTS 6.1.6.7.13
        e_attrs['ipanttrustpartner'] = [dn[0]['cn']]
        return dn


@register()
class trustdomain_del(LDAPDelete):
    __doc__ = _('Remove information about the domain associated '
                'with the trust.')

    msg_summary = _('Removed information about the trusted domain '
                    '"%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.api.Backend.ldap2
        verify_samba_component_presence(ldap, self.api)

        # Note that pre-/post- callback handling for LDAPDelete is causing
        # pre_callback to always receive empty keys. We need to catch the case
        # when root domain is being deleted

        for domain in keys[1]:
            try:
                self.obj.get_dn_if_exists(keys[0], domain, trust_type=u'ad')
            except errors.NotFound:
                if keys[0].lower() == domain:
                    raise errors.ValidationError(
                        name='domain',
                        error=_("cannot delete root domain of the trust, "
                                "use trust-del to delete the trust itself"))
                raise self.obj.handle_not_found(keys[0], domain)

            try:
                self.api.Command.trustdomain_enable(keys[0], domain)
            except errors.AlreadyActive:
                pass

        result = super(trustdomain_del, self).execute(*keys, **options)
        result['value'] = pkey_to_value(keys[1], options)
        return result


def fetch_domains_from_trust(myapi, trustinstance, **options):
    """
    Contact trust forest root DC and fetch trusted forest topology information.

    :param myapi: API instance
    :param trustinstance: Initialized instance of `dcerpc.TrustDomainJoins`
        class
    :param options: options passed from API command's `execute()` method

    :returns: dict containing forest domain information and forest-wide UPN
        suffixes (if any)
    """

    forest_root_name = trustinstance.remote_domain.info['dns_forest']

    # We want to use Kerberos if we have admin credentials even with SMB calls
    # as eventually use of NTLMSSP will be deprecated for trusted domain
    # operations If admin credentials are missing, 'creds' will be None and
    # fetch_domains will use HTTP/ipa.master@IPA.REALM principal, e.g. Kerberos
    # authentication as well.
    creds = generate_creds(trustinstance, style=CRED_STYLE_KERBEROS, **options)
    server = options.get('realm_server', None)
    domains = ipaserver.dcerpc.fetch_domains(
        myapi, trustinstance.local_flatname, forest_root_name, creds=creds,
        server=server)

    return domains


def add_new_domains_from_trust(myapi, trustinstance, trust_entry,
                               domains, **options):
    result = []
    if not domains:
        return result

    trust_name = trust_entry['cn'][0]
    # trust range must exist by the time add_new_domains_from_trust is called
    range_name = trust_name.upper() + '_id_range'
    old_range = myapi.Command.idrange_show(range_name, raw=True)['result']
    idrange_type = old_range['iparangetype'][0]

    suffixes = list()
    suffixes.extend(y['cn']
                    for x, y in six.iteritems(domains['suffixes'])
                    if x not in domains['domains'])

    try:
        dn = myapi.Object.trust.get_dn(trust_name, trust_type=u'ad')
        ldap = myapi.Backend.ldap2
        entry = ldap.get_entry(dn)
        tlns = entry.get('ipantadditionalsuffixes', [])
        tlns.extend(x for x in suffixes if x not in tlns)
        entry['ipantadditionalsuffixes'] = tlns
        ldap.update_entry(entry)
    except errors.EmptyModlist:
        pass

    is_nontransitive = int(trust_entry.get('ipanttrustattributes',
                           [0])[0]) & LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE

    if is_nontransitive:
        return result

    for dom in six.itervalues(domains['domains']):
        dom['trust_type'] = u'ad'
        try:
            name = dom['cn']
            del dom['cn']
            if 'all' in options:
                dom['all'] = options['all']
            if 'raw' in options:
                dom['raw'] = options['raw']

            try:
                res = myapi.Command.trustdomain_add(trust_name, name, **dom)
                result.append(res['result'])
            except errors.DuplicateEntry:
                # Ignore updating duplicate entries
                pass

            if idrange_type != u'ipa-ad-trust-posix':
                range_name = name.upper() + '_id_range'
                dom['range_type'] = u'ipa-ad-trust'
                add_range(myapi, trustinstance,
                          range_name, dom['ipanttrusteddomainsid'],
                          name, **dom)
        except errors.DuplicateEntry:
            # Ignore updating duplicate entries
            pass

    return result


@register()
class trust_fetch_domains(LDAPRetrieve):
    __doc__ = _('Refresh list of the domains associated with the trust')

    has_output = output.standard_list_of_entries
    takes_options = LDAPRetrieve.takes_options + (
        Str('realm_admin?',
            cli_name='admin',
            label=_("Active Directory domain administrator"),
            ),
        Password('realm_passwd?',
                 cli_name='password',
                 label=_("Active Directory domain administrator's password"),
                 confirm=False,
                 ),
        Str('realm_server?',
            cli_name='server',
            label=_('Domain controller for the Active Directory domain '
                    '(optional)'),
            ),
    )

    def execute(self, *keys, **options):
        ldap = self.api.Backend.ldap2
        verify_samba_component_presence(ldap, self.api)

        # Check first that the trust actually exists
        result = self.api.Command.trust_show(keys[0], all=True, raw=True)
        self.obj.warning_if_ad_trust_dom_have_missing_SID(result, **options)

        result = dict()
        result['result'] = []
        result['count'] = 0
        result['truncated'] = False

        # For one-way trust and external trust fetch over DBus.
        # We don't get the list in this case.
        # With privilege separation we also cannot authenticate as
        # HTTP/ principal because we have no access to its key material.
        # Thus, we'll use DBus call out to oddjobd helper in all cases
        fetch_trusted_domains_over_dbus(self.api, *keys, **options)
        result['summary'] = unicode(_('List of trust domains successfully '
                                      'refreshed. Use trustdomain-find '
                                      'command to list them.'))
        return result


@register()
class trustdomain_enable(LDAPQuery):
    __doc__ = _('Allow use of IPA resources by the domain of the trust')

    has_output = output.standard_value
    msg_summary = _('Enabled trust domain "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.api.Backend.ldap2
        verify_samba_component_presence(ldap, self.api)

        if keys[0].lower() == keys[1].lower():
            raise errors.ValidationError(
                name='domain',
                error=_("Root domain of the trust is always enabled "
                        "for the existing trust")
            )
        try:
            trust_dn = self.obj.get_dn(keys[0], trust_type=u'ad')
            trust_entry = ldap.get_entry(trust_dn)
        except errors.NotFound:
            raise self.api.Object[self.obj.parent_object].handle_not_found(
                keys[0])

        dn = self.obj.get_dn(keys[0], keys[1], trust_type=u'ad')
        try:
            entry = ldap.get_entry(dn)
            sid = entry.single_value.get('ipanttrusteddomainsid', None)
            if sid in trust_entry['ipantsidblacklistincoming']:
                trust_entry['ipantsidblacklistincoming'].remove(sid)
                ldap.update_entry(trust_entry)
            else:
                raise errors.AlreadyActive()
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        return dict(
            result=True,
            value=pkey_to_value(keys[1], options),
        )


@register()
class trustdomain_disable(LDAPQuery):
    __doc__ = _('Disable use of IPA resources by the domain of the trust')

    has_output = output.standard_value
    msg_summary = _('Disabled trust domain "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.api.Backend.ldap2
        verify_samba_component_presence(ldap, self.api)

        if keys[0].lower() == keys[1].lower():
            raise errors.ValidationError(
                name='domain',
                error=_("cannot disable root domain of the trust, "
                        "use trust-del to delete the trust itself")
            )
        try:
            trust_dn = self.obj.get_dn(keys[0], trust_type=u'ad')
            trust_entry = ldap.get_entry(trust_dn)
        except errors.NotFound:
            raise self.api.Object[self.obj.parent_object].handle_not_found(
                keys[0])

        dn = self.obj.get_dn(keys[0], keys[1], trust_type=u'ad')
        try:
            entry = ldap.get_entry(dn)
            sid = entry.single_value.get('ipanttrusteddomainsid', None)
            if sid not in trust_entry['ipantsidblacklistincoming']:
                trust_entry['ipantsidblacklistincoming'].append(sid)
                ldap.update_entry(trust_entry)
            else:
                raise errors.AlreadyInactive()
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        return dict(
            result=True,
            value=pkey_to_value(keys[1], options),
        )
