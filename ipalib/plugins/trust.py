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

from ipalib.plugable import Registry
from ipalib.plugins.baseldap import *
from ipalib.plugins.dns import dns_container_exists
from ipapython.ipautil import realm_to_suffix
from ipapython.ipa_log_manager import root_logger
from ipalib import api, Str, StrEnum, Password, Bool, _, ngettext
from ipalib import Command
from ipalib import errors
from ldap import SCOPE_SUBTREE
from time import sleep

try:
    import pysss_murmur #pylint: disable=F0401
    _murmur_installed = True
except Exception, e:
    _murmur_installed = False

try:
    import pysss_nss_idmap #pylint: disable=F0401
    _nss_idmap_installed = True
except Exception, e:
    _nss_idmap_installed = False

if api.env.in_server and api.env.context in ['lite', 'server']:
    try:
        import ipaserver.dcerpc #pylint: disable=F0401
        from ipaserver.dcerpc import TRUST_ONEWAY, TRUST_BIDIRECTIONAL
        import dbus, dbus.mainloop.glib
        _bindings_installed = True
    except ImportError:
        _bindings_installed = False

__doc__ = _("""
Cross-realm trusts

Manage trust relationship between IPA and Active Directory domains.

In order to allow users from a remote domain to access resources in IPA
domain, trust relationship needs to be established. Currently IPA supports
only trusts between IPA and Active Directory domains under control of Windows
Server 2008 or later, with functional level 2008 or later.

Please note that DNS on both IPA and Active Directory domain sides should be
configured properly to discover each other. Trust relationship relies on
ability to discover special resources in the other domain via DNS records.

Examples:

1. Establish cross-realm trust with Active Directory using AD administrator
   credentials:

   ipa trust-add --type=ad <ad.domain> --admin <AD domain administrator> --password

2. List all existing trust relationships:

   ipa trust-find

3. Show details of the specific trust relationship:

   ipa trust-show <ad.domain>

4. Delete existing trust relationship:

   ipa trust-del <ad.domain>

Once trust relationship is established, remote users will need to be mapped
to local POSIX groups in order to actually use IPA resources. The mapping should
be done via use of external membership of non-POSIX group and then this group
should be included into one of local POSIX groups.

Example:

1. Create group for the trusted domain admins' mapping and their local POSIX group:

   ipa group-add --desc='<ad.domain> admins external map' ad_admins_external --external
   ipa group-add --desc='<ad.domain> admins' ad_admins

2. Add security identifier of Domain Admins of the <ad.domain> to the ad_admins_external
   group:

   ipa group-add-member ad_admins_external --external 'AD\\Domain Admins'

3. Allow members of ad_admins_external group to be associated with ad_admins POSIX group:

   ipa group-add-member ad_admins --groups ad_admins_external

4. List members of external members of ad_admins_external group to see their SIDs:

   ipa group-show ad_admins_external


GLOBAL TRUST CONFIGURATION

When IPA AD trust subpackage is installed and ipa-adtrust-install is run,
a local domain configuration (SID, GUID, NetBIOS name) is generated. These
identifiers are then used when communicating with a trusted domain of the
particular type.

1. Show global trust configuration for Active Directory type of trusts:

   ipa trustconfig-show --type ad

2. Modify global configuration for all trusts of Active Directory type and set
   a different fallback primary group (fallback primary group GID is used as
   a primary user GID if user authenticating to IPA domain does not have any other
   primary GID already set):

   ipa trustconfig-mod --type ad --fallback-primary-group "alternative AD group"

3. Change primary fallback group back to default hidden group (any group with
   posixGroup object class is allowed):

   ipa trustconfig-mod --type ad --fallback-primary-group "Default SMB Group"
""")

register = Registry()

trust_output_params = (
    Str('trustdirection',
        label=_('Trust direction')),
    Str('trusttype',
        label=_('Trust type')),
    Str('truststatus',
        label=_('Trust status')),
)

_trust_type_dict = {1 : _('Non-Active Directory domain'),
                    2 : _('Active Directory domain'),
                    3 : _('RFC4120-compliant Kerberos realm')}
_trust_direction_dict = {1 : _('Trusting forest'),
                         2 : _('Trusted forest'),
                         3 : _('Two-way trust')}
_trust_status_dict = {True : _('Established and verified'),
                 False : _('Waiting for confirmation by remote side')}
_trust_type_dict_unknown = _('Unknown')

_trust_type_option = StrEnum('trust_type',
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

def trust_type_string(level):
    """
    Returns a string representing a type of the trust. The original field is an enum:
      LSA_TRUST_TYPE_DOWNLEVEL  = 0x00000001,
      LSA_TRUST_TYPE_UPLEVEL    = 0x00000002,
      LSA_TRUST_TYPE_MIT        = 0x00000003
    """
    string = _trust_type_dict.get(int(level), _trust_type_dict_unknown)
    return unicode(string)

def trust_direction_string(level):
    """
    Returns a string representing a direction of the trust. The original field is a bitmask taking two bits in use
      LSA_TRUST_DIRECTION_INBOUND  = 0x00000001,
      LSA_TRUST_DIRECTION_OUTBOUND = 0x00000002
    """
    string = _trust_direction_dict.get(int(level), _trust_type_dict_unknown)
    return unicode(string)

def trust_status_string(level):
    string = _trust_status_dict.get(level, _trust_type_dict_unknown)
    return unicode(string)

def make_trust_dn(env, trust_type, dn):
    assert isinstance(dn, DN)
    if trust_type:
        container_dn = DN(('cn', trust_type), env.container_trusts, env.basedn)
        return DN(dn, container_dn)
    return dn

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
       a string representing credentials with first % separating username and password
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
                sp.append(trustinstance.remote_domain.info['dns_forest'].upper())
        creds = u"{name}%{password}".format(name=sep.join(sp),
                                            password=password)
    return creds

def add_range(myapi, trustinstance, range_name, dom_sid, *keys, **options):
    """
    First, we try to derive the parameters of the ID range based on the
    information contained in the Active Directory.

    If that was not successful, we go for our usual defaults (random base,
    range size 200 000, ipa-ad-trust range type).

    Any of these can be overriden by passing appropriate CLI options
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
            creds = generate_creds(trustinstance, style=CRED_STYLE_KERBEROS, **options)
            if creds:
                domain_validator._admin_creds = creds
        # KDC might not get refreshed data at the first time,
        # retry several times
        for retry in range(10):
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
            root_logger.debug("Unable to gain POSIX info from the AD")
        else:
            if all(attr in info for attr in required_msSFU_attrs):
                root_logger.debug("Able to gain POSIX info from the AD")
                range_type = u'ipa-ad-trust-posix'

                max_uid = info.get('msSFU30MaxUidNumber')
                max_gid = info.get('msSFU30MaxGidNumber', None)
                max_id = int(max(max_uid, max_gid)[0])

                base_id = int(info.get('msSFU30OrderNumber')[0])
                range_size = (1 + (max_id - base_id) / DEFAULT_RANGE_SIZE)\
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
                len(dom_sid), 0xdeadbeefL
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

def fetch_trusted_domains_over_dbus(myapi, log, forest_name):
    if not _bindings_installed:
        return
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
        intf = bus.get_object(DBUS_IFACE_TRUST,"/", follow_name_owner_changes=True)
        fetch_domains_method = intf.get_dbus_method('fetch_domains', dbus_interface=DBUS_IFACE_TRUST)
        (_ret, _stdout, _stderr) = fetch_domains_method(forest_name)
    except dbus.DBusException, e:
        log.error('Failed to call %(iface)s.fetch_domains helper.'
                       'DBus exception is %(exc)s.' % dict(iface=DBUS_IFACE_TRUST, exc=str(e)))
        if _ret != 0:
            log.error('Helper was called for forest %(forest)s, return code is %(ret)d' % dict(forest=forest_name, ret=_ret))
            log.error('Standard output from the helper:\n%s---\n' % (_stdout))
            log.error('Error output from the helper:\n%s--\n' % (_stderr))
        raise errors.ServerCommandError(server=myapi.env.host,
                                        error=_('Fetching domains from trusted forest failed. '
                                                'See details in the error_log'))
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
    object_class = ['ipaNTTrustedDomain']
    default_attributes = ['cn', 'ipantflatname', 'ipanttrusteddomainsid',
        'ipanttrusttype', 'ipanttrustattributes', 'ipanttrustdirection',
        'ipanttrustpartner', 'ipanttrustforesttrustinfo',
        'ipanttrustposixoffset', 'ipantsupportedencryptiontypes' ]
    search_display_attributes = ['cn', 'ipantflatname',
                                 'ipanttrusteddomainsid', 'ipanttrusttype']
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
                'ipanttrustdirection'
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
            csv=True,
            cli_name='sid_blacklist_incoming',
            label=_('SID blacklist incoming'),
            flags=['no_create']),
        Str('ipantsidblacklistoutgoing*',
            csv=True,
            cli_name='sid_blacklist_outgoing',
            label=_('SID blacklist outgoing'),
            flags=['no_create']),
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
                    raise errors.ValidationError(name=attr,
                            error=_("invalid SID: %(value)s") % dict(value=value))

    def get_dn(self, *keys, **kwargs):
        sdn = map(lambda x: ('cn', x), keys)
        sdn.reverse()
        trust_type = kwargs.get('trust_type')
        if trust_type is None:
            ldap = self.backend
            filter = ldap.make_filter({'objectclass': ['ipaNTTrustedDomain'], 'cn': [keys[-1]] },
                                      rules=ldap.MATCH_ALL)
            filter = ldap.combine_filters((filter, "ipaNTSecurityIdentifier=*"), rules=ldap.MATCH_ALL)
            result = ldap.get_entries(DN(self.container_dn, self.env.basedn),
                                      ldap.SCOPE_SUBTREE, filter, [''])
            if len(result) > 1:
                raise errors.OnlyOneValueAllowed(attr='trust domain')
            return result[0].dn

        dn=make_trust_dn(self.env, trust_type, DN(*sdn))
        return dn

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
            label=_('Domain controller for the Active Directory domain (optional)'),
        ),
        Password('trust_secret?',
            cli_name='trust_secret',
            label=_('Shared secret for the trust'),
            confirm=False,
        ),
        Int('base_id?',
            cli_name='base_id',
            label=_('First Posix ID of the range reserved for the trusted domain'),
        ),
        Int('range_size?',
            cli_name='range_size',
            label=_('Size of the ID range reserved for the trusted domain'),
        ),
        StrEnum('range_type?',
            label=_('Range type'),
            cli_name='range_type',
            doc=(_('Type of trusted domain ID range, one of {vals}'
                 .format(vals=', '.join(range_types.keys())))),
            values=tuple(range_types.keys()),
        ),
        Bool('bidirectional?',
             label=_('Two-way trust'),
             cli_name='two_way',
             doc=(_('Establish bi-directional trust. By default trust is inbound one-way only.')),
             default=False,
        ),
    )

    msg_summary = _('Added Active Directory trust for realm "%(value)s"')
    msg_summary_existing = _('Re-established trust to domain "%(value)s"')
    has_output_params = LDAPCreate.has_output_params + trust_output_params

    def execute(self, *keys, **options):
        full_join = self.validate_options(*keys, **options)
        old_range, range_name, dom_sid = self.validate_range(*keys, **options)
        result = self.execute_ad(full_join, *keys, **options)

        if not old_range:
            # Store the created range type, since for POSIX trusts no
            # ranges for the subdomains should be added, POSIX attributes
            # provide a global mapping across all subdomains
            (created_range_type, _, _) = add_range(self.api, self.trustinstance,
                                                   range_name, dom_sid,
                                                   *keys, **options)
        else:
            created_range_type = old_range['result']['iparangetype'][0]

        trust_filter = "cn=%s" % result['value']
        ldap = self.obj.backend
        (trusts, truncated) = ldap.find_entries(
                         base_dn=DN(self.api.env.container_trusts, self.api.env.basedn),
                         filter=trust_filter)

        result['result'] = entry_to_dict(trusts[0], **options)

        # Fetch topology of the trust forest -- we need always to do it
        # for AD trusts, regardless of the type of idranges associated with it
        # Note that add_new_domains_from_trust will add needed ranges for
        # the algorithmic ID mapping case.
        if (options.get('trust_type') == u'ad' and
            options.get('trust_secret') is None):
            if options.get('bidirectional') == True:
                # Bidirectional trust allows us to use cross-realm TGT, so we can
                # run the call under original user's credentials
                res = fetch_domains_from_trust(self.api, self.trustinstance,
                                               result['result'], **options)
                domains = add_new_domains_from_trust(self.api, self.trustinstance,
                                                     result['result'], res, **options)
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
                fetch_trusted_domains_over_dbus(self.api, self.log, result['value'])

        # Format the output into human-readable values
        result['result']['trusttype'] = [trust_type_string(
            result['result']['ipanttrusttype'][0])]
        result['result']['trustdirection'] = [trust_direction_string(
            result['result']['ipanttrustdirection'][0])]
        result['result']['truststatus'] = [trust_status_string(
            result['verified'])]

        del result['verified']
        result['result'].pop('ipanttrustauthoutgoing', None)
        result['result'].pop('ipanttrustauthincoming', None)

        return result

    def interactive_prompt_callback(self, kw):
        """
        Also ensure that realm_admin is prompted for if --admin or
        --trust-secret is not specified when 'ipa trust-add' is run on the
        system.

        Also ensure that realm_passwd is prompted for if --password or
        --trust-secret is not specified when 'ipa trust-add' is run on the
        system.
        """

        trust_secret = kw.get('trust_secret')
        realm_admin = kw.get('realm_admin')
        realm_passwd = kw.get('realm_passwd')

        if trust_secret is None:
            if realm_admin is None:
                kw['realm_admin'] = self.prompt_param(
                           self.params['realm_admin'])

            if realm_passwd is None:
                kw['realm_passwd'] = self.Backend.textui.prompt_password(
                           self.params['realm_passwd'].label, confirm=False)

    def validate_options(self, *keys, **options):
        if not _bindings_installed:
            raise errors.NotFound(
                name=_('AD Trust setup'),
                reason=_(
                    'Cannot perform join operation without Samba 4 support '
                    'installed. Make sure you have installed server-trust-ad '
                    'sub-package of IPA'
                )
            )

        if not _murmur_installed and 'base_id' not in options:
            raise errors.ValidationError(
                name=_('missing base_id'),
                error=_(
                    'pysss_murmur is not available on the server '
                    'and no base-id is given.'
                )
            )

        if 'trust_type' not in options:
            raise errors.RequirementError(name=_('trust type'))

        if options['trust_type'] != u'ad':
            raise errors.ValidationError(
                name=_('trust type'),
                error=_('only "ad" is supported')
            )

        # If domain name and realm does not match, IPA server is not be able
        # to establish trust with Active Directory.

        realm_not_matching_domain = (self.api.env.domain.upper() != self.api.env.realm)

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

        self.realm_server = options.get('realm_server')
        self.realm_admin = options.get('realm_admin')
        self.realm_passwd = options.get('realm_passwd')

        if self.realm_admin:
            names = self.realm_admin.split('@')

            if len(names) > 1:
                # realm admin name is in UPN format, user@realm, check that
                # realm is the same as the one that we are attempting to trust
                if keys[-1].lower() != names[-1].lower():
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
                raise errors.ValidationError(name=_('range type change'),
                    error=_('ID range for the trusted domain already exists, '
                            'but it has a different type. Please remove the '
                            'old range manually, or do not enforce type '
                            'via --range-type option.'))

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
                error_message=_("Unable to resolve domain controller for '%s' domain. ") % (keys[-1])
                instructions=[]
                if dns_container_exists(self.obj.backend):
                    try:
                        dns_zone = self.api.Command.dnszone_show(keys[-1])['result']
                        if ('idnsforwardpolicy' in dns_zone) and dns_zone['idnsforwardpolicy'][0] == u'only':
                            instructions.append(_("Forward policy is defined for it in IPA DNS, "
                                                   "perhaps forwarder points to incorrect host?"))
                    except (errors.NotFound, KeyError) as e:
                        instructions.append(_("IPA manages DNS, please verify "
                                              "your DNS configuration and "
                                              "make sure that service records "
                                              "of the '%(domain)s' domain can "
                                              "be resolved. Examples how to "
                                              "configure DNS with CLI commands "
                                              "or the Web UI can be found in "
                                              "the documentation. " ) %
                                              dict(domain=keys[-1]))
                else:
                    instructions.append(_("Since IPA does not manage DNS records, ensure DNS "
                                           "is configured to resolve '%(domain)s' domain from "
                                           "IPA hosts and back.") % dict(domain=keys[-1]))
                raise errors.NotFound(reason=error_message, instructions=instructions)

            if result is None:
                raise errors.ValidationError(name=_('AD Trust setup'),
                                             error=_('Unable to verify write permissions to the AD'))

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

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

        self.obj.validate_sid_blacklists(entry_attrs)

        return dn

@register()
class trust_find(LDAPSearch):
    __doc__ = _('Search for trusts.')
    has_output_params = LDAPSearch.has_output_params + trust_output_params +\
                        (Str('ipanttrusttype'),)

    msg_summary = ngettext(
        '%(count)d trust matched', '%(count)d trusts matched', 0
    )

    # Since all trusts types are stored within separate containers under 'cn=trusts',
    # search needs to be done on a sub-tree scope
    def pre_callback(self, ldap, filters, attrs_list, base_dn, scope, *args, **options):
        # list only trust, not trust domains
        trust_filter = '(ipaNTSecurityIdentifier=*)'
        filter = ldap.combine_filters((filters, trust_filter), rules=ldap.MATCH_ALL)
        return (filter, base_dn, ldap.SCOPE_SUBTREE)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if options.get('pkey_only', False):
            return truncated

        for attrs in entries:
            # Translate ipanttrusttype to trusttype if --raw not used
            trust_type = attrs.get('ipanttrusttype', [None])[0]
            if not options.get('raw', False) and trust_type is not None:
                attrs['trusttype'] = trust_type_string(attrs['ipanttrusttype'][0])
                del attrs['ipanttrusttype']

        return truncated

@register()
class trust_show(LDAPRetrieve):
    __doc__ = _('Display information about a trust.')
    has_output_params = LDAPRetrieve.has_output_params + trust_output_params +\
                        (Str('ipanttrusttype'), Str('ipanttrustdirection'))

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):

        assert isinstance(dn, DN)
        # Translate ipanttrusttype to trusttype
        # and ipanttrustdirection to trustdirection
        # if --raw not used

        if not options.get('raw', False):
            trust_type = entry_attrs.get('ipanttrusttype', [None])[0]
            if trust_type is not None:
                entry_attrs['trusttype'] = trust_type_string(trust_type)
                del entry_attrs['ipanttrusttype']

            dir_str = entry_attrs.get('ipanttrustdirection', [None])[0]
            if dir_str is not None:
                entry_attrs['trustdirection'] = [trust_direction_string(dir_str)]
                del entry_attrs['ipanttrustdirection']

        return dn


_trustconfig_dn = {
    u'ad': DN(('cn', api.env.domain), api.env.container_cifsdomains, api.env.basedn),
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
    )

    def get_dn(self, *keys, **kwargs):
        trust_type = kwargs.get('trust_type')
        if trust_type is None:
            raise errors.RequirementError(name='trust_type')
        try:
            return _trustconfig_dn[kwargs['trust_type']]
        except KeyError:
            raise errors.ValidationError(name='trust_type',
                error=_("unsupported trust type"))

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
                self.api.Object['group'].handle_not_found(group)
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
                self.api.Object['group'].handle_not_found(group)
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

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        self.obj._normalize_groupdn(entry_attrs)
        return dn

    def execute(self, *keys, **options):
        result = super(trustconfig_mod, self).execute(*keys, **options)
        result['value'] = pkey_to_value(options['trust_type'], options)
        return result

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj._convert_groupdn(entry_attrs, options)
        return dn



@register()
class trustconfig_show(LDAPRetrieve):
    __doc__ = _('Show global trust configuration.')

    takes_options = LDAPRetrieve.takes_options + (_trust_type_option,)

    def execute(self, *keys, **options):
        result = super(trustconfig_show, self).execute(*keys, **options)
        result['value'] = pkey_to_value(options['trust_type'], options)
        return result

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj._convert_groupdn(entry_attrs, options)
        return dn


if _nss_idmap_installed:
    _idmap_type_dict = {
        pysss_nss_idmap.ID_USER  : 'user',
        pysss_nss_idmap.ID_GROUP : 'group',
        pysss_nss_idmap.ID_BOTH  : 'both',
    }
    def idmap_type_string(level):
        string = _idmap_type_dict.get(int(level), 'unknown')
        return unicode(string)

@register()
class trust_resolve(Command):
    NO_CLI = True
    __doc__ = _('Resolve security identifiers of users and groups in trusted domains')

    takes_options = (
        Str('sids+',
            label = _('Security Identifiers (SIDs)'),
            csv = True,
        ),
    )

    has_output_params = (
        Str('name', label= _('Name')),
        Str('sid', label= _('SID')),
    )

    has_output = (
        output.ListOfEntries('result'),
    )

    def execute(self, *keys, **options):
        result = list()
        if not _nss_idmap_installed:
            return dict(result=result)
        try:
            sids = map(lambda x: str(x), options['sids'])
            xlate = pysss_nss_idmap.getnamebysid(sids)
            for sid in xlate:
                entry = dict()
                entry['sid'] = [unicode(sid)]
                entry['name'] = [unicode(xlate[sid][pysss_nss_idmap.NAME_KEY])]
                entry['type'] = [idmap_type_string(xlate[sid][pysss_nss_idmap.TYPE_KEY])]
                result.append(entry)
        except ValueError, e:
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
    trust_type_idx = {'2':u'ad'}
    object_name = _('trust domain')
    object_name_plural = _('trust domains')
    object_class = ['ipaNTTrustedDomain']
    default_attributes = ['cn', 'ipantflatname', 'ipanttrusteddomainsid', 'ipanttrustpartner']
    search_display_attributes = ['cn', 'ipantflatname', 'ipanttrusteddomainsid', ]

    label = _('Trusted domains')
    label_singular = _('Trusted domain')

    takes_params = (
        Str('cn',
            label=_('Domain name'),
            cli_name='domain',
            primary_key=True
        ),
        Str('ipantflatname?',
            cli_name='flat_name',
            label=_('Domain NetBIOS name'),
        ),
        Str('ipanttrusteddomainsid?',
            cli_name='sid',
            label=_('Domain Security Identifier'),
        ),
        Str('ipanttrustpartner?',
            label=_('Trusted domain partner'),
            flags=['no_display', 'no_option'],
        ),
    )

    # LDAPObject.get_dn() only passes all but last element of keys and no kwargs
    # to the parent object's get_dn() no matter what you pass to it. Make own get_dn()
    # as we really need all elements to construct proper dn.
    def get_dn(self, *keys, **kwargs):
        sdn = map(lambda x: ('cn', x), keys)
        sdn.reverse()
        trust_type = kwargs.get('trust_type')
        if not trust_type:
            trust_type=u'ad'

        dn=make_trust_dn(self.env, trust_type, DN(*sdn))
        return dn

@register()
class trustdomain_find(LDAPSearch):
    __doc__ = _('Search domains of the trust')

    has_output_params = LDAPSearch.has_output_params + (
        Flag('domain_enabled', label= _('Domain enabled')),
    )
    def pre_callback(self, ldap, filters, attrs_list, base_dn, scope, *args, **options):
        return (filters, base_dn, ldap.SCOPE_SUBTREE)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if options.get('pkey_only', False):
            return truncated
        trust_dn = self.obj.get_dn(args[0], trust_type=u'ad')
        trust_entry = ldap.get_entry(trust_dn)
        for entry in entries:
            sid = entry['ipanttrusteddomainsid'][0]

            blacklist = trust_entry.get('ipantsidblacklistincoming')
            if blacklist is None:
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
    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        if 'ipanttrustpartner' in options:
            entry_attrs['ipanttrustpartner'] = [options['ipanttrustpartner']]
        return dn

@register()
class trustdomain_del(LDAPDelete):
    __doc__ = _('Remove infromation about the domain associated with the trust.')

    msg_summary = _('Removed information about the trusted domain "%(value)s"')

    def execute(self, *keys, **options):
        # Note that pre-/post- callback handling for LDAPDelete is causing pre_callback
        # to always receive empty keys. We need to catch the case when root domain is being deleted

        for domain in keys[1]:
            if keys[0].lower() == domain:
                raise errors.ValidationError(name='domain',
                    error=_("cannot delete root domain of the trust, use trust-del to delete the trust itself"))
            try:
                res = self.api.Command.trustdomain_enable(keys[0], domain)
            except errors.AlreadyActive:
                pass
        result = super(trustdomain_del, self).execute(*keys, **options)
        result['value'] = pkey_to_value(keys[1], options)
        return result


def fetch_domains_from_trust(myapi, trustinstance, trust_entry, **options):
    trust_name = trust_entry['cn'][0]
    creds = generate_creds(trustinstance, style=CRED_STYLE_SAMBA, **options)
    server = options.get('realm_server', None)
    domains = ipaserver.dcerpc.fetch_domains(myapi,
                                             trustinstance.local_flatname,
                                             trust_name, creds=creds, server=server)
    return domains

def add_new_domains_from_trust(myapi, trustinstance, trust_entry, domains, **options):
    result = []
    if not domains:
        return result

    trust_name = trust_entry['cn'][0]
    # trust range must exist by the time add_new_domains_from_trust is called
    range_name = trust_name.upper() + '_id_range'
    old_range = myapi.Command.idrange_show(range_name, raw=True)['result']
    idrange_type = old_range['iparangetype'][0]

    for dom in domains:
        dom['trust_type'] = u'ad'
        try:
            name = dom['cn']
            del dom['cn']
            if 'all' in options:
                dom['all'] = options['all']
            if 'raw' in options:
                dom['raw'] = options['raw']

            res = myapi.Command.trustdomain_add(trust_name, name, **dom)
            result.append(res['result'])

            if idrange_type != u'ipa-ad-trust-posix':
                range_name = name.upper() + '_id_range'
                dom['range_type'] = u'ipa-ad-trust'
                add_range(myapi, trustinstance, range_name, dom['ipanttrusteddomainsid'],
                          trust_name, name, **dom)
        except errors.DuplicateEntry:
            # Ignore updating duplicate entries
            pass
    return result

@register()
class trust_fetch_domains(LDAPRetrieve):
    __doc__ = _('Refresh list of the domains associated with the trust')

    has_output = output.standard_list_of_entries
    takes_options = LDAPRetrieve.takes_options + (
        Str('realm_server?',
            cli_name='server',
            label=_('Domain controller for the Active Directory domain (optional)'),
        ),
    )

    def execute(self, *keys, **options):
        if not _bindings_installed:
            raise errors.NotFound(
                name=_('AD Trust setup'),
                reason=_(
                    'Cannot perform join operation without Samba 4 support '
                    'installed. Make sure you have installed server-trust-ad '
                    'sub-package of IPA'
                )
            )
        trust = self.api.Command.trust_show(keys[0], raw=True)['result']

        result = dict()
        result['result'] = []
        result['count'] = 0
        result['truncated'] = False

        # For one-way trust fetch over DBus. we don't get the list in this case.
        if trust['ipanttrustdirection'] & TRUST_BIDIRECTIONAL != TRUST_BIDIRECTIONAL:
            fetch_trusted_domains_over_dbus(self.api, self.log, keys[0])
            result['summary'] = unicode(_('List of trust domains successfully refreshed. Use trustdomain-find command to list them.'))
            return result

        trustinstance = ipaserver.dcerpc.TrustDomainJoins(self.api)
        if not trustinstance.configured:
            raise errors.NotFound(
                name=_('AD Trust setup'),
                reason=_(
                    'Cannot perform join operation without own domain '
                    'configured. Make sure you have run ipa-adtrust-install '
                    'on the IPA server first'
                )
            )
        res = fetch_domains_from_trust(self.api, trustinstance, trust, **options)
        domains = add_new_domains_from_trust(self.api, trustinstance, trust, res, **options)

        if len(domains) > 0:
            result['summary'] = unicode(_('List of trust domains successfully refreshed'))
        else:
            result['summary'] = unicode(_('No new trust domains were found'))

        result['result'] = domains
        result['count'] = len(domains)
        return result


@register()
class trustdomain_enable(LDAPQuery):
    __doc__ = _('Allow use of IPA resources by the domain of the trust')

    has_output = output.standard_value
    msg_summary = _('Enabled trust domain "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.api.Backend.ldap2

        if keys[0].lower() == keys[1].lower():
            raise errors.ValidationError(name='domain',
                error=_("Root domain of the trust is always enabled for the existing trust"))
        try:
            trust_dn = self.obj.get_dn(keys[0], trust_type=u'ad')
            trust_entry = ldap.get_entry(trust_dn)
        except errors.NotFound:
            self.api.Object[self.obj.parent_object].handle_not_found(keys[0])

        dn = self.obj.get_dn(keys[0], keys[1], trust_type=u'ad')
        try:
            entry = ldap.get_entry(dn)
            sid = entry['ipanttrusteddomainsid'][0]
            if sid in trust_entry['ipantsidblacklistincoming']:
                trust_entry['ipantsidblacklistincoming'].remove(sid)
                ldap.update_entry(trust_entry)
                # Force MS-PAC cache re-initialization on KDC side
                domval = ipaserver.dcerpc.DomainValidator(self.api)
                (ccache_name, principal) = domval.kinit_as_http(keys[0])
            else:
                raise errors.AlreadyActive()
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

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

        if keys[0].lower() == keys[1].lower():
            raise errors.ValidationError(name='domain',
                error=_("cannot disable root domain of the trust, use trust-del to delete the trust itself"))
        try:
            trust_dn = self.obj.get_dn(keys[0], trust_type=u'ad')
            trust_entry = ldap.get_entry(trust_dn)
        except errors.NotFound:
            self.api.Object[self.obj.parent_object].handle_not_found(keys[0])

        dn = self.obj.get_dn(keys[0], keys[1], trust_type=u'ad')
        try:
            entry = ldap.get_entry(dn)
            sid = entry['ipanttrusteddomainsid'][0]
            if not (sid in trust_entry['ipantsidblacklistincoming']):
                trust_entry['ipantsidblacklistincoming'].append(sid)
                ldap.update_entry(trust_entry)
                # Force MS-PAC cache re-initialization on KDC side
                domval = ipaserver.dcerpc.DomainValidator(self.api)
                (ccache_name, principal) = domval.kinit_as_http(keys[0])
            else:
                raise errors.AlreadyInactive()
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        return dict(
            result=True,
            value=pkey_to_value(keys[1], options),
        )

