# Authors:
#     Alexander Bokovoy <abokovoy@redhat.com>
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

from ipalib.plugins.baseldap import *
from ipalib.plugins.dns import dns_container_exists
from ipalib import api, Str, StrEnum, Password, DefaultFrom, _, ngettext, Object
from ipalib.parameters import Enum
from ipalib import Command
from ipalib import errors
from ipapython import ipautil
from ipalib import util
try:
    import pysss_murmur #pylint: disable=F0401
    _murmur_installed = True
except Exception, e:
    _murmur_installed = False

if api.env.in_server and api.env.context in ['lite', 'server']:
    try:
        import ipaserver.dcerpc #pylint: disable=F0401
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

1. Make note of the trusted domain security identifier

   domainsid = `ipa trust-show <ad.domain> | grep Identifier | cut -d: -f2`

2. Create group for the trusted domain admins' mapping and their local POSIX group:

   ipa group-add --desc='<ad.domain> admins external map' ad_admins_external --external
   ipa group-add --desc='<ad.domain> admins' ad_admins

3. Add security identifier of Domain Admins of the <ad.domain> to the ad_admins_external
   group (security identifier of <ad.domain SID>-512 is Domain Admins group):

   ipa group-add-member ad_admins_external --external ${domainsid}-512

4. Allow members of ad_admins_external group to be associated with ad_admins POSIX group:

   ipa group-add-member ad_admins --groups ad_admins_external

""")

trust_output_params = (
    Str('ipantflatname',
        label=_('Domain NetBIOS name')),
    Str('ipanttrusteddomainsid',
        label=_('Domain Security Identifier')),
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
        'ipanttrusttype', 'ipanttrustattributes', 'ipanttrustdirection', 'ipanttrustpartner',
        'ipantauthtrustoutgoing', 'ipanttrustauthincoming', 'ipanttrustforesttrustinfo',
        'ipanttrustposixoffset', 'ipantsupportedencryptiontypes' ]
    search_display_attributes = ['cn', 'ipantflatname',
                                 'ipanttrusteddomainsid', 'ipanttrusttype' ]

    label = _('Trusts')
    label_singular = _('Trust')

    takes_params = (
        Str('cn',
            cli_name='realm',
            label=_('Realm name'),
            primary_key=True,
        ),
    )

def make_trust_dn(env, trust_type, dn):
    assert isinstance(dn, DN)
    if trust_type in trust.trust_types:
        container_dn = DN(('cn', trust_type), env.container_trusts, env.basedn)
        return DN(dn[0], container_dn)
    return dn

class trust_add(LDAPCreate):
    __doc__ = _('Add new trust to use')

    takes_options = LDAPCreate.takes_options + (
        StrEnum('trust_type',
            cli_name='type',
            label=_('Trust type (ad for Active Directory, default)'),
            values=(u'ad',),
            default=u'ad',
            autofill=True,
        ),
        Str('realm_admin?',
            cli_name='admin',
            label=_("Active Directory domain administrator"),
        ),
        Password('realm_passwd?',
            cli_name='password',
            label=_("Active directory domain administrator's password"),
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
            default=200000,
            autofill=True
        ),
    )

    msg_summary = _('Added Active Directory trust for realm "%(value)s"')
    has_output_params = LDAPCreate.has_output_params + trust_output_params

    def execute(self, *keys, **options):
        if not _murmur_installed and 'base_id' not in options:
            raise errors.ValidationError(name=_('missing base_id'),
                error=_('pysss_murmur is not available on the server ' \
                        'and no base-id is given.'))

        if 'trust_type' in options:
            if options['trust_type'] == u'ad':
                result = self.execute_ad(*keys, **options)
            else:
                raise errors.ValidationError(name=_('trust type'), error=_('only "ad" is supported'))
        else:
            raise errors.RequirementError(name=_('trust type'))

        self.add_range(*keys, **options)

        trust_filter = "cn=%s" % result['value']
        ldap = self.obj.backend
        (trusts, truncated) = ldap.find_entries(
                         base_dn = DN(api.env.container_trusts, api.env.basedn),
                         filter = trust_filter)

        result['result'] = trusts[0][1]
        result['result']['trusttype'] = [trust_type_string(result['result']['ipanttrusttype'][0])]
        result['result']['trustdirection'] = [trust_direction_string(result['result']['ipanttrustdirection'][0])]
        result['result']['truststatus'] = [trust_status_string(result['verified'])]
        del result['verified']

        return result

    def add_range(self, *keys, **options):
        new_obj = api.Command['trust_show'](keys[-1])
        dom_sid = new_obj['result']['ipanttrusteddomainsid'][0];

        range_name = keys[-1].upper()+'_id_range'

        try:
            old_range = api.Command['idrange_show'](range_name)
        except errors.NotFound, e:
            old_range = None

        if old_range:
            old_dom_sid = old_range['result']['ipanttrusteddomainsid'][0];

            if old_dom_sid == dom_sid:
                return

            raise errors.ValidationError(name=_('range exists'),
                    error=_('ID range with the same name but different ' \
                            'domain SID already exists. The ID range for ' \
                            'the new trusted domain must be created manually.'))

        if 'base_id' in options:
            base_id = options['base_id']
        else:
            base_id = 200000 + (pysss_murmur.murmurhash3(dom_sid, len(dom_sid), 0xdeadbeef) % 10000) * 200000

        try:
            new_range = api.Command['idrange_add'](range_name,
                                                 ipabaseid=base_id,
                                                 ipaidrangesize=options['range_size'],
                                                 ipabaserid=0,
                                                 ipanttrusteddomainsid=dom_sid)
        except Exception, e:
            raise errors.ValidationError(name=_('ID range exists'),
                   error = _('ID range already exists, must be added manually'))

    def execute_ad(self, *keys, **options):
        # Join domain using full credentials and with random trustdom
        # secret (will be generated by the join method)
        trustinstance = None
        if not _bindings_installed:
            raise errors.NotFound(name=_('AD Trust setup'),
                  reason=_('''Cannot perform join operation without Samba 4 support installed.
                              Make sure you have installed server-trust-ad sub-package of IPA'''))

        if 'realm_server' not in options:
            realm_server = None
        else:
            realm_server = options['realm_server']

        trustinstance = ipaserver.dcerpc.TrustDomainJoins(self.api)
        if not trustinstance.configured:
            raise errors.NotFound(name=_('AD Trust setup'),
                  reason=_('''Cannot perform join operation without own domain configured.
                              Make sure you have run ipa-adtrust-install on the IPA server first'''))

        # 1. Full access to the remote domain. Use admin credentials and
        # generate random trustdom password to do work on both sides
        if 'realm_admin' in options:
            realm_admin = options['realm_admin']
            names = realm_admin.split('@')
            if len(names) > 1:
                # realm admin name is in UPN format, user@realm, check that
                # realm is the same as the one that we are attempting to trust
                if keys[-1].lower() != names[-1].lower():
                    raise errors.ValidationError(name=_('AD Trust setup'),
                                 error=_('Trusted domain and administrator account use different realms'))
                realm_admin = names[0]

            if 'realm_passwd' not in options:
                raise errors.ValidationError(name=_('AD Trust setup'), error=_('Realm administrator password should be specified'))
            realm_passwd = options['realm_passwd']

            try:
                result = trustinstance.join_ad_full_credentials(keys[-1], realm_server, realm_admin, realm_passwd)
            except errors.NotFound, e:
                error_message=_("Unable to resolve domain controller for '%s' domain. ") % (keys[-1])
                instructions=[]
                if dns_container_exists(self.obj.backend):
                    try:
                        dns_zone = api.Command.dnszone_show(keys[-1])['result']
                        if ('idnsforwardpolicy' in dns_zone) and dns_zone['idnsforwardpolicy'][0] == u'only':
                            instructions.append(_("Forward policy is defined for it in IPA DNS, "
                                                   "perhaps forwarder points to incorrect host?"))
                    except (errors.NotFound, KeyError) as e:
                        instructions.append(_("IPA manages DNS, please configure forwarder to "
                                               "'%(domain)s' domain using following CLI command. "
                                               "Make sure to replace DNS_SERVER and IP_ADDRESS by "
                                               "actual values corresponding to the trusted domain's "
                                               "DNS server:") % dict(domain=keys[-1]))
                        # tab character at the beginning of a multiline error message will be replaced
                        # in the web UI by a colorful hint. Does not affect CLI.
                        instructions.append(_("\tipa dnszone-add %(domain)s --name-server=[DNS_SERVER] "
                                               "--admin-email='hostmaster@%(domain)s' "
                                               "--force --forwarder=[IP_ADDRESS] "
                                               "--forward-policy=only") % dict(domain=keys[-1]))
                        instructions.append(_("When using Web UI, please create DNS zone for domain '%(domain)s' "
                                               "first and then set forwarder and forward policy.") % dict(domain=keys[-1]))
                else:
                    instructions.append(_("Since IPA does not manage DNS records, ensure DNS "
                                           "is configured to resolve '%(domain)s' domain from "
                                           "IPA hosts and back.") % dict(domain=keys[-1]))
                raise errors.NotFound(reason=error_message, instructions=instructions)

            if result is None:
                raise errors.ValidationError(name=_('AD Trust setup'),
                                             error=_('Unable to verify write permissions to the AD'))

            return dict(value=trustinstance.remote_domain.info['dns_domain'], verified=result['verified'])

        # 2. We don't have access to the remote domain and trustdom password
        # is provided. Do the work on our side and inform what to do on remote
        # side.
        if 'trust_secret' in options:
            result = trustinstance.join_ad_ipa_half(keys[-1], realm_server, options['trust_secret'])
            return dict(value=trustinstance.remote_domain.info['dns_domain'], verified=result['verified'])
        raise errors.ValidationError(name=_('AD Trust setup'),
                                     error=_('Not enough arguments specified to perform trust setup'))

class trust_del(LDAPDelete):
    __doc__ = _('Delete a trust.')

    msg_summary = _('Deleted trust "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        try:
            result = self.api.Command.trust_show(keys[-1])
        except errors.NotFound, e:
            self.obj.handle_not_found(*keys)
        return result['result']['dn']

class trust_mod(LDAPUpdate):
    __doc__ = _("""
    Modify a trust (for future use).

    Currently only the default option to modify the LDAP attributes is
    available. More specific options will be added in coming releases.
    """)

    msg_summary = _('Modified trust "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        result = None
        try:
            result = self.api.Command.trust_show(keys[-1])
        except errors.NotFound, e:
            self.obj.handle_not_found(*keys)

        # TODO: we found the trust object, now modify it
        return result['result']['dn']

class trust_find(LDAPSearch):
    __doc__ = _('Search for trusts.')
    has_output_params = LDAPSearch.has_output_params + trust_output_params

    msg_summary = ngettext(
        '%(count)d trust matched', '%(count)d trusts matched', 0
    )

    # Since all trusts types are stored within separate containers under 'cn=trusts',
    # search needs to be done on a sub-tree scope
    def pre_callback(self, ldap, filters, attrs_list, base_dn, scope, *args, **options):
        assert isinstance(base_dn, DN)
        return (filters, base_dn, ldap.SCOPE_SUBTREE)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if options.get('pkey_only', False):
            return truncated

        for entry in entries:
            (dn, attrs) = entry
            attrs['trusttype'] = trust_type_string(attrs['ipanttrusttype'][0])

        return truncated

class trust_show(LDAPRetrieve):
    __doc__ = _('Display information about a trust.')
    has_output_params = LDAPRetrieve.has_output_params + trust_output_params

    def execute(self, *keys, **options):
        error = None
        result = None
        for trust_type in trust.trust_types:
            options['trust_show_type'] = trust_type
            try:
                result = super(trust_show, self).execute(*keys, **options)
            except errors.NotFound, e:
                result = None
                error = e
            if result:
                 result['result']['trusttype'] = [trust_type_string(result['result']['ipanttrusttype'][0])]
                 result['result']['trustdirection'] = [trust_direction_string(result['result']['ipanttrustdirection'][0])]
                 break
        if error or not result:
            self.obj.handle_not_found(*keys)

        return result

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        if 'trust_show_type' in options:
            return make_trust_dn(self.env, options['trust_show_type'], dn)
        return dn

api.register(trust)
api.register(trust_add)
api.register(trust_mod)
api.register(trust_del)
api.register(trust_find)
api.register(trust_show)
