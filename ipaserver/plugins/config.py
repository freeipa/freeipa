# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008  Red Hat
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

from ipalib import api
from ipalib import Bool, Int, Str, IA5Str, StrEnum, DNParam
from ipalib import errors
from ipalib.constants import MAXHOSTNAMELEN
from ipalib.plugable import Registry
from ipalib.util import validate_domain_name
from .baseldap import (
    LDAPObject,
    LDAPUpdate,
    LDAPRetrieve)
from .selinuxusermap import validate_selinuxuser
from ipalib import _
from ipapython.dn import DN

# 389-ds attributes that should be skipped in attribute checks
OPERATIONAL_ATTRIBUTES = ('nsaccountlock', 'member', 'memberof',
    'memberindirect', 'memberofindirect',)

DOMAIN_RESOLUTION_ORDER_SEPARATOR = u':'

__doc__ = _("""
Server configuration

Manage the default values that IPA uses and some of its tuning parameters.

NOTES:

The password notification value (--pwdexpnotify) is stored here so it will
be replicated. It is not currently used to notify users in advance of an
expiring password.

Some attributes are read-only, provided only for information purposes. These
include:

Certificate Subject base: the configured certificate subject base,
  e.g. O=EXAMPLE.COM.  This is configurable only at install time.
Password plug-in features: currently defines additional hashes that the
  password will generate (there may be other conditions).

When setting the order list for mapping SELinux users you may need to
quote the value so it isn't interpreted by the shell.

The maximum length of a hostname in Linux is controlled by
MAXHOSTNAMELEN in the kernel and defaults to 64. Some other operating
systems, Solaris for example, allows hostnames up to 255 characters.
This option will allow flexibility in length but by default limiting
to the Linux maximum length.

EXAMPLES:

 Show basic server configuration:
   ipa config-show

 Show all configuration options:
   ipa config-show --all

 Change maximum username length to 99 characters:
   ipa config-mod --maxusername=99

 Change maximum host name length to 255 characters:
   ipa config-mod --maxhostname=255

 Increase default time and size limits for maximum IPA server search:
   ipa config-mod --searchtimelimit=10 --searchrecordslimit=2000

 Set default user e-mail domain:
   ipa config-mod --emaildomain=example.com

 Enable migration mode to make "ipa migrate-ds" command operational:
   ipa config-mod --enable-migration=TRUE

 Define SELinux user map order:
   ipa config-mod --ipaselinuxusermaporder='guest_u:s0$xguest_u:s0$user_u:s0-s0:c0.c1023$staff_u:s0-s0:c0.c1023$unconfined_u:s0-s0:c0.c1023'
""")

register = Registry()


def validate_search_records_limit(ugettext, value):
    """Check if value is greater than a realistic minimum.

    Values 0 and -1 are valid, as they represent unlimited.
    """
    if value in {-1, 0}:
        return None
    if value < 10:
        return _('must be at least 10')
    return None

@register()
class config(LDAPObject):
    """
    IPA configuration object
    """
    object_name = _('configuration options')
    default_attributes = [
        'ipamaxusernamelength', 'ipahomesrootdir', 'ipadefaultloginshell',
        'ipadefaultprimarygroup', 'ipadefaultemaildomain', 'ipasearchtimelimit',
        'ipasearchrecordslimit', 'ipausersearchfields', 'ipagroupsearchfields',
        'ipamigrationenabled', 'ipacertificatesubjectbase',
        'ipapwdexpadvnotify', 'ipaselinuxusermaporder',
        'ipaselinuxusermapdefault', 'ipaconfigstring', 'ipakrbauthzdata',
        'ipauserauthtype', 'ipadomainresolutionorder', 'ipamaxhostnamelength',
    ]
    container_dn = DN(('cn', 'ipaconfig'), ('cn', 'etc'))
    permission_filter_objectclasses = ['ipaguiconfig']
    managed_permissions = {
        'System: Read Global Configuration': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'objectclass',
                'ipacertificatesubjectbase', 'ipaconfigstring',
                'ipadefaultemaildomain', 'ipadefaultloginshell',
                'ipadefaultprimarygroup', 'ipadomainresolutionorder',
                'ipagroupobjectclasses',
                'ipagroupsearchfields', 'ipahomesrootdir',
                'ipakrbauthzdata', 'ipamaxusernamelength',
                'ipamigrationenabled', 'ipapwdexpadvnotify',
                'ipaselinuxusermapdefault', 'ipaselinuxusermaporder',
                'ipasearchrecordslimit', 'ipasearchtimelimit',
                'ipauserauthtype', 'ipauserobjectclasses',
                'ipausersearchfields', 'ipacustomfields',
                'ipamaxhostnamelength',
            },
        },
    }

    label = _('Configuration')
    label_singular = _('Configuration')

    takes_params = (
        Int('ipamaxusernamelength',
            cli_name='maxusername',
            label=_('Maximum username length'),
            minvalue=1,
            maxvalue=255,
        ),
        Int('ipamaxhostnamelength',
            cli_name='maxhostname',
            label=_('Maximum hostname length'),
            minvalue=MAXHOSTNAMELEN,
            maxvalue=255,),
        IA5Str('ipahomesrootdir',
            cli_name='homedirectory',
            label=_('Home directory base'),
            doc=_('Default location of home directories'),
        ),
        Str('ipadefaultloginshell',
            cli_name='defaultshell',
            label=_('Default shell'),
            doc=_('Default shell for new users'),
        ),
        Str('ipadefaultprimarygroup',
            cli_name='defaultgroup',
            label=_('Default users group'),
            doc=_('Default group for new users'),
        ),
        Str('ipadefaultemaildomain?',
            cli_name='emaildomain',
            label=_('Default e-mail domain'),
            doc=_('Default e-mail domain'),
        ),
        Int('ipasearchtimelimit',
            cli_name='searchtimelimit',
            label=_('Search time limit'),
            doc=_('Maximum amount of time (seconds) for a search (-1 or 0 is unlimited)'),
            minvalue=-1,
        ),
        Int('ipasearchrecordslimit',
            validate_search_records_limit,
            cli_name='searchrecordslimit',
            label=_('Search size limit'),
            doc=_('Maximum number of records to search (-1 or 0 is unlimited)'),
        ),
        IA5Str('ipausersearchfields',
            cli_name='usersearch',
            label=_('User search fields'),
            doc=_('A comma-separated list of fields to search in when searching for users'),
        ),
        IA5Str('ipagroupsearchfields',
            cli_name='groupsearch',
            label=_('Group search fields'),
            doc=_('A comma-separated list of fields to search in when searching for groups'),
        ),
        Bool('ipamigrationenabled',
            cli_name='enable_migration',
            label=_('Enable migration mode'),
            doc=_('Enable migration mode'),
        ),
        DNParam('ipacertificatesubjectbase',
            cli_name='subject',
            label=_('Certificate Subject base'),
            doc=_('Base for certificate subjects (OU=Test,O=Example)'),
            flags=['no_update'],
        ),
        Str('ipagroupobjectclasses+',
            cli_name='groupobjectclasses',
            label=_('Default group objectclasses'),
            doc=_('Default group objectclasses (comma-separated list)'),
        ),
        Str('ipauserobjectclasses+',
            cli_name='userobjectclasses',
            label=_('Default user objectclasses'),
            doc=_('Default user objectclasses (comma-separated list)'),
        ),
        Int('ipapwdexpadvnotify',
            cli_name='pwdexpnotify',
            label=_('Password Expiration Notification (days)'),
            doc=_('Number of days\'s notice of impending password expiration'),
            minvalue=0,
        ),
        StrEnum('ipaconfigstring*',
            cli_name='ipaconfigstring',
            label=_('Password plugin features'),
            doc=_('Extra hashes to generate in password plug-in'),
            values=(u'AllowNThash',
                    u'KDC:Disable Last Success', u'KDC:Disable Lockout',
                    u'KDC:Disable Default Preauth for SPNs'),
        ),
        Str('ipaselinuxusermaporder',
            label=_('SELinux user map order'),
            doc=_('Order in increasing priority of SELinux users, delimited by $'),
        ),
        Str('ipaselinuxusermapdefault?',
            label=_('Default SELinux user'),
            doc=_('Default SELinux user when no match is found in SELinux map rule'),
        ),
        StrEnum('ipakrbauthzdata*',
            cli_name='pac_type',
            label=_('Default PAC types'),
            doc=_('Default types of PAC supported for services'),
            values=(u'MS-PAC', u'PAD', u'nfs:NONE'),
        ),
        StrEnum(
            'ipauserauthtype*',
            cli_name='user_auth_type',
            label=_('Default user authentication types'),
            doc=_('Default types of supported user authentication'),
            values=(u'password', u'radius', u'otp',
                    u'pkinit', u'hardened', u'disabled'),
        ),
        Str(
            'ipa_master_server*',
            label=_('IPA masters'),
            doc=_('List of all IPA masters'),
            flags={'virtual_attribute', 'no_create', 'no_update'}
        ),
        Str(
            'ipa_master_hidden_server*',
            label=_('Hidden IPA masters'),
            doc=_('List of all hidden IPA masters'),
            flags={'virtual_attribute', 'no_create', 'no_update'}
        ),
        Str(
            'pkinit_server_server*',
            label=_('IPA master capable of PKINIT'),
            doc=_('IPA master which can process PKINIT requests'),
            flags={'virtual_attribute', 'no_create', 'no_update'}
        ),
        Str(
            'ca_server_server*',
            label=_('IPA CA servers'),
            doc=_('IPA servers configured as certificate authority'),
            flags={'virtual_attribute', 'no_create', 'no_update'}
        ),
        Str(
            'ca_server_hidden_server*',
            label=_('Hidden IPA CA servers'),
            doc=_('Hidden IPA servers configured as certificate authority'),
            flags={'virtual_attribute', 'no_create', 'no_update'}
        ),
        Str(
            'ca_renewal_master_server?',
            label=_('IPA CA renewal master'),
            doc=_('Renewal master for IPA certificate authority'),
            flags={'virtual_attribute', 'no_create'}
        ),
        Str(
            'kra_server_server*',
            label=_('IPA KRA servers'),
            doc=_('IPA servers configured as key recovery agent'),
            flags={'virtual_attribute', 'no_create', 'no_update'}
        ),
        Str(
            'kra_server_hidden_server*',
            label=_('Hidden IPA KRA servers'),
            doc=_('Hidden IPA servers configured as key recovery agent'),
            flags={'virtual_attribute', 'no_create', 'no_update'}
        ),
        Str(
            'ipadomainresolutionorder?',
            cli_name='domain_resolution_order',
            label=_('Domain resolution order'),
            doc=_('colon-separated list of domains used for short name'
                  ' qualification')
        ),
        Str(
            'dns_server_server*',
            label=_('IPA DNS servers'),
            doc=_('IPA servers configured as domain name server'),
            flags={'virtual_attribute', 'no_create', 'no_update'}
        ),
        Str(
            'dns_server_hidden_server*',
            label=_('Hidden IPA DNS servers'),
            doc=_('Hidden IPA servers configured as domain name server'),
            flags={'virtual_attribute', 'no_create', 'no_update'}
        ),
        Str(
            'dnssec_key_master_server?',
            label=_('IPA DNSSec key master'),
            doc=_('DNSec key master'),
            flags={'virtual_attribute', 'no_create', 'no_update'}
        ),
    )

    def get_dn(self, *keys, **kwargs):
        return DN(('cn', 'ipaconfig'), ('cn', 'etc'), api.env.basedn)

    def update_entry_with_role_config(self, role_name, entry_attrs):
        backend = self.api.Backend.serverroles

        try:
            role_config = backend.config_retrieve(role_name)
        except errors.EmptyResult:
            # No role config means current user identity
            # has no rights to see it, return with no action
            return

        for key, value in role_config.items():
            try:
                entry_attrs.update({key: value})
            except errors.EmptyResult:
                # An update that doesn't change an entry is fine here
                # Just ignore and move to the next key pair
                pass


    def show_servroles_attributes(self, entry_attrs, *roles, **options):
        if options.get('raw', False):
            return

        for role in roles:
            self.update_entry_with_role_config(role, entry_attrs)

    def gather_trusted_domains(self):
        """
        Aggregate all trusted domains into a dict keyed by domain names with
        values corresponding to domain status (enabled/disabled)
        """
        command = self.api.Command
        try:
            ad_forests = command.trust_find(sizelimit=0)['result']
        except errors.NotFound:
            return {}

        trusted_domains = {}
        for forest_name in [a['cn'][0] for a in ad_forests]:
            forest_domains = command.trustdomain_find(
                forest_name, sizelimit=0)['result']

            trusted_domains.update(
                {
                    dom['cn'][0]: dom['domain_enabled'][0]
                    for dom in forest_domains if 'domain_enabled' in dom
                }
            )

        return trusted_domains

    def _validate_single_domain(self, attr_name, domain, known_domains):
        """
        Validate a single domain from domain resolution order

        :param attr_name: name of attribute that holds domain resolution order
        :param domain: domain name
        :param known_domains: dict of domains known to IPA keyed by domain name
            and valued by boolean value corresponding to domain status
            (enabled/disabled)

        :raises: ValidationError if the domain name is empty, syntactically
            invalid or corresponds to a disable domain
                 NotFound if a syntactically correct domain name unknown to IPA
                 is supplied (not IPA domain and not any of trusted domains)
        """
        if not domain:
            raise errors.ValidationError(
                name=attr_name,
                error=_("Empty domain is not allowed")
            )

        try:
            validate_domain_name(domain)
        except ValueError as e:
            raise errors.ValidationError(
                name=attr_name,
                error=_("Invalid domain name '%(domain)s': %(e)s")
                % dict(domain=domain, e=e))

        if domain not in known_domains:
            raise errors.NotFound(
                reason=_("Server has no information about domain '%(domain)s'")
                % dict(domain=domain)
            )

        if not known_domains[domain]:
            raise errors.ValidationError(
                name=attr_name,
                error=_("Disabled domain '%(domain)s' is not allowed")
                % dict(domain=domain)
            )

    def validate_domain_resolution_order(self, entry_attrs):
        """
        Validate domain resolution order, e.g. split by the delimiter (colon)
        and check each domain name for non-emptiness, syntactic correctness,
        and status (enabled/disabled).

        supplying empty order (':') bypasses validations and allows to specify
        empty attribute value.
        """
        attr_name = 'ipadomainresolutionorder'
        if attr_name not in entry_attrs:
            return

        domain_resolution_order = entry_attrs[attr_name]

        # setting up an empty string means that the previous configuration has
        # to be cleaned up/removed. So, do nothing and let it pass
        if not domain_resolution_order:
            return

        # empty resolution order is signalized by single separator, do nothing
        # and let it pass
        if domain_resolution_order == DOMAIN_RESOLUTION_ORDER_SEPARATOR:
            return

        submitted_domains = domain_resolution_order.split(
                DOMAIN_RESOLUTION_ORDER_SEPARATOR)

        known_domains = self.gather_trusted_domains()

        # add FreeIPA domain to the list of domains. This one is always enabled
        known_domains.update({self.api.env.domain: True})

        for domain in submitted_domains:
            self._validate_single_domain(attr_name, domain, known_domains)


@register()
class config_mod(LDAPUpdate):
    __doc__ = _('Modify configuration options.')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        if 'ipadefaultprimarygroup' in entry_attrs:
            group=entry_attrs['ipadefaultprimarygroup']
            try:
                api.Object['group'].get_dn_if_exists(group)
            except errors.NotFound:
                raise errors.NotFound(message=_("The group doesn't exist"))
        kw = {}
        if 'ipausersearchfields' in entry_attrs:
            kw['ipausersearchfields'] = 'ipauserobjectclasses'
        if 'ipagroupsearchfields' in entry_attrs:
            kw['ipagroupsearchfields']  = 'ipagroupobjectclasses'
        if kw:
            config = ldap.get_ipa_config(list(kw.values()))
            for (k, v) in kw.items():
                allowed_attrs = ldap.get_allowed_attributes(config[v])
                # normalize attribute names
                attributes = [field.strip().lower()
                              for field in entry_attrs[k].split(',')]
                # test if all base types (without sub-types) are allowed
                for a in attributes:
                    a, _unused1, _unused2 = a.partition(';')
                    if a not in allowed_attrs:
                        raise errors.ValidationError(
                            name=k, error=_('attribute "%s" not allowed') % a
                        )
            # write normalized form to LDAP
            entry_attrs[k] = ','.join(attributes)

        # Set ipasearchrecordslimit to -1 if 0 is used
        if 'ipasearchrecordslimit' in entry_attrs:
            if entry_attrs['ipasearchrecordslimit'] == 0:
                 entry_attrs['ipasearchrecordslimit'] = -1

        # Set ipasearchtimelimit to -1 if 0 is used
        if 'ipasearchtimelimit' in entry_attrs:
            if entry_attrs['ipasearchtimelimit'] == 0:
                 entry_attrs['ipasearchtimelimit'] = -1

        for (attr, obj) in (('ipauserobjectclasses', 'user'),
                            ('ipagroupobjectclasses', 'group')):
            if attr in entry_attrs:
                if not entry_attrs[attr]:
                    raise errors.ValidationError(name=attr,
                        error=_('May not be empty'))
                objectclasses = list(set(entry_attrs[attr]).union(
                        self.api.Object[obj].possible_objectclasses))
                new_allowed_attrs = ldap.get_allowed_attributes(objectclasses,
                                        raise_on_unknown=True)
                checked_attrs = self.api.Object[obj].default_attributes
                if self.api.Object[obj].uuid_attribute:
                    checked_attrs = checked_attrs + [self.api.Object[obj].uuid_attribute]
                for obj_attr in checked_attrs:
                    obj_attr, _unused1, _unused2 = obj_attr.partition(';')
                    if obj_attr in OPERATIONAL_ATTRIBUTES:
                        continue
                    if obj_attr in self.api.Object[obj].params and \
                      'virtual_attribute' in \
                      self.api.Object[obj].params[obj_attr].flags:
                        # skip virtual attributes
                        continue
                    if obj_attr not in new_allowed_attrs:
                        raise errors.ValidationError(name=attr,
                                error=_('%(obj)s default attribute %(attr)s would not be allowed!') \
                                % dict(obj=obj, attr=obj_attr))

        if ('ipaselinuxusermapdefault' in entry_attrs or
          'ipaselinuxusermaporder' in entry_attrs):
            config = None
            failedattr = 'ipaselinuxusermaporder'

            if 'ipaselinuxusermapdefault' in entry_attrs:
                defaultuser = entry_attrs['ipaselinuxusermapdefault']
                failedattr = 'ipaselinuxusermapdefault'

                # validate the new default user first
                if defaultuser is not None:
                    error_message = validate_selinuxuser(_, defaultuser)

                    if error_message:
                        raise errors.ValidationError(name='ipaselinuxusermapdefault',
                                error=error_message)

            else:
                config = ldap.get_ipa_config()
                defaultuser = config.get('ipaselinuxusermapdefault', [None])[0]

            if 'ipaselinuxusermaporder' in entry_attrs:
                order = entry_attrs['ipaselinuxusermaporder']
                userlist = order.split('$')

                # validate the new user order first
                for user in userlist:
                    if not user:
                        raise errors.ValidationError(name='ipaselinuxusermaporder',
                                error=_('A list of SELinux users delimited by $ expected'))

                    error_message = validate_selinuxuser(_, user)
                    if error_message:
                        error_message = _("SELinux user '%(user)s' is not "
                                "valid: %(error)s") % dict(user=user,
                                                          error=error_message)
                        raise errors.ValidationError(name='ipaselinuxusermaporder',
                                error=error_message)
            else:
                if not config:
                    config = ldap.get_ipa_config()
                order = config['ipaselinuxusermaporder']
                userlist = order[0].split('$')
            if defaultuser and defaultuser not in userlist:
                raise errors.ValidationError(name=failedattr,
                    error=_('SELinux user map default user not in order list'))

        if 'ca_renewal_master_server' in options:
            new_master = options['ca_renewal_master_server']

            try:
                self.api.Object.server.get_dn_if_exists(new_master)
            except errors.NotFound:
                raise self.api.Object.server.handle_not_found(new_master)

            backend = self.api.Backend.serverroles
            backend.config_update(ca_renewal_master_server=new_master)

        self.obj.validate_domain_resolution_order(entry_attrs)

        return dn

    def exc_callback(self, keys, options, exc, call_func,
                     *call_args, **call_kwargs):
        if (isinstance(exc, errors.EmptyModlist) and
                call_func.__name__ == 'update_entry' and
                'ca_renewal_master_server' in options):
            return

        super(config_mod, self).exc_callback(
            keys, options, exc, call_func, *call_args, **call_kwargs)

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.show_servroles_attributes(
            entry_attrs, "CA server", "KRA server", "IPA master",
            "DNS server", **options)
        return dn


@register()
class config_show(LDAPRetrieve):
    __doc__ = _('Show the current configuration.')

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.show_servroles_attributes(
            entry_attrs, "CA server", "KRA server", "IPA master",
            "DNS server", **options)
        return dn
