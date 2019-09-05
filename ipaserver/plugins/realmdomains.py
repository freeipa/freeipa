# Authors:
#   Ana Krivokapic <akrivoka@redhat.com>
#
# Copyright (C) 2013  Red Hat
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

import six

from ipalib import api, errors, messages
from ipalib import Str, Flag
from ipalib import _
from ipalib.plugable import Registry
from .baseldap import LDAPObject, LDAPUpdate, LDAPRetrieve
from ipalib.util import has_soa_or_ns_record, validate_domain_name
from ipalib.util import detect_dns_zone_realm_type
from ipapython.dn import DN

if six.PY3:
    unicode = str

__doc__ = _("""
Realm domains

Manage the list of domains associated with IPA realm.

EXAMPLES:

 Display the current list of realm domains:
   ipa realmdomains-show

 Replace the list of realm domains:
   ipa realmdomains-mod --domain=example.com
   ipa realmdomains-mod --domain={example1.com,example2.com,example3.com}

 Add a domain to the list of realm domains:
   ipa realmdomains-mod --add-domain=newdomain.com

 Delete a domain from the list of realm domains:
   ipa realmdomains-mod --del-domain=olddomain.com
""")

register = Registry()

def _domain_name_normalizer(d):
    return d.lower().rstrip('.')

def _domain_name_validator(ugettext, value):
    try:
        validate_domain_name(value, allow_slash=False, check_sld=True)
    except ValueError as e:
        return unicode(e)
    return None


@register()
class realmdomains(LDAPObject):
    """
    List of domains associated with IPA realm.
    """
    container_dn = api.env.container_realm_domains
    permission_filter_objectclasses = ['domainrelatedobject']
    object_name = _('Realm domains')
    search_attributes = ['associateddomain']
    default_attributes = ['associateddomain']
    managed_permissions = {
        'System: Read Realm Domains': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass', 'cn', 'associateddomain',
            },
        },
        'System: Modify Realm Domains': {
            'ipapermbindruletype': 'permission',
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'associatedDomain',
            },
            'default_privileges': {'DNS Administrators'},
        },
    }

    label = _('Realm Domains')
    label_singular = _('Realm Domains')

    takes_params = (
        Str('associateddomain+',
            _domain_name_validator,
            normalizer=_domain_name_normalizer,
            cli_name='domain',
            label=_('Domain'),
        ),
        Str('add_domain?',
            _domain_name_validator,
            normalizer=_domain_name_normalizer,
            cli_name='add_domain',
            label=_('Add domain'),
        ),
        Str('del_domain?',
            _domain_name_validator,
            normalizer=_domain_name_normalizer,
            cli_name='del_domain',
            label=_('Delete domain'),
        ),
    )



@register()
class realmdomains_mod(LDAPUpdate):
    __doc__ = _('Modify realm domains.')

    takes_options = LDAPUpdate.takes_options + (
        Flag('force',
            label=_('Force'),
            doc=_('Force adding domain even if not in DNS'),
        ),
    )

    def validate_domains(self, domains, force):
        """
        Validates the list of domains as candidates for additions to the
        realmdomains list.

        Requirements:
        - Each domain has SOA or NS record
        - Each domain belongs to the current realm
        """

        # Unless forced, check that each domain has SOA or NS records
        if not force:
            invalid_domains = [
                d for d in domains
                if not has_soa_or_ns_record(d)
            ]

            if invalid_domains:
                raise errors.ValidationError(
                    name='domain',
                    error= _(
                        "DNS zone for each realmdomain must contain "
                        "SOA or NS records. No records found for: %s"
                    ) % ','.join(invalid_domains)
                )

        # Check realm alliegence for each domain
        domains_with_realm = [
            (domain, detect_dns_zone_realm_type(self.api, domain))
            for domain in domains
        ]

        foreign_domains = [
            domain for domain, realm in domains_with_realm
            if realm == 'foreign'
        ]

        unknown_domains = [
            domain for domain, realm in domains_with_realm
            if realm == 'unknown'
        ]

        # If there are any foreing realm domains, bail out
        if foreign_domains:
            raise errors.ValidationError(
                name='domain',
                error=_(
                    'The following domains do not belong '
                    'to this realm: %(domains)s'
                ) % dict(domains=','.join(foreign_domains))
            )

        # If there are any unknown domains, error out,
        # asking for _kerberos TXT records

        # Note: This can be forced, since realmdomains-mod
        #       is called from dnszone-add where we know that
        #       the domain being added belongs to our realm
        if not force and unknown_domains:
            raise errors.ValidationError(
                name='domain',
                error=_(
                    'The realm of the following domains could '
                    'not be detected: %(domains)s. If these are '
                    'domains that belong to the this realm, please '
                    'create a _kerberos TXT record containing "%(realm)s" '
                    'in each of them.'
                ) % dict(domains=','.join(unknown_domains),
                         realm=self.api.env.realm)
            )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        associateddomain = entry_attrs.get('associateddomain')
        add_domain = entry_attrs.get('add_domain')
        del_domain = entry_attrs.get('del_domain')
        force = options.get('force')

        current_domain = self.api.env.domain

        # User specified the list of domains explicitly
        if associateddomain:
            if add_domain or del_domain:
                raise errors.MutuallyExclusiveError(
                    reason=_(
                        "The --domain option cannot be used together "
                        "with --add-domain or --del-domain. Use --domain "
                        "to specify the whole realm domain list explicitly, "
                        "to add/remove individual domains, use "
                        "--add-domain/del-domain.")
                )

            # Make sure our domain is included in the list
            if current_domain not in associateddomain:
                raise errors.ValidationError(
                    name='realmdomain list',
                    error=_("IPA server domain cannot be omitted")
                )

            # Validate that each domain satisfies the requirements
            # for realmdomain
            self.validate_domains(domains=associateddomain, force=force)

            return dn

        # If --add-domain or --del-domain options were provided, read
        # the curent list from LDAP, modify it, and write the changes back
        domains = ldap.get_entry(dn)['associateddomain']

        if add_domain:
            self.validate_domains(domains=[add_domain], force=force)
            del entry_attrs['add_domain']
            domains.append(add_domain)

        if del_domain:
            if del_domain == current_domain:
                raise errors.ValidationError(
                    name='del_domain',
                    error=_("IPA server domain cannot be deleted")
                )
            del entry_attrs['del_domain']

            try:
                domains.remove(del_domain)
            except ValueError:
                raise errors.AttrValueNotFound(
                    attr='associateddomain',
                    value=del_domain
                )

        entry_attrs['associateddomain'] = domains
        return dn

    def execute(self, *keys, **options):
        dn = self.obj.get_dn(*keys, **options)
        ldap = self.obj.backend

        domains_old = set(ldap.get_entry(dn)['associateddomain'])
        result = super(realmdomains_mod, self).execute(*keys, **options)
        domains_new = set(ldap.get_entry(dn)['associateddomain'])

        domains_added = domains_new - domains_old
        domains_deleted = domains_old - domains_new

        # Add a _kerberos TXT record for zones that correspond with
        # domains which were added
        for domain in domains_added:

            # Skip our own domain
            if domain == api.env.domain:
                continue

            try:
                self.api.Command['dnsrecord_add'](
                    unicode(domain),
                    u'_kerberos',
                    txtrecord=api.env.realm
                )
            except (errors.EmptyModlist, errors.NotFound,
                    errors.ValidationError) as error:

                # If creation of the _kerberos TXT record failed, prompt
                # for manual intervention
                messages.add_message(
                    options['version'],
                    result,
                    messages.KerberosTXTRecordCreationFailure(
                        domain=domain,
                        error=unicode(error),
                        realm=self.api.env.realm
                    )
                )

        # Delete _kerberos TXT record from zones that correspond with
        # domains which were deleted
        for domain in domains_deleted:

            # Skip our own domain
            if domain == api.env.domain:
                continue

            try:
                self.api.Command['dnsrecord_del'](
                    unicode(domain),
                    u'_kerberos',
                    txtrecord=api.env.realm
                )
            except (errors.AttrValueNotFound, errors.NotFound,
                    errors.ValidationError) as error:
                # If deletion of the _kerberos TXT record failed, prompt
                # for manual intervention
                messages.add_message(
                    options['version'],
                    result,
                    messages.KerberosTXTRecordDeletionFailure(
                        domain=domain, error=unicode(error)
                    )
                )

        return result



@register()
class realmdomains_show(LDAPRetrieve):
    __doc__ = _('Display the list of realm domains.')
