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

from ipalib import api, errors
from ipalib import Str, Flag
from ipalib import _
from ipalib.plugable import Registry
from ipalib.plugins.baseldap import LDAPObject, LDAPUpdate, LDAPRetrieve
from ipalib.util import has_soa_or_ns_record, validate_domain_name
from ipapython.dn import DN
from ipapython.ipautil import get_domain_name


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
        validate_domain_name(value, allow_slash=False)
    except ValueError, e:
        return unicode(e)


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

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        associateddomain = entry_attrs.get('associateddomain')
        add_domain = entry_attrs.get('add_domain')
        del_domain = entry_attrs.get('del_domain')
        force = options.get('force')

        if associateddomain:
            if add_domain or del_domain:
                raise errors.MutuallyExclusiveError(reason=_("you cannot specify the --domain option together with --add-domain or --del-domain"))
            if get_domain_name() not in associateddomain:
                raise errors.ValidationError(name='domain', error=_("cannot delete domain of IPA server"))
            if not force:
                bad_domains = [d for d in associateddomain if not has_soa_or_ns_record(d)]
                if bad_domains:
                    bad_domains = ', '.join(bad_domains)
                    raise errors.ValidationError(name='domain', error=_("no SOA or NS records found for domains: %s" % bad_domains))
            return dn

        # If --add-domain or --del-domain options were provided, read
        # the curent list from LDAP, modify it, and write the changes back
        domains = ldap.get_entry(dn)['associateddomain']

        if add_domain:
            if not force and not has_soa_or_ns_record(add_domain):
                raise errors.ValidationError(name='add_domain', error=_("no SOA or NS records found for domain %s" % add_domain))
            del entry_attrs['add_domain']
            domains.append(add_domain)

        if del_domain:
            if del_domain == get_domain_name():
                raise errors.ValidationError(name='del_domain', error=_("cannot delete domain of IPA server"))
            del entry_attrs['del_domain']
            try:
                domains.remove(del_domain)
            except ValueError:
                raise errors.AttrValueNotFound(attr='associateddomain', value=del_domain)

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
        for d in domains_added:
            # Skip our own domain
            if d == api.env.domain:
                continue
            try:
                api.Command['dnsrecord_add'](
                    unicode(d),
                    u'_kerberos',
                    txtrecord=api.env.realm
                )
            except (errors.EmptyModlist, errors.NotFound):
                pass

        # Delete _kerberos TXT record from zones that correspond with
        # domains which were deleted
        for d in domains_deleted:
            # Skip our own domain
            if d == api.env.domain:
                continue
            try:
                api.Command['dnsrecord_del'](
                    unicode(d),
                    u'_kerberos',
                    txtrecord=api.env.realm
                )
            except (errors.AttrValueNotFound, errors.NotFound):
                pass

        return result



@register()
class realmdomains_show(LDAPRetrieve):
    __doc__ = _('Display the list of realm domains.')

