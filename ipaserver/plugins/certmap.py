# Authors:
#   Florence Blanc-Renaud <flo@redhat.com>
#
# Copyright (C) 2017  Red Hat
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

from ipalib import api, errors
from ipalib.parameters import Bool, DNSNameParam, Flag, Int, Str
from ipalib.plugable import Registry
from .baseldap import (
    LDAPCreate,
    LDAPDelete,
    LDAPObject,
    LDAPQuery,
    LDAPRetrieve,
    LDAPSearch,
    LDAPUpdate,
    pkey_to_value)
from ipalib import _, ngettext
from ipalib import output


if six.PY3:
    unicode = str

__doc__ = _("""
Certificate Identity Mapping
""") + _("""
Manage Certificate Identity Mapping configuration and rules.
""") + _("""
IPA supports the use of certificates for authentication. Certificates can
either be stored in the user entry (full certificate in the usercertificate
attribute), or simply linked to the user entry through a mapping.
This code enables the management of the rules allowing to link a
certificate to a user entry.
""") + _("""
EXAMPLES:
""") + _("""
 Display the Certificate Identity Mapping global configuration:
   ipa certmapconfig-show
""") + _("""
 Modify Certificate Identity Mapping global configuration:
   ipa certmapconfig-mod --promptusername=TRUE
""") + _("""
 Create a new Certificate Identity Mapping Rule:
   ipa certmaprule-add rule1 --desc="Link certificate with subject and issuer"
""") + _("""
 Modify a Certificate Identity Mapping Rule:
   ipa certmaprule-mod rule1 --maprule="<ALT-SEC-ID-I-S:altSecurityIdentities>"
""") + _("""
 Disable a Certificate Identity Mapping Rule:
   ipa certmaprule-disable rule1
""") + _("""
 Enable a Certificate Identity Mapping Rule:
   ipa certmaprule-enable rule1
""") + _("""
 Display information about a Certificate Identity Mapping Rule:
   ipa certmaprule-show rule1
""") + _("""
 Find all Certificate Identity Mapping Rules with the specified domain:
   ipa certmaprule-find --domain example.com
""") + _("""
 Delete a Certificate Identity Mapping Rule:
   ipa certmaprule-del rule1
""")

register = Registry()


def check_associateddomain_is_trusted(api_inst, options):
    """
    Check that the associateddomain in options are either IPA domain or
    a trusted domain.

    :param api_inst: API instance
    :param associateddomain: domains to be checked

    :raises: ValidationError if the domain is neither IPA domain nor trusted
    """
    domains = options.get('associateddomain')
    if domains:
        trust_suffix_namespace = set()
        trust_suffix_namespace.add(api_inst.env.domain.lower())

        trust_objects = api_inst.Command.trust_find(sizelimit=0)['result']
        for obj in trust_objects:
            trustdomains = api_inst.Command.trustdomain_find(
                obj['cn'][0], sizelimit=0)['result']
            for domain in trustdomains:
                trust_suffix_namespace.add(domain['cn'][0].lower())

        for dom in domains:
            if not str(dom).lower() in trust_suffix_namespace:
                raise errors.ValidationError(
                    name=_('domain'),
                    error=_('The domain %s is neither IPA domain nor a trusted'
                            'domain.') % dom
                    )


@register()
class certmapconfig(LDAPObject):
    """
    Certificate Identity Mapping configuration object
    """
    object_name = _('Certificate Identity Mapping configuration options')
    default_attributes = ['ipacertmappromptusername']

    container_dn = api.env.container_certmap

    label = _('Certificate Identity Mapping Global Configuration')
    label_singular = _('Certificate Identity Mapping Global Configuration')

    takes_params = (
        Bool(
            'ipacertmappromptusername',
            cli_name='promptusername',
            label=_('Prompt for the username'),
            doc=_('Prompt for the username when multiple identities'
                  ' are mapped to a certificate'),
        ),
    )

    permission_filter_objectclasses = ['ipacertmapconfigobject']
    managed_permissions = {
        'System: Read Certmap Configuration': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'ipacertmappromptusername',
                'cn',
            },
        },
        'System: Modify Certmap Configuration': {
            'replaces_global_anonymous_aci': True,
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'ipacertmappromptusername',
            },
            'default_privileges': {
                'Certificate Identity Mapping Administrators'},
        },
    }


@register()
class certmapconfig_mod(LDAPUpdate):
    __doc__ = _('Modify Certificate Identity Mapping configuration.')


@register()
class certmapconfig_show(LDAPRetrieve):
    __doc__ = _('Show the current Certificate Identity Mapping configuration.')


@register()
class certmaprule(LDAPObject):
    """
    Certificate Identity Mapping Rules
    """

    label = _('Certificate Identity Mapping Rules')
    label_singular = _('Certificate Identity Mapping Rule')

    object_name = _('Certificate Identity Mapping Rule')
    object_name_plural = _('Certificate Identity Mapping Rules')
    object_class = ['ipacertmaprule']

    container_dn = api.env.container_certmaprules
    default_attributes = [
        'cn', 'description',
        'ipacertmapmaprule',
        'ipacertmapmatchrule',
        'associateddomain',
        'ipacertmappriority',
        'ipaenabledflag'
    ]
    search_attributes = [
        'cn', 'description',
        'ipacertmapmaprule',
        'ipacertmapmatchrule',
        'associateddomain',
        'ipacertmappriority',
        'ipaenabledflag'
    ]

    takes_params = (
        Str(
            'cn',
            cli_name='rulename',
            primary_key=True,
            label=_('Rule name'),
            doc=_('Certificate Identity Mapping Rule name'),
        ),
        Str(
            'description?',
            cli_name='desc',
            label=_('Description'),
            doc=_('Certificate Identity Mapping Rule description'),
        ),
        Str(
            'ipacertmapmaprule?',
            cli_name='maprule',
            label=_('Mapping rule'),
            doc=_('Rule used to map the certificate with a user entry'),
        ),
        Str(
            'ipacertmapmatchrule?',
            cli_name='matchrule',
            label=_('Matching rule'),
            doc=_('Rule used to check if a certificate can be used for'
                  ' authentication'),
        ),
        DNSNameParam(
            'associateddomain*',
            cli_name='domain',
            label=_('Domain name'),
            doc=_('Domain where the user entry will be searched'),
        ),
        Int(
            'ipacertmappriority?',
            cli_name='priority',
            label=_('Priority'),
            doc=_('Priority of the rule (higher number means lower priority'),
            minvalue=0,
        ),
        Flag(
            'ipaenabledflag?',
            label=_('Enabled'),
            flags=['no_option'],
            default=True
        ),
    )

    permission_filter_objectclasses = ['ipacertmaprule']
    managed_permissions = {
        'System: Add Certmap Rules': {
            'replaces_global_anonymous_aci': True,
            'ipapermright': {'add'},
            'default_privileges': {
                'Certificate Identity Mapping Administrators'},
        },
        'System: Read Certmap Rules': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass', 'cn', 'description',
                'ipacertmapmaprule', 'ipacertmapmatchrule', 'associateddomain',
                'ipacertmappriority', 'ipaenabledflag',
            },
        },
        'System: Delete Certmap Rules': {
            'replaces_global_anonymous_aci': True,
            'ipapermright': {'delete'},
            'default_privileges': {
                'Certificate Identity Mapping Administrators'},
        },
        'System: Modify Certmap Rules': {
            'replaces_global_anonymous_aci': True,
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'objectclass', 'cn', 'description',
                'ipacertmapmaprule', 'ipacertmapmatchrule', 'associateddomain',
                'ipacertmappriority', 'ipaenabledflag',
            },
            'default_privileges': {
                'Certificate Identity Mapping Administrators'},
        },
    }


@register()
class certmaprule_add(LDAPCreate):
    __doc__ = _('Create a new Certificate Identity Mapping Rule.')

    msg_summary = _('Added Certificate Identity Mapping Rule "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys,
                     **options):
        check_associateddomain_is_trusted(self.api, options)
        return dn


@register()
class certmaprule_mod(LDAPUpdate):
    __doc__ = _('Modify a Certificate Identity Mapping Rule.')

    msg_summary = _('Modified Certificate Identity Mapping Rule "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys,
                     **options):
        check_associateddomain_is_trusted(self.api, options)
        return dn


@register()
class certmaprule_find(LDAPSearch):
    __doc__ = _('Search for Certificate Identity Mapping Rules.')

    msg_summary = ngettext(
        '%(count)d Certificate Identity Mapping Rule matched',
        '%(count)d Certificate Identity Mapping Rules matched', 0
    )


@register()
class certmaprule_show(LDAPRetrieve):
    __doc__ = _('Display information about a Certificate Identity Mapping'
                ' Rule.')


@register()
class certmaprule_del(LDAPDelete):
    __doc__ = _('Delete a Certificate Identity Mapping Rule.')

    msg_summary = _('Deleted Certificate Identity Mapping Rule "%(value)s"')


@register()
class certmaprule_enable(LDAPQuery):
    __doc__ = _('Enable a Certificate Identity Mapping Rule.')

    msg_summary = _('Enabled Certificate Identity Mapping Rule "%(value)s"')
    has_output = output.standard_value

    def execute(self, cn, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)
        try:
            entry_attrs = ldap.get_entry(dn, ['ipaenabledflag'])
        except errors.NotFound:
            self.obj.handle_not_found(cn)

        entry_attrs['ipaenabledflag'] = ['TRUE']

        try:
            ldap.update_entry(entry_attrs)
        except errors.EmptyModlist:
            pass

        return dict(
            result=True,
            value=pkey_to_value(cn, options),
        )


@register()
class certmaprule_disable(LDAPQuery):
    __doc__ = _('Disable a Certificate Identity Mapping Rule.')

    msg_summary = _('Disabled Certificate Identity Mapping Rule "%(value)s"')
    has_output = output.standard_value

    def execute(self, cn, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)
        try:
            entry_attrs = ldap.get_entry(dn, ['ipaenabledflag'])
        except errors.NotFound:
            self.obj.handle_not_found(cn)

        entry_attrs['ipaenabledflag'] = ['FALSE']

        try:
            ldap.update_entry(entry_attrs)
        except errors.EmptyModlist:
            pass

        return dict(
            result=True,
            value=pkey_to_value(cn, options),
        )
