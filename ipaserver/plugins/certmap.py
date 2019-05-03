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

import logging

import dbus
import six

from cryptography import x509 as crypto_x509

from ipalib import api, errors, x509
from ipalib.crud import Search
from ipalib.frontend import Object
from ipalib.parameters import Bool, DNSNameParam, Flag, Int, Str, Certificate
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

logger = logging.getLogger(__name__)

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


def check_maprule_is_for_trusted_domain(api_inst, options, entry_attrs):
    """
    Check that the certmap rule references altSecurityIdentities and
    associateddomain in options is a trusted domain.

    :param api_inst: API instance
    :param options: options passed to the command
                    at least ipacertmapmaprule and
                    associateddomain options are expected for the check

    :raises: ValidationError if altSecurityIdentities is present in the
             rule but no Active Directory trusted domain listed in
             associated domains
    """
    is_trusted_domain_required = False

    # If no explicit option passed, fallback to the content of the entry.
    # This helps to catch cases when an associated domain value is removed
    # while the rule requires its presence.
    #
    # In certmap-mod pre-callback we pass LDAPEntry instance instead of a dict
    # LDAEntry.get() returns lists, even for single valued attrs. Using
    # LDAPEntry.single_value would give us a single-valued result instead.
    maprule_entry = entry_attrs
    if not isinstance(maprule_entry, dict):
        maprule_entry = entry_attrs.single_value

    maprule = options.get('ipacertmapmaprule',
                          maprule_entry.get('ipacertmapmaprule'))

    if maprule:
        if 'altsecurityidentities' in maprule.lower():
            is_trusted_domain_required = True

    if is_trusted_domain_required:
        domains = options.get('associateddomain',
                              entry_attrs.get('associateddomain'))
        if domains:
            trusted_domains = api_inst.Object.config.gather_trusted_domains()
            trust_suffix_namespace = {dom_name.lower() for dom_name in
                                      trusted_domains}

            candidates = {str(dom).lower() for dom in domains}
            invalid = candidates - trust_suffix_namespace

            if invalid == candidates or len(trust_suffix_namespace) == 0:
                raise errors.ValidationError(
                    name=_('domain'),
                    error=_('The domain(s) "%s" cannot be used to apply '
                            'altSecurityIdentities check.') %
                    ", ".join(list(invalid))
                )
        else:
            raise errors.ValidationError(
                name=_('domain'),
                error=_('The mapping rule with altSecurityIdentities '
                        'should be applied to a trusted Active Directory '
                        'domain but no domain was associated with the rule.')
            )


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
        trusted_domains = api_inst.Object.config.gather_trusted_domains()
        trust_suffix_namespace = {dom_name.lower() for dom_name in
                                  trusted_domains}
        trust_suffix_namespace.add(api_inst.env.domain.lower())

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
        check_maprule_is_for_trusted_domain(self.api, options, entry_attrs)
        return dn


@register()
class certmaprule_mod(LDAPUpdate):
    __doc__ = _('Modify a Certificate Identity Mapping Rule.')

    msg_summary = _('Modified Certificate Identity Mapping Rule "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys,
                     **options):
        check_associateddomain_is_trusted(self.api, options)
        # For update of the existing certmaprule we need to retrieve
        # content of the LDAP entry because modification may affect two cases:
        # - altSecurityIdentities might be removed by the modification
        # - trusted domains may be removed by the modification while they
        #   should be in place
        #
        # For both these cases we need to know actual content of the entry but
        # LDAPUpdate.execute() provides us with entry_attrs built from the
        # options, not the original content.
        entry = ldap.get_entry(dn)
        check_maprule_is_for_trusted_domain(self.api, options, entry)
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
            raise self.obj.handle_not_found(cn)

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
            raise self.obj.handle_not_found(cn)

        entry_attrs['ipaenabledflag'] = ['FALSE']

        try:
            ldap.update_entry(entry_attrs)
        except errors.EmptyModlist:
            pass

        return dict(
            result=True,
            value=pkey_to_value(cn, options),
        )


DBUS_SSSD_NAME = 'org.freedesktop.sssd.infopipe'
DBUS_PROPERTY_IF = 'org.freedesktop.DBus.Properties'
DBUS_SSSD_USERS_PATH = '/org/freedesktop/sssd/infopipe/Users'
DBUS_SSSD_USERS_IF = 'org.freedesktop.sssd.infopipe.Users'
DBUS_SSSD_USER_IF = 'org.freedesktop.sssd.infopipe.Users.User'


class _sssd:
    """
    Auxiliary class for SSSD infopipe DBus.
    """
    def __init__(self):
        """
        Initialize the Users object and interface.

       :raise RemoteRetrieveError: if DBus error occurs
        """
        try:
            self._bus = dbus.SystemBus()
            self._users_obj = self._bus.get_object(
                DBUS_SSSD_NAME, DBUS_SSSD_USERS_PATH)
            self._users_iface = dbus.Interface(
                self._users_obj, DBUS_SSSD_USERS_IF)
        except dbus.DBusException as e:
            logger.error(
                'Failed to initialize DBus interface %s. DBus '
                'exception is %s.', DBUS_SSSD_USERS_IF, e
                )
            raise errors.RemoteRetrieveError(
                reason=_('Failed to connect to sssd over SystemBus. '
                         'See details in the error_log'))

    def list_users_by_cert(self, cert):
        """
        Look for users matching the cert.

        Call Users.ListByCertificate interface and return a dict
        with key = domain, value = list of uids
        corresponding to the users matching the provided cert

        :param cert: DER cert, Certificate instances (IPACertificate)
        :raise RemoteRetrieveError: if DBus error occurs
        """
        if isinstance(cert, crypto_x509.Certificate):
            cert_pem = cert.public_bytes(x509.Encoding.PEM)
        else:
            cert_obj = x509.load_der_x509_certificate(cert)
            cert_pem = cert_obj.public_bytes(x509.Encoding.PEM)

        try:
            # bug 3306 in sssd returns 0 entry when max_entries = 0
            # Temp workaround is to use a non-null value, not too high
            # to avoid reserving unneeded memory
            max_entries = dbus.UInt32(100)
            user_paths = self._users_iface.ListByCertificate(
                cert_pem, max_entries)
            users = dict()
            for user_path in user_paths:
                user_obj = self._bus.get_object(DBUS_SSSD_NAME, user_path)
                user_iface = dbus.Interface(user_obj, DBUS_PROPERTY_IF)
                user_login = user_iface.Get(DBUS_SSSD_USER_IF, 'name')

                # Extract name@domain
                items = user_login.split('@')
                domain = api.env.realm if len(items) < 2 else items[1]
                name = items[0]

                # Retrieve the list of users for the given domain,
                # or initialize to an empty list
                # and add the name
                users_for_dom = users.setdefault(domain, list())
                users_for_dom.append(name)
            return users
        except dbus.DBusException as e:
            err_name = e.get_dbus_name()
            # If there is no matching user, do not consider this as an
            # exception and return an empty list
            if err_name == 'org.freedesktop.sssd.Error.NotFound':
                return dict()
            logger.error(
                'Failed to use interface %s. DBus '
                'exception is %s.', DBUS_SSSD_USERS_IF, e)
            raise errors.RemoteRetrieveError(
                reason=_('Failed to find users over SystemBus. '
                         ' See details in the error_log'))


@register()
class certmap(Object):
    """
    virtual object for certmatch_map API
    """
    takes_params = (
        DNSNameParam(
            'domain',
            label=_('Domain'),
            flags={'no_search'},
        ),
        Str(
            'uid*',
            label=_('User logins'),
            flags={'no_search'},
        ),
    )


@register()
class certmap_match(Search):
    __doc__ = _("""
    Search for users matching the provided certificate.

    This command relies on SSSD to retrieve the list of matching users and
    may return cached data. For more information on purging SSSD cache,
    please refer to sss_cache documentation.
    """)

    msg_summary = ngettext('%(count)s user matched',
                           '%(count)s users matched', 0)

    def get_summary_default(self, output):
        """
        Need to sum the numbre of matching users for each domain.
        """
        count = sum(len(entry['uid']) for entry in output['result'])
        return self.msg_summary % dict(count=count)

    def get_args(self):
        for arg in super(certmap_match, self).get_args():
            if arg.name == 'criteria':
                continue
            yield arg
        yield Certificate(
            'certificate',
            cli_name='certificate',
            label=_('Certificate'),
            doc=_('Base-64 encoded user certificate'),
            flags=['virtual_attribute']
        )

    def execute(self, *args, **options):
        """
        Search for users matching the provided certificate.

        The search is performed using SSSD's DBus interface
        Users.ListByCertificate.
        SSSD does the lookup based on certificate mapping rules, using
        FreeIPA domain and trusted domains.
        :raise RemoteRetrieveError: if DBus returns an exception
        """
        sssd = _sssd()

        cert = args[0]
        users = sssd.list_users_by_cert(cert)
        result = [{'domain': domain, 'uid': userlist}
                  for (domain, userlist) in users.items()]
        count = len(result)

        return dict(
            result=result,
            count=count,
            truncated=False,
        )
