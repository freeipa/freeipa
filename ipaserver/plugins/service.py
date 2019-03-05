# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
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

import logging

from cryptography.hazmat.primitives import hashes
import six

from ipalib import api, errors, messages
from ipalib import StrEnum, Bool, Str, Flag
from ipalib.parameters import Principal, Certificate
from ipalib.plugable import Registry
from .baseldap import (
    host_is_master,
    add_missing_object_class,
    pkey_to_value,
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPUpdate,
    LDAPSearch,
    LDAPRetrieve,
    LDAPAddMember,
    LDAPRemoveMember,
    LDAPQuery,
    LDAPAddAttribute,
    LDAPRemoveAttribute,
    LDAPAddAttributeViaOption,
    LDAPRemoveAttributeViaOption,
    DNA_MAGIC)
from ipalib import x509
from ipalib import _, ngettext
from ipalib import util
from ipalib import output
from ipapython import kerberos
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

if six.PY3:
    unicode = str

__doc__ = _("""
Services

A IPA service represents a service that runs on a host. The IPA service
record can store a Kerberos principal, an SSL certificate, or both.

An IPA service can be managed directly from a machine, provided that
machine has been given the correct permission. This is true even for
machines other than the one the service is associated with. For example,
requesting an SSL certificate using the host service principal credentials
of the host. To manage a service using host credentials you need to
kinit as the host:

 # kinit -kt /etc/krb5.keytab host/ipa.example.com@EXAMPLE.COM

Adding an IPA service allows the associated service to request an SSL
certificate or keytab, but this is performed as a separate step; they
are not produced as a result of adding the service.

Only the public aspect of a certificate is stored in a service record;
the private key is not stored.

EXAMPLES:

 Add a new IPA service:
   ipa service-add HTTP/web.example.com

 Allow a host to manage an IPA service certificate:
   ipa service-add-host --hosts=web.example.com HTTP/web.example.com
   ipa role-add-member --hosts=web.example.com certadmin

 Override a default list of supported PAC types for the service:
   ipa service-mod HTTP/web.example.com --pac-type=MS-PAC

   A typical use case where overriding the PAC type is needed is NFS.
   Currently the related code in the Linux kernel can only handle Kerberos
   tickets up to a maximal size. Since the PAC data can become quite large it
   is recommended to set --pac-type=NONE for NFS services.

 Delete an IPA service:
   ipa service-del HTTP/web.example.com

 Find all IPA services associated with a host:
   ipa service-find web.example.com

 Find all HTTP services:
   ipa service-find HTTP

 Disable the service Kerberos key and SSL certificate:
   ipa service-disable HTTP/web.example.com

 Request a certificate for an IPA service:
   ipa cert-request --principal=HTTP/web.example.com example.csr
""") + _("""
 Allow user to create a keytab:
   ipa service-allow-create-keytab HTTP/web.example.com --users=tuser1
""") + _("""
 Generate and retrieve a keytab for an IPA service:
   ipa-getkeytab -s ipa.example.com -p HTTP/web.example.com -k /etc/httpd/httpd.keytab

""")

logger = logging.getLogger(__name__)

register = Registry()

output_params = (
    Flag('has_keytab',
        label=_('Keytab'),
    ),
    Str('managedby_host',
        label='Managed by',
    ),
    Str('ipaallowedtoperform_read_keys_user',
        label=_('Users allowed to retrieve keytab'),
    ),
    Str('ipaallowedtoperform_read_keys_group',
        label=_('Groups allowed to retrieve keytab'),
    ),
    Str('ipaallowedtoperform_read_keys_host',
        label=_('Hosts allowed to retrieve keytab'),
    ),
    Str('ipaallowedtoperform_read_keys_hostgroup',
        label=_('Host Groups allowed to retrieve keytab'),
    ),
    Str('ipaallowedtoperform_write_keys_user',
        label=_('Users allowed to create keytab'),
    ),
    Str('ipaallowedtoperform_write_keys_group',
        label=_('Groups allowed to create keytab'),
    ),
    Str('ipaallowedtoperform_write_keys_host',
        label=_('Hosts allowed to create keytab'),
    ),
    Str('ipaallowedtoperform_write_keys_hostgroup',
        label=_('Host Groups allowed to create keytab'),
    ),
    Str('ipaallowedtoperform_read_keys',
        label=_('Failed allowed to retrieve keytab'),
    ),
    Str('ipaallowedtoperform_write_keys',
        label=_('Failed allowed to create keytab'),
    ),
)

ticket_flags_params = (
    Bool('ipakrbrequirespreauth?',
        cli_name='requires_pre_auth',
        label=_('Requires pre-authentication'),
        doc=_('Pre-authentication is required for the service'),
        flags=['virtual_attribute', 'no_search'],
    ),
    Bool('ipakrbokasdelegate?',
        cli_name='ok_as_delegate',
        label=_('Trusted for delegation'),
        doc=_('Client credentials may be delegated to the service'),
        flags=['virtual_attribute', 'no_search'],
    ),
    Bool('ipakrboktoauthasdelegate?',
        cli_name='ok_to_auth_as_delegate',
        label=_('Trusted to authenticate as user'),
        doc=_('The service is allowed to authenticate on behalf of a client'),
        flags=['virtual_attribute', 'no_search'],
    ),
)

_ticket_flags_map = {
    'ipakrbrequirespreauth': 0x00000080,
    'ipakrbokasdelegate': 0x00100000,
    'ipakrboktoauthasdelegate': 0x00200000,
}

_ticket_flags_default = _ticket_flags_map['ipakrbrequirespreauth']


def validate_realm(ugettext, principal):
    """
    Check that the principal's realm matches IPA realm if present
    """
    realm = principal.realm
    if realm is not None and realm != api.env.realm:
        raise errors.RealmMismatch()


def normalize_principal(value):
    """
    Ensure that the name in the principal is lower-case. The realm is
    upper-case by convention but it isn't required.

    The principal is validated at this point.
    """
    try:
        principal = kerberos.Principal(value, realm=api.env.realm)
    except ValueError:
        raise errors.ValidationError(
            name='principal', reason=_("Malformed principal"))

    return unicode(principal)


def revoke_certs(certs):
    """
    revoke the certificates removed from host/service entry

    :param certs: Output of a 'cert_find' command.

    """
    for cert in certs:
        if 'cacn' not in cert:
            # Cert is known to IPA, but has no associated CA.
            # If it was issued by 3rd-party CA, we can't revoke it.
            # If it was issued by a Dogtag lightweight CA that was
            # subsequently deleted, we can't revoke it via IPA.
            # We could go directly to Dogtag to revoke it, but the
            # issuer's cert should have been revoked so never mind.
            continue

        if cert['revoked']:
            # cert is already revoked
            continue

        try:
            api.Command['cert_revoke'](
                cert['serial_number'],
                cacn=cert['cacn'],
                revocation_reason=4,
            )
        except errors.NotImplementedError:
            # some CA's might not implement revoke
            pass


def set_certificate_attrs(entry_attrs):
    """
    Set individual attributes from some values from a certificate.

    entry_attrs is a dict of an entry

    returns nothing
    """
    if not 'usercertificate' in entry_attrs:
        return
    if type(entry_attrs['usercertificate']) in (list, tuple):
        cert = entry_attrs['usercertificate'][0]
    else:
        cert = entry_attrs['usercertificate']
    entry_attrs['subject'] = unicode(DN(cert.subject))
    entry_attrs['serial_number'] = unicode(cert.serial_number)
    entry_attrs['serial_number_hex'] = u'0x%X' % cert.serial_number
    entry_attrs['issuer'] = unicode(DN(cert.issuer))
    entry_attrs['valid_not_before'] = x509.format_datetime(
            cert.not_valid_before)
    entry_attrs['valid_not_after'] = x509.format_datetime(cert.not_valid_after)
    entry_attrs['sha1_fingerprint'] = x509.to_hex_with_colons(
        cert.fingerprint(hashes.SHA1()))
    entry_attrs['sha256_fingerprint'] = x509.to_hex_with_colons(
        cert.fingerprint(hashes.SHA256()))

def check_required_principal(ldap, principal):
    """
    Raise an error if the host of this principal is an IPA master and one
    of the principals required for proper execution.
    """
    if not principal.is_service:
        # bypass check if principal is not a service principal,
        # see https://pagure.io/freeipa/issue/7793
        return
    try:
        host_is_master(ldap, principal.hostname)
    except errors.ValidationError:
        service_types = ['HTTP', 'ldap', 'DNS', 'dogtagldap']
        if principal.service_name in service_types:
            raise errors.ValidationError(name='principal', error=_('This principal is required by the IPA master'))

def update_krbticketflags(ldap, entry_attrs, attrs_list, options, existing):
    add = remove = 0

    for (name, value) in _ticket_flags_map.items():
        if name not in options:
            continue
        if options[name]:
            add |= value
        else:
            remove |= value

    if not add and not remove:
        return

    if 'krbticketflags' not in entry_attrs and existing:
        old_entry_attrs = ldap.get_entry(entry_attrs.dn, ['krbticketflags'])
    else:
        old_entry_attrs = entry_attrs

    try:
        ticket_flags = old_entry_attrs.single_value['krbticketflags']
        ticket_flags = int(ticket_flags)
    except (KeyError, ValueError):
        ticket_flags = _ticket_flags_default

    ticket_flags |= add
    ticket_flags &= ~remove

    entry_attrs['krbticketflags'] = [ticket_flags]
    attrs_list.append('krbticketflags')

def set_kerberos_attrs(entry_attrs, options):
    if options.get('raw', False):
        return

    try:
        ticket_flags = entry_attrs.single_value.get('krbticketflags',
                                                    _ticket_flags_default)
        ticket_flags = int(ticket_flags)
    except ValueError:
        return

    all_opt = options.get('all', False)

    for (name, value) in _ticket_flags_map.items():
        if name in options or all_opt:
            entry_attrs[name] = bool(ticket_flags & value)

def rename_ipaallowedtoperform_from_ldap(entry_attrs, options):
    if options.get('raw', False):
        return

    for subtype in ('read_keys', 'write_keys'):
        name = 'ipaallowedtoperform;%s' % subtype
        if name in entry_attrs:
            new_name = 'ipaallowedtoperform_%s' % subtype
            entry_attrs[new_name] = entry_attrs.pop(name)

def rename_ipaallowedtoperform_to_ldap(entry_attrs):
    for subtype in ('read_keys', 'write_keys'):
        name = 'ipaallowedtoperform_%s' % subtype
        if name in entry_attrs:
            new_name = 'ipaallowedtoperform;%s' % subtype
            entry_attrs[new_name] = entry_attrs.pop(name)

@register()
class service(LDAPObject):
    """
    Service object.
    """
    container_dn = api.env.container_service
    object_name = _('service')
    object_name_plural = _('services')
    object_class = [
        'krbprincipal', 'krbprincipalaux', 'krbticketpolicyaux', 'ipaobject',
        'ipaservice', 'pkiuser'
    ]
    possible_objectclasses = ['ipakrbprincipal', 'ipaallowedoperations']
    permission_filter_objectclasses = ['ipaservice']
    search_attributes = ['krbprincipalname', 'managedby', 'ipakrbauthzdata']
    default_attributes = [
        'krbprincipalname', 'krbcanonicalname', 'usercertificate', 'managedby',
        'ipakrbauthzdata', 'memberof', 'ipaallowedtoperform',
        'krbprincipalauthind']
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'managedby': ['host'],
        'memberof': ['role'],
        'ipaallowedtoperform_read_keys': ['user', 'group', 'host', 'hostgroup'],
        'ipaallowedtoperform_write_keys': ['user', 'group', 'host', 'hostgroup'],
    }
    bindable = True
    relationships = {
        'managedby': ('Managed by', 'man_by_', 'not_man_by_'),
        'ipaallowedtoperform_read_keys': ('Allow to retrieve keytab by', 'retrieve_keytab_by_', 'not_retrieve_keytab_by_'),
        'ipaallowedtoperform_write_keys': ('Allow to create keytab by', 'write_keytab_by_', 'not_write_keytab_by'),
    }
    password_attributes = [('krbprincipalkey', 'has_keytab')]
    managed_permissions = {
        'System: Read Services': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass',
                'ipauniqueid', 'managedby', 'memberof', 'usercertificate',
                'krbprincipalname', 'krbcanonicalname', 'krbprincipalaliases',
                'krbprincipalexpiration', 'krbpasswordexpiration',
                'krblastpwdchange', 'ipakrbauthzdata', 'ipakrbprincipalalias',
                'krbobjectreferences', 'krbprincipalauthind',
            },
        },
        'System: Add Services': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///krbprincipalname=*,cn=services,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Add Services";allow (add) groupdn = "ldap:///cn=Add Services,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Service Administrators'},
        },
        'System: Manage Service Keytab': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'krblastpwdchange', 'krbprincipalkey'},
            'replaces': [
                '(targetattr = "krbprincipalkey || krblastpwdchange")(target = "ldap:///krbprincipalname=*,cn=services,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Manage service keytab";allow (write) groupdn = "ldap:///cn=Manage service keytab,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Service Administrators', 'Host Administrators'},
        },
        'System: Manage Service Keytab Permissions': {
            'ipapermright': {'read', 'search', 'compare', 'write'},
            'ipapermdefaultattr': {
                'ipaallowedtoperform;write_keys',
                'ipaallowedtoperform;read_keys', 'objectclass'
            },
            'default_privileges': {'Service Administrators', 'Host Administrators'},
        },
        'System: Modify Services': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'usercertificate', 'krbprincipalauthind'},
            'replaces': [
                '(targetattr = "usercertificate")(target = "ldap:///krbprincipalname=*,cn=services,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Modify Services";allow (write) groupdn = "ldap:///cn=Modify Services,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Service Administrators'},
        },
        'System: Manage Service Principals': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'krbprincipalname', 'krbcanonicalname'},
            'default_privileges': {
                'Service Administrators',
            },
        },
        'System: Remove Services': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///krbprincipalname=*,cn=services,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Remove Services";allow (delete) groupdn = "ldap:///cn=Remove Services,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Service Administrators'},
        },
        'System: Read POSIX details of SMB services': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass', 'cn', 'uid', 'gecos', 'gidnumber',
                'homedirectory', 'loginshell', 'uidnumber',
                'ipantsecurityidentifier',
            },
        }
    }

    label = _('Services')
    label_singular = _('Service')

    takes_params = (
        Principal(
            'krbcanonicalname',
            validate_realm,
            cli_name='canonical_principal',
            label=_('Principal name'),
            doc=_('Service principal'),
            primary_key=True,
            normalizer=normalize_principal,
            require_service=True
        ),
        Principal(
            'krbprincipalname*',
            validate_realm,
            cli_name='principal',
            label=_('Principal alias'),
            doc=_('Service principal alias'),
            normalizer=normalize_principal,
            require_service=True,
            flags={'no_create'}
        ),
        Certificate('usercertificate*',
            cli_name='certificate',
            label=_('Certificate'),
            doc=_('Base-64 encoded service certificate'),
            flags=['no_search',],
        ),
        Str('subject',
            label=_('Subject'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('serial_number',
            label=_('Serial Number'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('serial_number_hex',
            label=_('Serial Number (hex)'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('issuer',
            label=_('Issuer'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('valid_not_before',
            label=_('Not Before'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('valid_not_after',
            label=_('Not After'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('sha1_fingerprint',
            label=_('Fingerprint (SHA1)'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('sha256_fingerprint',
            label=_('Fingerprint (SHA256)'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('revocation_reason?',
            label=_('Revocation reason'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        StrEnum('ipakrbauthzdata*',
            cli_name='pac_type',
            label=_('PAC type'),
            doc=_("Override default list of supported PAC types."
                  " Use 'NONE' to disable PAC support for this service,"
                  " e.g. this might be necessary for NFS services."),
            values=(u'MS-PAC', u'PAD', u'NONE'),
        ),
        Str('krbprincipalauthind*',
            cli_name='auth_ind',
            label=_('Authentication Indicators'),
            doc=_("Defines a whitelist for Authentication Indicators."
                  " Use 'otp' to allow OTP-based 2FA authentications."
                  " Use 'radius' to allow RADIUS-based 2FA authentications."
                  " Other values may be used for custom configurations."),
        ),
    ) + ticket_flags_params

    def validate_ipakrbauthzdata(self, entry):
        new_value = entry.get('ipakrbauthzdata', [])

        if not new_value:
            return

        if not isinstance(new_value, (list, tuple)):
            new_value = set([new_value])
        else:
            new_value = set(new_value)

        if u'NONE' in new_value and len(new_value) > 1:
            raise errors.ValidationError(name='ipakrbauthzdata',
                error=_('NONE value cannot be combined with other PAC types'))

    def get_dn(self, *keys, **kwargs):
        key = keys[0]
        if isinstance(key, str):
            key = kerberos.Principal(key)

        key = unicode(normalize_principal(key))

        parent_dn = DN(self.container_dn, self.api.env.basedn)
        true_rdn = 'krbprincipalname'

        return self.backend.make_dn_from_attr(
            true_rdn, key, parent_dn
        )

    def get_primary_key_from_dn(self, dn):
        """
        If the entry has krbcanonicalname set return the value of the
        attribute. If the attribute is not found, assume old-style entry which
        should have only single value of krbprincipalname and return it.

        Otherwise return input DN.
        """
        assert isinstance(dn, DN)

        try:
            entry_attrs = self.backend.get_entry(
                dn, [self.primary_key.name]
            )
            try:
                return entry_attrs[self.primary_key.name][0]
            except (KeyError, IndexError):
                return ''
        except errors.NotFound:
            pass

        try:
            return dn['krbprincipalname']
        except KeyError:
            return unicode(dn)

    def populate_krbcanonicalname(self, entry_attrs, options):
        if options.get('raw', False):
            return

        entry_attrs.setdefault(
            'krbcanonicalname', entry_attrs['krbprincipalname'])


@register()
class service_add(LDAPCreate):
    __doc__ = _('Add a new IPA service.')

    msg_summary = _('Added service "%(value)s"')
    member_attributes = ['managedby']
    has_output_params = LDAPCreate.has_output_params + output_params
    takes_options = LDAPCreate.takes_options + (
        Flag('force',
             label=_('Force'),
             doc=_('force principal name even if host not in DNS'),
        ),
        Flag('skip_host_check',
             label=_('Skip host check'),
             doc=_('force service to be created even when host '
                   'object does not exist to manage it'),
             ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        principal = keys[-1]
        hostname = principal.hostname

        if principal.is_host and not options['force']:
            raise errors.HostService()

        if not options['skip_host_check']:
            try:
                hostresult = self.api.Command['host_show'](hostname)['result']
            except errors.NotFound:
                raise errors.NotFound(reason=_(
                    "The host '%s' does not exist to add a service to.") %
                    hostname)

        self.obj.validate_ipakrbauthzdata(entry_attrs)

        if not options.get('force', False):
            # We know the host exists if we've gotten this far but we
            # really want to discourage creating services for hosts that
            # don't exist in DNS.
            util.verify_host_resolvable(hostname)
        if not (options['skip_host_check'] or 'managedby' in entry_attrs):
            entry_attrs['managedby'] = hostresult['dn']

        # Enforce ipaKrbPrincipalAlias to aid case-insensitive searches
        # as krbPrincipalName/krbCanonicalName are case-sensitive in Kerberos
        # schema
        entry_attrs['ipakrbprincipalalias'] = keys[-1]

        # Objectclass ipakrbprincipal providing ipakrbprincipalalias is not in
        # in a list of default objectclasses, add it manually
        entry_attrs['objectclass'].append('ipakrbprincipal')

        # set krbcanonicalname attribute to enable principal canonicalization
        util.set_krbcanonicalname(entry_attrs)

        update_krbticketflags(ldap, entry_attrs, attrs_list, options, False)

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        set_kerberos_attrs(entry_attrs, options)
        rename_ipaallowedtoperform_from_ldap(entry_attrs, options)
        self.obj.populate_krbcanonicalname(entry_attrs, options)
        return dn


@register()
class service_add_smb(LDAPCreate):
    __doc__ = _('Add a new SMB service.')

    msg_summary = _('Added service "%(value)s"')
    member_attributes = ['managedby']
    has_output_params = LDAPCreate.has_output_params + output_params
    smb_takes_args = (
        Str('fqdn', util.hostname_validator,
            cli_name='hostname',
            label=_('Host name'),
            primary_key=True,
            normalizer=util.normalize_hostname,
            flags={'virtual_attribute', 'no_display', 'no_update',
                   'no_search'},
            ),
        Str('ipantflatname?',
            cli_name='netbiosname',
            label=_('SMB service NetBIOS name'),
            flags={'virtual_attribute', 'no_display', 'no_update',
                   'no_search'},
            ),
    )

    takes_options = LDAPCreate.takes_options

    def get_args(self):
        """
        Rewrite arguments to service-add-smb command to make sure we accept
        hostname instead of a principal as we'll be constructing the principal
        ourselves
        """
        for arg in self.smb_takes_args:
            yield arg
        for arg in super(service_add_smb, self).get_args():
            if arg not in self.smb_takes_args and not arg.primary_key:
                yield arg

    def get_options(self):
        """
        Rewrite options to service-add-smb command to filter out cannonical
        principal which is autoconstructed. Also filter out options which
        make no sense for SMB service.
        """
        excluded = ('ipakrbauthzdata', 'krbprincipalauthind',
                    'ipakrbrequirespreauth')
        for arg in self.takes_options:
            yield arg
        for arg in super(service_add_smb, self).get_options():
            check = all([arg not in self.takes_options,
                         not arg.primary_key,
                         arg.name not in excluded])
            if check:
                yield arg

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list,
                     *keys, **options):
        assert isinstance(dn, DN)
        hostname = keys[0]
        if len(keys) == 2:
            netbiosname = keys[1]
        else:
            # By default take leftmost label from the host name
            netbiosname = DNSName.from_text(hostname)[0].decode().upper()

        # SMB service requires existence of the host object
        # because DCE RPC calls authenticated with GSSAPI are using
        # host/.. principal by default for validation
        try:
            hostresult = self.api.Command['host_show'](hostname)['result']
        except errors.NotFound:
            raise errors.NotFound(reason=_(
                "The host '%s' does not exist to add a service to.") %
                hostname)

        # We cannot afford the host not being resolvable even for
        # clustered environments with CTDB because the target name
        # has to exist even in that case
        util.verify_host_resolvable(hostname)

        smbaccount = '{name}$'.format(name=netbiosname)
        smbprincipal = 'cifs/{hostname}'.format(hostname=hostname)

        entry_attrs['krbprincipalname'] = [
            str(kerberos.Principal(smbprincipal, realm=self.api.env.realm)),
            str(kerberos.Principal(smbaccount, realm=self.api.env.realm))]

        entry_attrs['krbcanonicalname'] = entry_attrs['krbprincipalname'][0]

        # Rewrite DN using proper rdn and new canonical name because when
        # LDAPCreate.execute() was called, it set DN to krbcanonicalname=$value
        dn = DN(('krbprincipalname', entry_attrs['krbcanonicalname']),
                DN(self.obj.container_dn, api.env.basedn))

        # Enforce ipaKrbPrincipalAlias to aid case-insensitive searches as
        # krbPrincipalName/krbCanonicalName are case-sensitive in Kerberos
        # schema
        entry_attrs['ipakrbprincipalalias'] = entry_attrs['krbcanonicalname']

        for o in ('ipakrbprincipal', 'ipaidobject', 'krbprincipalaux',
                  'posixaccount'):
            if o not in entry_attrs['objectclass']:
                entry_attrs['objectclass'].append(o)

        entry_attrs['uid'] = ['/'.join(
            kerberos.Principal(smbprincipal).components)]
        entry_attrs['uid'].append(smbaccount)
        entry_attrs['cn'] = netbiosname
        entry_attrs['homeDirectory'] = '/dev/null'
        entry_attrs['uidNumber'] = DNA_MAGIC
        entry_attrs['gidNumber'] = DNA_MAGIC

        self.obj.validate_ipakrbauthzdata(entry_attrs)

        if 'managedby' not in entry_attrs:
            entry_attrs['managedby'] = hostresult['dn']

        update_krbticketflags(ldap, entry_attrs, attrs_list, options, False)

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        set_kerberos_attrs(entry_attrs, options)
        rename_ipaallowedtoperform_from_ldap(entry_attrs, options)
        self.obj.populate_krbcanonicalname(entry_attrs, options)
        return dn


@register()
class service_del(LDAPDelete):
    __doc__ = _('Delete an IPA service.')

    msg_summary = _('Deleted service "%(value)s"')
    member_attributes = ['managedby']
    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        # In the case of services we don't want IPA master services to be
        # deleted. This is a limited few though. If the user has their own
        # custom services allow them to manage them.
        check_required_principal(ldap, keys[-1])
        if self.api.Command.ca_is_enabled()['result']:
            certs = self.api.Command.cert_find(service=keys)['result']
            revoke_certs(certs)

        return dn



@register()
class service_mod(LDAPUpdate):
    __doc__ = _('Modify an existing IPA service.')

    msg_summary = _('Modified service "%(value)s"')
    takes_options = LDAPUpdate.takes_options
    has_output_params = LDAPUpdate.has_output_params + output_params

    member_attributes = ['managedby']

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

        self.obj.validate_ipakrbauthzdata(entry_attrs)

        # verify certificates
        certs = entry_attrs.get('usercertificate') or []
        # revoke removed certificates
        ca_is_enabled = self.api.Command.ca_is_enabled()['result']
        if 'usercertificate' in options and ca_is_enabled:
            try:
                entry_attrs_old = ldap.get_entry(dn, ['usercertificate'])
            except errors.NotFound:
                raise self.obj.handle_not_found(*keys)
            old_certs = entry_attrs_old.get('usercertificate', [])
            removed_certs = set(old_certs) - set(certs)
            for cert in removed_certs:
                rm_certs = api.Command.cert_find(
                    certificate=cert.public_bytes(x509.Encoding.DER),
                    service=keys)['result']
                revoke_certs(rm_certs)

        if certs:
            entry_attrs['usercertificate'] = certs

        update_krbticketflags(ldap, entry_attrs, attrs_list, options, True)

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        set_certificate_attrs(entry_attrs)
        set_kerberos_attrs(entry_attrs, options)
        rename_ipaallowedtoperform_from_ldap(entry_attrs, options)
        self.obj.populate_krbcanonicalname(entry_attrs, options)
        return dn



@register()
class service_find(LDAPSearch):
    __doc__ = _('Search for IPA services.')

    msg_summary = ngettext(
        '%(count)d service matched', '%(count)d services matched', 0
    )
    member_attributes = ['managedby']
    sort_result_entries = False

    takes_options = LDAPSearch.takes_options
    has_output_params = LDAPSearch.has_output_params + output_params

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args, **options):
        assert isinstance(base_dn, DN)
        # lisp style!
        custom_filter = '(&(objectclass=ipaService)' \
                          '(!(objectClass=posixAccount))' \
                          '(!(|(krbprincipalname=kadmin/*)' \
                              '(krbprincipalname=K/M@*)' \
                              '(krbprincipalname=krbtgt/*))' \
                          ')' \
                        ')'
        if options.get('pkey_only', False):
            attrs_list.append('krbprincipalname')

        return (
            ldap.combine_filters((custom_filter, filter), rules=ldap.MATCH_ALL),
            base_dn, scope
        )

    def post_callback(self, ldap, entries, truncated, *args, **options):
        # we have to sort entries manually instead of relying on inherited
        # mechanisms
        def sort_key(x):
            if 'krbcanonicalname' in x:
                return x['krbcanonicalname'][0]
            else:
                return x['krbprincipalname'][0]

        entries.sort(key=sort_key)

        if options.get('pkey_only', False):
            return truncated
        for entry_attrs in entries:
            self.obj.get_password_attributes(ldap, entry_attrs.dn, entry_attrs)
            principal = entry_attrs['krbprincipalname']
            if isinstance(principal, (tuple, list)):
                principal = principal[0]
            try:
                set_certificate_attrs(entry_attrs)
            except errors.CertificateFormatError as e:
                self.add_message(
                    messages.CertificateInvalid(
                        subject=principal,
                        reason=e
                    )
                )
                logger.error("Invalid certificate: %s", e)
                del(entry_attrs['usercertificate'])

            set_kerberos_attrs(entry_attrs, options)
            rename_ipaallowedtoperform_from_ldap(entry_attrs, options)
            self.obj.populate_krbcanonicalname(entry_attrs, options)
        return truncated



@register()
class service_show(LDAPRetrieve):
    __doc__ = _('Display information about an IPA service.')

    member_attributes = ['managedby']
    takes_options = LDAPRetrieve.takes_options + (
        Str('out?',
            doc=_('file to store certificate in'),
        ),
    )
    has_output_params = LDAPRetrieve.has_output_params + output_params

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.get_password_attributes(ldap, dn, entry_attrs)

        principal = entry_attrs['krbprincipalname']
        if isinstance(principal, (tuple, list)):
            principal = principal[0]
        try:
            set_certificate_attrs(entry_attrs)
        except errors.CertificateFormatError as e:
            self.add_message(
                messages.CertificateInvalid(
                    subject=principal,
                    reason=e,
                )
            )
            logger.error("Invalid certificate: %s", e)
            del(entry_attrs['usercertificate'])

        set_kerberos_attrs(entry_attrs, options)
        rename_ipaallowedtoperform_from_ldap(entry_attrs, options)
        self.obj.populate_krbcanonicalname(entry_attrs, options)

        return dn

@register()
class service_add_host(LDAPAddMember):
    __doc__ = _('Add hosts that can manage this service.')

    member_attributes = ['managedby']
    has_output_params = LDAPAddMember.has_output_params + output_params



@register()
class service_remove_host(LDAPRemoveMember):
    __doc__ = _('Remove hosts that can manage this service.')

    member_attributes = ['managedby']
    has_output_params = LDAPRemoveMember.has_output_params + output_params


@register()
class service_allow_retrieve_keytab(LDAPAddMember):
    __doc__ = _('Allow users, groups, hosts or host groups to retrieve a keytab'
                ' of this service.')
    member_attributes = ['ipaallowedtoperform_read_keys']
    has_output_params = LDAPAddMember.has_output_params + output_params

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        rename_ipaallowedtoperform_to_ldap(found)
        rename_ipaallowedtoperform_to_ldap(not_found)
        add_missing_object_class(ldap, u'ipaallowedoperations', dn)
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        rename_ipaallowedtoperform_from_ldap(entry_attrs, options)
        rename_ipaallowedtoperform_from_ldap(failed, options)
        self.obj.populate_krbcanonicalname(entry_attrs, options)
        return (completed, dn)


@register()
class service_disallow_retrieve_keytab(LDAPRemoveMember):
    __doc__ = _('Disallow users, groups, hosts or host groups to retrieve a '
                'keytab of this service.')
    member_attributes = ['ipaallowedtoperform_read_keys']
    has_output_params = LDAPRemoveMember.has_output_params + output_params

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        rename_ipaallowedtoperform_to_ldap(found)
        rename_ipaallowedtoperform_to_ldap(not_found)
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        rename_ipaallowedtoperform_from_ldap(entry_attrs, options)
        rename_ipaallowedtoperform_from_ldap(failed, options)
        self.obj.populate_krbcanonicalname(entry_attrs, options)
        return (completed, dn)


@register()
class service_allow_create_keytab(LDAPAddMember):
    __doc__ = _('Allow users, groups, hosts or host groups to create a keytab '
                'of this service.')
    member_attributes = ['ipaallowedtoperform_write_keys']
    has_output_params = LDAPAddMember.has_output_params + output_params

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        rename_ipaallowedtoperform_to_ldap(found)
        rename_ipaallowedtoperform_to_ldap(not_found)
        add_missing_object_class(ldap, u'ipaallowedoperations', dn)
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        rename_ipaallowedtoperform_from_ldap(entry_attrs, options)
        rename_ipaallowedtoperform_from_ldap(failed, options)
        self.obj.populate_krbcanonicalname(entry_attrs, options)
        return (completed, dn)


@register()
class service_disallow_create_keytab(LDAPRemoveMember):
    __doc__ = _('Disallow users, groups, hosts or host groups to create a '
                'keytab of this service.')
    member_attributes = ['ipaallowedtoperform_write_keys']
    has_output_params = LDAPRemoveMember.has_output_params + output_params

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        rename_ipaallowedtoperform_to_ldap(found)
        rename_ipaallowedtoperform_to_ldap(not_found)
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        rename_ipaallowedtoperform_from_ldap(entry_attrs, options)
        rename_ipaallowedtoperform_from_ldap(failed, options)
        self.obj.populate_krbcanonicalname(entry_attrs, options)
        return (completed, dn)


@register()
class service_disable(LDAPQuery):
    __doc__ = _('Disable the Kerberos key and SSL certificate of a service.')

    has_output = output.standard_value
    msg_summary = _('Disabled service "%(value)s"')
    has_output_params = LDAPQuery.has_output_params + output_params

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)
        entry_attrs = ldap.get_entry(dn, ['usercertificate'])

        check_required_principal(ldap, keys[-1])

        # See if we do any work at all here and if not raise an exception
        done_work = False

        if self.api.Command.ca_is_enabled()['result']:
            certs = self.api.Command.cert_find(service=keys)['result']

            if len(certs) > 0:
                revoke_certs(certs)
                # Remove the usercertificate altogether
                entry_attrs['usercertificate'] = None
                ldap.update_entry(entry_attrs)
                done_work = True

        self.obj.get_password_attributes(ldap, dn, entry_attrs)
        if entry_attrs['has_keytab']:
            ldap.remove_principal_key(dn)
            done_work = True

        if not done_work:
            raise errors.AlreadyInactive()

        return dict(
            result=True,
            value=pkey_to_value(keys[0], options),
        )


@register()
class service_add_cert(LDAPAddAttributeViaOption):
    __doc__ = _('Add new certificates to a service')
    msg_summary = _('Added certificates to service principal "%(value)s"')
    attribute = 'usercertificate'


@register()
class service_remove_cert(LDAPRemoveAttributeViaOption):
    __doc__ = _('Remove certificates from a service')
    msg_summary = _('Removed certificates from service principal "%(value)s"')
    attribute = 'usercertificate'

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)

        for cert in options.get('usercertificate', []):
            revoke_certs(api.Command.cert_find(
                certificate=cert,
                service=keys)['result'])

        return dn


@register()
class service_add_principal(LDAPAddAttribute):
    __doc__ = _('Add new principal alias to a service')
    msg_summary = _('Added new aliases to the service principal "%(value)s"')
    attribute = 'krbprincipalname'

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        util.check_principal_realm_in_trust_namespace(self.api, *keys)
        util.ensure_krbcanonicalname_set(ldap, entry_attrs)
        return dn


@register()
class service_remove_principal(LDAPRemoveAttribute):
    __doc__ = _('Remove principal alias from a service')
    msg_summary = _('Removed aliases to the service principal "%(value)s"')
    attribute = 'krbprincipalname'

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        util.ensure_last_krbprincipalname(ldap, entry_attrs, *keys)
        return dn
