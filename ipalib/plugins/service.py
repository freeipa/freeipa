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

import base64
import os

from ipalib import api, errors, util
from ipalib import Str, Flag, Bytes, StrEnum, Bool
from ipalib.plugable import Registry
from ipalib.plugins.baseldap import *
from ipalib import x509
from ipalib import _, ngettext
from ipalib import util
import nss.nss as nss
from nss.error import NSPRError
from ipapython.ipautil import file_exists

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

register = Registry()

output_params = (
    Flag('has_keytab',
        label=_('Keytab'),
    ),
    Str('managedby_host',
        label='Managed by',
    ),
    Str('subject',
        label=_('Subject'),
    ),
    Str('serial_number',
        label=_('Serial Number'),
    ),
    Str('serial_number_hex',
        label=_('Serial Number (hex)'),
    ),
    Str('issuer',
        label=_('Issuer'),
    ),
    Str('valid_not_before',
        label=_('Not Before'),
    ),
    Str('valid_not_after',
        label=_('Not After'),
    ),
    Str('md5_fingerprint',
        label=_('Fingerprint (MD5)'),
    ),
    Str('sha1_fingerprint',
        label=_('Fingerprint (SHA1)'),
    ),
    Str('revocation_reason?',
        label=_('Revocation reason'),
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
)

_ticket_flags_map = {
    'ipakrbrequirespreauth': 0x00000080,
    'ipakrbokasdelegate': 0x00100000,
}

_ticket_flags_default = _ticket_flags_map['ipakrbrequirespreauth']

def split_any_principal(principal):
    service = hostname = realm = None

    # Break down the principal into its component parts, which may or
    # may not include the realm.
    sp = principal.split('/')
    name_and_realm = None
    if len(sp) > 2:
        raise errors.MalformedServicePrincipal(reason=_('unable to determine service'))
    elif len(sp) == 2:
        service = sp[0]
        if len(service) == 0:
            raise errors.MalformedServicePrincipal(reason=_('blank service'))
        name_and_realm = sp[1]
    else:
        name_and_realm = sp[0]

    sr = name_and_realm.split('@')
    if len(sr) > 2:
        raise errors.MalformedServicePrincipal(
            reason=_('unable to determine realm'))

    hostname = sr[0].lower()
    if len(sr) == 2:
        realm = sr[1].upper()
        # At some point we'll support multiple realms
        if realm != api.env.realm:
            raise errors.RealmMismatch()
    else:
        realm = api.env.realm

    # Note that realm may be None.
    return service, hostname, realm

def split_principal(principal):
    service, name, realm = split_any_principal(principal)
    if service is None:
        raise errors.MalformedServicePrincipal(reason=_('missing service'))
    return service, name, realm

def validate_principal(ugettext, principal):
    (service, hostname, principal) = split_principal(principal)
    return None

def normalize_principal(principal):
    # The principal is already validated when it gets here
    (service, hostname, realm) = split_principal(principal)
    # Put the principal back together again
    principal = '%s/%s@%s' % (service, hostname, realm)
    return unicode(principal)

def validate_certificate(ugettext, cert):
    """
    Check whether the certificate is properly encoded to DER
    """
    if api.env.in_server:
        x509.validate_certificate(cert, datatype=x509.DER)


def revoke_certs(certs, logger=None):
    """
    revoke the certificates removed from host/service entry
    """
    for cert in certs:
        try:
            cert = x509.normalize_certificate(cert)
        except errors.CertificateFormatError as e:
            if logger is not None:
                logger.info("Problem decoding certificate: %s" % e)

        serial = unicode(x509.get_serial_number(cert, x509.DER))

        try:
            result = api.Command['cert_show'](unicode(serial))['result']
        except errors.CertificateOperationError:
            continue
        if 'revocation_reason' in result:
            continue
        if x509.normalize_certificate(result['certificate']) != cert:
            continue

        try:
            api.Command['cert_revoke'](unicode(serial),
                                       revocation_reason=4)
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
    cert = x509.normalize_certificate(cert)
    cert = x509.load_certificate(cert, datatype=x509.DER)
    entry_attrs['subject'] = unicode(cert.subject)
    entry_attrs['serial_number'] = unicode(cert.serial_number)
    entry_attrs['serial_number_hex'] = u'0x%X' % cert.serial_number
    entry_attrs['issuer'] = unicode(cert.issuer)
    entry_attrs['valid_not_before'] = unicode(cert.valid_not_before_str)
    entry_attrs['valid_not_after'] = unicode(cert.valid_not_after_str)
    entry_attrs['md5_fingerprint'] = unicode(nss.data_to_hex(nss.md5_digest(cert.der_data), 64)[0])
    entry_attrs['sha1_fingerprint'] = unicode(nss.data_to_hex(nss.sha1_digest(cert.der_data), 64)[0])

def check_required_principal(ldap, hostname, service):
    """
    Raise an error if the host of this prinicipal is an IPA master and one
    of the principals required for proper execution.
    """
    try:
        host_is_master(ldap, hostname)
    except errors.ValidationError, e:
        service_types = ['HTTP', 'ldap', 'DNS', 'dogtagldap']
        if service in service_types:
            raise errors.ValidationError(name='principal', error=_('This principal is required by the IPA master'))

def update_krbticketflags(ldap, entry_attrs, attrs_list, options, existing):
    add = remove = 0

    for (name, value) in _ticket_flags_map.iteritems():
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

    for (name, value) in _ticket_flags_map.iteritems():
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
    search_attributes = ['krbprincipalname', 'managedby', 'ipakrbauthzdata',
        'ipaallowedtoperform']
    default_attributes = ['krbprincipalname', 'usercertificate', 'managedby',
        'ipakrbauthzdata', 'memberof', 'ipaallowedtoperform']
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
                'krbobjectreferences',
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
            'ipapermdefaultattr': {'usercertificate'},
            'replaces': [
                '(targetattr = "usercertificate")(target = "ldap:///krbprincipalname=*,cn=services,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Modify Services";allow (write) groupdn = "ldap:///cn=Modify Services,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Service Administrators'},
        },
        'System: Remove Services': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///krbprincipalname=*,cn=services,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Remove Services";allow (delete) groupdn = "ldap:///cn=Remove Services,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Service Administrators'},
        },
    }

    label = _('Services')
    label_singular = _('Service')

    takes_params = (
        Str('krbprincipalname', validate_principal,
            cli_name='principal',
            label=_('Principal'),
            doc=_('Service principal'),
            primary_key=True,
            normalizer=lambda value: normalize_principal(value),
        ),
        Bytes('usercertificate*', validate_certificate,
            cli_name='certificate',
            label=_('Certificate'),
            doc=_('Base-64 encoded server certificate'),
            flags=['no_search',],
        ),
        StrEnum('ipakrbauthzdata*',
            cli_name='pac_type',
            label=_('PAC type'),
            doc=_("Override default list of supported PAC types."
                  " Use 'NONE' to disable PAC support for this service,"
                  " e.g. this might be necessary for NFS services."),
            values=(u'MS-PAC', u'PAD', u'NONE'),
            csv=True,
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
        keys = (normalize_principal(k) for k in keys)
        return super(service, self).get_dn(*keys, **kwargs)


@register()
class service_add(LDAPCreate):
    __doc__ = _('Add a new IPA new service.')

    msg_summary = _('Added service "%(value)s"')
    member_attributes = ['managedby']
    has_output_params = LDAPCreate.has_output_params + output_params
    takes_options = LDAPCreate.takes_options + (
        Flag('force',
            label=_('Force'),
            doc=_('force principal name even if not in DNS'),
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        (service, hostname, realm) = split_principal(keys[-1])
        if service.lower() == 'host' and not options['force']:
            raise errors.HostService()

        try:
            hostresult = api.Command['host_show'](hostname)['result']
        except errors.NotFound:
            raise errors.NotFound(
                reason=_("The host '%s' does not exist to add a service to.") %
                    hostname)

        self.obj.validate_ipakrbauthzdata(entry_attrs)

        certs = options.get('usercertificate', [])
        certs_der = map(x509.normalize_certificate, certs)
        for dercert in certs_der:
            x509.verify_cert_subject(ldap, hostname, dercert)
        entry_attrs['usercertificate'] = certs_der

        if not options.get('force', False):
             # We know the host exists if we've gotten this far but we
             # really want to discourage creating services for hosts that
             # don't exist in DNS.
             util.validate_host_dns(self.log, hostname)
        if not 'managedby' in entry_attrs:
            entry_attrs['managedby'] = hostresult['dn']

        # Enforce ipaKrbPrincipalAlias to aid case-insensitive searches
        # as krbPrincipalName/krbCanonicalName are case-sensitive in Kerberos
        # schema
        entry_attrs['ipakrbprincipalalias'] = keys[-1]

        # Objectclass ipakrbprincipal providing ipakrbprincipalalias is not in
        # in a list of default objectclasses, add it manually
        entry_attrs['objectclass'].append('ipakrbprincipal')

        update_krbticketflags(ldap, entry_attrs, attrs_list, options, False)

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        set_kerberos_attrs(entry_attrs, options)
        rename_ipaallowedtoperform_from_ldap(entry_attrs, options)
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
        (service, hostname, realm) = split_principal(keys[-1])
        check_required_principal(ldap, hostname, service)
        if self.api.Command.ca_is_enabled()['result']:
            try:
                entry_attrs = ldap.get_entry(dn, ['usercertificate'])
            except errors.NotFound:
                self.obj.handle_not_found(*keys)
            revoke_certs(entry_attrs.get('usercertificate', []), self.log)

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

        (service, hostname, realm) = split_principal(keys[-1])

        # verify certificates
        certs = entry_attrs.get('usercertificate') or []
        certs_der = map(x509.normalize_certificate, certs)
        for dercert in certs_der:
            x509.verify_cert_subject(ldap, hostname, dercert)
        # revoke removed certificates
        if certs and self.api.Command.ca_is_enabled()['result']:
            try:
                entry_attrs_old = ldap.get_entry(dn, ['usercertificate'])
            except errors.NotFound:
                self.obj.handle_not_found(*keys)
            old_certs = entry_attrs_old.get('usercertificate', [])
            old_certs_der = map(x509.normalize_certificate, old_certs)
            removed_certs_der = set(old_certs_der) - set(certs_der)
            revoke_certs(removed_certs_der, self.log)

        if certs:
            entry_attrs['usercertificate'] = certs_der

        update_krbticketflags(ldap, entry_attrs, attrs_list, options, True)

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        set_certificate_attrs(entry_attrs)
        set_kerberos_attrs(entry_attrs, options)
        rename_ipaallowedtoperform_from_ldap(entry_attrs, options)
        return dn



@register()
class service_find(LDAPSearch):
    __doc__ = _('Search for IPA services.')

    msg_summary = ngettext(
        '%(count)d service matched', '%(count)d services matched', 0
    )
    member_attributes = ['managedby']
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
        return (
            ldap.combine_filters((custom_filter, filter), rules=ldap.MATCH_ALL),
            base_dn, scope
        )

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if options.get('pkey_only', False):
            return truncated
        for entry_attrs in entries:
            self.obj.get_password_attributes(ldap, entry_attrs.dn, entry_attrs)
            set_certificate_attrs(entry_attrs)
            set_kerberos_attrs(entry_attrs, options)
            rename_ipaallowedtoperform_from_ldap(entry_attrs, options)
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

        set_certificate_attrs(entry_attrs)
        set_kerberos_attrs(entry_attrs, options)
        rename_ipaallowedtoperform_from_ldap(entry_attrs, options)

        return dn

    def forward(self, *keys, **options):
        if 'out' in options:
            util.check_writable_file(options['out'])
            result = super(service_show, self).forward(*keys, **options)
            if 'usercertificate' in result['result']:
                x509.write_certificate_list(
                    result['result']['usercertificate'],
                    options['out']
                )
                result['summary'] = (
                    _('Certificate(s) stored in file \'%(file)s\'')
                    % dict(file=options['out'])
                )
                return result
            else:
                raise errors.NoCertificateError(entry=keys[-1])
        else:
            return super(service_show, self).forward(*keys, **options)


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

        (service, hostname, realm) = split_principal(keys[-1])
        check_required_principal(ldap, hostname, service)

        # See if we do any work at all here and if not raise an exception
        done_work = False

        if self.api.Command.ca_is_enabled()['result']:
            certs = entry_attrs.get('usercertificate', [])

            if len(certs) > 0:
                revoke_certs(certs, self.log)
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
class service_add_cert(LDAPAddAttribute):
    __doc__ = _('Add new certificates to a service')
    msg_summary = _('Added certificates to service principal "%(value)s"')
    attribute = 'usercertificate'


@register()
class service_remove_cert(LDAPRemoveAttribute):
    __doc__ = _('Remove certificates from a service')
    msg_summary = _('Removed certificates from service principal "%(value)s"')
    attribute = 'usercertificate'

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)

        if 'usercertificate' in options:
            revoke_certs(options['usercertificate'], self.log)

        return dn
