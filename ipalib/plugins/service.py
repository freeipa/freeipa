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
"""
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

 Generate and retrieve a keytab for an IPA service:
   ipa-getkeytab -s ipa.example.com -p HTTP/web.example.com -k /etc/httpd/httpd.keytab

"""
import base64
import os

from ipalib import api, errors, util
from ipalib import Str, Flag, Bytes
from ipalib.plugins.baseldap import *
from ipalib import x509
from ipalib import _, ngettext
from ipalib import util
import nss.nss as nss
from nss.error import NSPRError
from ipapython.ipautil import file_exists


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
    )
)

def split_principal(principal):
    service = hostname = realm = None

    # Break down the principal into its component parts, which may or
    # may not include the realm.
    sp = principal.split('/')
    if len(sp) != 2:
        raise errors.MalformedServicePrincipal(reason='missing service')

    service = sp[0]
    if len(service) == 0:
        raise errors.MalformedServicePrincipal(
            reason='blank service'
        )
    sr = sp[1].split('@')
    if len(sr) > 2:
        raise errors.MalformedServicePrincipal(
            reason='unable to determine realm'
        )

    hostname = sr[0].lower()
    if len(sr) == 2:
        realm = sr[1].upper()
        # At some point we'll support multiple realms
        if realm != api.env.realm:
            raise errors.RealmMismatch()
    else:
        realm = api.env.realm

    # Note that realm may be None.
    return (service, hostname, realm)

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
    For now just verify that it is properly base64-encoded.
    """
    if cert and util.isvalid_base64(cert):
        try:
            base64.b64decode(cert)
        except Exception, e:
            raise errors.Base64DecodeError(reason=str(e))
    else:
        # We'll assume this is DER data
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
    entry_attrs['issuer'] = unicode(cert.issuer)
    entry_attrs['valid_not_before'] = unicode(cert.valid_not_before_str)
    entry_attrs['valid_not_after'] = unicode(cert.valid_not_after_str)
    entry_attrs['md5_fingerprint'] = unicode(nss.data_to_hex(nss.md5_digest(cert.der_data), 64)[0])
    entry_attrs['sha1_fingerprint'] = unicode(nss.data_to_hex(nss.sha1_digest(cert.der_data), 64)[0])

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
    search_attributes = ['krbprincipalname', 'managedby']
    default_attributes = ['krbprincipalname', 'usercertificate', 'managedby', 'krblastpwdchange']
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'managedby': ['host'],
    }
    bindable = True
    relationships = {
        'managedby': ('Managed by', 'man_by_', 'not_man_by_'),
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
        Bytes('usercertificate?', validate_certificate,
            cli_name='certificate',
            label=_('Certificate'),
            doc=_('Base-64 encoded server certificate'),
            flags=['no_search',],
        )
    )

api.register(service)


class service_add(LDAPCreate):
    """
    Add a new IPA new service.
    """
    msg_summary = _('Added service "%(value)s"')
    member_attributes = ['managedby']
    has_output_params = LDAPCreate.has_output_params + output_params
    takes_options = (
        Flag('force',
            label=_('Force'),
            doc=_('force principal name even if not in DNS'),
        ),
    )
    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        (service, hostname, realm) = split_principal(keys[-1])
        if service.lower() == 'host' and not options['force']:
            raise errors.HostService()

        try:
            hostresult = api.Command['host_show'](hostname)['result']
        except errors.NotFound:
            raise errors.NotFound(reason="The host '%s' does not exist to add a service to." % hostname)

        cert = options.get('usercertificate')
        if cert:
            dercert = x509.normalize_certificate(cert)
            x509.verify_cert_subject(ldap, hostname, dercert)
            entry_attrs['usercertificate'] = dercert

        if not options.get('force', False):
             # We know the host exists if we've gotten this far but we
             # really want to discourage creating services for hosts that
             # don't exist in DNS.
             util.validate_host_dns(self.log, hostname)
        if not 'managedby' in entry_attrs:
             entry_attrs['managedby'] = hostresult['dn']

        return dn

api.register(service_add)


class service_del(LDAPDelete):
    """
    Delete an IPA service.
    """
    msg_summary = _('Deleted service "%(value)s"')
    member_attributes = ['managedby']
    def pre_callback(self, ldap, dn, *keys, **options):
        if self.api.env.enable_ra:
            (dn, entry_attrs) = ldap.get_entry(dn, ['usercertificate'])
            cert = entry_attrs.get('usercertificate')
            if cert:
                cert = cert[0]
                try:
                    serial = unicode(x509.get_serial_number(cert, x509.DER))
                    try:
                        result = api.Command['cert_show'](unicode(serial))['result']
                        if 'revocation_reason' not in result:
                            try:
                                api.Command['cert_revoke'](unicode(serial), revocation_reason=4)
                            except errors.NotImplementedError:
                                # some CA's might not implement revoke
                                pass
                    except errors.NotImplementedError:
                        # some CA's might not implement revoke
                        pass
                except NSPRError, nsprerr:
                    if nsprerr.errno == -8183:
                        # If we can't decode the cert them proceed with
                        # removing the service.
                        self.log.info("Problem decoding certificate %s" % nsprerr.args[1])
                    else:
                        raise nsprerr
        return dn

api.register(service_del)


class service_mod(LDAPUpdate):
    """
    Modify an existing IPA service.
    """
    msg_summary = _('Modified service "%(value)s"')
    takes_options = LDAPUpdate.takes_options
    has_output_params = LDAPUpdate.has_output_params + output_params

    member_attributes = ['managedby']

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if 'usercertificate' in options:
            (service, hostname, realm) = split_principal(keys[-1])
            cert = options.get('usercertificate')
            if cert:
                dercert = x509.normalize_certificate(cert)
                x509.verify_cert_subject(ldap, hostname, dercert)
                (dn, entry_attrs_old) = ldap.get_entry(dn, ['usercertificate'])
                if 'usercertificate' in entry_attrs_old:
                    # FIXME: what to do here? do we revoke the old cert?
                    fmt = 'entry already has a certificate, serial number: %s' % (
                        x509.get_serial_number(entry_attrs_old['usercertificate'][0], x509.DER)
                    )
                    raise errors.GenericError(format=fmt)
                entry_attrs['usercertificate'] = dercert
            else:
                entry_attrs['usercertificate'] = None
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        set_certificate_attrs(entry_attrs)

api.register(service_mod)


class service_find(LDAPSearch):
    """
    Search for IPA services.
    """
    msg_summary = ngettext(
        '%(count)d service matched', '%(count)d services matched', 0
    )
    member_attributes = ['managedby']
    takes_options = LDAPSearch.takes_options
    has_output_params = LDAPSearch.has_output_params + output_params
    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args, **options):
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
        for entry in entries:
            entry_attrs = entry[1]
            if 'krblastpwdchange' in entry_attrs:
                entry_attrs['has_keytab'] = True
                if not options.get('all', False):
                    del entry_attrs['krblastpwdchange']
            else:
                entry_attrs['has_keytab'] = False
            set_certificate_attrs(entry_attrs)

api.register(service_find)


class service_show(LDAPRetrieve):
    """
    Display information about an IPA service.
    """
    member_attributes = ['managedby']
    takes_options = LDAPRetrieve.takes_options + (
        Str('out?',
            doc=_('file to store certificate in'),
        ),
    )

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if 'krblastpwdchange' in entry_attrs:
            entry_attrs['has_keytab'] = True
            if not options.get('all', False):
                del entry_attrs['krblastpwdchange']
        else:
            entry_attrs['has_keytab'] = False

        set_certificate_attrs(entry_attrs)

        return dn

    def forward(self, *keys, **options):
        if 'out' in options:
            util.check_writable_file(options['out'])
            result = super(service_show, self).forward(*keys, **options)
            if 'usercertificate' in result['result']:
                x509.write_certificate(result['result']['usercertificate'][0], options['out'])
                result['summary'] = _('Certificate stored in file \'%(file)s\'') % dict(file=options['out'])
                return result
            else:
                raise errors.NoCertificateError(entry=keys[-1])
        else:
            return super(service_show, self).forward(*keys, **options)

api.register(service_show)

class service_add_host(LDAPAddMember):
    """
    Add hosts that can manage this service.
    """
    member_attributes = ['managedby']
    has_output_params = LDAPAddMember.has_output_params + output_params

api.register(service_add_host)


class service_remove_host(LDAPRemoveMember):
    """
    Remove hosts that can manage this service.
    """
    member_attributes = ['managedby']
    has_output_params = LDAPRemoveMember.has_output_params + output_params

api.register(service_remove_host)


class service_disable(LDAPQuery):
    """
    Disable the Kerberos key and SSL certificate of a service.
    """
    has_output = output.standard_value
    msg_summary = _('Disabled service "%(value)s"')
    has_output_params = LDAPQuery.has_output_params + output_params

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)
        (dn, entry_attrs) = ldap.get_entry(dn, ['krblastpwdchange', 'usercertificate'])

        # See if we do any work at all here and if not raise an exception
        done_work = False

        if 'usercertificate' in entry_attrs:
            cert = x509.normalize_certificate(entry_attrs.get('usercertificate')[0])
            try:
                serial = unicode(x509.get_serial_number(cert, x509.DER))
                try:
                    result = api.Command['cert_show'](unicode(serial))['result']
                    if 'revocation_reason' not in result:
                        try:
                            api.Command['cert_revoke'](unicode(serial), revocation_reason=4)
                        except errors.NotImplementedError:
                            # some CA's might not implement revoke
                            pass
                except errors.NotImplementedError:
                    # some CA's might not implement revoke
                    pass
            except NSPRError, nsprerr:
                if nsprerr.errno == -8183:
                    # If we can't decode the cert them proceed with
                    # disabling the service
                    self.log.info("Problem decoding certificate %s" % nsprerr.args[1])
                else:
                    raise nsprerr

            # Remove the usercertificate altogether
            ldap.update_entry(dn, {'usercertificate': None})
            done_work = True

        if 'krblastpwdchange' in entry_attrs:
            ldap.remove_principal_key(dn)
            done_work = True

        if not done_work:
            raise errors.AlreadyInactive()

        return dict(
            result=True,
            value=keys[0],
        )

api.register(service_disable)
