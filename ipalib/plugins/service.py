# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
"""
Services (Identity)
"""
import base64

from ipalib import api, errors
from ipalib import Str, Flag, Bytes
from ipalib.plugins.baseldap import *
from ipalib import x509
from pyasn1.error import PyAsn1Error
from ipalib import _, ngettext


def get_serial(certificate):
    """
    Given a certificate, return the serial number in that
    cert as a Python long object.
    """
    if type(certificate) in (list, tuple):
        certificate = certificate[0]

    try:
        serial = x509.get_serial_number(certificate, type=x509.DER)
    except PyAsn1Error, e:
        raise errors.GenericError(
            format='Unable to decode certificate in entry: %s' % e
        )
    return serial

def split_principal(principal):
    service = hostname = realm = None

    # Break down the principal into its component parts, which may or
    # may not include the realm.
    sp = principal.split('/')
    if len(sp) != 2:
        raise errors.MalformedServicePrincipal(reason='missing service')

    service = sp[0]
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
    try:
        base64.b64decode(cert)
    except Exception, e:
        raise errors.Base64DecodeError(reason=str(e))


class service(LDAPObject):
    """
    Service object.
    """
    container_dn = api.env.container_service
    object_name = 'service'
    object_name_plural = 'services'
    object_class = [
        'krbprincipal', 'krbprincipalaux', 'krbticketpolicyaux', 'ipaobject',
        'ipaservice', 'pkiuser'
    ]
    default_attributes = ['krbprincipalname', 'usercertificate', 'managedby']
    uuid_attribute = 'ipauniqueid'
    attribute_names = {
        'krbprincipalname': 'kerberos principal',
        'usercertificate': 'user certificate',
        'ipauniqueid': 'unique identifier',
        'managedby': 'managed by',
    }
    attribute_members = {
        'managedby': ['host'],
    }

    label = _('Services')

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
        ),
    )

api.register(service)


class service_add(LDAPCreate):
    """
    Add new service.
    """
    msg_summary = _('Added service "%(value)s"')
    member_attributes = ['managedby']
    takes_options = (
        Flag('force',
            doc='force principal name even if not in DNS',
        ),
    )
    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        (service, hostname, realm) = split_principal(keys[-1])
        if service.lower() == 'host' and not options['force']:
            raise errors.HostService()

        try:
            api.Command['host_show'](hostname)
        except errors.NotFound:
            raise errors.NotFound(reason="The host '%s' does not exist to add a service to." % hostname)

        cert = entry_attrs.get('usercertificate')
        if cert:
            # FIXME: should be in a normalizer: need to fix normalizers
            #        to work on non-unicode data
            entry_attrs['usercertificate'] = base64.b64decode(cert)
            # FIXME: shouldn't we request signing at this point?

        # TODO: once DNS client is done (code below for reference only!)
        # if not kw['force']:
        #     fqdn = hostname + '.'
        #     rs = dnsclient.query(fqdn, dnsclient.DNS_C_IN, dnsclient.DNS_T_A)
        #     if len(rs) == 0:
        #         self.log.debug(
        #             'IPA: DNS A record lookup failed for '%s'" % hostname
        #         )
        #         raise ipaerror.gen_exception(ipaerror.INPUT_NOT_DNS_A_RECORD)
        #     else:
        #         self.log.debug(
        #             'IPA: found %d records for '%s'" % (len(rs), hostname)
        #         )

        return dn

api.register(service_add)


class service_del(LDAPDelete):
    """
    Delete an existing service.
    """
    msg_summary = _('Deleted service "%(value)s"')
    member_attributes = ['managedby']
    def pre_callback(self, ldap, dn, *keys, **options):
        if self.api.env.enable_ra:
            (dn, entry_attrs) = ldap.get_entry(dn, ['usercertificate'])
            cert = entry_attrs.get('usercertificate')
            if cert:
                serial = unicode(get_serial(cert))
                try:
                    self.api.Command['cert_revoke'](serial, revocation_reason=5)
                except errors.NotImplementedError:
                    # selfsign CA doesn't do revocation
                    pass
        return dn

api.register(service_del)


class service_mod(LDAPUpdate):
    """
    Modify service.
    """
    member_attributes = ['managedby']
    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        cert = entry_attrs.get('usercertificate')
        if cert:
            (dn, entry_attrs_old) = ldap.get_entry(dn, ['usercertificate'])
            if 'usercertificate' in entry_attrs_old:
                # FIXME: what to do here? do we revoke the old cert?
                fmt = 'entry already has a certificate, serial number: %s' % (
                    get_serial(entry_attrs_old['usercertificate'])
                )
                raise errors.GenericError(format=fmt)
            # FIXME: should be in normalizer; see service_add
            entry_attrs['usercertificate'] = base64.b64decode(cert)
        return dn

api.register(service_mod)


class service_find(LDAPSearch):
    """
    Search for services.
    """
    member_attributes = ['managedby']
    def pre_callback(self, ldap, filter, attrs_list, base_dn, *args, **options):
        # lisp style!
        custom_filter = '(&(objectclass=ipaService)' \
                          '(!(objectClass=posixAccount))' \
                          '(!(|(krbprincipalname=kadmin/*)' \
                              '(krbprincipalname=K/M@*)' \
                              '(krbprincipalname=krbtgt/*))' \
                          ')' \
                        ')'
        return ldap.combine_filters(
            (custom_filter, filter), rules=ldap.MATCH_ALL
        )

api.register(service_find)


class service_show(LDAPRetrieve):
    """
    Display service.
    """
    member_attributes = ['managedby']

api.register(service_show)

class service_add_host(LDAPAddMember):
    """
    Add hosts that can manage this service.
    """
    member_attributes = ['managedby']

api.register(service_add_host)


class service_remove_host(LDAPRemoveMember):
    """
    Remove hosts that can manage this service.
    """
    member_attributes = ['managedby']

api.register(service_remove_host)
