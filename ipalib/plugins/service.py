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

from OpenSSL import crypto

from ipalib import api, crud, errors
from ipalib import Object
from ipalib import Str, Flag, Bytes

_container_dn = api.env.container_service
_default_attributes = ['krbprincipalname', 'usercertificate']


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


class service(Object):
    """
    Service object.
    """
    takes_params = (
        Str('krbprincipalname', validate_principal,
            cli_name='principal',
            doc='Service principal',
            primary_key=True,
            normalizer=lambda value: normalize_principal(value),
        ),
        Bytes('usercertificate?', validate_certificate,
            cli_name='certificate',
            doc='Base-64 encoded server certificate',
        ),
    )

api.register(service)


class service_add(crud.Create):
    """
    Add new service.
    """
    takes_options = (
        Flag('force',
            doc='Force principal name even if not in DNS',
        ),
    )
    def execute(self, principal, **kw):
        """
        Execute the service-add operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry as it will be created in LDAP.

        :param principal: The service to be added in the form: service/hostname
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'krbprincipalname' not in kw
        ldap = self.api.Backend.ldap2
        # FIXME: should be in a normalizer. Need to fix normalizers to work
        # on non-unicode data
        if kw.get('usercertificate'):
            kw['usercertificate'] = base64.b64decode(kw['usercertificate'])

        (service, hostname, realm) = split_principal(principal)

        if service.lower() == 'host' and not kw['force']:
            raise errors.HostService()

        # FIXME: once DNS client is done
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

        entry_attrs = self.args_options_2_entry(principal, **kw)
        entry_attrs['objectclass'] = [
            'krbprincipal', 'krbprincipalaux', 'krbticketpolicyaux',
            'ipaservice', 'pkiuser'
        ]
        dn = ldap.make_dn(entry_attrs, 'krbprincipalname', _container_dn)

        ldap.add_entry(dn, entry_attrs)

        return ldap.get_entry(dn, entry_attrs.keys())

    def output_for_cli(self, textui, result, principal, **options):
        (dn, entry_attrs) = result

        textui.print_name(self.name)
        textui.print_attribute('dn', dn)
        textui.print_entry(entry_attrs)
        textui.print_dashed('Created service "%s".' % principal)

api.register(service_add)


class service_del(crud.Delete):
    """
    Delete an existing service.
    """
    def execute(self, principal, **kw):
        """
        Delete a service principal.

        principal is the krbprincipalname of the entry to delete.

        This should be called with much care.

        :param principal: The service to be added in the form: service/hostname
        :param kw: not used
        """
        ldap = self.api.Backend.ldap2

        (dn, entry_attrs) = ldap.find_entry_by_attr(
            'krbprincipalname', principal, 'ipaservice'
        )

        if 'usercerfificate' in entry_attrs:
            cert = entry_attrs['usercertificate']
            x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
            serial = str(x509.get_serial_number())
            api.Command['cert_revoke'](unicode(serial), revocation_reason=5)

        ldap.delete_entry(dn)

        return True

    def output_for_cli(self, textui, result, principal, **options):
        textui.print_name(self.name)
        textui.print_dashed('Deleted service "%s".' % principal)

api.register(service_del)


class service_mod(crud.Update):
    """
    Modify service.
    """
    def execute(self, principal, **kw):
        ldap = self.api.Backend.ldap
        # FIXME, should be in a normalizer. Need to fix normalizers to work
        # on non-unicode data.
        if kw.get('usercertificate'):
            kw['usercertificate'] = base64.b64decode(kw['usercertificate'])

        dn = ldap.make_dn(entry_attrs, 'krbprincipalname', _container_dn)

        (dn, old_entry_attrs) = ldap.get_entry(dn)
        if 'usercertificate' in old_entry_attrs and 'usercerficate' in kw:
            # FIXME, what to do here? Do we revoke the old cert?
            raise errors.GenericError(format='entry already has a certificate')

        entry_attrs = self.args_options_to_entry(principal, **kw)

        try:
            ldap.update_entry(dn, entry_attrs)
        except errors.EmptyModlist:
            pass

        return ldap.get_entry(dn, entry_attrs.keys())

    def output_to_cli(self, textui, result, principal, **options):
        (dn, entry_attrs) = result

        textui.print_name(self.name)
        textui.print_attribute('dn', dn)
        textui.print_entry(entry_attrs)
        textui.print_dashed('Modified service "%s".' % principal)

api.register(service_mod)


class service_find(crud.Search):
    """
    Search for services.
    """
    takes_options = (
        Flag('all',
            doc='Retrieve all attributes'
        ),
    )

    def execute(self, term, **kw):
        ldap = self.api.Backend.ldap2

        # lisp style!
        custom_filter = '(&(objectclass=ipaService)' \
                          '(!(objectClass=posixAccount))' \
                          '(!(|(krbprincipalname=kadmin/*)' \
                              '(krbprincipalname=K/M@*)' \
                              '(krbprincipalname=krbtgt/*))' \
                          ')' \
                        ')'

        search_kw = self.args_options_2_entry(**kw)
        search_kw['objectclass'] = 'krbprincipal'
        filter = ldap.make_filter(search_kw, rules=ldap.MATCH_ALL)

        search_kw = {}
        for a in _default_attributes:
            search_kw[a] = term
        term_filter = ldap.make_filter(search_kw, exact=False)

        filter = ldap.combine_filters(
            (custom_filter, filter, term_filter), rules=ldap.MATCH_ALL
        )

        if kw['all']:
            attrs_list = ['*']
        else:
            attrs_list = _default_attributes

        try:
            (entries, truncated) = ldap.find_entries(
                filter, attrs_list, _container_dn
            )
        except errors.NotFound:
            (entries, truncated) = (tuple(), False)

        return entries

    def output_for_cli(self, textui, result, principal, **options):
        (entries, truncated) = result

        textui.print_name(self.name)
        for (dn, entry_attrs) in entries:
            textui.print_attribute('dn', dn)
            textui.print_entry(entry_attrs)
            textui.print_plain('')
        textui.print_count(
            len(result), '%i service matched.', '%i services matched.'
        )
        if truncated:
            textui.print_dashed('These results are truncated.', below=False)
            textui.print_dashed(
                'Please refine your search and try again.', above=False
            )

api.register(service_find)


class service_show(crud.Retrieve):
    """
    Display service.
    """
    takes_options = (
        Flag('all',
            doc='Retrieve all attributes'
        ),
    )

    def execute(self, principal, **kw):
        """
        Execute the service-show operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param principal: The service principal to retrieve
        :param kw: Not used.
        """
        ldap = self.api.Backend.ldap2

        dn = ldap.make_dn_from_attr(
            'krbprincipalname', principal, _container_dn
        )

        if kw['all']:
            attrs_list = ['*']
        else:
            attrs_list = _default_attributes

        return ldap.get_entry(dn, attrs_list)

    def output_for_cli(self, textui, result, principal, **options):
        (dn, entry_attrs) = result

        textui.print_name(self.name)
        textui.print_attribute('dn', dn)
        textui.print_entry(entry_attrs)

api.register(service_show)

