# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#   Rob Crittenden <rcritten@redhat.com>
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
Frontend plugins for service (Identity).
"""

from ipalib import api, crud, errors
from ipalib import Object  # Plugin base classes
from ipalib import Str, Flag, Bytes # Parameter types
import base64

default_attributes = ['krbprincipalname', 'usercertificate']

def validate_principal(ugettext, principal):
    # Break down the principal into its component parts, which may or
    # may not include the realm.
    sp = principal.split('/')
    if len(sp) != 2:
        raise errors.MalformedServicePrincipal(reason="missing service")

    sr = sp[1].split('@')
    if len(sr) > 2:
        raise errors.MalformedServicePrincipal(reason="unable to determine realm")

    if len(sr) == 2:
        realm = sr[1].upper()

        # At some point we'll support multiple realms
        if (realm != api.env.realm):
            raise errors.RealmMismatch()

def normalize_principal(principal):
    # The principal is already validated when it gets here
    sp = principal.split('/')
    service = sp[0]

    sr = sp[1].split('@')
    if len(sr) == 1:
        hostname = sr[0].lower()
        realm = api.env.realm
    elif len(sr) == 2:
        hostname = sr[0].lower()
        realm = sr[1].upper()

    # Put the principal back together again
    principal = service + "/" + hostname + "@" + realm

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
        Str('principal',
            validate_principal,
            primary_key=True,
            normalizer=lambda value: normalize_principal(value),
        ),
        Bytes('usercertificate?',
            validate_certificate,
            cli_name='certificate',
            doc='Base-64 encoded server certificate',
        ),
    )
api.register(service)


class service_add(crud.Add):
    """
    Add a new service.
    """

    takes_options = (
        Flag('force',
            doc='Force a service principal name even if not found in DNS',
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
        ldap = self.api.Backend.ldap

        force = kw.get('force', False)
        try:
            del kw['force']
        except:
            pass

        sp = principal.split('/')
        service = sp[0]

        if service.lower() == "host":
            raise errors.HostService()

        """
        FIXME once DNS client is done
        if not force:
            fqdn = hostname + "."
            rs = dnsclient.query(fqdn, dnsclient.DNS_C_IN, dnsclient.DNS_T_A)
            if len(rs) == 0:
                self.log.debug("IPA: DNS A record lookup failed for '%s'" % hostname)
                raise ipaerror.gen_exception(ipaerror.INPUT_NOT_DNS_A_RECORD)
            else:
                self.log.debug("IPA: found %d records for '%s'" % (len(rs), hostname))
        """

        # FIXME, should be in a normalizer. Need to fix normalizers to work
        # on non-unicode data
        if kw.get('usercertificate'):
            kw['usercertificate'] = base64.b64decode(kw['usercertificate'])

        dn = ldap.make_service_dn(principal)

        kw['dn'] = dn
        kw['objectclass'] = ['krbPrincipal', 'krbPrincipalAux', 'krbTicketPolicyAux', 'ipaService', 'pkiUser']

        return ldap.create(**kw)

    def output_for_cli(self, textui, result, *args, **options):
        textui.print_plain("Service added")
        textui.print_entry(result)

api.register(service_add)


class service_del(crud.Del):
    'Delete an existing service.'
    def execute(self, principal, **kw):
        """
        Delete a service principal.

        principal is the krbprincipalname of the entry to delete.

        This should be called with much care.

        :param principal: The service to be added in the form: service/hostname
        :param kw: not used
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("krbprincipalname", principal, object_type="ipaService")
        return ldap.delete(dn)

    def output_to_cli(self, ret):
        textui.print_plain("Service removed")

api.register(service_del)

class service_mod(crud.Update):
    'Update an existing service.'

    def execute(self, principal, **kw):
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("krbprincipalname", principal, object_type="ipaService")

        entry = ldap.retrieve(dn)
        if entry.get('usercertificate') and kw.get('usercertificate'):
            # FIXME, what to do here? Do we revoke the old cert?
            raise errors.GenericError(format='entry already has a certificate')

        # FIXME, should be in a normalizer. Need to fix normalizers to work
        # on non-unicode data.
        if kw.get('usercertificate'):
            kw['usercertificate'] = base64.b64decode(kw['usercertificate'])

        return ldap.update(dn, **kw)

    def output_to_cli(self, ret):
        textui.print_plain("Service updated")
        textui.print_entry(result)

api.register(service_mod)


class service_find(crud.Search):
    'Search the existing services.'
    takes_options = (
        Flag('all', doc='Retrieve all attributes'),
    )
    def execute(self, principal, **kw):
        ldap = self.api.Backend.ldap

        search_kw = {}
        search_kw['filter'] = "&(objectclass=ipaService)(!(objectClass=posixAccount))(!(|(krbprincipalname=kadmin/*)(krbprincipalname=K/M@*)(krbprincipalname=krbtgt/*)))"
        search_kw['krbprincipalname'] = principal

        object_type = ldap.get_object_type("krbprincipalname")
        if object_type and not kw.get('objectclass'):
            search_kw['objectclass'] = object_type

        if kw.get('all', False):
            search_kw['attributes'] = ['*']
        else:
            search_kw['attributes'] = default_attributes

        return ldap.search(**search_kw)

    def output_for_cli(self, textui, result, *args, **options):
        counter = result[0]
        services = result[1:]
        if counter == 0:
            textui.print_plain("No entries found")
            return

        for s in services:
            textui.print_entry(s)

        if counter == -1:
            textui.print_plain("These results are truncated.")
            textui.print_plain("Please refine your search and try again.")
        textui.print_count(services, '%d services matched')

api.register(service_find)


class service_show(crud.Get):
    'Examine an existing service.'
    takes_options = (
        Flag('all', doc='Display all service attributes'),
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
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("krbprincipalname", principal, object_type="ipaService")
        # FIXME: should kw contain the list of attributes to display?
        if kw.get('all', False):
            return ldap.retrieve(dn)
        else:
            return ldap.retrieve(dn, default_attributes)

    def output_for_cli(self, textui, result, *args, **options):
        textui.print_entry(result)

api.register(service_show)
