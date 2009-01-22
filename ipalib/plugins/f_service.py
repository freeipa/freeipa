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
from ipalib import Str, Flag # Parameter types


class service(Object):
    """
    Service object.
    """
    takes_params = (
        Str('principal', primary_key=True),
    )
api.register(service)


class service_add(crud.Add):
    """
    Add a new service.
    """

    takes_options = (
        Flag('force',
            doc='Force a service principal name',
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

        # Break down the principal into its component parts, which may or
        # may not include the realm.
        sp = principal.split('/')
        if len(sp) != 2:
            raise errors.MalformedServicePrincipal
        service = sp[0]

        if service.lower() == "host":
            raise errors.HostService

        sr = sp[1].split('@')
        if len(sr) == 1:
            hostname = sr[0].lower()
            realm = self.api.env.realm
        elif len(sr) == 2:
            hostname = sr[0].lower()
            realm = sr[1]
        else:
            raise MalformedServicePrincipal

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

        # At some point we'll support multiple realms
        if (realm != self.api.env.realm):
            raise errors.RealmMismatch

        # Put the principal back together again
        princ_name = service + "/" + hostname + "@" + realm

        dn = ldap.make_service_dn(princ_name)

        kw['dn'] = dn
        kw['objectClass'] = ['krbPrincipal', 'krbPrincipalAux', 'krbTicketPolicyAux']

        return ldap.create(**kw)

    def output_to_cli(self, ret):
        if ret:
            print "Service added"

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
        dn = ldap.find_entry_dn("krbprincipalname", principal)
        return ldap.delete(dn)

    def output_to_cli(self, ret):
        if ret:
            print "Service removed"

api.register(service_del)

# There is no service-mod. The principal itself contains nothing that
# is user-changeable

class service_find(crud.Find):
    'Search the existing services.'
    def execute(self, principal, **kw):
        ldap = self.api.Backend.ldap

        search_kw = {}
        search_kw['filter'] = "&(objectclass=krbPrincipalAux)(!(objectClass=posixAccount))(!(|(krbprincipalname=kadmin/*)(krbprincipalname=K/M@*)(krbprincipalname=krbtgt/*)))"
        search_kw['krbprincipalname'] = principal

        object_type = ldap.get_object_type("krbprincipalname")
        if object_type and not kw.get('objectclass'):
            search_kw['objectclass'] = object_type

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
        dn = ldap.find_entry_dn("krbprincipalname", principal)
        # FIXME: should kw contain the list of attributes to display?
        return ldap.retrieve(dn)
    def output_for_cli(self, textui, result, *args, **options):
        textui.print_entry(result)

api.register(service_show)
