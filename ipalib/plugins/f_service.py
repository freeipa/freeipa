# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
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

from ipalib import frontend
from ipalib import crud
from ipalib.frontend import Param
from ipalib import api
from ipalib import errors
from ipalib import ipa_types
from ipa_server import servercore
from ipa_server import ipaldap
import ldap

class service(frontend.Object):
    """
    Service object.
    """
    takes_params = (
        Param('principal', primary_key=True),
    )
api.register(service)


class service_add(crud.Add):
    'Add a new service.'
    """
    my_params = (
        Param('force', type=ipa_types.Bool(), default=False),
    )
    def get_options(self):
        for param in self.my_params:
            yield param
    """
    def execute(self, *args, **kw):
        """args[0] = service principal to add
           kw{force} determines whether we continue on errors
        """
        force = kw.get('force', False)

        principal = args[0]

        # Break down the principal into its component parts, which may or
        # may not include the realm.
        sp = principal.split('/')
        if len(sp) != 2:
            raise errors.MalformedServicePrincipal
        service = sp[0]

        sr = sp[1].split('@')
        if len(sr) == 1:
            hostname = sr[0].lower()
            realm = servercore.realm
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
                logging.debug("IPA: DNS A record lookup failed for '%s'" % hostname)
                raise ipaerror.gen_exception(ipaerror.INPUT_NOT_DNS_A_RECORD)
            else:
                logging.debug("IPA: found %d records for '%s'" % (len(rs), hostname))
        """

        service_container = servercore.DefaultServiceContainer

        # At some point we'll support multiple realms
        if (realm != servercore.realm):
            raise errors.RealmMismatch

        # Put the principal back together again
        princ_name = service + "/" + hostname + "@" + realm

        dn = "krbprincipalname=%s,%s,%s" % (ldap.dn.escape_dn_chars(princ_name),
                                            service_container,servercore.basedn)
        entry = ipaldap.Entry(dn)

        entry.setValues('objectClass', 'krbPrincipal', 'krbPrincipalAux', 'krbTicketPolicyAux')
        entry.setValues('krbprincipalname', princ_name)

        result = servercore.add_entry(entry)
        return result
    def forward(self, *args, **kw):
        result = super(crud.Add, self).forward(*args, **kw)
        if result:
            print "Service %s added" % args[0]
api.register(service_add)


class service_del(crud.Del):
    'Delete an existing service.'
    def execute(self, *args, **kw):
        """args[0] = princial to remove

           Delete a service principal.

           principal is the full DN of the entry to delete.

           This should be called with much care.
        """
        principal = args[0]
        return False
    def forward(self, *args, **kw):
        result = super(crud.Del, self).forward(*args, **kw)
        if result:
            print "Service %s removed" % args[0]
api.register(service_del)


class service_mod(crud.Mod):
    'Edit an existing service.'
api.register(service_mod)


class service_find(crud.Find):
    'Search the existing services.'
api.register(service_find)


class service_show(crud.Get):
    'Examine an existing service.'
    def execute(self, *args, **kw):
        filter = "(&(objectclass=krbPrincipalAux)(!(objectClass=person))(!(|(krbprincipalname=kadmin/*)(krbprincipalname=K/M@*)(krbprincipalname=krbtgt/*)))(&(|(krbprincipalname=%s))))" % args[0]
        result = servercore.get_sub_entry(servercore.basedn, filter,  ["*"])
        return result
    def forward(self, *args, **kw):
        result = super(crud.Get, self).forward(*args, **kw)
        return result
api.register(service_show)
