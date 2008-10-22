# Authors:
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
Frontend plugins for host/machine Identity.
"""

from ipalib import frontend
from ipalib import crud
from ipalib import util
from ipalib.frontend import Param
from ipalib import api
from ipalib import errors
from ipalib import ipa_types


def get_host(hostname):
    """
    Try to get the hostname as fully-qualified first, then fall back to
    just a host name search.
    """
    ldap = api.Backend.ldap

    # Strip off trailing dot
    if hostname.endswith('.'):
        hostname = hostname[:-1]
    try:
        dn = ldap.find_entry_dn("cn", hostname, "ipaHost")
    except errors.NotFound:
        dn = ldap.find_entry_dn("serverhostname", hostname, "ipaHost")
    return dn

def validate_host(cn):
    """
    Require at least one dot in the hostname (to support localhost.localdomain)
    """
    dots = len(cn.split('.'))
    if dots < 2:
        return 'Fully-qualified hostname required'
    return None


class host(frontend.Object):
    """
    Host object.
    """
    takes_params = (
        Param('cn',
            cli_name='hostname',
            primary_key=True,
            normalize=lambda value: value.lower(),
            rules=(validate_host,)
        ),
        Param('description?',
            doc='Description of the host',
        ),
        Param('localityname?',
            cli_name='locality',
            doc='Locality of this host (Baltimore, MD)',
        ),
        Param('nshostlocation?',
            cli_name='location',
            doc='Location of this host (e.g. Lab 2)',
        ),
        Param('nshardwareplatform?',
            cli_name='platform',
            doc='Hardware platform of this host (e.g. Lenovo T61)',
        ),
        Param('nsosversion?',
            cli_name='os',
            doc='Operating System and version on this host (e.g. Fedora 9)',
        ),
        Param('userpassword?',
            cli_name='password',
            doc='Set a password to be used in bulk enrollment',
        ),
    )
api.register(host)


class host_add(crud.Add):
    'Add a new host.'
    def execute(self, hostname, **kw):
        """
        Execute the host-add operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry as it will be created in LDAP.

        :param hostname: The name of the host being added.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'cn' not in kw
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap

        kw['cn'] = hostname
        kw['serverhostname'] = hostname.split('.',1)[0]
        kw['dn'] = ldap.make_host_dn(hostname)
        kw['krbPrincipalName'] = "host/%s@%s" % (hostname, self.api.env.realm)

        # FIXME: do a DNS lookup to ensure host exists

        current = util.get_current_principal()
        if not current:
            raise errors.NotFound('Unable to determine current user')
        kw['enrolledBy'] = ldap.find_entry_dn("krbPrincipalName", current, "person")

        # Get our configuration
        config = ldap.get_ipa_config()

        # some required objectclasses
        # FIXME: add this attribute to cn=ipaconfig
        #kw['objectClass'] =  config.get('ipahostobjectclasses')
        kw['objectClass'] = ['nsHost', 'krbPrincipalAux', 'ipaHost']

        return ldap.create(**kw)
    def output_for_cli(self, ret):
        """
        Output result of this command to command line interface.
        """
        if ret:
            print "Host added"

api.register(host_add)


class host_del(crud.Del):
    'Delete an existing host.'
    def execute(self, hostname, **kw):
        """Delete a host.

           hostname is the name of the host to delete

           :param hostname: The name of the host being removed.
           :param kw: Not used.
        """
        ldap = self.api.Backend.ldap
        dn = get_host(hostname)
        return ldap.delete(dn)
    def output_for_cli(self, ret):
        """
        Output result of this command to command line interface.
        """
        if ret:
            print "Host deleted"

api.register(host_del)


class host_mod(crud.Mod):
    'Edit an existing host.'
    def execute(self, hostname, **kw):
        """
        Execute the host-mod operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param hostname: The name of the host to retrieve.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'cn' not in kw
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap
        dn = get_host(hostname)
        return ldap.update(dn, **kw)

    def output_for_cli(self, ret):
        """
        Output result of this command to command line interface.
        """
        if ret:
            print "Host updated"

api.register(host_mod)


class host_find(crud.Find):
    'Search the hosts.'
    def get_args(self):
        """
        Override Find.get_args() so we can exclude the validation rules
        """
        yield self.obj.primary_key.__clone__(rules=tuple())
    def execute(self, term, **kw):
        ldap = self.api.Backend.ldap

        # Pull the list of searchable attributes out of the configuration.
        #config = ldap.get_ipa_config()
        # FIXME: add this attribute to cn=ipaconfig
        #search_fields_conf_str = config.get('ipahostsearchfields')
        #search_fields = search_fields_conf_str.split(",")
        search_fields = ['cn','serverhostname','description','localityname','nshostlocation','nshardwareplatform','nsosversion']

        for s in search_fields:
            kw[s] = term

        # Can't use ldap.get_object_type() since cn is also used for group dns
        kw['objectclass'] = "ipaHost"
        return ldap.search(**kw)
    def output_for_cli(self, hosts):
        if not hosts:
            return
        counter = hosts[0]
        hosts = hosts[1:]
        if counter == 0:
            print "No entries found"
            return
        elif counter == -1:
            print "These results are truncated."
            print "Please refine your search and try again."

        for h in hosts:
            for a in h.keys():
                print "%s: %s" % (a, h[a])
api.register(host_find)


class host_show(crud.Get):
    'Examine an existing host.'
    takes_options = (
        Param('all?', type=ipa_types.Bool(), doc='Display all host attributes'),
    )
    def execute(self, hostname, **kw):
        """
        Execute the host-show operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param hostname: The login name of the host to retrieve.
        :param kw: "all" set to True = return all attributes
        """
        ldap = self.api.Backend.ldap
        dn = get_host(hostname)
        # FIXME: should kw contain the list of attributes to display?
        if kw.get('all', False):
            return ldap.retrieve(dn)
        else:
            value = ldap.retrieve(dn, ['cn','description','localityname','nshostlocation','nshardwareplatform','nsosversion'])
            del value['dn']
            return value
    def output_for_cli(self, host):
        if host:
            for a in host.keys():
                print "%s: %s" % (a, host[a])

api.register(host_show)
