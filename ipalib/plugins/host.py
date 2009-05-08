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

from ipalib import api, crud, errors, util
from ipalib import Object  # Plugin base class
from ipalib import Str, Flag  # Parameter types
import sys
import os
import platform


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

def validate_host(ugettext, cn):
    """
    Require at least one dot in the hostname (to support localhost.localdomain)
    """
    dots = len(cn.split('.'))
    if dots < 2:
        return 'Fully-qualified hostname required'
    return None

default_attributes = ['cn','description','localityname','nshostlocation','nshardwareplatform','nsosversion']

def determine_os():
    (sysname, nodename, release, version, machine) = os.uname()
    if sys.platform == "linux2":
        # something like 'fedora 9 Sulpher'
        return unicode(" ".join(platform.dist()))
    else:
        # on Solaris this will be: 'SunOS 5.10'
        return unicode(sysname + " " + release)

def determine_platform():
    (sysname, nodename, release, version, machine) = os.uname()
    return unicode(machine)

class host(Object):
    """
    Host object.
    """
    takes_params = (
        Str('cn', validate_host,
            cli_name='hostname',
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description?',
            doc='Description of the host',
        ),
        Str('localityname?',
            cli_name='locality',
            doc='Locality of this host (Baltimore, MD)',
        ),
        Str('nshostlocation?',
            cli_name='location',
            doc='Location of this host (e.g. Lab 2)',
        ),
        Str('nshardwareplatform?',
            cli_name='platform',
            doc='Hardware platform of this host (e.g. Lenovo T61)',
            default=determine_platform(),
            autofill=True,
        ),
        Str('nsosversion?',
            cli_name='os',
            doc='Operating System and version on this host (e.g. Fedora 9)',
            default=determine_os(),
            autofill=True,
        ),
        Str('userpassword?',
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

        If password is set then this is considered a 'bulk' host so we
        do not create a kerberos service principal.

        Returns the entry as it will be created in LDAP.

        :param hostname: The name of the host being added.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'cn' not in kw
        assert 'dn' not in kw
        assert 'krbprincipalname' not in kw
        ldap = self.api.Backend.ldap

        kw['cn'] = hostname
        kw['serverhostname'] = hostname.split('.',1)[0]
        kw['dn'] = ldap.make_host_dn(hostname)

        # FIXME: do a DNS lookup to ensure host exists

        current = util.get_current_principal()
        if not current:
            raise errors.NotFound(reason='Unable to determine current user')
        kw['enrolledby'] = ldap.find_entry_dn("krbPrincipalName", current, "posixAccount")

        # Get our configuration
        config = ldap.get_ipa_config()

        # some required objectclasses
        # FIXME: add this attribute to cn=ipaconfig
        #kw['objectclass'] =  config.get('ipahostobjectclasses')
        kw['objectclass'] = ['nsHost', 'ipaHost', 'pkiUser']

        # Ensure the list of objectclasses is lower-case
        kw['objectclass'] = map(lambda z: z.lower(), kw.get('objectclass'))

        if not kw.get('userpassword', False):
            kw['krbprincipalname'] = "host/%s@%s" % (hostname, self.api.env.realm)

            if 'krbprincipalaux' not in kw.get('objectclass'):
               kw['objectclass'].append('krbprincipalaux')
               kw['objectclass'].append('krbprincipal')
        else:
            if 'krbprincipalaux' in kw.get('objectclass'):
                kw['objectclass'].remove('krbprincipalaux')

        return ldap.create(**kw)
    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_plain("Host added")

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

        # Remove all service records for this host
        services=api.Command['service_find'](hostname, **{})

        counter = services[0]
        services = services[1:]
        if counter > 0:
            for s in services:
                principal = s.get('krbprincipalname').decode('UTF-8')
                api.Command['service_del'](principal, **{})

        return ldap.delete(dn)
    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_plain("Host deleted")

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

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_plain("Host updated")

api.register(host_mod)


class host_find(crud.Find):
    'Search the hosts.'

    takes_options = (
        Flag('all', doc='Retrieve all attributes'),
    )

     # FIXME: This should no longer be needed with the Param.query kwarg.
#    def get_args(self):
#        """
#        Override Find.get_args() so we can exclude the validation rules
#        """
#        yield self.obj.primary_key.__clone__(rules=tuple())

    def execute(self, term, **kw):
        ldap = self.api.Backend.ldap

        # Pull the list of searchable attributes out of the configuration.
        #config = ldap.get_ipa_config()
        # FIXME: add this attribute to cn=ipaconfig
        #search_fields_conf_str = config.get('ipahostsearchfields')
        #search_fields = search_fields_conf_str.split(",")
        search_fields = ['cn','serverhostname','description','localityname','nshostlocation','nshardwareplatform','nsosversion']

        search_kw = {}
        for s in search_fields:
            search_kw[s] = term

        # Can't use ldap.get_object_type() since cn is also used for group dns
        search_kw['objectclass'] = "ipaHost"
        if kw.get('all', False):
            search_kw['attributes'] = ['*']
        else:
            search_kw['attributes'] = default_attributes
        return ldap.search(**search_kw)
    def output_for_cli(self, textui, result, *args, **options):
        counter = result[0]
        hosts = result[1:]
        if counter == 0:
            textui.print_plain("No entries found")
            return

        for h in hosts:
            textui.print_entry(h)
        if counter == -1:
            textui.print_plain("These results are truncated.")
            textui.print_plain("Please refine your search and try again.")
api.register(host_find)


class host_show(crud.Get):
    'Examine an existing host.'
    takes_options = (
        Flag('all', doc='Display all host attributes'),
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
            value = ldap.retrieve(dn, default_attributes)
            del value['dn']
            return value
    def output_for_cli(self, textui, result, *args, **options):
        textui.print_entry(result)

api.register(host_show)
