# Authors:
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
Hosts/Machines (Identity)
"""

import platform
import os
import sys

from ipalib import api, crud, errors, util
from ipalib import Object
from ipalib import Str, Flag
from ipalib.plugins.service import split_principal

_container_dn = api.env.container_host
_default_attributes = [
    'fqdn', 'description', 'localityname', 'nshostlocation',
    'nshardwareplatform', 'nsosversion'
]


def get_host(ldap, hostname):
    """
    Try to get the hostname as fully-qualified first, then fall back to
    just a host name search.
    """
    if hostname.endswith('.'):
        hostname = hostname[:-1]
    try:
        dn = ldap.find_entry_by_attr('fqdn', hostname, 'ipaHost')[0]
    except errors.NotFound:
        dn = ldap.find_entry_by_attr('serverhostname', hostname, 'ipaHost')[0]
    return dn

def validate_host(ugettext, fqdn):
    """
    Require at least one dot in the hostname (to support localhost.localdomain)
    """
    if fqdn.index('.') == -1:
        return 'Fully-qualified hostname required'
    return None

def determine_os():
    """
    Return OS name (e.g. redhat 10 Cambridge).
    """
    (sysname, nodename, release, version, machine) = os.uname()
    if sys.platform == 'linux2':
        # something like 'fedora 9 Sulpher'
        return unicode(' '.join(platform.dist()))
    else:
        # on Solaris this will be: 'SunOS 5.10'
        return unicode(sysname + ' ' + release)

def determine_platform():
    """
    Return platform name (e.g. i686).
    """
    (sysname, nodename, release, version, machine) = os.uname()
    return unicode(machine)


class host(Object):
    """
    Host object.
    """
    takes_params = (
        # FIXME: All Object params get cloned with query=True in the new
        #        CRUD base classes, so there's no validation going on
        Str('fqdn', validate_host,
            cli_name='hostname',
            doc='Hostname',
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description?',
            doc='Description of the host',
        ),
        Str('localityname?',
            cli_name='locality',
            doc='Locality of the host (Baltimore, MD)',
        ),
        Str('nshostlocation?',
            cli_name='location',
            doc='Location of the host (e.g. Lab 2)',
        ),
        Str('nshardwareplatform?',
            cli_name='platform',
            doc='Hardware platform of the host (e.g. Lenovo T61)',
            default=determine_platform(),
            autofill=True,
        ),
        Str('nsosversion?',
            cli_name='os',
            doc='Operating System and version of the host (e.g. Fedora 9)',
            default=determine_os(),
            autofill=True,
        ),
        Str('userpassword?',
            cli_name='password',
            doc='Password used in bulk enrollment',
        ),
    )

api.register(host)


class host_add(crud.Create):
    """
    Create new host.
    """
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
        assert 'fqdn' not in kw
        assert 'cn' not in kw
        assert 'dn' not in kw
        assert 'krbprincipalname' not in kw
        ldap = self.api.Backend.ldap2

        entry_attrs = self.args_options_2_entry(hostname, **kw)
        entry_attrs['cn'] = hostname
        entry_attrs['serverhostname'] = hostname.split('.', 1)[0]

        dn = ldap.make_dn(entry_attrs, 'fqdn', _container_dn)

        # FIXME: do a DNS lookup to ensure host exists

        current = util.get_current_principal()
        if not current:
            raise errors.NotFound(reason='Unable to determine current user')
        entry_attrs['enrolledby'] = ldap.find_entry_by_attr(
            'krbprincipalname', current, 'posixAccount'
        )[0]

        # FIXME: add this attribute to cn=ipaconfig
        # config = ldap.get_ipa_config()[1]
        # kw['objectclass'] =  config.get('ipahostobjectclasses')
        entry_attrs['objectclass'] = ['nshost', 'ipahost', 'pkiuser']

        if 'userpassword' not in entry_attrs:
            entry_attrs['krbprincipalname'] = 'host/%s@%s' % (
                hostname, self.api.env.realm
            )
            if 'krbprincipalaux' not in entry_attrs['objectclass']:
                entry_attrs['objectclass'].append('krbprincipalaux')
                entry_attrs['objectclass'].append('krbprincipal')
        elif 'krbprincipalaux' in entry_attrs['objectclass']:
            entry_attrs['objectclass'].remove('krbprincipalaux')

        ldap.add_entry(dn, entry_attrs)

        return ldap.get_entry(dn, entry_attrs.keys())

    def output_for_cli(self, textui, result, hostname, **options):
        """
        Output result of this command to command line interface.
        """
        (dn, entry_attrs) = result

        textui.print_name(self.name)
        textui.print_attribute('dn', dn)
        textui.print_entry(entry_attrs)
        textui.print_dashed('Created host "%s".' % hostname)

api.register(host_add)


class host_del(crud.Delete):
    """
    Delete host.
    """
    def execute(self, hostname, **kw):
        """
        Delete a host.

        hostname is the name of the host to delete

        :param hostname: The name of the host being removed.
        :param kw: Not used.
        """
        ldap = self.api.Backend.ldap2
        dn = get_host(ldap, hostname)
        hostname = hostname.lower()

        # Remove all service records for this host
        (services, truncated) = api.Command['service_find'](hostname)
        for (dn_, entry_attrs) in services:
            principal = entry_attrs['krbprincipalname'][0]
            (service, hostname_, realm) = split_principal(principal)
            if hostname_.lower() == hostname:
                api.Command['service_del'](principal)

        ldap.delete_entry(dn)

        return True

    def output_for_cli(self, textui, result, hostname, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_name(self.name)
        textui.print_dashed('Deleted host "%s".' % hostname)

api.register(host_del)


class host_mod(crud.Update):
    """
    Modify host.
    """
    def execute(self, hostname, **kw):
        """
        Execute the host-mod operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param hostname: The name of the host to retrieve.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'fqdn' not in kw
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap2
        dn = get_host(ldap, hostname)

        entry_attrs = self.args_options_2_entry(**kw)

        try:
            ldap.update_entry(dn, entry_attrs)
        except errors.EmptyModlist:
            pass

        return ldap.get_entry(dn, entry_attrs.keys())

    def output_for_cli(self, textui, result, hostname, **options):
        """
        Output result of this command to command line interface.
        """
        (dn, entry_attrs) = result

        textui.print_name(self.name)
        textui.print_attribute('dn', dn)
        textui.print_entry(entry_attrs)
        textui.print_dashed('Modified host "%s".' % hostname)

api.register(host_mod)


class host_find(crud.Search):
    """
    Search for hosts.
    """

    takes_options = (
        Flag('all',
            doc='Retrieve all attributes'
        ),
    )

    def execute(self, term, **kw):
        ldap = self.api.Backend.ldap2

        search_kw = self.args_options_2_entry(**kw)
        search_kw['objectclass'] = 'ipaHost'
        filter = ldap.make_filter(search_kw, rules=ldap.MATCH_ALL)

        search_kw = {}
        for a in _default_attributes:
            search_kw[a] = term
        term_filter = ldap.make_filter(search_kw, exact=False)

        filter = ldap.combine_filters(
            (filter, term_filter), rules=ldap.MATCH_ALL
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

        return (entries, truncated)

    def output_for_cli(self, textui, result, term, **options):
        (entries, truncated) = result

        textui.print_name(self.name)
        for (dn, entry_attrs) in entries:
            textui.print_attribute('dn', dn)
            textui.print_entry(entry_attrs)
            textui.print_plain('')
        textui.print_count(
            len(entries), '%i host matched.', '%i hosts matched.'
        )
        if truncated:
            textui.print_dashed('These results are truncated.', below=False)
            textui.print_dashed(
                'Please refine your search and try again.', above=False
            )

api.register(host_find)


class host_show(crud.Retrieve):
    """
    Display host.
    """
    takes_options = (
        Flag('all',
            doc='Retrieve all attributes'
        ),
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
        ldap = self.api.Backend.ldap2
        dn = get_host(ldap, hostname)

        if kw['all']:
            attrs_list = ['*']
        else:
            attrs_list = _default_attributes

        return ldap.get_entry(dn, attrs_list)

    def output_for_cli(self, textui, result, *args, **options):
        (dn, entry_attrs) = result

        textui.print_name(self.name)
        textui.print_attribute('dn', dn)
        textui.print_entry(entry_attrs)

api.register(host_show)

