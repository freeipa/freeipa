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

from ipalib import api, errors, util
from ipalib import Str, Flag, Bytes
from ipalib.plugins.baseldap import *
from ipalib.plugins.service import split_principal
from ipalib.plugins.service import validate_certificate
from ipalib.plugins.service import get_serial
from ipalib import _, ngettext
import base64


def validate_host(ugettext, fqdn):
    """
    Require at least one dot in the hostname (to support localhost.localdomain)
    """
    if fqdn.index('.') == -1:
        return 'Fully-qualified hostname required'
    return None


class host(LDAPObject):
    """
    Host object.
    """
    container_dn = api.env.container_host
    object_name = 'host'
    object_name_plural = 'hosts'
    object_class = ['ipaobject', 'nshost', 'ipahost', 'pkiuser', 'ipaservice']
    # object_class_config = 'ipahostobjectclasses'
    default_attributes = [
        'fqdn', 'description', 'l', 'nshostlocation',
        'nshardwareplatform', 'nsosversion', 'usercertificate',
    ]
    uuid_attribute = 'ipauniqueid'
    attribute_names = {
        'cn': 'name',
        'fqdn': 'hostname',
        'localityname': 'locality',
        'l': 'locality',
        'nshostlocation': 'location',
        'nshardwareplatform': 'platform',
        'nsosversion': 'operating system',
        'serverhostname': 'server hostname',
        'enrolledby user': 'enrolled by',
        'krbprincipalname': 'kerberos principal',
        'ipauniqueid': 'unique identifier',
        'memberof hostgroup': 'member of hostgroups',
        'memberof netgroup': 'member of netgroups',
        'memberof rolegroup': 'member of rolegroups',
    }
    attribute_members = {
        'enrolledby': ['user'],
        'memberof': ['hostgroup', 'netgroup', 'rolegroup'],
    }

    label = _('Hosts')

    takes_params = (
        Str('fqdn', validate_host,
            cli_name='hostname',
            label='Hostname',
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description?',
            cli_name='desc',
            label='Description',
            doc='Description of the host',
        ),
        Str('locality?',
            cli_name='locality',
            label='Locality',
            doc='Locality of the host (Baltimore, MD)',
        ),
        Str('nshostlocation?',
            cli_name='location',
            label='Location',
            doc='Location of the host (e.g. Lab 2)',
        ),
        Str('nshardwareplatform?',
            cli_name='platform',
            label='Platform',
            doc='Hardware platform of the host (e.g. Lenovo T61)',
        ),
        Str('nsosversion?',
            cli_name='os',
            label='Operating system',
            doc='Operating System and version of the host (e.g. Fedora 9)',
        ),
        Str('userpassword?',
            cli_name='password',
            label='User password',
            doc='Password used in bulk enrollment',
        ),
        Bytes('usercertificate?', validate_certificate,
            cli_name='certificate',
            doc='base-64 encoded server certificate',
        ),
    )

    def get_dn(self, *keys, **options):
        if keys[-1].endswith('.'):
            keys[-1] = keys[-1][:-1]
        dn = super(host, self).get_dn(*keys, **options)
        try:
            self.backend.get_entry(dn, [''])
        except errors.NotFound:
            try:
                (dn, entry_attrs) = self.backend.find_entry_by_attr(
                    'serverhostname', keys[-1], self.object_class, [''],
                    self.container_dn
                )
            except errors.NotFound:
                pass
        return dn

api.register(host)


class host_add(LDAPCreate):
    """
    Create new host.
    """

    msg_summary = _('Added host "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        if 'locality' in entry_attrs:
            entry_attrs['l'] = entry_attrs['locality']
            del entry_attrs['locality']
        entry_attrs['cn'] = keys[-1]
        entry_attrs['serverhostname'] = keys[-1].split('.', 1)[0]
        # FIXME: do DNS lookup to ensure host exists
        if 'userpassword' not in entry_attrs:
            entry_attrs['krbprincipalname'] = 'host/%s@%s' % (
                keys[-1], self.api.env.realm
            )
            if 'krbprincipalaux' not in entry_attrs['objectclass']:
                entry_attrs['objectclass'].append('krbprincipalaux')
                entry_attrs['objectclass'].append('krbprincipal')
        elif 'krbprincipalaux' in entry_attrs['objectclass']:
            entry_attrs['objectclass'].remove('krbprincipalaux')
        entry_attrs['managedby'] = dn
        return dn

api.register(host_add)


class host_del(LDAPDelete):
    """
    Delete host.
    """

    msg_summary = _('Deleted host "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        # Remove all service records for this host
        truncated = True
        while truncated:
            try:
                ret = api.Command['service_find'](keys[-1])
                truncated = ret['truncated']
                services = ret['result']
            except errors.NotFound:
                break
            else:
                for entry_attrs in services:
                    principal = entry_attrs['krbprincipalname'][0]
                    (service, hostname, realm) = split_principal(principal)
                    if hostname.lower() == keys[-1]:
                        api.Command['service_del'](principal)
        return dn

api.register(host_del)


class host_mod(LDAPUpdate):
    """
    Modify host.
    """

    msg_summary = _('Modified host "%(value)s"')

    takes_options = LDAPUpdate.takes_options + (
        Str('krbprincipalname?',
            cli_name='principalname',
            doc='Kerberos principal name for this host',
            attribute=True,
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        # Once a principal name is set it cannot be changed
        if 'locality' in entry_attrs:
            entry_attrs['l'] = entry_attrs['locality']
            del entry_attrs['locality']
        if 'krbprincipalname' in entry_attrs:
            (dn, entry_attrs_old) = ldap.get_entry(
                dn, ['objectclass', 'krbprincipalname']
            )
            if 'krbprincipalname' in entry_attrs_old:
                msg = 'Principal name already set, it is unchangeable.'
                raise errors.ACIError(info=msg)
            obj_classes = entry_attrs_old['objectclass']
            if 'krbprincipalaux' not in obj_classes:
                obj_classes.append('krbprincipalaux')
                entry_attrs['objectclass'] = obj_classes
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

api.register(host_mod)


class host_find(LDAPSearch):
    """
    Search for hosts.
    """

    msg_summary = ngettext(
        '%(count)d host matched', '%(count)d hosts matched'
    )

    def pre_callback(self, ldap, filter, attrs_list, base_dn, *args, **options):
        if 'locality' in attrs_list:
            attrs_list.remove('locality')
            attrs_list.append('l')
        return filter.replace('locality', 'l')

api.register(host_find)


class host_show(LDAPRetrieve):
    """
    Display host.
    """

api.register(host_show)
