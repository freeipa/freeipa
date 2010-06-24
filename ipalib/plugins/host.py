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

A host represents a machine. It can be used in a number of contexts:
- service entries are associated with a host
- a host stores the host/ service principal
- a host may be used in Host-Based Access Control (HBAC) rules
- every enrolled client generates a host entry

ENROLLMENT:

There are three enrollment scenarios when enrolling a new client.

1. You are enrolling as a full administrator (hostadmin rolegroup). The
   host entry may exist or not.
2. You are enrolling as a limited administrator (enrollhost rolegroup). The
   host must already exist.
3. The host has been created with a one-time password.

A host may only be enrolled once. If a client has enrolled and needs to
be re-enrolled then the host entry needs to be removed and re-created.
Note that this will result in all services for this host being removed too,
and all SSL certificates associated with those services to be revoked.

A host can optionally store information such as where it is located,
the OS that it runs, etc.

EXAMPLES:

 Create a new host
   ipa host-add --location='3rd floor lab' --locality=Dallas test.example.com

 Remove a host
   ipa host-del test.example.com

 Create a new host with a one-time password
   ipa host-add --os='Fedora 12' --password=Secret123 test.example.com

 Update information about a host
   ipa host-mod --os='Fedora 12' test.example.com

 Disable the host kerberos key
   ipa host-disable test.example.com
"""

import platform
import os
import sys

from ipalib import api, errors, util
from ipalib import Str, Flag, Bytes
from ipalib.plugins.baseldap import *
from ipalib.plugins.service import split_principal
from ipalib.plugins.service import validate_certificate
from ipalib import _, ngettext
from ipalib import x509
import base64


def validate_host(ugettext, fqdn):
    """
    Require at least one dot in the hostname (to support localhost.localdomain)
    """
    if fqdn.find('.') == -1:
        return _('Fully-qualified hostname required')
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
    search_attributes = [
        'fqdn', 'description', 'l', 'nshostlocation', 'krbprincipalname',
        'nshardwareplatform', 'nsosversion',
    ]
    default_attributes = [
        'fqdn', 'description', 'l', 'nshostlocation', 'krbprincipalname',
        'nshardwareplatform', 'nsosversion', 'usercertificate', 'memberof',
        'krblastpwdchange',
    ]
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'enrolledby': ['user'],
        'memberof': ['hostgroup', 'netgroup', 'rolegroup'],
    }

    label = _('Hosts')

    takes_params = (
        Str('fqdn', validate_host,
            cli_name='hostname',
            label=_('Host name'),
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
            doc=_('A description of this host'),
        ),
        Str('l?',
            cli_name='locality',
            label=_('Locality'),
            doc=_('Host locality (e.g. "Baltimore, MD")'),
        ),
        Str('nshostlocation?',
            cli_name='location',
            label=_('Location'),
            doc=_('Host location (e.g. "Lab 2")'),
        ),
        Str('nshardwareplatform?',
            cli_name='platform',
            label=_('Platform'),
            doc=_('Host hardware platform (e.g. "Lenovo T61")'),
        ),
        Str('nsosversion?',
            cli_name='os',
            label=_('Operating system'),
            doc=_('Host operating system and version (e.g. "Fedora 9")'),
        ),
        Str('userpassword?',
            cli_name='password',
            label=_('User password'),
            doc=_('Password used in bulk enrollment'),
        ),
        Bytes('usercertificate?', validate_certificate,
            cli_name='certificate',
            label=_('Certificate'),
            doc=_('Base-64 encoded server certificate'),
        ),
        Str('krbprincipalname?',
            label=_('Principal name'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberof_hostgroup?',
            label=_('Member of host-groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberof_netgroup?',
            label=_('Member of net-groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberof_rolegroup?',
            label=_('Member of role-groups'),
            flags=['no_create', 'no_update', 'no_search'],
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
        # If we aren't given a fqdn, find it
        if validate_host(None, keys[-1]) is not None:
            hostentry = api.Command['host_show'](keys[-1])['result']
            fqdn = hostentry['fqdn'][0]
        else:
            fqdn = keys[-1]
        # Remove all service records for this host
        truncated = True
        while truncated:
            try:
                ret = api.Command['service_find'](fqdn)
                truncated = ret['truncated']
                services = ret['result']
            except errors.NotFound:
                break
            else:
                for entry_attrs in services:
                    principal = entry_attrs['krbprincipalname'][0]
                    (service, hostname, realm) = split_principal(principal)
                    if hostname.lower() == fqdn:
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
            label=_('Principal name'),
            doc=_('Kerberos principal name for this host'),
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
                    x509.get_serial_number(entry_attrs_old['usercertificate'][0], x509.DER)
                )
                raise errors.GenericError(format=fmt)
            # FIXME: decoding should be in normalizer; see service_add
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
    has_output_params = (
        Flag('has_keytab',
            label=_('Keytab'),
        )
    )

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if 'krblastpwdchange' in entry_attrs:
            entry_attrs['has_keytab'] = True
            if not options.get('all', False):
                del entry_attrs['krblastpwdchange']
        else:
            entry_attrs['has_keytab'] = False

        return dn

api.register(host_show)


class host_disable(LDAPQuery):
    """
    Disable the kerberos key of this host.
    """
    has_output = output.standard_value
    msg_summary = _('Removed kerberos key from "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)
        (dn, entry_attrs) = ldap.get_entry(dn, ['krblastpwdchange'])

        if 'krblastpwdchange' not in entry_attrs:
            error_msg = _('Host principal has no kerberos key')
            raise errors.NotFound(reason=error_msg)

        ldap.remove_principal_key(dn)

        return dict(
            result=True,
            value=keys[0],
        )

api.register(host_disable)
