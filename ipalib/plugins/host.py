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
Hosts/Machines

A host represents a machine. It can be used in a number of contexts:
- service entries are associated with a host
- a host stores the host/ service principal
- a host can be used in Host-Based Access Control (HBAC) rules
- every enrolled client generates a host entry

ENROLLMENT:

There are three enrollment scenarios when enrolling a new client:

1. You are enrolling as a full administrator. The host entry may exist
   or not. A full administrator is a member of the hostadmin rolegroup
   or the admins group.
2. You are enrolling as a limited administrator. The host must already
   exist. A limited administrator is a member of the enrollhost rolegroup.
3. The host has been created with a one-time password.

A host can only be enrolled once. If a client has enrolled and needs to
be re-enrolled, the host entry must be removed and re-created. Note that
re-creating the host entry will result in all services for the host being
removed, and all SSL certificates associated with those services being
revoked.

A host can optionally store information such as where it is located,
the OS that it runs, etc.

EXAMPLES:

 Add a new host:
   ipa host-add --location="3rd floor lab" --locality=Dallas test.example.com

 Delete a host:
   ipa host-del test.example.com

 Add a new host with a one-time password:
   ipa host-add --os='Fedora 12' --password=Secret123 test.example.com

 Add a new host with a random one-time password:
   ipa host-add --os='Fedora 12' --random test.example.com

 Modify information about a host:
   ipa host-mod --os='Fedora 12' test.example.com

 Disable the host kerberos key:
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
from ipalib.plugins.service import normalize_certificate
from ipalib.plugins.service import set_certificate_attrs
from ipalib import _, ngettext
from ipalib import x509
from ipapython.ipautil import ipa_generate_password
from ipalib.request import context
import base64
import nss.nss as nss


def validate_host(ugettext, fqdn):
    """
    Require at least one dot in the hostname (to support localhost.localdomain)
    """
    if fqdn.find('.') == -1:
        return _('Fully-qualified hostname required')
    return None

host_output_params = (
    Flag('has_keytab',
        label=_('Keytab'),
    ),
    Str('subject',
        label=_('Subject'),
    ),
    Str('serial_number',
        label=_('Serial Number'),
    ),
    Str('issuer',
        label=_('Issuer'),
    ),
    Str('valid_not_before',
        label=_('Not Before'),
    ),
    Str('valid_not_after',
        label=_('Not After'),
    ),
    Str('md5_fingerprint',
        label=_('Fingerprint (MD5)'),
    ),
    Str('sha1_fingerprint',
        label=_('Fingerprint (SHA1)'),
    ),
    Str('revocation_reason?',
        label=_('Revocation reason'),
    )
)

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
        Flag('random?',
            doc=_('Generate a random password to be used in bulk enrollment'),
            flags=['no_search'],
            default=False,
        ),
        Str('randompassword?',
            label=_('Random password'),
            flags=['no_create', 'no_update', 'no_search'],
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
    Add a new host.
    """

    has_output_params = LDAPCreate.has_output_params + host_output_params
    msg_summary = _('Added host "%(value)s"')
    takes_options = (
        Flag('force',
            doc=_('force host name even if not in DNS'),
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        if not options.get('force', False):
            util.validate_host_dns(self.log, keys[-1])
        if 'locality' in entry_attrs:
            entry_attrs['l'] = entry_attrs['locality']
            del entry_attrs['locality']
        entry_attrs['cn'] = keys[-1]
        entry_attrs['serverhostname'] = keys[-1].split('.', 1)[0]
        if 'userpassword' not in entry_attrs and \
            options.get('random', False) == False:
            entry_attrs['krbprincipalname'] = 'host/%s@%s' % (
                keys[-1], self.api.env.realm
            )
            if 'krbprincipalaux' not in entry_attrs['objectclass']:
                entry_attrs['objectclass'].append('krbprincipalaux')
                entry_attrs['objectclass'].append('krbprincipal')
        elif 'krbprincipalaux' in entry_attrs['objectclass']:
            entry_attrs['objectclass'].remove('krbprincipalaux')
        if 'random' in options:
            if options.get('random'):
                entry_attrs['userpassword'] = ipa_generate_password()
                # save the password so it can be displayed in post_callback
                setattr(context, 'randompassword', entry_attrs['userpassword'])
            del entry_attrs['random']
        entry_attrs['managedby'] = dn
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if options.get('random', False):
            try:
                entry_attrs['randompassword'] = unicode(getattr(context, 'randompassword'))
            except AttributeError:
                # On the off-chance some other extension deletes this from the
                # context, don't crash.
                pass
        set_certificate_attrs(entry_attrs)
        return dn

api.register(host_add)


class host_del(LDAPDelete):
    """
    Delete a host.
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
        (dn, entry_attrs) = ldap.get_entry(dn, ['usercertificate'])
        if 'usercertificate' in entry_attrs:
            cert = normalize_certificate(entry_attrs.get('usercertificate')[0])
            try:
                serial = unicode(x509.get_serial_number(cert, x509.DER))
                try:
                    result = api.Command['cert_show'](unicode(serial))['result'
]
                    if 'revocation_reason' not in result:
                        try:
                            api.Command['cert_revoke'](unicode(serial), revocation_reason=4)
                        except errors.NotImplementedError:
                            # some CA's might not implement revoke
                            pass
                except errors.NotImplementedError:
                    # some CA's might not implement revoke
                    pass
            except NSPRError, nsprerr:
                if nsprerr.errno == -8183:
                    # If we can't decode the cert them proceed with
                    # removing the host.
                    self.log.info("Problem decoding certificate %s" % nsprerr.args[1])
                else:
                    raise nsprerr

        return dn

api.register(host_del)


class host_mod(LDAPUpdate):
    """
    Modify information about a host.
    """

    has_output_params = LDAPUpdate.has_output_params + host_output_params
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
        cert = normalize_certificate(entry_attrs.get('usercertificate'))
        if cert:
            (dn, entry_attrs_old) = ldap.get_entry(dn, ['usercertificate'])
            if 'usercertificate' in entry_attrs_old:
                oldcert = normalize_certificate(entry_attrs_old.get('usercertificate')[0])
                try:
                    serial = unicode(x509.get_serial_number(oldcert, x509.DER))
                    try:
                        result = api.Command['cert_show'](unicode(serial))['result']
                        if 'revocation_reason' not in result:
                            try:
                                api.Command['cert_revoke'](unicode(serial), revocation_reason=4)
                            except errors.NotImplementedError:
                                # some CA's might not implement revoke
                                pass
                    except errors.NotImplementedError:
                        # some CA's might not implement revoke
                        pass
                except NSPRError, nsprerr:
                    if nsprerr.errno == -8183:
                        # If we can't decode the cert them proceed with
                        # modifying the host.
                        self.log.info("Problem decoding certificate %s" % nsprerr.args[1])
                    else:
                        raise nsprerr

            entry_attrs['usercertificate'] = cert
        if 'random' in options:
            if options.get('random'):
                entry_attrs['userpassword'] = ipa_generate_password()
                setattr(context, 'randompassword', entry_attrs['userpassword'])
            del entry_attrs['random']
        entry_attrs['managedby'] = dn

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if options.get('random', False):
            entry_attrs['randompassword'] = unicode(getattr(context, 'randompassword'))
        set_certificate_attrs(entry_attrs)
        return dn

api.register(host_mod)


class host_find(LDAPSearch):
    """
    Search for hosts.
    """

    has_output_params = LDAPSearch.has_output_params + host_output_params
    msg_summary = ngettext(
        '%(count)d host matched', '%(count)d hosts matched'
    )

    def pre_callback(self, ldap, filter, attrs_list, base_dn, *args, **options):
        if 'locality' in attrs_list:
            attrs_list.remove('locality')
            attrs_list.append('l')
        return filter.replace('locality', 'l')

    def post_callback(self, ldap, entries, truncated, *args, **options):
        for entry in entries:
            entry_attrs = entry[1]
            set_certificate_attrs(entry_attrs)

api.register(host_find)


class host_show(LDAPRetrieve):
    """
    Display information about a host.
    """
    has_output_params = LDAPRetrieve.has_output_params + host_output_params

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if 'krblastpwdchange' in entry_attrs:
            entry_attrs['has_keytab'] = True
            if not options.get('all', False):
                del entry_attrs['krblastpwdchange']
        else:
            entry_attrs['has_keytab'] = False

        set_certificate_attrs(entry_attrs)

        return dn

api.register(host_show)


class host_disable(LDAPQuery):
    """
    Disable the kerberos key of a host.
    """
    has_output = output.standard_value
    msg_summary = _('Removed kerberos key and disabled all services for "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        # If we aren't given a fqdn, find it
        if validate_host(None, keys[-1]) is not None:
            hostentry = api.Command['host_show'](keys[-1])['result']
            fqdn = hostentry['fqdn'][0]
        else:
            fqdn = keys[-1]

        # See if we actually do anthing here, and if not raise an exception
        done_work = False

        dn = self.obj.get_dn(*keys, **options)
        (dn, entry_attrs) = ldap.get_entry(dn, ['krblastpwdchange', 'usercertificate'])

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
                        try:
                            api.Command['service_disable'](principal)
                            done_work = True
                        except errors.AlreadyInactive:
                            pass
        if 'usercertificate' in entry_attrs:
            cert = normalize_certificate(entry_attrs.get('usercertificate')[0])
            try:
                serial = unicode(x509.get_serial_number(cert, x509.DER))
                try:
                    result = api.Command['cert_show'](unicode(serial))['result'
]
                    if 'revocation_reason' not in result:
                        try:
                            api.Command['cert_revoke'](unicode(serial), revocation_reason=4)
                        except errors.NotImplementedError:
                            # some CA's might not implement revoke
                            pass
                except errors.NotImplementedError:
                    # some CA's might not implement revoke
                    pass
            except NSPRError, nsprerr:
                if nsprerr.errno == -8183:
                    # If we can't decode the cert them proceed with
                    # disabling the host.
                    self.log.info("Problem decoding certificate %s" % nsprerr.args[1])
                else:
                    raise nsprerr

            # Remove the usercertificate altogether
            ldap.update_entry(dn, {'usercertificate': None})
            done_work = True

        if 'krblastpwdchange' in entry_attrs:
            ldap.remove_principal_key(dn)
            api.Command['host_mod'](fqdn=keys[-1], setattr=u'enrolledby=')
            done_work = True

        if not done_work:
            raise errors.AlreadyInactive()

        return dict(
            result=True,
            value=keys[0],
        )

api.register(host_disable)
