# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import platform
import os
import sys
from nss.error import NSPRError
import nss.nss as nss
import netaddr
import string

from ipalib import api, errors, util
from ipalib import Str, Flag, Bytes
from ipalib.plugins.baseldap import *
from ipalib.plugins.service import split_principal
from ipalib.plugins.service import validate_certificate
from ipalib.plugins.service import set_certificate_attrs
from ipalib.plugins.dns import (dns_container_exists, _record_types,
        add_records_for_host_validation, add_records_for_host,
        _hostname_validator, get_reverse_zone)
from ipalib.plugins.dns import get_reverse_zone
from ipalib import _, ngettext
from ipalib import x509
from ipalib.request import context
from ipalib.util import (normalize_sshpubkey, validate_sshpubkey_no_options,
    convert_sshpubkey_post)
from ipapython.ipautil import ipa_generate_password, CheckedIPAddress
from ipapython.ssh import SSHPublicKey
from ipapython.dn import DN

__doc__ = _("""
Hosts/Machines

A host represents a machine. It can be used in a number of contexts:
- service entries are associated with a host
- a host stores the host/ service principal
- a host can be used in Host-based Access Control (HBAC) rules
- every enrolled client generates a host entry

ENROLLMENT:

There are three enrollment scenarios when enrolling a new client:

1. You are enrolling as a full administrator. The host entry may exist
   or not. A full administrator is a member of the hostadmin role
   or the admins group.
2. You are enrolling as a limited administrator. The host must already
   exist. A limited administrator is a member a role with the
   Host Enrollment privilege.
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

 Remove SSH public keys of a host and update DNS to reflect this change:
   ipa host-mod --sshpubkey= --updatedns test.example.com

 Disable the host Kerberos key, SSL certificate and all of its services:
   ipa host-disable test.example.com

 Add a host that can manage this host's keytab and certificate:
   ipa host-add-managedby --hosts=test2 test
""")

# Characters to be used by random password generator
# The set was chosen to avoid the need for escaping the characters by user
host_pwd_chars=string.digits + string.ascii_letters + '_,.@+-='

def remove_fwd_ptr(ipaddr, host, domain, recordtype):
    api.log.debug('deleting ipaddr %s' % ipaddr)
    try:
        revzone, revname = get_reverse_zone(ipaddr)

        # in case domain is in FQDN form with a trailing dot, we needn't add
        # another one, in case it has no trailing dot, dnsrecord-del will
        # normalize the entry
        delkw = { 'ptrrecord' : "%s.%s" % (host, domain) }

        api.Command['dnsrecord_del'](revzone, revname, **delkw)
    except errors.NotFound:
        pass

    try:
        delkw = { recordtype : ipaddr }
        api.Command['dnsrecord_del'](domain, host, **delkw)
    except errors.NotFound:
        pass

def update_sshfp_record(zone, record, entry_attrs):
    if 'ipasshpubkey' not in entry_attrs:
        return

    pubkeys = entry_attrs['ipasshpubkey'] or ()
    sshfps=[]
    for pubkey in pubkeys:
        try:
            sshfp = SSHPublicKey(pubkey).fingerprint_dns_sha1()
        except ValueError, UnicodeDecodeError:
            continue
        if sshfp is not None:
            sshfps.append(sshfp)

    try:
        api.Command['dnsrecord_mod'](zone, record, sshfprecord=sshfps)
    except errors.EmptyModlist:
        pass

host_output_params = (
    Flag('has_keytab',
        label=_('Keytab'),
    ),
    Str('managedby_host',
        label='Managed by',
    ),
    Str('managing_host',
        label='Managing',
    ),
    Str('subject',
        label=_('Subject'),
    ),
    Str('serial_number',
        label=_('Serial Number'),
    ),
    Str('serial_number_hex',
        label=_('Serial Number (hex)'),
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
    ),
    Str('managedby',
        label=_('Failed managedby'),
    ),
    Str('sshpubkeyfp*',
        label=_('SSH public key fingerprint'),
    ),
)

def validate_ipaddr(ugettext, ipaddr):
    """
    Verify that we have either an IPv4 or IPv6 address.
    """
    try:
        ip = CheckedIPAddress(ipaddr, match_local=False)
    except Exception, e:
        return unicode(e)
    return None

def normalize_hostname(hostname):
    """Use common fqdn form without the trailing dot"""
    if hostname.endswith(u'.'):
        hostname = hostname[:-1]
    hostname = hostname.lower()
    return hostname

class host(LDAPObject):
    """
    Host object.
    """
    container_dn = api.env.container_host
    object_name = _('host')
    object_name_plural = _('hosts')
    object_class = ['ipaobject', 'nshost', 'ipahost', 'pkiuser', 'ipaservice']
    # object_class_config = 'ipahostobjectclasses'
    search_attributes = [
        'fqdn', 'description', 'l', 'nshostlocation', 'krbprincipalname',
        'nshardwareplatform', 'nsosversion', 'managedby'
    ]
    default_attributes = [
        'fqdn', 'description', 'l', 'nshostlocation', 'krbprincipalname',
        'nshardwareplatform', 'nsosversion', 'usercertificate', 'memberof',
        'managedby', 'memberindirect', 'memberofindirect', 'macaddress',
    ]
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'enrolledby': ['user'],
        'memberof': ['hostgroup', 'netgroup', 'role', 'hbacrule', 'sudorule'],
        'managedby': ['host'],
        'managing': ['host'],
        'memberofindirect': ['hostgroup', 'netgroup', 'role', 'hbacrule',
        'sudorule'],
    }
    bindable = True
    relationships = {
        'memberof': ('Member Of', 'in_', 'not_in_'),
        'enrolledby': ('Enrolled by', 'enroll_by_', 'not_enroll_by_'),
        'managedby': ('Managed by', 'man_by_', 'not_man_by_'),
        'managing': ('Managing', 'man_', 'not_man_'),
    }
    password_attributes = [('userpassword', 'has_password'),
                           ('krbprincipalkey', 'has_keytab')]

    label = _('Hosts')
    label_singular = _('Host')

    takes_params = (
        Str('fqdn', _hostname_validator,
            cli_name='hostname',
            label=_('Host name'),
            primary_key=True,
            normalizer=normalize_hostname,
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
            flags=('no_search', 'virtual_attribute'),
            default=False,
        ),
        Str('randompassword?',
            label=_('Random password'),
            flags=('no_create', 'no_update', 'no_search', 'virtual_attribute'),
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
        Str('macaddress*',
            normalizer=lambda value: value.upper(),
            pattern='^([a-fA-F0-9]{2}[:|\-]?){5}[a-fA-F0-9]{2}$',
            pattern_errmsg='Must be of the form HH:HH:HH:HH:HH:HH, where each H is a hexadecimal character.',
            csv=True,
            label=_('MAC address'),
            doc=_('Hardware MAC address(es) on this host'),
        ),
        Str('ipasshpubkey*', validate_sshpubkey_no_options,
            cli_name='sshpubkey',
            label=_('SSH public key'),
            normalizer=normalize_sshpubkey,
            csv=True,
            flags=['no_search'],
        ),
    )

    def get_dn(self, *keys, **options):
        hostname = keys[-1]
        dn = super(host, self).get_dn(hostname, **options)
        try:
            self.backend.get_entry(dn, [''])
        except errors.NotFound:
            try:
                (dn, entry_attrs) = self.backend.find_entry_by_attr(
                    'serverhostname', hostname, self.object_class, [''],
                    self.container_dn
                )
            except errors.NotFound:
                pass
        return dn

    def get_managed_hosts(self, dn):
        host_filter = 'managedBy=%s' % dn
        host_attrs = ['fqdn']
        ldap = self.api.Backend.ldap2
        managed_hosts = []

        try:
            (hosts, truncated) = ldap.find_entries(base_dn=self.container_dn,
                                    filter=host_filter, attrs_list=host_attrs)

            for host in hosts:
                managed_hosts.append(host[0])
        except errors.NotFound:
            return []

        return managed_hosts

    def suppress_netgroup_memberof(self, entry_attrs):
        """
        We don't want to show managed netgroups so remove them from the
        memberofindirect list.
        """
        ng_container = DN(api.env.container_netgroup, api.env.basedn)
        if 'memberofindirect' in entry_attrs:
            for member in entry_attrs['memberofindirect']:
                memberdn = DN(member)
                if memberdn.endswith(ng_container):
                    try:
                        netgroup = api.Command['netgroup_show'](memberdn['cn'], all=True)['result']
                        if self.has_objectclass(netgroup['objectclass'], 'mepmanagedentry'):
                            entry_attrs['memberofindirect'].remove(member)
                    except errors.NotFound:
                        pass

api.register(host)


class host_add(LDAPCreate):
    __doc__ = _('Add a new host.')

    has_output_params = LDAPCreate.has_output_params + host_output_params
    msg_summary = _('Added host "%(value)s"')
    member_attributes = ['managedby']
    takes_options = LDAPCreate.takes_options + (
        Flag('force',
            label=_('Force'),
            doc=_('force host name even if not in DNS'),
        ),
        Flag('no_reverse',
            doc=_('skip reverse DNS detection'),
        ),
        Str('ip_address?', validate_ipaddr,
            doc=_('Add the host to DNS with this IP address'),
            label=_('IP Address'),
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        if options.get('ip_address') and dns_container_exists(ldap):
            parts = keys[-1].split('.')
            host = parts[0]
            domain = unicode('.'.join(parts[1:]))
            check_reverse = not options.get('no_reverse', False)
            add_records_for_host_validation('ip_address', host, domain,
                    options['ip_address'],
                    check_forward=True,
                    check_reverse=check_reverse)
        if not options.get('force', False) and not 'ip_address' in options:
            util.validate_host_dns(self.log, keys[-1])
        if 'locality' in entry_attrs:
            entry_attrs['l'] = entry_attrs['locality']
            del entry_attrs['locality']
        entry_attrs['cn'] = keys[-1]
        entry_attrs['serverhostname'] = keys[-1].split('.', 1)[0]
        if 'userpassword' not in entry_attrs and not options.get('random', False):
            entry_attrs['krbprincipalname'] = 'host/%s@%s' % (
                keys[-1], self.api.env.realm
            )
            if 'krbprincipalaux' not in entry_attrs['objectclass']:
                entry_attrs['objectclass'].append('krbprincipalaux')
            if 'krbprincipal' not in entry_attrs['objectclass']:
                entry_attrs['objectclass'].append('krbprincipal')
        else:
            if 'krbprincipalaux' in entry_attrs['objectclass']:
                entry_attrs['objectclass'].remove('krbprincipalaux')
            if 'krbprincipal' in entry_attrs['objectclass']:
                entry_attrs['objectclass'].remove('krbprincipal')
        if options.get('random'):
            entry_attrs['userpassword'] = ipa_generate_password(characters=host_pwd_chars)
            # save the password so it can be displayed in post_callback
            setattr(context, 'randompassword', entry_attrs['userpassword'])
        cert = options.get('usercertificate')
        if cert:
            cert = x509.normalize_certificate(cert)
            x509.verify_cert_subject(ldap, keys[-1], cert)
            entry_attrs['usercertificate'] = cert
        entry_attrs['managedby'] = dn
        entry_attrs['objectclass'].append('ieee802device')
        entry_attrs['objectclass'].append('ipasshhost')
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        exc = None
        if dns_container_exists(ldap):
            try:
                parts = keys[-1].split('.')
                host = parts[0]
                domain = unicode('.'.join(parts[1:]))

                if options.get('ip_address'):
                    add_reverse = not options.get('no_reverse', False)

                    add_records_for_host(host, domain, options['ip_address'],
                                         add_forward=True,
                                         add_reverse=add_reverse)
                    del options['ip_address']

                update_sshfp_record(domain, unicode(parts[0]), entry_attrs)
            except Exception, e:
                exc = e
        if options.get('random', False):
            try:
                entry_attrs['randompassword'] = unicode(getattr(context, 'randompassword'))
            except AttributeError:
                # On the off-chance some other extension deletes this from the
                # context, don't crash.
                pass
        if exc:
            raise errors.NonFatalError(
                reason=_('The host was added but the DNS update failed with: %(exc)s') % dict(exc=exc)
            )
        set_certificate_attrs(entry_attrs)

        if options.get('all', False):
            entry_attrs['managing'] = self.obj.get_managed_hosts(dn)
        self.obj.get_password_attributes(ldap, dn, entry_attrs)
        if entry_attrs['has_password']:
            # If an OTP is set there is no keytab, at least not one
            # fetched anywhere.
            entry_attrs['has_keytab'] = False

        convert_sshpubkey_post(ldap, dn, entry_attrs)

        return dn

api.register(host_add)


class host_del(LDAPDelete):
    __doc__ = _('Delete a host.')

    msg_summary = _('Deleted host "%(value)s"')
    member_attributes = ['managedby']

    takes_options = (
        Flag('updatedns?',
            doc=_('Remove entries from DNS'),
            default=False,
        ),
    )

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        # If we aren't given a fqdn, find it
        if _hostname_validator(None, keys[-1]) is not None:
            hostentry = api.Command['host_show'](keys[-1])['result']
            fqdn = hostentry['fqdn'][0]
        else:
            fqdn = keys[-1]
        host_is_master(ldap, fqdn)
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
        updatedns = options.get('updatedns', False)
        if updatedns:
            try:
                updatedns = dns_container_exists(ldap)
            except errors.NotFound:
                updatedns = False

        if updatedns:
            # Remove DNS entries
            parts = fqdn.split('.')
            domain = unicode('.'.join(parts[1:]))
            try:
                result = api.Command['dnszone_show'](domain)['result']
                domain = result['idnsname'][0]
            except errors.NotFound:
                self.obj.handle_not_found(*keys)
            # Get all forward resources for this host
            records = api.Command['dnsrecord_find'](domain, idnsname=parts[0])['result']
            for record in records:
                if 'arecord' in record:
                    remove_fwd_ptr(record['arecord'][0], parts[0],
                                   domain, 'arecord')
                if 'aaaarecord' in record:
                    remove_fwd_ptr(record['aaaarecord'][0], parts[0],
                                   domain, 'aaaarecord')
                else:
                    # Try to delete all other record types too
                    _attribute_types = [str('%srecord' % t.lower()) for t in _record_types]
                    for attr in _attribute_types:
                        if attr not in ['arecord', 'aaaarecord'] and attr in record:
                            for i in xrange(len(record[attr])):
                                if (record[attr][i].endswith(parts[0]) or
                                    record[attr][i].endswith(fqdn+'.')):
                                    delkw = { unicode(attr) : record[attr][i] }
                                    api.Command['dnsrecord_del'](domain,
                                            record['idnsname'][0],
                                            **delkw)
                            break

        try:
            (dn, entry_attrs) = ldap.get_entry(dn, ['usercertificate'])
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        if 'usercertificate' in entry_attrs:
            cert = x509.normalize_certificate(entry_attrs.get('usercertificate')[0])
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
    __doc__ = _('Modify information about a host.')

    has_output_params = LDAPUpdate.has_output_params + host_output_params
    msg_summary = _('Modified host "%(value)s"')
    member_attributes = ['managedby']

    takes_options = LDAPUpdate.takes_options + (
        Str('krbprincipalname?',
            cli_name='principalname',
            label=_('Principal name'),
            doc=_('Kerberos principal name for this host'),
            attribute=True,
        ),
        Flag('updatedns?',
            doc=_('Update DNS entries'),
            default=False,
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        # Allow an existing OTP to be reset but don't allow a OTP to be
        # added to an enrolled host.
        if options.get('userpassword') or options.get('random'):
            entry = {}
            self.obj.get_password_attributes(ldap, dn, entry)
            if not entry['has_password'] and entry['has_keytab']:
                raise errors.ValidationError(name='password', error=_('Password cannot be set on enrolled host.'))

        # Once a principal name is set it cannot be changed
        if 'cn' in entry_attrs:
            raise errors.ACIError(info=_('cn is immutable'))
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
        cert = x509.normalize_certificate(entry_attrs.get('usercertificate'))
        if cert:
            x509.verify_cert_subject(ldap, keys[-1], cert)
            (dn, entry_attrs_old) = ldap.get_entry(dn, ['usercertificate'])
            if 'usercertificate' in entry_attrs_old:
                oldcert = x509.normalize_certificate(entry_attrs_old.get('usercertificate')[0])
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

        if options.get('random'):
            entry_attrs['userpassword'] = ipa_generate_password(characters=host_pwd_chars)
            setattr(context, 'randompassword', entry_attrs['userpassword'])
        if 'macaddress' in entry_attrs:
            if 'objectclass' in entry_attrs:
                obj_classes = entry_attrs['objectclass']
            else:
                (_dn, _entry_attrs) = ldap.get_entry(
                    dn, ['objectclass']
                )
                obj_classes = _entry_attrs['objectclass']
            if 'ieee802device' not in obj_classes:
                obj_classes.append('ieee802device')
                entry_attrs['objectclass'] = obj_classes

        if options.get('updatedns', False) and dns_container_exists(ldap):
            parts = keys[-1].split('.')
            domain = unicode('.'.join(parts[1:]))
            try:
                result = api.Command['dnszone_show'](domain)['result']
                domain = result['idnsname'][0]
            except errors.NotFound:
                self.obj.handle_not_found(*keys)
            update_sshfp_record(domain, unicode(parts[0]), entry_attrs)

        if 'ipasshpubkey' in entry_attrs:
            if 'objectclass' in entry_attrs:
                obj_classes = entry_attrs['objectclass']
            else:
                (_dn, _entry_attrs) = ldap.get_entry(dn, ['objectclass'])
                obj_classes = entry_attrs['objectclass'] = _entry_attrs['objectclass']
            if 'ipasshhost' not in obj_classes:
                obj_classes.append('ipasshhost')

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        if options.get('random', False):
            entry_attrs['randompassword'] = unicode(getattr(context, 'randompassword'))
        set_certificate_attrs(entry_attrs)
        self.obj.get_password_attributes(ldap, dn, entry_attrs)
        if entry_attrs['has_password']:
            # If an OTP is set there is no keytab, at least not one
            # fetched anywhere.
            entry_attrs['has_keytab'] = False

        if options.get('all', False):
            entry_attrs['managing'] = self.obj.get_managed_hosts(dn)

        self.obj.suppress_netgroup_memberof(entry_attrs)

        convert_sshpubkey_post(ldap, dn, entry_attrs)

        return dn

api.register(host_mod)


class host_find(LDAPSearch):
    __doc__ = _('Search for hosts.')

    has_output_params = LDAPSearch.has_output_params + host_output_params
    msg_summary = ngettext(
        '%(count)d host matched', '%(count)d hosts matched', 0
    )
    member_attributes = ['memberof', 'enrolledby', 'managedby']

    def get_options(self):
        for option in super(host_find, self).get_options():
            yield option
        # "managing" membership has to be added and processed separately
        for option in self.get_member_options('managing'):
            yield option

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args, **options):
        assert isinstance(base_dn, DN)
        if 'locality' in attrs_list:
            attrs_list.remove('locality')
            attrs_list.append('l')
        if 'man_host' in options or 'not_man_host' in options:
            hosts = []
            if options.get('man_host') is not None:
                for pkey in options.get('man_host', []):
                    dn = self.obj.get_dn(pkey)
                    try:
                        (dn, entry_attrs) = ldap.get_entry(dn, ['managedby'])
                    except errors.NotFound:
                        self.obj.handle_not_found(pkey)
                    hosts.append(set(entry_attrs.get('managedby', '')))
                hosts = list(reduce(lambda s1, s2: s1 & s2, hosts))

                if not hosts:
                    # There is no host managing _all_ hosts in --man-hosts
                    filter = ldap.combine_filters(
                        (filter, '(objectclass=disabled)'), ldap.MATCH_ALL
                    )

            not_hosts = []
            if options.get('not_man_host') is not None:
                for pkey in options.get('not_man_host', []):
                    dn = self.obj.get_dn(pkey)
                    try:
                        (dn, entry_attrs) = ldap.get_entry(dn, ['managedby'])
                    except errors.NotFound:
                        self.obj.handle_not_found(pkey)
                    not_hosts += entry_attrs.get('managedby', [])
                not_hosts = list(set(not_hosts))

            for target_hosts, filter_op in ((hosts, ldap.MATCH_ANY),
                                            (not_hosts, ldap.MATCH_NONE)):
                hosts_avas = [DN(host)[0][0] for host in target_hosts]
                hosts_filters = [ldap.make_filter_from_attr(ava.attr, ava.value) for ava in hosts_avas]
                hosts_filter = ldap.combine_filters(hosts_filters, filter_op)

                filter = ldap.combine_filters(
                        (filter, hosts_filter), ldap.MATCH_ALL
                    )

        return (filter.replace('locality', 'l'), base_dn, scope)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if options.get('pkey_only', False):
            return truncated
        for entry in entries:
            (dn, entry_attrs) = entry
            set_certificate_attrs(entry_attrs)
            self.obj.get_password_attributes(ldap, dn, entry_attrs)
            self.obj.suppress_netgroup_memberof(entry_attrs)
            if entry_attrs['has_password']:
                # If an OTP is set there is no keytab, at least not one
                # fetched anywhere.
                entry_attrs['has_keytab'] = False

            if options.get('all', False):
                entry_attrs['managing'] = self.obj.get_managed_hosts(entry[0])

            convert_sshpubkey_post(ldap, dn, entry_attrs)

        return truncated

api.register(host_find)


class host_show(LDAPRetrieve):
    __doc__ = _('Display information about a host.')

    has_output_params = LDAPRetrieve.has_output_params + host_output_params
    takes_options = LDAPRetrieve.takes_options + (
        Str('out?',
            doc=_('file to store certificate in'),
        ),
    )

    member_attributes = ['managedby']

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.get_password_attributes(ldap, dn, entry_attrs)
        if entry_attrs['has_password']:
            # If an OTP is set there is no keytab, at least not one
            # fetched anywhere.
            entry_attrs['has_keytab'] = False

        set_certificate_attrs(entry_attrs)

        if options.get('all', False):
            entry_attrs['managing'] = self.obj.get_managed_hosts(dn)

        self.obj.suppress_netgroup_memberof(entry_attrs)

        convert_sshpubkey_post(ldap, dn, entry_attrs)

        return dn

    def forward(self, *keys, **options):
        if 'out' in options:
            util.check_writable_file(options['out'])
            result = super(host_show, self).forward(*keys, **options)
            if 'usercertificate' in result['result']:
                x509.write_certificate(result['result']['usercertificate'][0], options['out'])
                result['summary'] = _('Certificate stored in file \'%(file)s\'') % dict(file=options['out'])
                return result
            else:
                raise errors.NoCertificateError(entry=keys[-1])
        else:
            return super(host_show, self).forward(*keys, **options)

api.register(host_show)


class host_disable(LDAPQuery):
    __doc__ = _('Disable the Kerberos key, SSL certificate and all services of a host.')

    has_output = output.standard_value
    msg_summary = _('Disabled host "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        # If we aren't given a fqdn, find it
        if _hostname_validator(None, keys[-1]) is not None:
            hostentry = api.Command['host_show'](keys[-1])['result']
            fqdn = hostentry['fqdn'][0]
        else:
            fqdn = keys[-1]

        host_is_master(ldap, fqdn)

        # See if we actually do anthing here, and if not raise an exception
        done_work = False

        dn = self.obj.get_dn(*keys, **options)
        try:
            (dn, entry_attrs) = ldap.get_entry(dn, ['usercertificate'])
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

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
            cert = x509.normalize_certificate(entry_attrs.get('usercertificate')[0])
            try:
                serial = unicode(x509.get_serial_number(cert, x509.DER))
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
                    # disabling the host.
                    self.log.info("Problem decoding certificate %s" % nsprerr.args[1])
                else:
                    raise nsprerr

            # Remove the usercertificate altogether
            ldap.update_entry(dn, {'usercertificate': None})
            done_work = True

        self.obj.get_password_attributes(ldap, dn, entry_attrs)
        if entry_attrs['has_keytab']:
            ldap.remove_principal_key(dn)
            done_work = True

        if not done_work:
            raise errors.AlreadyInactive()

        return dict(
            result=True,
            value=keys[0],
        )

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.suppress_netgroup_memberof(entry_attrs)
        return dn

api.register(host_disable)

class host_add_managedby(LDAPAddMember):
    __doc__ = _('Add hosts that can manage this host.')

    member_attributes = ['managedby']
    has_output_params = LDAPAddMember.has_output_params + host_output_params
    allow_same = True

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.suppress_netgroup_memberof(entry_attrs)
        return (completed, dn)

api.register(host_add_managedby)


class host_remove_managedby(LDAPRemoveMember):
    __doc__ = _('Remove hosts that can manage this host.')

    member_attributes = ['managedby']
    has_output_params = LDAPRemoveMember.has_output_params + host_output_params

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.suppress_netgroup_memberof(entry_attrs)
        return (completed, dn)

api.register(host_remove_managedby)
