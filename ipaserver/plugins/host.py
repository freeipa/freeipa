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

from __future__ import absolute_import

import logging

import dns.resolver

import six

from ipalib import api, errors, util
from ipalib import messages
from ipalib import Str, Flag
from ipalib.parameters import Principal, Certificate
from ipalib.plugable import Registry
from .baseldap import (LDAPQuery, LDAPObject, LDAPCreate,
                                     LDAPDelete, LDAPUpdate, LDAPSearch,
                                     LDAPRetrieve, LDAPAddMember,
                                     LDAPRemoveMember, host_is_master,
                                     pkey_to_value, add_missing_object_class,
                                     LDAPAddAttribute, LDAPRemoveAttribute,
                                     LDAPAddAttributeViaOption,
                                     LDAPRemoveAttributeViaOption)
from .service import (
    validate_realm, normalize_principal,
    set_certificate_attrs, ticket_flags_params, update_krbticketflags,
    set_kerberos_attrs, rename_ipaallowedtoperform_from_ldap,
    rename_ipaallowedtoperform_to_ldap, revoke_certs)
from .dns import (dns_container_exists,
        add_records_for_host_validation, add_records_for_host,
        get_reverse_zone)
from ipalib import _, ngettext
from ipalib import output
from ipalib.request import context
from ipalib.util import (normalize_sshpubkey, validate_sshpubkey_no_options,
    convert_sshpubkey_post,
    add_sshpubkey_to_attrs_pre,
    remove_sshpubkey_from_output_post,
    remove_sshpubkey_from_output_list_post,
    normalize_hostname,
    hostname_validator,
    set_krbcanonicalname
)
from ipapython.ipautil import (
    ipa_generate_password,
    CheckedIPAddress,
    TMP_PWD_ENTROPY_BITS
)
from ipapython.dnsutil import DNSName
from ipapython.ssh import SSHPublicKey
from ipapython.dn import DN
from ipapython import kerberos
from functools import reduce

if six.PY3:
    unicode = str

__doc__ = _("""
Hosts/Machines

A host represents a machine. It can be used in a number of contexts:
- service entries are associated with a host
- a host stores the host/ service principal
- a host can be used in Host-based Access Control (HBAC) rules
- every enrolled client generates a host entry
""") + _("""
ENROLLMENT:

There are three enrollment scenarios when enrolling a new client:

1. You are enrolling as a full administrator. The host entry may exist
   or not. A full administrator is a member of the hostadmin role
   or the admins group.
2. You are enrolling as a limited administrator. The host must already
   exist. A limited administrator is a member a role with the
   Host Enrollment privilege.
3. The host has been created with a one-time password.
""") + _("""
RE-ENROLLMENT:

Host that has been enrolled at some point, and lost its configuration (e.g. VM
destroyed) can be re-enrolled.

For more information, consult the manual pages for ipa-client-install.

A host can optionally store information such as where it is located,
the OS that it runs, etc.
""") + _("""
EXAMPLES:
""") + _("""
 Add a new host:
   ipa host-add --location="3rd floor lab" --locality=Dallas test.example.com
""") + _("""
 Delete a host:
   ipa host-del test.example.com
""") + _("""
 Add a new host with a one-time password:
   ipa host-add --os='Fedora 12' --password=Secret123 test.example.com
""") + _("""
 Add a new host with a random one-time password:
   ipa host-add --os='Fedora 12' --random test.example.com
""") + _("""
 Modify information about a host:
   ipa host-mod --os='Fedora 12' test.example.com
""") + _("""
 Remove SSH public keys of a host and update DNS to reflect this change:
   ipa host-mod --sshpubkey= --updatedns test.example.com
""") + _("""
 Disable the host Kerberos key, SSL certificate and all of its services:
   ipa host-disable test.example.com
""") + _("""
 Add a host that can manage this host's keytab and certificate:
   ipa host-add-managedby --hosts=test2 test
""") + _("""
 Allow user to create a keytab:
   ipa host-allow-create-keytab test2 --users=tuser1
""")

logger = logging.getLogger(__name__)

register = Registry()


def remove_ptr_rec(ipaddr, fqdn):
    """
    Remove PTR record of IP address (ipaddr)
    :return: True if PTR record was removed, False if record was not found
    """
    logger.debug('deleting PTR record of ipaddr %s', ipaddr)
    try:
        revzone, revname = get_reverse_zone(ipaddr)

        # assume that target in PTR record is absolute name (otherwise it is
        # non-standard configuration)
        delkw = {'ptrrecord': u"%s" % fqdn.make_absolute()}

        api.Command['dnsrecord_del'](revzone, revname, **delkw)
    except (errors.NotFound, errors.AttrValueNotFound):
        logger.debug('PTR record of ipaddr %s not found', ipaddr)
        return False

    return True


def update_sshfp_record(zone, record, entry_attrs):
    if 'ipasshpubkey' not in entry_attrs:
        return

    pubkeys = entry_attrs['ipasshpubkey'] or ()
    sshfps = []
    for pubkey in pubkeys:
        try:
            sshfp = SSHPublicKey(pubkey).fingerprint_dns_sha1()
        except (ValueError, UnicodeDecodeError):
            continue
        if sshfp is not None:
            sshfps.append(sshfp)

        try:
            sshfp = SSHPublicKey(pubkey).fingerprint_dns_sha256()
        except (ValueError, UnicodeDecodeError):
            continue
        if sshfp is not None:
            sshfps.append(sshfp)

    try:
        api.Command['dnsrecord_mod'](zone, record, sshfprecord=sshfps)
    except errors.EmptyModlist:
        pass


def convert_ipaassignedidview_post(entry_attrs, options):
    """
    Converts the ID View DN to its name for the better looking output.
    """

    if 'ipaassignedidview' in entry_attrs and not options.get('raw'):
        idview_name = entry_attrs.single_value['ipaassignedidview'][0].value
        entry_attrs.single_value['ipaassignedidview'] = idview_name


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
    Str('managedby',
        label=_('Failed managedby'),
    ),
    Str('ipaallowedtoperform_read_keys_user',
        label=_('Users allowed to retrieve keytab'),
    ),
    Str('ipaallowedtoperform_read_keys_group',
        label=_('Groups allowed to retrieve keytab'),
    ),
    Str('ipaallowedtoperform_read_keys_host',
        label=_('Hosts allowed to retrieve keytab'),
    ),
    Str('ipaallowedtoperform_read_keys_hostgroup',
        label=_('Host Groups allowed to retrieve keytab'),
    ),
    Str('ipaallowedtoperform_write_keys_user',
        label=_('Users allowed to create keytab'),
    ),
    Str('ipaallowedtoperform_write_keys_group',
        label=_('Groups allowed to create keytab'),
    ),
    Str('ipaallowedtoperform_write_keys_host',
        label=_('Hosts allowed to create keytab'),
    ),
    Str('ipaallowedtoperform_write_keys_hostgroup',
        label=_('Host Groups allowed to create keytab'),
    ),
    Str('ipaallowedtoperform_read_keys',
        label=_('Failed allowed to retrieve keytab'),
    ),
    Str('ipaallowedtoperform_write_keys',
        label=_('Failed allowed to create keytab'),
    ),
)


def validate_ipaddr(ugettext, ipaddr):
    """
    Verify that we have either an IPv4 or IPv6 address.
    """
    try:
        CheckedIPAddress(ipaddr)
    except Exception as e:
        return unicode(e)
    return None


@register()
class host(LDAPObject):
    """
    Host object.
    """
    container_dn = api.env.container_host
    object_name = _('host')
    object_name_plural = _('hosts')
    object_class = ['ipaobject', 'nshost', 'ipahost', 'pkiuser', 'ipaservice']
    possible_objectclasses = ['ipaallowedoperations']
    permission_filter_objectclasses = ['ipahost']
    # object_class_config = 'ipahostobjectclasses'
    search_attributes = [
        'fqdn', 'description', 'l', 'nshostlocation', 'krbcanonicalname',
        'krbprincipalname', 'nshardwareplatform', 'nsosversion', 'managedby',
    ]
    default_attributes = [
        'fqdn', 'description', 'l', 'nshostlocation', 'krbcanonicalname',
        'krbprincipalname',
        'nshardwareplatform', 'nsosversion', 'usercertificate', 'memberof',
        'managedby', 'memberofindirect', 'macaddress',
        'userclass', 'ipaallowedtoperform', 'ipaassignedidview', 'krbprincipalauthind'
    ]
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'enrolledby': ['user'],
        'memberof': ['hostgroup', 'netgroup', 'role', 'hbacrule', 'sudorule'],
        'managedby': ['host'],
        'managing': ['host'],
        'memberofindirect': ['hostgroup', 'netgroup', 'role', 'hbacrule',
        'sudorule'],
        'ipaallowedtoperform_read_keys': ['user', 'group', 'host', 'hostgroup'],
        'ipaallowedtoperform_write_keys': ['user', 'group', 'host', 'hostgroup'],
    }
    bindable = True
    relationships = {
        'memberof': ('Member Of', 'in_', 'not_in_'),
        'enrolledby': ('Enrolled by', 'enroll_by_', 'not_enroll_by_'),
        'managedby': ('Managed by', 'man_by_', 'not_man_by_'),
        'managing': ('Managing', 'man_', 'not_man_'),
        'ipaallowedtoperform_read_keys': ('Allow to retrieve keytab by', 'retrieve_keytab_by_', 'not_retrieve_keytab_by_'),
        'ipaallowedtoperform_write_keys': ('Allow to create keytab by', 'write_keytab_by_', 'not_write_keytab_by'),
    }
    password_attributes = [('userpassword', 'has_password'),
                           ('krbprincipalkey', 'has_keytab')]
    managed_permissions = {
        'System: Read Hosts': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'description', 'fqdn', 'ipaclientversion',
                'ipakrbauthzdata', 'ipasshpubkey', 'ipauniqueid',
                'krbprincipalname', 'l', 'macaddress', 'nshardwareplatform',
                'nshostlocation', 'nsosversion', 'objectclass',
                'serverhostname', 'usercertificate', 'userclass',
                'enrolledby', 'managedby', 'ipaassignedidview',
                'krbprincipalname', 'krbcanonicalname', 'krbprincipalaliases',
                'krbprincipalexpiration', 'krbpasswordexpiration',
                'krblastpwdchange', 'krbprincipalauthind',
            },
        },
        'System: Read Host Membership': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'memberof',
            },
        },
        'System: Add Hosts': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///fqdn=*,cn=computers,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Add Hosts";allow (add) groupdn = "ldap:///cn=Add Hosts,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Host Administrators'},
        },
        'System: Add krbPrincipalName to a Host': {
            # Allow an admin to enroll a host that has a one-time password.
            # When a host is created with a password no krbPrincipalName is set.
            # This will let it be added if the client ends up enrolling with
            # an administrator instead.
            'ipapermright': {'write'},
            'ipapermtargetfilter': [
                '(objectclass=ipahost)',
                '(!(krbprincipalname=*))',
            ],
            'ipapermdefaultattr': {'krbprincipalname'},
            'replaces': [
                '(target = "ldap:///fqdn=*,cn=computers,cn=accounts,$SUFFIX")(targetfilter = "(!(krbprincipalname=*))")(targetattr = "krbprincipalname")(version 3.0;acl "permission:Add krbPrincipalName to a host"; allow (write) groupdn = "ldap:///cn=Add krbPrincipalName to a host,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Host Administrators', 'Host Enrollment'},
        },
        'System: Enroll a Host': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'objectclass', 'enrolledby'},
            'replaces': [
                '(targetattr = "objectclass")(target = "ldap:///fqdn=*,cn=computers,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Enroll a host";allow (write) groupdn = "ldap:///cn=Enroll a host,cn=permissions,cn=pbac,$SUFFIX";)',
                '(targetattr = "enrolledby || objectclass")(target = "ldap:///fqdn=*,cn=computers,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Enroll a host";allow (write) groupdn = "ldap:///cn=Enroll a host,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Host Administrators', 'Host Enrollment'},
        },
        'System: Manage Host SSH Public Keys': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'ipasshpubkey'},
            'replaces': [
                '(targetattr = "ipasshpubkey")(target = "ldap:///fqdn=*,cn=computers,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Manage Host SSH Public Keys";allow (write) groupdn = "ldap:///cn=Manage Host SSH Public Keys,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Host Administrators'},
        },
        'System: Manage Host Keytab': {
            'ipapermright': {'write'},
            'ipapermtargetfilter': [
                '(objectclass=ipahost)',
                '(!(memberOf=%s))' % DN('cn=ipaservers',
                                        api.env.container_hostgroup,
                                        api.env.basedn),
            ],
            'ipapermdefaultattr': {'krblastpwdchange', 'krbprincipalkey'},
            'replaces': [
                '(targetattr = "krbprincipalkey || krblastpwdchange")(target = "ldap:///fqdn=*,cn=computers,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Manage host keytab";allow (write) groupdn = "ldap:///cn=Manage host keytab,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Host Administrators', 'Host Enrollment'},
        },
        'System: Manage Host Keytab Permissions': {
            'ipapermright': {'read', 'search', 'compare', 'write'},
            'ipapermdefaultattr': {
                'ipaallowedtoperform;write_keys',
                'ipaallowedtoperform;read_keys', 'objectclass'
            },
            'default_privileges': {'Host Administrators'},
        },
        'System: Modify Hosts': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'description', 'l', 'nshardwareplatform', 'nshostlocation',
                'nsosversion', 'macaddress', 'userclass', 'ipaassignedidview',
                'krbprincipalauthind',
            },
            'replaces': [
                '(targetattr = "description || l || nshostlocation || nshardwareplatform || nsosversion")(target = "ldap:///fqdn=*,cn=computers,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Modify Hosts";allow (write) groupdn = "ldap:///cn=Modify Hosts,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Host Administrators'},
        },
        'System: Remove Hosts': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///fqdn=*,cn=computers,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Remove Hosts";allow (delete) groupdn = "ldap:///cn=Remove Hosts,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Host Administrators'},
        },
        'System: Manage Host Certificates': {
            'ipapermbindruletype': 'permission',
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'usercertificate'},
            'default_privileges': {'Host Administrators', 'Host Enrollment'},
        },
        'System: Manage Host Principals': {
            'ipapermbindruletype': 'permission',
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'krbprincipalname', 'krbcanonicalname'},
            'default_privileges': {'Host Administrators', 'Host Enrollment'},
        },
        'System: Manage Host Enrollment Password': {
            'ipapermbindruletype': 'permission',
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'userpassword'},
            'default_privileges': {'Host Administrators', 'Host Enrollment'},
        },
        'System: Read Host Compat Tree': {
            'non_object': True,
            'ipapermbindruletype': 'anonymous',
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN('cn=computers', 'cn=compat', api.env.basedn),
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass', 'cn', 'macaddress',
            },
        },
    }

    label = _('Hosts')
    label_singular = _('Host')

    takes_params = (
        Str('fqdn', hostname_validator,
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
        Certificate('usercertificate*',
            cli_name='certificate',
            label=_('Certificate'),
            doc=_('Base-64 encoded host certificate'),
        ),
        Str('subject',
            label=_('Subject'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('serial_number',
            label=_('Serial Number'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('serial_number_hex',
            label=_('Serial Number (hex)'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('issuer',
            label=_('Issuer'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('valid_not_before',
            label=_('Not Before'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('valid_not_after',
            label=_('Not After'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('sha1_fingerprint',
            label=_('Fingerprint (SHA1)'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('sha256_fingerprint',
            label=_('Fingerprint (SHA256)'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('revocation_reason?',
            label=_('Revocation reason'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Principal(
            'krbcanonicalname?',
            validate_realm,
            label=_('Principal name'),
            normalizer=normalize_principal,
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Principal(
            'krbprincipalname*',
            validate_realm,
            label=_('Principal alias'),
            normalizer=normalize_principal,
            flags=['no_create', 'no_search'],
        ),
        Str('macaddress*',
            normalizer=lambda value: value.upper(),
            pattern='^([a-fA-F0-9]{2}[:|\-]?){5}[a-fA-F0-9]{2}$',
            pattern_errmsg=('Must be of the form HH:HH:HH:HH:HH:HH, where '
                            'each H is a hexadecimal character.'),
            label=_('MAC address'),
            doc=_('Hardware MAC address(es) on this host'),
        ),
        Str('ipasshpubkey*', validate_sshpubkey_no_options,
            cli_name='sshpubkey',
            label=_('SSH public key'),
            normalizer=normalize_sshpubkey,
            flags=['no_search'],
        ),
        Str('sshpubkeyfp*',
            label=_('SSH public key fingerprint'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('userclass*',
            cli_name='class',
            label=_('Class'),
            doc=_('Host category (semantics placed on this attribute are for '
                  'local interpretation)'),
        ),
        Str('ipaassignedidview?',
            label=_('Assigned ID View'),
            flags=['no_option'],
        ),
        Str('krbprincipalauthind*',
            cli_name='auth_ind',
            label=_('Authentication Indicators'),
            doc=_("Defines a whitelist for Authentication Indicators."
                  " Use 'otp' to allow OTP-based 2FA authentications."
                  " Use 'radius' to allow RADIUS-based 2FA authentications."
                  " Other values may be used for custom configurations."),
        ),
    ) + ticket_flags_params

    def get_dn(self, *keys, **options):
        hostname = keys[-1]
        dn = super(host, self).get_dn(hostname, **options)
        try:
            self.backend.get_entry(dn, [''])
        except errors.NotFound:
            try:
                entry_attrs = self.backend.find_entry_by_attr(
                    'serverhostname', hostname, self.object_class, [''],
                    DN(self.container_dn, api.env.basedn))
                dn = entry_attrs.dn
            except errors.NotFound:
                pass
        return dn

    def get_managed_hosts(self, dn):
        host_filter = 'managedBy=%s' % dn
        host_attrs = ['fqdn']
        ldap = self.api.Backend.ldap2
        managed_hosts = []

        try:
            (hosts, _truncated) = ldap.find_entries(
                base_dn=DN(self.container_dn, api.env.basedn),
                filter=host_filter, attrs_list=host_attrs)

            for host in hosts:
                managed_hosts.append(host.dn)
        except errors.NotFound:
            return []

        return managed_hosts

    def suppress_netgroup_memberof(self, ldap, entry_attrs):
        """
        We don't want to show managed netgroups so remove them from the
        memberofindirect list.
        """
        ng_container = DN(api.env.container_netgroup, api.env.basedn)
        for member in list(entry_attrs.get('memberofindirect', [])):
            memberdn = DN(member)
            if not memberdn.endswith(ng_container):
                continue

            filter = ldap.make_filter({'objectclass': 'mepmanagedentry'})
            try:
                ldap.get_entries(memberdn, ldap.SCOPE_BASE, filter, [''])
            except errors.NotFound:
                pass
            else:
                entry_attrs['memberofindirect'].remove(member)


@register()
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
            add_records_for_host_validation('ip_address',
                    DNSName(host),
                    DNSName(domain).make_absolute(),
                    options['ip_address'],
                    check_forward=True,
                    check_reverse=check_reverse)
        if not options.get('force', False) and 'ip_address' not in options:
            util.verify_host_resolvable(keys[-1])
        if 'locality' in entry_attrs:
            entry_attrs['l'] = entry_attrs['locality']
        entry_attrs['cn'] = keys[-1]
        entry_attrs['serverhostname'] = keys[-1].split('.', 1)[0]
        if not entry_attrs.get('userpassword', False) and not options.get('random', False):
            entry_attrs['krbprincipalname'] = 'host/%s@%s' % (
                keys[-1], self.api.env.realm
            )
            if 'krbprincipalaux' not in entry_attrs['objectclass']:
                entry_attrs['objectclass'].append('krbprincipalaux')
            if 'krbprincipal' not in entry_attrs['objectclass']:
                entry_attrs['objectclass'].append('krbprincipal')
            set_krbcanonicalname(entry_attrs)
        else:
            if 'krbprincipalaux' in entry_attrs['objectclass']:
                entry_attrs['objectclass'].remove('krbprincipalaux')
            if 'krbprincipal' in entry_attrs['objectclass']:
                entry_attrs['objectclass'].remove('krbprincipal')
        if options.get('random'):
            entry_attrs['userpassword'] = ipa_generate_password(
                entropy_bits=TMP_PWD_ENTROPY_BITS, special=None)
            # save the password so it can be displayed in post_callback
            setattr(context, 'randompassword', entry_attrs['userpassword'])

        entry_attrs['managedby'] = dn
        entry_attrs['objectclass'].append('ieee802device')
        entry_attrs['objectclass'].append('ipasshhost')
        update_krbticketflags(ldap, entry_attrs, attrs_list, options, False)
        if 'krbticketflags' in entry_attrs:
            entry_attrs['objectclass'].append('krbticketpolicyaux')
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        if dns_container_exists(ldap):
            try:
                parts = keys[-1].split('.')
                host = parts[0]
                domain = unicode('.'.join(parts[1:]))

                if options.get('ip_address'):
                    add_reverse = not options.get('no_reverse', False)

                    add_records_for_host(DNSName(host),
                                         DNSName(domain).make_absolute(),
                                         options['ip_address'],
                                         add_forward=True,
                                         add_reverse=add_reverse)
                    del options['ip_address']

                update_sshfp_record(domain, unicode(parts[0]), entry_attrs)
            except Exception as e:
                self.add_message(messages.FailedToAddHostDNSRecords(reason=e))
        if options.get('random', False):
            try:
                entry_attrs['randompassword'] = unicode(
                    getattr(context, 'randompassword'))
            except AttributeError:
                # On the off-chance some other extension deletes this from the
                # context, don't crash.
                pass
        set_certificate_attrs(entry_attrs)
        set_kerberos_attrs(entry_attrs, options)
        rename_ipaallowedtoperform_from_ldap(entry_attrs, options)

        if options.get('all', False):
            entry_attrs['managing'] = self.obj.get_managed_hosts(dn)
        self.obj.get_password_attributes(ldap, dn, entry_attrs)
        if entry_attrs['has_password']:
            # If an OTP is set there is no keytab, at least not one
            # fetched anywhere.
            entry_attrs['has_keytab'] = False

        convert_sshpubkey_post(entry_attrs)

        return dn


@register()
class host_del(LDAPDelete):
    __doc__ = _('Delete a host.')

    msg_summary = _('Deleted host "%(value)s"')
    member_attributes = ['managedby']

    takes_options = LDAPDelete.takes_options + (
        Flag('updatedns?',
            doc=_('Remove A, AAAA, SSHFP and PTR records of the host(s) '
                  'managed by IPA DNS'),
            default=False,
        ),
    )

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        # If we aren't given a fqdn, find it
        if hostname_validator(None, keys[-1]) is not None:
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
                    principal = kerberos.Principal(
                        entry_attrs['krbprincipalname'][0])
                    hostname = principal.hostname
                    if hostname.lower() == fqdn:
                        api.Command['service_del'](principal)
        updatedns = options.get('updatedns', False)
        if updatedns:
            try:
                updatedns = dns_container_exists(ldap)
            except errors.NotFound:
                updatedns = False

        if updatedns:
            # Remove A, AAAA, SSHFP and PTR records of the host
            fqdn_dnsname = DNSName(fqdn).make_absolute()
            zone = DNSName(dns.resolver.zone_for_name(fqdn_dnsname))
            relative_hostname = fqdn_dnsname.relativize(zone)

            # Get all resources for this host
            rec_removed = False
            try:
                record = api.Command['dnsrecord_show'](
                    zone, relative_hostname)['result']
            except errors.NotFound:
                pass
            else:
                # remove PTR records first
                for attr in ('arecord', 'aaaarecord'):
                    for val in record.get(attr, []):
                        rec_removed = (
                            remove_ptr_rec(val, fqdn_dnsname) or
                            rec_removed
                        )
                try:
                    # remove all A, AAAA, SSHFP records of the host
                    api.Command['dnsrecord_mod'](
                        zone,
                        record['idnsname'][0],
                        arecord=[],
                        aaaarecord=[],
                        sshfprecord=[]
                        )
                except errors.EmptyModlist:
                    pass
                else:
                    rec_removed = True

            if not rec_removed:
                self.add_message(
                    messages.FailedToRemoveHostDNSRecords(
                        host=fqdn,
                        reason=_("No A, AAAA, SSHFP or PTR records found.")
                    )
                )

        if self.api.Command.ca_is_enabled()['result']:
            certs = self.api.Command.cert_find(host=keys)['result']
            revoke_certs(certs)

        return dn


@register()
class host_mod(LDAPUpdate):
    __doc__ = _('Modify information about a host.')

    has_output_params = LDAPUpdate.has_output_params + host_output_params
    msg_summary = _('Modified host "%(value)s"')
    member_attributes = ['managedby']

    takes_options = LDAPUpdate.takes_options + (
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
                raise errors.ValidationError(
                    name='password',
                    error=_('Password cannot be set on enrolled host.'))

        # Once a principal name is set it cannot be changed
        if 'cn' in entry_attrs:
            raise errors.ACIError(info=_('cn is immutable'))
        if 'locality' in entry_attrs:
            entry_attrs['l'] = entry_attrs['locality']
        if 'krbprincipalname' in entry_attrs:
            entry_attrs_old = ldap.get_entry(
                dn, ['objectclass', 'krbprincipalname']
            )
            if 'krbprincipalname' in entry_attrs_old:
                msg = 'Principal name already set, it is unchangeable.'
                raise errors.ACIError(info=msg)
            obj_classes = entry_attrs_old['objectclass']
            if 'krbprincipalaux' not in (item.lower() for item in
                                         obj_classes):
                obj_classes.append('krbprincipalaux')
                entry_attrs['objectclass'] = obj_classes

        # verify certificates
        certs = entry_attrs.get('usercertificate') or []

        # revoke removed certificates
        ca_is_enabled = self.api.Command.ca_is_enabled()['result']
        if 'usercertificate' in options and ca_is_enabled:
            try:
                entry_attrs_old = ldap.get_entry(dn, ['usercertificate'])
            except errors.NotFound:
                raise self.obj.handle_not_found(*keys)
            old_certs = entry_attrs_old.get('usercertificate', [])
            removed_certs = set(old_certs) - set(certs)
            for cert in removed_certs:
                rm_certs = api.Command.cert_find(
                    certificate=cert,
                    host=keys)['result']
                revoke_certs(rm_certs)

        if certs:
            entry_attrs['usercertificate'] = certs

        if options.get('random'):
            entry_attrs['userpassword'] = ipa_generate_password(
                entropy_bits=TMP_PWD_ENTROPY_BITS)
            setattr(context, 'randompassword', entry_attrs['userpassword'])

        if 'macaddress' in entry_attrs:
            if 'objectclass' in entry_attrs:
                obj_classes = entry_attrs['objectclass']
            else:
                _entry_attrs = ldap.get_entry(dn, ['objectclass'])
                obj_classes = _entry_attrs['objectclass']
            if 'ieee802device' not in (item.lower() for item in obj_classes):
                obj_classes.append('ieee802device')
                entry_attrs['objectclass'] = obj_classes

        if options.get('updatedns', False) and dns_container_exists(ldap):
            parts = keys[-1].split('.')
            domain = unicode('.'.join(parts[1:]))
            try:
                result = api.Command['dnszone_show'](domain)['result']
                domain = result['idnsname'][0]
            except errors.NotFound:
                raise self.obj.handle_not_found(*keys)
            update_sshfp_record(domain, unicode(parts[0]), entry_attrs)

        if 'ipasshpubkey' in entry_attrs:
            if 'objectclass' in entry_attrs:
                obj_classes = entry_attrs['objectclass']
            else:
                _entry_attrs = ldap.get_entry(dn, ['objectclass'])
                obj_classes = entry_attrs['objectclass'] = _entry_attrs['objectclass']
            if 'ipasshhost' not in (item.lower() for item in obj_classes):
                obj_classes.append('ipasshhost')

        update_krbticketflags(ldap, entry_attrs, attrs_list, options, True)

        if 'krbticketflags' in entry_attrs:
            if 'objectclass' not in entry_attrs:
                entry_attrs_old = ldap.get_entry(dn, ['objectclass'])
                entry_attrs['objectclass'] = entry_attrs_old['objectclass']
            if 'krbticketpolicyaux' not in (item.lower() for item in
                                            entry_attrs['objectclass']):
                entry_attrs['objectclass'].append('krbticketpolicyaux')

        if 'krbprincipalauthind' in entry_attrs:
            if 'objectclass' not in entry_attrs:
                entry_attrs_old = ldap.get_entry(dn, ['objectclass'])
                entry_attrs['objectclass'] = entry_attrs_old['objectclass']
            if 'krbprincipalaux' not in (item.lower() for item in
                                         entry_attrs['objectclass']):
                entry_attrs['objectclass'].append('krbprincipalaux')

        add_sshpubkey_to_attrs_pre(self.context, attrs_list)

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        if options.get('random', False):
            entry_attrs['randompassword'] = unicode(getattr(context, 'randompassword'))
        set_certificate_attrs(entry_attrs)
        set_kerberos_attrs(entry_attrs, options)
        rename_ipaallowedtoperform_from_ldap(entry_attrs, options)
        self.obj.get_password_attributes(ldap, dn, entry_attrs)
        if entry_attrs['has_password']:
            # If an OTP is set there is no keytab, at least not one
            # fetched anywhere.
            entry_attrs['has_keytab'] = False

        if options.get('all', False):
            entry_attrs['managing'] = self.obj.get_managed_hosts(dn)

        self.obj.suppress_netgroup_memberof(ldap, entry_attrs)

        convert_sshpubkey_post(entry_attrs)
        remove_sshpubkey_from_output_post(self.context, entry_attrs)
        convert_ipaassignedidview_post(entry_attrs, options)

        return dn


@register()
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
                        entry_attrs = ldap.get_entry(dn, ['managedby'])
                    except errors.NotFound:
                        raise self.obj.handle_not_found(pkey)
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
                        entry_attrs = ldap.get_entry(dn, ['managedby'])
                    except errors.NotFound:
                        raise self.obj.handle_not_found(pkey)
                    not_hosts += entry_attrs.get('managedby', [])
                not_hosts = list(set(not_hosts))

            for target_hosts, filter_op in ((hosts, ldap.MATCH_ANY),
                                            (not_hosts, ldap.MATCH_NONE)):
                hosts_avas = [DN(host)[0][0] for host in target_hosts]
                hosts_filters = [ldap.make_filter_from_attr(ava.attr, ava.value)
                                 for ava in hosts_avas]
                hosts_filter = ldap.combine_filters(hosts_filters, filter_op)

                filter = ldap.combine_filters(
                        (filter, hosts_filter), ldap.MATCH_ALL
                    )

        add_sshpubkey_to_attrs_pre(self.context, attrs_list)

        return (filter.replace('locality', 'l'), base_dn, scope)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if options.get('pkey_only', False):
            return truncated
        for entry_attrs in entries:
            hostname = entry_attrs['fqdn']
            if isinstance(hostname, (tuple, list)):
                hostname = hostname[0]
            try:
                set_certificate_attrs(entry_attrs)
            except errors.CertificateFormatError as e:
                self.add_message(
                    messages.CertificateInvalid(
                        subject=hostname,
                        reason=e,
                    )
                )
                logger.error("Invalid certificate: %s", e)
                del(entry_attrs['usercertificate'])

            set_kerberos_attrs(entry_attrs, options)
            rename_ipaallowedtoperform_from_ldap(entry_attrs, options)
            self.obj.suppress_netgroup_memberof(ldap, entry_attrs)

            if options.get('all', False):
                entry_attrs['managing'] = self.obj.get_managed_hosts(entry_attrs.dn)

            convert_sshpubkey_post(entry_attrs)
            convert_ipaassignedidview_post(entry_attrs, options)

        remove_sshpubkey_from_output_list_post(self.context, entries)

        return truncated


@register()
class host_show(LDAPRetrieve):
    __doc__ = _('Display information about a host.')

    has_output_params = LDAPRetrieve.has_output_params + host_output_params
    takes_options = LDAPRetrieve.takes_options + (
        Str('out?',
            doc=_('file to store certificate in'),
        ),
    )

    member_attributes = ['managedby']

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        add_sshpubkey_to_attrs_pre(self.context, attrs_list)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.get_password_attributes(ldap, dn, entry_attrs)
        if entry_attrs['has_password']:
            # If an OTP is set there is no keytab, at least not one
            # fetched anywhere.
            entry_attrs['has_keytab'] = False

        hostname = entry_attrs['fqdn']
        if isinstance(hostname, (tuple, list)):
            hostname = hostname[0]
        try:
            set_certificate_attrs(entry_attrs)
        except errors.CertificateFormatError as e:
            self.add_message(
                messages.CertificateInvalid(
                    subject=hostname,
                    reason=e,
                )
            )
            del(entry_attrs['usercertificate'])

        set_kerberos_attrs(entry_attrs, options)
        rename_ipaallowedtoperform_from_ldap(entry_attrs, options)

        if options.get('all', False):
            entry_attrs['managing'] = self.obj.get_managed_hosts(dn)

        self.obj.suppress_netgroup_memberof(ldap, entry_attrs)

        convert_sshpubkey_post(entry_attrs)
        remove_sshpubkey_from_output_post(self.context, entry_attrs)
        convert_ipaassignedidview_post(entry_attrs, options)

        return dn


@register()
class host_disable(LDAPQuery):
    __doc__ = _('Disable the Kerberos key, SSL certificate and all services of a host.')

    has_output = output.standard_value
    msg_summary = _('Disabled host "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        # If we aren't given a fqdn, find it
        if hostname_validator(None, keys[-1]) is not None:
            hostentry = api.Command['host_show'](keys[-1])['result']
            fqdn = hostentry['fqdn'][0]
        else:
            fqdn = keys[-1]

        host_is_master(ldap, fqdn)

        # See if we actually do anthing here, and if not raise an exception
        done_work = False

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
                    principal = kerberos.Principal(
                        entry_attrs['krbprincipalname'][0])
                    hostname = principal.hostname
                    if hostname.lower() == fqdn:
                        try:
                            api.Command['service_disable'](principal)
                            done_work = True
                        except errors.AlreadyInactive:
                            pass

        dn = self.obj.get_dn(*keys, **options)
        try:
            entry_attrs = ldap.get_entry(dn, ['usercertificate'])
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)
        if self.api.Command.ca_is_enabled()['result']:
            certs = self.api.Command.cert_find(host=keys)['result']

            if certs:
                revoke_certs(certs)
                # Remove the usercertificate altogether
                entry_attrs['usercertificate'] = None
                ldap.update_entry(entry_attrs)
                done_work = True

        self.obj.get_password_attributes(ldap, dn, entry_attrs)
        if entry_attrs['has_keytab']:
            ldap.remove_principal_key(dn)
            done_work = True

        if not done_work:
            raise errors.AlreadyInactive()

        return dict(
            result=True,
            value=pkey_to_value(keys[0], options),
        )

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.suppress_netgroup_memberof(ldap, entry_attrs)
        return dn


@register()
class host_add_managedby(LDAPAddMember):
    __doc__ = _('Add hosts that can manage this host.')

    member_attributes = ['managedby']
    has_output_params = LDAPAddMember.has_output_params + host_output_params
    allow_same = True

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.suppress_netgroup_memberof(ldap, entry_attrs)
        return (completed, dn)


@register()
class host_remove_managedby(LDAPRemoveMember):
    __doc__ = _('Remove hosts that can manage this host.')

    member_attributes = ['managedby']
    has_output_params = LDAPRemoveMember.has_output_params + host_output_params

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.suppress_netgroup_memberof(ldap, entry_attrs)
        return (completed, dn)


@register()
class host_allow_retrieve_keytab(LDAPAddMember):
    __doc__ = _('Allow users, groups, hosts or host groups to retrieve a keytab'
                ' of this host.')
    member_attributes = ['ipaallowedtoperform_read_keys']
    has_output_params = LDAPAddMember.has_output_params + host_output_params

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        rename_ipaallowedtoperform_to_ldap(found)
        rename_ipaallowedtoperform_to_ldap(not_found)
        add_missing_object_class(ldap, u'ipaallowedoperations', dn)
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        rename_ipaallowedtoperform_from_ldap(entry_attrs, options)
        rename_ipaallowedtoperform_from_ldap(failed, options)
        return (completed, dn)


@register()
class host_disallow_retrieve_keytab(LDAPRemoveMember):
    __doc__ = _('Disallow users, groups, hosts or host groups to retrieve a '
                'keytab of this host.')
    member_attributes = ['ipaallowedtoperform_read_keys']
    has_output_params = LDAPRemoveMember.has_output_params + host_output_params

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        rename_ipaallowedtoperform_to_ldap(found)
        rename_ipaallowedtoperform_to_ldap(not_found)
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        rename_ipaallowedtoperform_from_ldap(entry_attrs, options)
        rename_ipaallowedtoperform_from_ldap(failed, options)
        return (completed, dn)


@register()
class host_allow_create_keytab(LDAPAddMember):
    __doc__ = _('Allow users, groups, hosts or host groups to create a keytab '
                'of this host.')
    member_attributes = ['ipaallowedtoperform_write_keys']
    has_output_params = LDAPAddMember.has_output_params + host_output_params

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        rename_ipaallowedtoperform_to_ldap(found)
        rename_ipaallowedtoperform_to_ldap(not_found)
        add_missing_object_class(ldap, u'ipaallowedoperations', dn)
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        rename_ipaallowedtoperform_from_ldap(entry_attrs, options)
        rename_ipaallowedtoperform_from_ldap(failed, options)
        return (completed, dn)


@register()
class host_disallow_create_keytab(LDAPRemoveMember):
    __doc__ = _('Disallow users, groups, hosts or host groups to create a '
                'keytab of this host.')
    member_attributes = ['ipaallowedtoperform_write_keys']
    has_output_params = LDAPRemoveMember.has_output_params + host_output_params

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        rename_ipaallowedtoperform_to_ldap(found)
        rename_ipaallowedtoperform_to_ldap(not_found)
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        rename_ipaallowedtoperform_from_ldap(entry_attrs, options)
        rename_ipaallowedtoperform_from_ldap(failed, options)
        return (completed, dn)


@register()
class host_add_cert(LDAPAddAttributeViaOption):
    __doc__ = _('Add certificates to host entry')
    msg_summary = _('Added certificates to host "%(value)s"')
    attribute = 'usercertificate'


@register()
class host_remove_cert(LDAPRemoveAttributeViaOption):
    __doc__ = _('Remove certificates from host entry')
    msg_summary = _('Removed certificates from host "%(value)s"')
    attribute = 'usercertificate'

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)

        for cert in options.get('usercertificate', []):
            revoke_certs(api.Command.cert_find(
                certificate=cert,
                host=keys)['result'])

        return dn


@register()
class host_add_principal(LDAPAddAttribute):
    __doc__ = _('Add new principal alias to host entry')
    msg_summary = _('Added new aliases to host "%(value)s"')
    attribute = 'krbprincipalname'

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        util.check_principal_realm_in_trust_namespace(self.api, *keys)
        util.ensure_krbcanonicalname_set(ldap, entry_attrs)
        return dn


@register()
class host_remove_principal(LDAPRemoveAttribute):
    __doc__ = _('Remove principal alias from a host entry')
    msg_summary = _('Removed aliases from host "%(value)s"')
    attribute = 'krbprincipalname'

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        util.ensure_last_krbprincipalname(ldap, entry_attrs, *keys)
        return dn
