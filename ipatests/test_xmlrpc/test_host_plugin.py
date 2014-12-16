# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008, 2009  Red Hat
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

"""
Test the `ipalib.plugins.host` module.
"""

import os
import tempfile
import base64

import pytest
from pytest_sourceorder import ordered

from ipapython import ipautil
from ipalib import api, errors, x509
from ipalib.util import normalize_zone
from ipapython.dn import DN
from ipapython.dnsutil import DNSName
from ipatests.test_xmlrpc.xmlrpc_test import (RPCTest, XMLRPC_test,
    fuzzy_uuid, fuzzy_digits, fuzzy_hash, fuzzy_date, fuzzy_issuer,
    fuzzy_hex, raises_exact)
from ipatests.test_xmlrpc.test_user_plugin import get_group_dn
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.testcert import get_testcert
from ipatests.util import assert_deepequal

self_server_ns = normalize_zone(api.env.host)
self_server_ns_dnsname = DNSName(self_server_ns)

fqdn1 = u'testhost1.%s' % api.env.domain
short1 = u'testhost1'
dn1 = DN(('fqdn',fqdn1),('cn','computers'),('cn','accounts'),
         api.env.basedn)
service1 = u'dns/%s@%s' % (fqdn1, api.env.realm)
service1dn = DN(('krbprincipalname',service1.lower()),('cn','services'),
                ('cn','accounts'),api.env.basedn)
fqdn2 = u'shouldnotexist.%s' % api.env.domain
dn2 = DN(('fqdn',fqdn2),('cn','computers'),('cn','accounts'),
         api.env.basedn)
fqdn3 = u'testhost2.%s' % api.env.domain
short3 = u'testhost2'
dn3 = DN(('fqdn',fqdn3),('cn','computers'),('cn','accounts'),
         api.env.basedn)
fqdn4 = u'testhost2.lab.%s' % api.env.domain
dn4 = DN(('fqdn',fqdn4),('cn','computers'),('cn','accounts'),
         api.env.basedn)
invalidfqdn1 = u'foo_bar.lab.%s' % api.env.domain

# DNS integration tests
dnszone = u'zone-ipv6host.test'
dnszone_absolute = dnszone + '.'
dnszone_dnsname = DNSName(dnszone_absolute)
dnszone_dn = DN(('idnsname', dnszone_absolute), api.env.container_dns, api.env.basedn)
dnszone_ns = u'ns1.%s' % dnszone_absolute
dnszone_ns_dnsname = DNSName(dnszone_ns)
dnszone_rname = u'root.%s' % dnszone_absolute
dnszone_rname_dnsname = DNSName(dnszone_rname)
dnszone_ip = u'172.16.29.1'

revzone = u'29.16.172.in-addr.arpa.'
revzone_dnsname = DNSName(revzone)
revzone_ip = u'172.16.29.0'
revzone_ipprefix = u'172.16.29.'
revzone_dn = DN(('idnsname', revzone), api.env.container_dns, api.env.basedn)

revipv6zone = u'0.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.'
revipv6zone_dnsname = DNSName(revipv6zone)
revipv6zone_ip = u'2001:db8:1::'
revipv6zone_ipprefix = u'2001:db8:1:'
revipv6zone_dn = DN(('idnsname', revipv6zone), api.env.container_dns, api.env.basedn)

arec = u'172.16.29.22'
aaaarec = u'2001:db8:1::beef'

arec2 = u'172.16.29.33'
aaaarec2 = u'2001:db8:1::dead'

ipv6only = u'testipv6onlyhost'
ipv6only_dnsname = DNSName(ipv6only)
ipv6only_dn = DN(('idnsname', ipv6only), dnszone_dn)
ipv6only_host_fqdn = u'%s.%s' % (ipv6only, dnszone)
ipv6only_host_dn = DN(('fqdn',ipv6only_host_fqdn),('cn','computers'),('cn','accounts'),
         api.env.basedn)

ipv4only = u'testipv4onlyhost'
ipv4only_dnsname = DNSName(ipv4only)
ipv4only_dn = DN(('idnsname', ipv4only), dnszone_dn)
ipv4only_host_fqdn = u'%s.%s' % (ipv4only, dnszone)
ipv4only_host_dn = DN(('fqdn',ipv4only_host_fqdn),('cn','computers'),('cn','accounts'),
         api.env.basedn)

ipv46both = u'testipv4and6host'
ipv46both_dnsname = DNSName(ipv46both)
ipv46both_dn = DN(('idnsname', ipv46both), dnszone_dn)
ipv46both_host_fqdn = u'%s.%s' % (ipv46both, dnszone)
ipv46both_host_dn = DN(('fqdn',ipv46both_host_fqdn),('cn','computers'),('cn','accounts'),
         api.env.basedn)

ipv4_fromip = u'withipv4addr'
ipv4_fromip_ip = u'172.16.29.40'
ipv4_fromip_arec = ipv4_fromip_ip
ipv4_fromip_dnsname = DNSName(ipv4_fromip)
ipv4_fromip_dn = DN(('idnsname', ipv4_fromip), dnszone_dn)
ipv4_fromip_host_fqdn = u'%s.%s' % (ipv4_fromip, dnszone)
ipv4_fromip_host_dn = DN(('fqdn',ipv4_fromip_host_fqdn),('cn','computers'),('cn','accounts'),
         api.env.basedn)
ipv4_fromip_ptr = u'40'
ipv4_fromip_ptrrec = ipv4_fromip_host_fqdn + '.'
ipv4_fromip_ptr_dnsname = DNSName(ipv4_fromip_ptr)
ipv4_fromip_ptr_dn = DN(('idnsname', ipv4_fromip_ptr), revzone_dn)

ipv6_fromip = u'withipv6addr'
ipv6_fromip_ipv6 = u'2001:db8:1::9'
ipv6_fromip_aaaarec = ipv6_fromip_ipv6
ipv6_fromip_dnsname = DNSName(ipv6_fromip)
ipv6_fromip_dn = DN(('idnsname', ipv6_fromip), dnszone_dn)
ipv6_fromip_host_fqdn = u'%s.%s' % (ipv6_fromip, dnszone)
ipv6_fromip_host_dn = DN(('fqdn',ipv6_fromip_host_fqdn),('cn','computers'),('cn','accounts'),
         api.env.basedn)
ipv6_fromip_ptr = u'9.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0'
ipv6_fromip_ptrrec = ipv6_fromip_host_fqdn + '.'
ipv6_fromip_ptr_dnsname = DNSName(ipv6_fromip_ptr)
ipv6_fromip_ptr_dn = DN(('idnsname', ipv6_fromip_ptr), revipv6zone_dn)

sshpubkey = u'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGAX3xAeLeaJggwTqMjxNwa6XHBUAikXPGMzEpVrlLDCZtv00djsFTBi38PkgxBJVkgRWMrcBsr/35lq7P6w8KGIwA8GI48Z0qBS2NBMJ2u9WQ2hjLN6GdMlo77O0uJY3251p12pCVIS/bHRSq8kHO2No8g7KA9fGGcagPfQH+ee3t7HUkpbQkFTmbPPN++r3V8oVUk5LxbryB3UIIVzNmcSIn3JrXynlvui4MixvrtX6zx+O/bBo68o8/eZD26QrahVbA09fivrn/4h3TM019Eu/c2jOdckfU3cHUV/3Tno5d6JicibyaoDDK7S/yjdn5jhaz8MSEayQvFkZkiF0L public key test'
sshpubkeyfp = u'13:67:6B:BF:4E:A2:05:8E:AE:25:8B:A1:31:DE:6F:1B public key test (ssh-rsa)'

user1 = u'tuser1'
user2 = u'tuser2'
group1 = u'group1'
group1_dn = get_group_dn(group1)
group2 = u'group2'
group2_dn = get_group_dn(group2)
hostgroup1 = u'testhostgroup1'
hostgroup1_dn = DN(('cn',hostgroup1),('cn','hostgroups'),('cn','accounts'),
                    api.env.basedn)


class TestNonexistentHost(RPCTest):
    @classmethod
    def clean_up(cls):
        cls.clean('host_del', fqdn1)

    def test_retrieve_nonexistent(self, command):
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % fqdn1)):
            result = command('host_show', fqdn1)

    def test_update_nonexistent(self, command):
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % fqdn1)):
            result = command('host_mod', fqdn1, description=u'Nope')

    def test_delete_nonexistent(self, command):
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % fqdn1)):
            result = command('host_del', fqdn1)


@ordered
class TestHost(RPCTest):
    @classmethod
    def clean_up(cls):
        cls.clean('host_del', fqdn1)

    def test_create_host(self, command):
        result = command('host_add', fqdn1,
                         description=u'Test host 1',
                         l=u'Undisclosed location 1',
                         force=True)
        assert_deepequal(dict(
            value=fqdn1,
            summary=u'Added host "%s"' % fqdn1,
            result=dict(
                dn=dn1,
                fqdn=[fqdn1],
                description=[u'Test host 1'],
                l=[u'Undisclosed location 1'],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                objectclass=objectclasses.host,
                ipauniqueid=[fuzzy_uuid],
                managedby_host=[fqdn1],
                has_keytab=False,
                has_password=False,
            ),
        ), result)

    def test_create_duplicate(self, command):
        with raises_exact(errors.DuplicateEntry(
                message=u'host with name "%s" already exists' % fqdn1)):
            result = command('host_add', fqdn1,
                             description=u'Test host 1',
                             l=u'Undisclosed location 1',
                             force=True)

    def test_retrieve(self, command):
        result = command('host_show', fqdn1)
        assert_deepequal(dict(
            value=fqdn1,
            summary=None,
            result=dict(
                dn=dn1,
                fqdn=[fqdn1],
                description=[u'Test host 1'],
                l=[u'Undisclosed location 1'],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                has_keytab=False,
                has_password=False,
                managedby_host=[fqdn1],
            ),
        ), result)

    def test_retrieve_all(self, command):
        result = command('host_show', fqdn1, all=True)
        assert_deepequal(dict(
            value=fqdn1,
            summary=None,
            result=dict(
                dn=dn1,
                cn=[fqdn1],
                fqdn=[fqdn1],
                description=[u'Test host 1'],
                l=[u'Undisclosed location 1'],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                serverhostname=[u'testhost1'],
                objectclass=objectclasses.host,
                managedby_host=[fqdn1],
                managing_host=[fqdn1],
                ipauniqueid=[fuzzy_uuid],
                has_keytab=False,
                has_password=False,
                ipakrbokasdelegate=False,
                ipakrbrequirespreauth=True,
            ),
        ), result)

    def test_search(self, command):
        result = command('host_find', fqdn1)
        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary=u'1 host matched',
            result=[
                dict(
                    dn=dn1,
                    fqdn=[fqdn1],
                    description=[u'Test host 1'],
                    l=[u'Undisclosed location 1'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                    managedby_host=[u'%s' % fqdn1],
                    has_keytab=False,
                    has_password=False,
                ),
            ],
        ), result)

    def test_search_all(self, command):
        result = command('host_find', fqdn1, all=True)
        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary=u'1 host matched',
            result=[
                dict(
                    dn=dn1,
                    cn=[fqdn1],
                    fqdn=[fqdn1],
                    description=[u'Test host 1'],
                    l=[u'Undisclosed location 1'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                    serverhostname=[u'testhost1'],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[u'%s' % fqdn1],
                    managing_host=[u'%s' % fqdn1],
                    has_keytab=False,
                    has_password=False,
                    ipakrbokasdelegate=False,
                    ipakrbrequirespreauth=True,
                ),
            ]
        ), result)

    def test_update(self, command):
        result = command('host_mod', fqdn1,
                         description=u'Updated host 1',
                         usercertificate=get_testcert())
        assert_deepequal(dict(
            value=fqdn1,
            summary=u'Modified host "%s"' % fqdn1,
            result=dict(
                description=[u'Updated host 1'],
                fqdn=[fqdn1],
                l=[u'Undisclosed location 1'],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                managedby_host=[u'%s' % fqdn1],
                usercertificate=[base64.b64decode(get_testcert())],
                valid_not_before=fuzzy_date,
                valid_not_after=fuzzy_date,
                subject=DN(('CN', api.env.host), x509.subject_base()),
                serial_number=fuzzy_digits,
                serial_number_hex=fuzzy_hex,
                md5_fingerprint=fuzzy_hash,
                sha1_fingerprint=fuzzy_hash,
                issuer=fuzzy_issuer,
                has_keytab=False,
                has_password=False,
            ),
        ), result)

    def test_retrieve_2(self, command):
        result = command('host_show', fqdn1)
        assert_deepequal(dict(
            value=fqdn1,
            summary=None,
            result=dict(
                dn=dn1,
                fqdn=[fqdn1],
                description=[u'Updated host 1'],
                l=[u'Undisclosed location 1'],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                has_keytab=False,
                has_password=False,
                managedby_host=[u'%s' % fqdn1],
                usercertificate=[base64.b64decode(get_testcert())],
                valid_not_before=fuzzy_date,
                valid_not_after=fuzzy_date,
                subject=DN(('CN', api.env.host), x509.subject_base()),
                serial_number=fuzzy_digits,
                serial_number_hex=fuzzy_hex,
                md5_fingerprint=fuzzy_hash,
                sha1_fingerprint=fuzzy_hash,
                issuer=fuzzy_issuer,
            ),
        ), result)

    def test_try_rename(self, command):
        with raises_exact(errors.NotAllowedOnRDN()):
            result = command('host_mod', fqdn1,
                             setattr=u'fqdn=changed.example.com')

    def test_add_mac_address(self, command):
        result = command('host_mod', fqdn1, macaddress=u'00:50:56:30:F6:5F')
        assert_deepequal(dict(
            value=fqdn1,
            summary=u'Modified host "%s"' % fqdn1,
            result=dict(
                description=[u'Updated host 1'],
                fqdn=[fqdn1],
                l=[u'Undisclosed location 1'],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                managedby_host=[u'%s' % fqdn1],
                usercertificate=[base64.b64decode(get_testcert())],
                valid_not_before=fuzzy_date,
                valid_not_after=fuzzy_date,
                subject=DN(('CN', api.env.host), x509.subject_base()),
                serial_number=fuzzy_digits,
                serial_number_hex=fuzzy_hex,
                md5_fingerprint=fuzzy_hash,
                sha1_fingerprint=fuzzy_hash,
                macaddress=[u'00:50:56:30:F6:5F'],
                issuer=fuzzy_issuer,
                has_keytab=False,
                has_password=False,
            ),
        ), result)

    def test_add_mac_addresses(self, command):
        result = command('host_mod', fqdn1,
                         macaddress=[u'00:50:56:30:F6:5F',
                                     u'00:50:56:2C:8D:82'])
        assert_deepequal(dict(
            value=fqdn1,
            summary=u'Modified host "%s"' % fqdn1,
            result=dict(
                description=[u'Updated host 1'],
                fqdn=[fqdn1],
                l=[u'Undisclosed location 1'],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                managedby_host=[u'%s' % fqdn1],
                usercertificate=[base64.b64decode(get_testcert())],
                valid_not_before=fuzzy_date,
                valid_not_after=fuzzy_date,
                subject=DN(('CN', api.env.host), x509.subject_base()),
                serial_number=fuzzy_digits,
                serial_number_hex=fuzzy_hex,
                md5_fingerprint=fuzzy_hash,
                sha1_fingerprint=fuzzy_hash,
                macaddress=[u'00:50:56:30:F6:5F', u'00:50:56:2C:8D:82'],
                issuer=fuzzy_issuer,
                has_keytab=False,
                has_password=False,
            ),
        ), result)

    def test_try_illegal_mac(self, command):
        with raises_exact(errors.ValidationError(
                name='macaddress',
                error=u'Must be of the form HH:HH:HH:HH:HH:HH, where ' +
                      u'each H is a hexadecimal character.')):
            result = command('host_mod', fqdn1, macaddress=[u'xx'])

    def test_add_ssh_pubkey(self, command):
        result = command('host_mod', fqdn1,
                         ipasshpubkey=[sshpubkey])
        assert_deepequal(dict(
            value=fqdn1,
            summary=u'Modified host "%s"' % fqdn1,
            result=dict(
                description=[u'Updated host 1'],
                fqdn=[fqdn1],
                l=[u'Undisclosed location 1'],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                managedby_host=[u'%s' % fqdn1],
                usercertificate=[base64.b64decode(get_testcert())],
                valid_not_before=fuzzy_date,
                valid_not_after=fuzzy_date,
                subject=DN(('CN', api.env.host), x509.subject_base()),
                serial_number=fuzzy_digits,
                serial_number_hex=fuzzy_hex,
                md5_fingerprint=fuzzy_hash,
                sha1_fingerprint=fuzzy_hash,
                issuer=fuzzy_issuer,
                macaddress=[u'00:50:56:30:F6:5F', u'00:50:56:2C:8D:82'],
                ipasshpubkey=[sshpubkey],
                sshpubkeyfp=[sshpubkeyfp],
                has_keytab=False,
                has_password=False,
            ),
        ), result)

    def test_try_illegal_ssh_pubkey(self, command):
        with raises_exact(errors.ValidationError(
                name='sshpubkey', error=u'options are not allowed')):
            result = command('host_mod', fqdn1,
                             ipasshpubkey=[u'no-pty %s' % sshpubkey])

    def test_delete_host(self, command):
        result = command('host_del', fqdn1)
        assert_deepequal(dict(
            value=[fqdn1],
            summary=u'Deleted host "%s"' % fqdn1,
            result=dict(failed=[]),
        ), result)

    def test_retrieve_nonexistent_2(self, command):
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % fqdn1)):
            result = command('host_show', fqdn1)

    def test_update_nonexistent_2(self, command):
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % fqdn1)):
            result = command('host_mod', fqdn1, description=u'Nope')

    def test_delete_nonexistent_2(self, command):
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % fqdn1)):
            result = command('host_del', fqdn1)


@ordered
class TestHostWithService(RPCTest):
    @classmethod
    def clean_up(cls):
        cls.clean('host_del', fqdn1)
        cls.clean('service_del', service1)

    # Test deletion using a non-fully-qualified hostname. Services
    # associated with this host should also be removed.

    def test_recreate_host(self, command):
        result = command('host_add', fqdn1,
                         description=u'Test host 1',
                         l=u'Undisclosed location 1',
                         force=True)
        assert_deepequal(dict(
            value=fqdn1,
            summary=u'Added host "%s"' % fqdn1,
            result=dict(
                dn=dn1,
                fqdn=[fqdn1],
                description=[u'Test host 1'],
                l=[u'Undisclosed location 1'],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                objectclass=objectclasses.host,
                ipauniqueid=[fuzzy_uuid],
                managedby_host=[fqdn1],
                has_keytab=False,
                has_password=False,
            ),
        ), result)

    def test_add_service_to_host(self, command):
        result = command('service_add', service1, force=True)
        assert_deepequal(dict(
            value=service1,
            summary=u'Added service "%s"' % service1,
            result=dict(
                dn=service1dn,
                krbprincipalname=[service1],
                objectclass=objectclasses.service,
                managedby_host=[fqdn1],
                ipauniqueid=[fuzzy_uuid],
            ),
        ), result)

    def test_delete_using_hostname(self, command):
        result = command('host_del', short1)
        assert_deepequal(dict(
            value=[short1],
            summary=u'Deleted host "%s"' % short1,
            result=dict(failed=[]),
        ), result)

    def test_try_find_services(self, command):
        result = command('service_find', fqdn1)
        assert_deepequal(dict(
            count=0,
            truncated=False,
            summary=u'0 services matched',
            result=[],
        ), result)


@ordered
class TestAddHostNotInDNS(RPCTest):
    @classmethod
    def clean_up(cls):
        cls.clean('host_del', fqdn2)

    def test_try_add_not_in_dns(self, command):
        with raises_exact(errors.DNSNotARecordError(
                reason=u'Host does not have corresponding DNS A/AAAA record')):
            result = command('host_add', fqdn2)

    def test_add_not_in_dns(self, command):
        result = command('host_add', fqdn2,
                         description=u'Test host 2',
                         l=u'Undisclosed location 2',
                         userclass=[u'webserver', u'mailserver'],
                         force=True)
        assert_deepequal(dict(
                value=fqdn2,
                summary=u'Added host "%s"' % fqdn2,
                result=dict(
                    dn=dn2,
                    fqdn=[fqdn2],
                    description=[u'Test host 2'],
                    l=[u'Undisclosed location 2'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn2, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[fqdn2],
                    userclass=[u'webserver', u'mailserver'],
                    has_keytab=False,
                    has_password=False,
                ),
        ), result)


@ordered
class TestManagedHosts(RPCTest):
    @classmethod
    def clean_up(cls):
        cls.clean('host_del', fqdn1, fqdn2, fqdn3, fqdn4, **{'continue': True})
        cls.clean('service_del', service1)

    def test_create_host(self, command):
        result = command('host_add', fqdn1,
                         description=u'Test host 1',
                         l=u'Undisclosed location 1',
                         force=True)
        assert_deepequal(dict(
            value=fqdn1,
            summary=u'Added host "%s"' % fqdn1,
            result=dict(
                dn=dn1,
                fqdn=[fqdn1],
                description=[u'Test host 1'],
                l=[u'Undisclosed location 1'],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                objectclass=objectclasses.host,
                ipauniqueid=[fuzzy_uuid],
                managedby_host=[fqdn1],
                has_keytab=False,
                has_password=False,
            ),
        ), result)

    @pytest.mark.parametrize(['fqdn', 'dn', 'n'],
                             [(fqdn3, dn3, 2), (fqdn4, dn4, 4)])
    def test_create_more(self, command, fqdn, dn, n):
        result = command('host_add', fqdn,
                         description=u'Test host %s' % n,
                         l=u'Undisclosed location %s' % n,
                         force=True)
        assert_deepequal(dict(
            value=fqdn,
            summary=u'Added host "%s"' % fqdn,
            result=dict(
                dn=dn,
                fqdn=[fqdn],
                description=[u'Test host %s' % n],
                l=[u'Undisclosed location %s' % n],
                krbprincipalname=[u'host/%s@%s' % (fqdn, api.env.realm)],
                objectclass=objectclasses.host,
                ipauniqueid=[fuzzy_uuid],
                managedby_host=[u'%s' % fqdn],
                has_keytab=False,
                has_password=False,
            ),
        ), result)

    def test_add_managed_host(self, command):
        result = command('host_add_managedby', fqdn3, host=fqdn1)
        assert_deepequal(dict(
            completed=1,
            failed=dict(
                managedby=dict(
                    host=tuple(),
                ),
            ),
            result=dict(
                dn=dn3,
                fqdn=[fqdn3],
                description=[u'Test host 2'],
                l=[u'Undisclosed location 2'],
                krbprincipalname=[u'host/%s@%s' % (fqdn3, api.env.realm)],
                managedby_host=[u'%s' % fqdn3, u'%s' % fqdn1],
            ),
        ), result)

    def test_show_managed_host(self, command):
        result = command('host_show', fqdn3)
        assert_deepequal(dict(
            value=fqdn3,
            summary=None,
            result=dict(
                dn=dn3,
                fqdn=[fqdn3],
                description=[u'Test host 2'],
                l=[u'Undisclosed location 2'],
                krbprincipalname=[u'host/%s@%s' % (fqdn3, api.env.realm)],
                has_keytab=False,
                has_password=False,
                managedby_host=[u'%s' % fqdn3, u'%s' % fqdn1],
            ),
        ), result)

    def test_search_man_noman_hosts(self, command):
        result = command('host_find', fqdn3,
                         man_host=fqdn3,
                         not_man_host=fqdn1)
        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary=u'1 host matched',
            result=[
                dict(
                    dn=dn3,
                    fqdn=[fqdn3],
                    description=[u'Test host 2'],
                    l=[u'Undisclosed location 2'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn3, api.env.realm)],
                    has_keytab=False,
                    has_password=False,
                    managedby_host=[u'%s' % fqdn3, u'%s' % fqdn1],
                ),
            ],
        ), result)

    def test_search_man_hosts(self, command):
        result = command('host_find', man_host=[fqdn3, fqdn4])
        assert_deepequal(dict(
            count=0,
            truncated=False,
            summary=u'0 hosts matched',
            result=[],
        ), result)

    def test_remove_man_hosts(self, command):
        result = command('host_remove_managedby', fqdn3, host=u'%s' % fqdn1)
        assert_deepequal(dict(
            completed=1,
            failed=dict(
                managedby=dict(
                    host=tuple(),
                ),
            ),
            result=dict(
                dn=dn3,
                fqdn=[fqdn3],
                description=[u'Test host 2'],
                l=[u'Undisclosed location 2'],
                krbprincipalname=[u'host/%s@%s' % (fqdn3, api.env.realm)],
                managedby_host=[u'%s' % fqdn3],
            ),
        ), result)

    def test_try_show_multiple_matches(self, command):
        with raises_exact(errors.SingleMatchExpected(found=2)):
            result = command('host_show', short3)

    # ---

    def test_add_managed_host_2(self, command):
        result = command('host_add_managedby', fqdn4, host=fqdn3)
        assert_deepequal(dict(
            completed=1,
            failed=dict(
                managedby=dict(
                    host=tuple(),
                ),
            ),
            result=dict(
                dn=dn4,
                fqdn=[fqdn4],
                description=[u'Test host 4'],
                l=[u'Undisclosed location 4'],
                krbprincipalname=[u'host/%s@%s' % (fqdn4, api.env.realm)],
                managedby_host=[fqdn4, fqdn3],
            ),
        ), result)

    def test_delete_managed_host_2(self, command):
        result = command('host_del', fqdn3)
        assert_deepequal(dict(
            value=[fqdn3],
            summary=u'Deleted host "%s"' % fqdn3,
            result=dict(failed=[]),
        ), result)

    def test_retrieve_managed_host_2(self, command):
        result = command('host_show', fqdn4)
        assert_deepequal(dict(
            value=fqdn4,
            summary=None,
            result=dict(
                dn=dn4,
                fqdn=[fqdn4],
                description=[u'Test host 4'],
                l=[u'Undisclosed location 4'],
                krbprincipalname=[u'host/%s@%s' % (fqdn4, api.env.realm)],
                has_keytab=False,
                has_password=False,
                managedby_host=[fqdn4],
            ),
        ), result)


class TestAddWithNullPassword(RPCTest):
    @classmethod
    def clean_up(cls):
        cls.clean('host_del', fqdn3)

    def test_add_host_with_null_password(self, command):
        result = command('host_add', fqdn3,
                         description=u'Test host 3',
                         force=True,
                         userpassword=None)
        assert_deepequal(dict(
            value=fqdn3,
            summary=u'Added host "%s"' % fqdn3,
            result=dict(
                dn=dn3,
                fqdn=[fqdn3],
                description=[u'Test host 3'],
                krbprincipalname=[u'host/%s@%s' % (fqdn3, api.env.realm)],
                objectclass=objectclasses.host,
                ipauniqueid=[fuzzy_uuid],
                managedby_host=[u'%s' % fqdn3],
                has_keytab=False,
                has_password=False,
            ),
        ), result)


class TestProtectedMaster(RPCTest):
    def test_try_delete_master(self, command):
        with raises_exact(errors.ValidationError(
                name='hostname',
                error=u'An IPA master host cannot be deleted or disabled')):
            result = command('host_del', api.env.host)

    def test_try_disable_master(self, command):
        with raises_exact(errors.ValidationError(
                name='hostname',
                error=u'An IPA master host cannot be deleted or disabled')):
            result = command('host_disable', api.env.host)


class TestValidation(RPCTest):
    def test_try_validate_add(self, command):
        with raises_exact(errors.ValidationError(
                name='hostname',
                error=u"invalid domain-name: only letters, numbers, '-' are " +
                      u"allowed. DNS label may not start or end with '-'")):
            result = command('host_add', invalidfqdn1)

    # The assumption on these next 4 tests is that if we don't get a
    # validation error then the request was processed normally.

    def test_try_validate_mod(self, command):
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % invalidfqdn1)):
            result = command('host_mod', invalidfqdn1)

    def test_try_validate_del(self, command):
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % invalidfqdn1)):
            result = command('host_del', invalidfqdn1)

    def test_try_validate_show(self, command):
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % invalidfqdn1)):
            result = command('host_show', invalidfqdn1)

    def test_try_validate_find(self, command):
        result = command('host_find', invalidfqdn1)
        assert_deepequal(dict(
            count=0,
            truncated=False,
            summary=u'0 hosts matched',
            result=[],
        ), result)


@ordered
class TestHostFalsePwdChange(XMLRPC_test):

    fqdn1 = u'testhost1.%s' % api.env.domain
    short1 = u'testhost1'
    new_pass = u'pass_123'
    command = "ipa-client/ipa-join"

    @classmethod
    def setup_class(cls):
        super(TestHostFalsePwdChange, cls).setup_class()
        [cls.keytabfd,cls.keytabname] = tempfile.mkstemp()
        os.close(cls.keytabfd)

        does_command_exist = os.path.isfile(cls.command)

        if not does_command_exist:
            pytest.skip("Command '%s' not found" % cls.command)

    # auxiliary function for checking whether the join operation has set
    # correct attributes
    def host_joined(self):
        ret = api.Command['host_show'](self.fqdn1, all=True)
        assert (ret['result']['has_keytab'] == True)
        assert (ret['result']['has_password'] == False)

    def test_a_join_host(self):
        """
        Create a test host and join him into IPA.
        """

        # create a test host with bulk enrollment password
        host = api.Command['host_add'](self.fqdn1, random=True, force=True)
        random_pass = host['result']['randompassword']

        # joint the host with the bulk password
        new_args = [self.command,
                    "-s", api.env.host,
                    "-h", self.fqdn1,
                    "-k", self.keytabname,
                    "-w", random_pass,
                    "-q",
                   ]
        try:
            # join operation may fail on 'adding key into keytab', but
            # the keytab is not necessary for further tests
            (out, err, rc) = ipautil.run(new_args, None)
        except ipautil.CalledProcessError as e:
            pass
        finally:
            self.host_joined()

    def test_b_try_password(self):
        """
        Try to change the password of enrolled host with specified password
        """
        with pytest.raises(errors.ValidationError):
            api.Command['host_mod'](self.fqdn1, userpassword=self.new_pass)

    def test_c_try_random(self):
        """
        Try to change the password of enrolled host with random password
        """
        with pytest.raises(errors.ValidationError):
            api.Command['host_mod'](self.fqdn1, random=True)

    def test_d_cleanup(self):
        """
        Clean up test data
        """
        os.unlink(self.keytabname)
        api.Command['host_del'](self.fqdn1)
        # verify that it's gone
        with pytest.raises(errors.NotFound):
            api.Command['host_show'](self.fqdn1)


@ordered
class TestHostDNS(RPCTest):

    @classmethod
    def clean_up(cls):
        cls.clean('host_del',
                  ipv6only_host_fqdn, ipv4only_host_fqdn, ipv46both_host_fqdn,
                  ipv4_fromip_host_fqdn, ipv6_fromip_host_fqdn,
                  **{'continue': True})
        cls.clean('dnszone_del', dnszone, revzone, revipv6zone,
                  **{'continue': True})

    def test_create_zone(self, command):
        result = command('dnszone_add', dnszone, idnssoarname=dnszone_rname)
        assert_deepequal({
            'value': dnszone_dnsname,
            'summary': None,
            'result': {
                'dn': dnszone_dn,
                'idnsname': [dnszone_dnsname],
                'idnszoneactive': [u'TRUE'],
                'idnssoamname': [self_server_ns_dnsname],
                'nsrecord': lambda x: True,
                'idnssoarname': [dnszone_rname_dnsname],
                'idnssoaserial': [fuzzy_digits],
                'idnssoarefresh': [fuzzy_digits],
                'idnssoaretry': [fuzzy_digits],
                'idnssoaexpire': [fuzzy_digits],
                'idnssoaminimum': [fuzzy_digits],
                'idnsallowdynupdate': [u'FALSE'],
                'idnsupdatepolicy': [u'grant %(realm)s krb5-self * A; '
                                     u'grant %(realm)s krb5-self * AAAA; '
                                     u'grant %(realm)s krb5-self * SSHFP;' %
                                        dict(realm=api.env.realm)],
                'idnsallowtransfer': [u'none;'],
                'idnsallowquery': [u'any;'],
                'objectclass': objectclasses.dnszone,
            },
        }, result)

    def test_create_reverse_zone(self, command):
        result = command('dnszone_add', revzone, idnssoarname=dnszone_rname)
        assert_deepequal({
            'value': revzone_dnsname,
            'summary': None,
            'result': {
                'dn': revzone_dn,
                'idnsname': [revzone_dnsname],
                'idnszoneactive': [u'TRUE'],
                'idnssoamname': [self_server_ns_dnsname],
                'nsrecord': lambda x: True,
                'idnssoarname': [dnszone_rname_dnsname],
                'idnssoaserial': [fuzzy_digits],
                'idnssoarefresh': [fuzzy_digits],
                'idnssoaretry': [fuzzy_digits],
                'idnssoaexpire': [fuzzy_digits],
                'idnssoaminimum': [fuzzy_digits],
                'idnsallowdynupdate': [u'FALSE'],
                'idnsupdatepolicy': [
                    u'grant %(realm)s krb5-subdomain %(zone)s PTR;' %
                    dict(realm=api.env.realm, zone=revzone)],
                'idnsallowtransfer': [u'none;'],
                'idnsallowquery': [u'any;'],
                'objectclass': objectclasses.dnszone,
            },
        }, result)

    def test_create_ipv6_reverse_zone(self, command):
        result = command('dnszone_add', revipv6zone,
                         idnssoarname=dnszone_rname)
        assert_deepequal({
            'value': revipv6zone_dnsname,
            'summary': None,
            'result': {
                'dn': revipv6zone_dn,
                'idnsname': [revipv6zone_dnsname],
                'idnszoneactive': [u'TRUE'],
                'idnssoamname': [self_server_ns_dnsname],
                'nsrecord': lambda x: True,
                'idnssoarname': [dnszone_rname_dnsname],
                'idnssoaserial': [fuzzy_digits],
                'idnssoarefresh': [fuzzy_digits],
                'idnssoaretry': [fuzzy_digits],
                'idnssoaexpire': [fuzzy_digits],
                'idnssoaminimum': [fuzzy_digits],
                'idnsallowdynupdate': [u'FALSE'],
                'idnsupdatepolicy': [
                    u'grant %(realm)s krb5-subdomain %(zone)s PTR;' %
                    dict(realm=api.env.realm, zone=revipv6zone)],
                'idnsallowtransfer': [u'none;'],
                'idnsallowquery': [u'any;'],
                'objectclass': objectclasses.dnszone,
            },
        }, result)

    def test_add_ipv6only_a_record(self, command):
        result = command('dnsrecord_add', dnszone, ipv6only,
                         aaaarecord=aaaarec)
        assert_deepequal({
            'value': ipv6only_dnsname,
            'summary': None,
            'result': {
                'dn': ipv6only_dn,
                'idnsname': [ipv6only_dnsname],
                'aaaarecord': [aaaarec],
                'objectclass': objectclasses.dnsrecord,
            },
        }, result)

    def test_add_ipv4only_a_record(self, command):
        result = command('dnsrecord_add', dnszone, ipv4only, arecord=arec)
        assert_deepequal({
            'value': ipv4only_dnsname,
            'summary': None,
            'result': {
                'dn': ipv4only_dn,
                'idnsname': [ipv4only_dnsname],
                'arecord': [arec],
                'objectclass': objectclasses.dnsrecord,
            },
        }, result)

    def test_add_ipv46both_aaaa_records(self, command):
        result = command('dnsrecord_add', dnszone, ipv46both,
                         arecord=arec2, aaaarecord=aaaarec)
        assert_deepequal({
            'value': ipv46both_dnsname,
            'summary': None,
            'result': {
                'dn': ipv46both_dn,
                'idnsname': [ipv46both_dnsname],
                'arecord': [arec2],
                'aaaarecord': [aaaarec],
                'objectclass': objectclasses.dnsrecord,
            },
        }, result)

    def test_add_ipv6only_host(self, command):
        result = command('host_add', ipv6only_host_fqdn,
                         description=u'Test host 5',
                         l=u'Undisclosed location 5')
        assert_deepequal(dict(
            value=ipv6only_host_fqdn,
            summary=u'Added host "%s"' % ipv6only_host_fqdn,
            result=dict(
                dn=ipv6only_host_dn,
                fqdn=[ipv6only_host_fqdn],
                description=[u'Test host 5'],
                l=[u'Undisclosed location 5'],
                krbprincipalname=[u'host/%s@%s' % (ipv6only_host_fqdn,
                                                   api.env.realm)],
                objectclass=objectclasses.host,
                ipauniqueid=[fuzzy_uuid],
                managedby_host=[ipv6only_host_fqdn],
                has_keytab=False,
                has_password=False,
            ),
        ), result)

    def test_add_ipv4only_host(self, command):
        result = command('host_add', ipv4only_host_fqdn,
                         description=u'Test host 6',
                         l=u'Undisclosed location 6')
        assert_deepequal(dict(
            value=ipv4only_host_fqdn,
            summary=u'Added host "%s"' % ipv4only_host_fqdn,
            result=dict(
                dn=ipv4only_host_dn,
                fqdn=[ipv4only_host_fqdn],
                description=[u'Test host 6'],
                l=[u'Undisclosed location 6'],
                krbprincipalname=[u'host/%s@%s' % (ipv4only_host_fqdn,
                                                   api.env.realm)],
                objectclass=objectclasses.host,
                ipauniqueid=[fuzzy_uuid],
                managedby_host=[ipv4only_host_fqdn],
                has_keytab=False,
                has_password=False,
            ),
        ), result)

    def test_add_ipv46both_host(self, command):
        result = command('host_add', ipv46both_host_fqdn,
                         description=u'Test host 7',
                         l=u'Undisclosed location 7')
        assert_deepequal(dict(
            value=ipv46both_host_fqdn,
            summary=u'Added host "%s"' % ipv46both_host_fqdn,
            result=dict(
                dn=ipv46both_host_dn,
                fqdn=[ipv46both_host_fqdn],
                description=[u'Test host 7'],
                l=[u'Undisclosed location 7'],
                krbprincipalname=[u'host/%s@%s' % (ipv46both_host_fqdn,
                                                   api.env.realm)],
                objectclass=objectclasses.host,
                ipauniqueid=[fuzzy_uuid],
                managedby_host=[ipv46both_host_fqdn],
                has_keytab=False,
                has_password=False,
            ),
        ), result)

    def test_add_ipv4_host_from_ip(self, command):
        result = command('host_add', ipv4_fromip_host_fqdn,
                         description=u'Test host 8',
                         l=u'Undisclosed location 8',
                         ip_address=ipv4_fromip_ip)
        assert_deepequal(dict(
            value=ipv4_fromip_host_fqdn,
            summary=u'Added host "%s"' % ipv4_fromip_host_fqdn,
            result=dict(
                dn=ipv4_fromip_host_dn,
                fqdn=[ipv4_fromip_host_fqdn],
                description=[u'Test host 8'],
                l=[u'Undisclosed location 8'],
                krbprincipalname=[u'host/%s@%s' % (ipv4_fromip_host_fqdn,
                                                   api.env.realm)],
                objectclass=objectclasses.host,
                ipauniqueid=[fuzzy_uuid],
                managedby_host=[ipv4_fromip_host_fqdn],
                has_keytab=False,
                has_password=False,
            ),
        ), result)

    def test_ipv4_a_record_created(self, command):
        result = command('dnsrecord_show', dnszone, ipv4_fromip)
        assert_deepequal(dict(
            value=ipv4_fromip_dnsname,
            summary=None,
            result=dict(
                dn=ipv4_fromip_dn,
                idnsname=[ipv4_fromip_dnsname],
                arecord=[ipv4_fromip_arec],
            ),
        ), result)

    def test_ipv4_ptr_record_created(self, command):
        result = command('dnsrecord_show', revzone, ipv4_fromip_ptr)
        assert_deepequal(dict(
            value=ipv4_fromip_ptr_dnsname,
            summary=None,
            result=dict(
                dn=ipv4_fromip_ptr_dn,
                idnsname=[ipv4_fromip_ptr_dnsname],
                ptrrecord=[ipv4_fromip_ptrrec],
            ),
        ), result)

    def test_add_ipv6_host_from_ip(self, command):
        result = command('host_add', ipv6_fromip_host_fqdn,
                         description=u'Test host 9',
                         l=u'Undisclosed location 9',
                         ip_address=ipv6_fromip_ipv6)
        assert_deepequal(dict(
            value=ipv6_fromip_host_fqdn,
            summary=u'Added host "%s"' % ipv6_fromip_host_fqdn,
            result=dict(
                dn=ipv6_fromip_host_dn,
                fqdn=[ipv6_fromip_host_fqdn],
                description=[u'Test host 9'],
                l=[u'Undisclosed location 9'],
                krbprincipalname=[u'host/%s@%s' % (ipv6_fromip_host_fqdn,
                                                   api.env.realm)],
                objectclass=objectclasses.host,
                ipauniqueid=[fuzzy_uuid],
                managedby_host=[ipv6_fromip_host_fqdn],
                has_keytab=False,
                has_password=False,
            ),
        ), result)

    def test_ipv6_aaaa_record_created(self, command):
        result = command('dnsrecord_show', dnszone, ipv6_fromip)
        assert_deepequal(dict(
            value=ipv6_fromip_dnsname,
            summary=None,
            result=dict(
                dn=ipv6_fromip_dn,
                idnsname=[ipv6_fromip_dnsname],
                aaaarecord=[ipv6_fromip_aaaarec],
            ),
        ), result)

    def test_ipv6_ptr_record_added(self, command):
        result = command('dnsrecord_show', revipv6zone, ipv6_fromip_ptr)
        assert_deepequal(dict(
            value=ipv6_fromip_ptr_dnsname,
            summary=None,
            result=dict(
                dn=ipv6_fromip_ptr_dn,
                idnsname=[ipv6_fromip_ptr_dnsname],
                ptrrecord=[ipv6_fromip_ptrrec],
            ),
        ), result)


@ordered
class TestHostAllowedTo(RPCTest):

    @classmethod
    def clean_up(cls):
        cls.clean('user_del', user1, user2, **{'continue': True})
        cls.clean('group_del', group1, group2, **{'continue': True})
        cls.clean('host_del', fqdn1, fqdn3, **{'continue': True})
        cls.clean('hostgroup_del', hostgroup1, **{'continue': True})

    def test_prepare_entries(self, command):
        result = command('user_add', givenname=u'Test', sn=u'User1')
        result = command('user_add', givenname=u'Test', sn=u'User2')
        result = command('group_add', group1)
        result = command('group_add', group2)
        result = command('host_add', fqdn1, force=True)
        result = command('host_add', fqdn3, force=True)
        result = command('hostgroup_add', hostgroup1,
                         description=u'Test hostgroup 1')

    def test_user_allow_retrieve_keytab(self, command):
        result = command('host_allow_retrieve_keytab', fqdn1, user=user1)
        assert_deepequal(dict(
            failed=dict(
                ipaallowedtoperform_read_keys=dict(
                    group=[], host=[], hostgroup=[], user=[]),
            ),
            completed=1,
            result=dict(
                dn=dn1,
                fqdn=[fqdn1],
                ipaallowedtoperform_read_keys_user=[user1],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                managedby_host=[fqdn1],
            ),
        ), result)

    def test_duplicate_add_user(self, command):
        result = command('host_allow_retrieve_keytab', fqdn1, user=user1)
        assert_deepequal(dict(
            failed=dict(
                ipaallowedtoperform_read_keys=dict(
                    group=[],
                    host=[],
                    hostgroup=[],
                    user=[[user1, u'This entry is already a member']],
                ),
            ),
            completed=0,
            result=dict(
                dn=dn1,
                fqdn=[fqdn1],
                ipaallowedtoperform_read_keys_user=[user1],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                managedby_host=[fqdn1],
            ),
        ), result)

    def test_group_allow_retrieve_keytab(self, command):
        result = command('host_allow_retrieve_keytab', fqdn1,
                         group=[group1, group2], host=[fqdn3],
                         hostgroup=[hostgroup1])
        assert_deepequal(dict(
            failed=dict(
                ipaallowedtoperform_read_keys=dict(
                    group=[], host=[], hostgroup=[], user=[]),
            ),
            completed=4,
            result=dict(
                dn=dn1,
                fqdn=[fqdn1],
                ipaallowedtoperform_read_keys_user=[user1],
                ipaallowedtoperform_read_keys_group=[group1, group2],
                ipaallowedtoperform_read_keys_host=[fqdn3],
                ipaallowedtoperform_read_keys_hostgroup=[hostgroup1],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                managedby_host=[fqdn1],
            ),
        ), result)

    def test_invalid_disallow_retrieve(self, command):
        result = command('host_disallow_retrieve_keytab', fqdn1,
                         user=[user2])
        assert_deepequal(dict(
            failed=dict(
                ipaallowedtoperform_read_keys=dict(
                    group=[],
                    host=[],
                    hostgroup=[],
                    user=[[user2, u'This entry is not a member']],
                ),
            ),
            completed=0,
            result=dict(
                dn=dn1,
                fqdn=[fqdn1],
                ipaallowedtoperform_read_keys_user=[user1],
                ipaallowedtoperform_read_keys_group=[group1, group2],
                ipaallowedtoperform_read_keys_host=[fqdn3],
                ipaallowedtoperform_read_keys_hostgroup=[hostgroup1],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                managedby_host=[fqdn1],
            ),
        ), result)

    def test_disallow_retrieve(self, command):
        result = command('host_disallow_retrieve_keytab', fqdn1,
                         group=[group2])
        assert_deepequal(dict(
            failed=dict(
                ipaallowedtoperform_read_keys=dict(
                    group=[], host=[], hostgroup=[], user=[]),
            ),
            completed=1,
            result=dict(
                dn=dn1,
                fqdn=[fqdn1],
                ipaallowedtoperform_read_keys_user=[user1],
                ipaallowedtoperform_read_keys_group=[group1],
                ipaallowedtoperform_read_keys_host=[fqdn3],
                ipaallowedtoperform_read_keys_hostgroup=[hostgroup1],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                managedby_host=[fqdn1],
            ),
        ), result)

    def test_allow_create(self, command):
        result = command('host_allow_create_keytab', fqdn1,
                         group=[group1, group2], user=[user1], host=[fqdn3],
                         hostgroup=[hostgroup1])
        assert_deepequal(dict(
            failed=dict(
                ipaallowedtoperform_write_keys=dict(
                    group=[], host=[], hostgroup=[], user=[]),
            ),
            completed=5,
            result=dict(
                dn=dn1,
                fqdn=[fqdn1],
                ipaallowedtoperform_read_keys_user=[user1],
                ipaallowedtoperform_read_keys_group=[group1],
                ipaallowedtoperform_read_keys_host=[fqdn3],
                ipaallowedtoperform_read_keys_hostgroup=[hostgroup1],
                ipaallowedtoperform_write_keys_user=[user1],
                ipaallowedtoperform_write_keys_group=[group1, group2],
                ipaallowedtoperform_write_keys_host=[fqdn3],
                ipaallowedtoperform_write_keys_hostgroup=[hostgroup1],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                managedby_host=[fqdn1],
            ),
       ), result)

    def test_duplicate_allow_create(self, command):
        result = command('host_allow_create_keytab', fqdn1,
                         group=[group1], user=[user1], host=[fqdn3],
                         hostgroup=[hostgroup1])
        assert_deepequal(dict(
            failed=dict(
                ipaallowedtoperform_write_keys=dict(
                    group=[[group1, u'This entry is already a member']],
                    host=[[fqdn3, u'This entry is already a member']],
                    user=[[user1, u'This entry is already a member']],
                    hostgroup=[[hostgroup1,
                                u'This entry is already a member']],
                ),
            ),
            completed=0,
            result=dict(
                dn=dn1,
                fqdn=[fqdn1],
                ipaallowedtoperform_read_keys_user=[user1],
                ipaallowedtoperform_read_keys_group=[group1],
                ipaallowedtoperform_read_keys_host=[fqdn3],
                ipaallowedtoperform_read_keys_hostgroup=[hostgroup1],
                ipaallowedtoperform_write_keys_user=[user1],
                ipaallowedtoperform_write_keys_group=[group1, group2],
                ipaallowedtoperform_write_keys_host=[fqdn3],
                ipaallowedtoperform_write_keys_hostgroup=[hostgroup1],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                managedby_host=[fqdn1],
            ),
       ), result)

    def test_invalid_disallow_create(self, command):
        result = command('host_disallow_create_keytab', fqdn1,
                         user=[user2])
        assert_deepequal(dict(
            failed=dict(
                ipaallowedtoperform_write_keys=dict(
                    group=[],
                    host=[],
                    hostgroup=[],
                    user=[[user2, u'This entry is not a member']],
                ),
            ),
            completed=0,
            result=dict(
                dn=dn1,
                fqdn=[fqdn1],
                ipaallowedtoperform_read_keys_user=[user1],
                ipaallowedtoperform_read_keys_group=[group1],
                ipaallowedtoperform_read_keys_host=[fqdn3],
                ipaallowedtoperform_read_keys_hostgroup=[hostgroup1],
                ipaallowedtoperform_write_keys_user=[user1],
                ipaallowedtoperform_write_keys_group=[group1, group2],
                ipaallowedtoperform_write_keys_host=[fqdn3],
                ipaallowedtoperform_write_keys_hostgroup=[hostgroup1],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                managedby_host=[fqdn1],
            ),
       ), result)

    def test_disallow_create(self, command):
        result = command('host_disallow_create_keytab', fqdn1,
                         group=[group2])
        assert_deepequal(dict(
            failed=dict(
                ipaallowedtoperform_write_keys=dict(
                    group=[],
                    host=[],
                    hostgroup=[],
                    user=[],
                ),
            ),
            completed=1,
            result=dict(
                dn=dn1,
                fqdn=[fqdn1],
                ipaallowedtoperform_read_keys_user=[user1],
                ipaallowedtoperform_read_keys_group=[group1],
                ipaallowedtoperform_read_keys_host=[fqdn3],
                ipaallowedtoperform_read_keys_hostgroup=[hostgroup1],
                ipaallowedtoperform_write_keys_user=[user1],
                ipaallowedtoperform_write_keys_group=[group1],
                ipaallowedtoperform_write_keys_host=[fqdn3],
                ipaallowedtoperform_write_keys_hostgroup=[hostgroup1],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                managedby_host=[fqdn1],
            ),
       ), result)

    def test_host_show(self, command):
        result = command('host_show', fqdn1)
        assert_deepequal(dict(
            value=fqdn1,
            summary=None,
            result=dict(
                dn=dn1,
                fqdn=[fqdn1],
                has_keytab=False,
                has_password=False,
                ipaallowedtoperform_read_keys_user=[user1],
                ipaallowedtoperform_read_keys_group=[group1],
                ipaallowedtoperform_read_keys_host=[fqdn3],
                ipaallowedtoperform_read_keys_hostgroup=[hostgroup1],
                ipaallowedtoperform_write_keys_user=[user1],
                ipaallowedtoperform_write_keys_group=[group1],
                ipaallowedtoperform_write_keys_host=[fqdn3],
                ipaallowedtoperform_write_keys_hostgroup=[hostgroup1],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                managedby_host=[fqdn1],
            ),
       ), result)

    def test_host_mod(self, command):
        result = command('host_mod', fqdn1, description=u"desc")
        assert_deepequal(dict(
            value=fqdn1,
            summary=u'Modified host "%s"' % fqdn1,
            result=dict(
                description=[u"desc"],
                fqdn=[fqdn1],
                has_keytab=False,
                has_password=False,
                ipaallowedtoperform_read_keys_user=[user1],
                ipaallowedtoperform_read_keys_group=[group1],
                ipaallowedtoperform_read_keys_host=[fqdn3],
                ipaallowedtoperform_read_keys_hostgroup=[hostgroup1],
                ipaallowedtoperform_write_keys_user=[user1],
                ipaallowedtoperform_write_keys_group=[group1],
                ipaallowedtoperform_write_keys_host=[fqdn3],
                ipaallowedtoperform_write_keys_hostgroup=[hostgroup1],
                krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                managedby_host=[fqdn1],
            ),
       ), result)
