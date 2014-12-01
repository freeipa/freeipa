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
from ipapython import ipautil
from ipalib import api, errors, x509
from ipalib.util import normalize_zone
from ipapython.dn import DN
from ipapython.dnsutil import DNSName
from nose.tools import raises, assert_raises
from nose.plugins.skip import SkipTest
from ipatests.test_xmlrpc.xmlrpc_test import (Declarative, XMLRPC_test,
    fuzzy_uuid, fuzzy_digits, fuzzy_hash, fuzzy_date, fuzzy_issuer,
    fuzzy_hex)
from ipatests.test_xmlrpc.test_user_plugin import (
    get_user_result, get_user_dn, get_group_dn)
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.testcert import get_testcert
import base64

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

class test_host(Declarative):

    cleanup_commands = [
        ('host_del', [fqdn1, fqdn2, fqdn3, fqdn4], {'continue': True}),
        ('service_del', [service1], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent %r' % fqdn1,
            command=('host_show', [fqdn1], {}),
            expected=errors.NotFound(
                reason=u'%s: host not found' % fqdn1),
        ),


        dict(
            desc='Try to update non-existent %r' % fqdn1,
            command=('host_mod', [fqdn1], dict(description=u'Nope')),
            expected=errors.NotFound(
                reason=u'%s: host not found' % fqdn1),
        ),


        dict(
            desc='Try to delete non-existent %r' % fqdn1,
            command=('host_del', [fqdn1], {}),
            expected=errors.NotFound(
                reason=u'%s: host not found' % fqdn1),
        ),


        dict(
            desc='Create %r' % fqdn1,
            command=('host_add', [fqdn1],
                dict(
                    description=u'Test host 1',
                    l=u'Undisclosed location 1',
                    force=True,
                ),
            ),
            expected=dict(
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
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % fqdn1,
            command=('host_add', [fqdn1],
                dict(
                    description=u'Test host 1',
                    l=u'Undisclosed location 1',
                    force=True,
                ),
            ),
            expected=errors.DuplicateEntry(message=u'host with name ' +
                u'"%s" already exists' %  fqdn1),
        ),


        dict(
            desc='Retrieve %r' % fqdn1,
            command=('host_show', [fqdn1], {}),
            expected=dict(
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
            ),
        ),


        dict(
            desc='Retrieve %r with all=True' % fqdn1,
            command=('host_show', [fqdn1], dict(all=True)),
            expected=dict(
                value=fqdn1,
                summary=None,
                result=dict(
                    dn=dn1,
                    cn=[fqdn1],
                    fqdn=[fqdn1],
                    description=[u'Test host 1'],
                    # FIXME: Why is 'localalityname' returned as 'l' with --all?
                    # It is intuitive for --all to return additional attributes,
                    # but not to return existing attributes under different
                    # names.
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
            ),
        ),


        dict(
            desc='Search for %r' % fqdn1,
            command=('host_find', [fqdn1], {}),
            expected=dict(
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
            ),
        ),


        dict(
            desc='Search for %r with all=True' % fqdn1,
            command=('host_find', [fqdn1], dict(all=True)),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 host matched',
                result=[
                    dict(
                        dn=dn1,
                        cn=[fqdn1],
                        fqdn=[fqdn1],
                        description=[u'Test host 1'],
                        # FIXME: Why is 'localalityname' returned as 'l' with --all?
                        # It is intuitive for --all to return additional attributes,
                        # but not to return existing attributes under different
                        # names.
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
                ],
            ),
        ),


        dict(
            desc='Update %r' % fqdn1,
            command=('host_mod', [fqdn1], dict(description=u'Updated host 1',
                usercertificate=get_testcert())),
            expected=dict(
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
                    subject=DN(('CN',api.env.host),x509.subject_base()),
                    serial_number=fuzzy_digits,
                    serial_number_hex=fuzzy_hex,
                    md5_fingerprint=fuzzy_hash,
                    sha1_fingerprint=fuzzy_hash,
                    issuer=fuzzy_issuer,
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),


        dict(
            desc='Retrieve %r to verify update' % fqdn1,
            command=('host_show', [fqdn1], {}),
            expected=dict(
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
                    subject=DN(('CN',api.env.host),x509.subject_base()),
                    serial_number=fuzzy_digits,
                    serial_number_hex=fuzzy_hex,
                    md5_fingerprint=fuzzy_hash,
                    sha1_fingerprint=fuzzy_hash,
                    issuer=fuzzy_issuer,
                ),
            ),
        ),

        dict(
            desc='Create %r' % fqdn3,
            command=('host_add', [fqdn3],
                dict(
                    description=u'Test host 2',
                    l=u'Undisclosed location 2',
                    force=True,
                ),
            ),
            expected=dict(
                value=fqdn3,
                summary=u'Added host "%s"' % fqdn3,
                result=dict(
                    dn=dn3,
                    fqdn=[fqdn3],
                    description=[u'Test host 2'],
                    l=[u'Undisclosed location 2'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn3, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[u'%s' % fqdn3],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),


        dict(
            desc='Create %r' % fqdn4,
            command=('host_add', [fqdn4],
                dict(
                    description=u'Test host 4',
                    l=u'Undisclosed location 4',
                    force=True,
                ),
            ),
            expected=dict(
                value=fqdn4,
                summary=u'Added host "%s"' % fqdn4,
                result=dict(
                    dn=dn4,
                    fqdn=[fqdn4],
                    description=[u'Test host 4'],
                    l=[u'Undisclosed location 4'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn4, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[u'%s' % fqdn4],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),


        dict(
            desc='Add managedby_host %r to %r' % (fqdn1, fqdn3),
            command=('host_add_managedby', [fqdn3],
                dict(
                    host=u'%s' % fqdn1,
                ),
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    managedby = dict(
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
            ),
        ),

        dict(
            desc='Retrieve %r' % fqdn3,
            command=('host_show', [fqdn3], {}),
            expected=dict(
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
            ),
        ),

        dict(
            desc='Search for hosts with --man-hosts and --not-man-hosts',
            command=('host_find', [], {'man_host' : fqdn3, 'not_man_host' : fqdn1}),
            expected=dict(
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
            ),
        ),

        dict(
            desc='Try to search for hosts with --man-hosts',
            command=('host_find', [], {'man_host' : [fqdn3,fqdn4]}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 hosts matched',
                result=[],
            ),
        ),

        dict(
            desc='Remove managedby_host %r from %r' % (fqdn1, fqdn3),
            command=('host_remove_managedby', [fqdn3],
                dict(
                    host=u'%s' % fqdn1,
                ),
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    managedby = dict(
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
            ),
        ),


        dict(
            desc='Show a host with multiple matches %s' % short3,
            command=('host_show', [short3], {}),
            expected=errors.SingleMatchExpected(found=2),
        ),


        dict(
            desc='Try to rename %r' % fqdn1,
            command=('host_mod', [fqdn1], dict(setattr=u'fqdn=changed.example.com')),
            expected=errors.NotAllowedOnRDN()
        ),


        dict(
            desc='Add MAC address to %r' % fqdn1,
            command=('host_mod', [fqdn1], dict(macaddress=u'00:50:56:30:F6:5F')),
            expected=dict(
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
                    subject=DN(('CN',api.env.host),x509.subject_base()),
                    serial_number=fuzzy_digits,
                    serial_number_hex=fuzzy_hex,
                    md5_fingerprint=fuzzy_hash,
                    sha1_fingerprint=fuzzy_hash,
                    macaddress=[u'00:50:56:30:F6:5F'],
                    issuer=fuzzy_issuer,
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),


        dict(
            desc='Add another MAC address to %r' % fqdn1,
            command=('host_mod', [fqdn1], dict(macaddress=[u'00:50:56:30:F6:5F', u'00:50:56:2C:8D:82'])),
            expected=dict(
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
                    subject=DN(('CN',api.env.host),x509.subject_base()),
                    serial_number=fuzzy_digits,
                    serial_number_hex=fuzzy_hex,
                    md5_fingerprint=fuzzy_hash,
                    sha1_fingerprint=fuzzy_hash,
                    macaddress=[u'00:50:56:30:F6:5F', u'00:50:56:2C:8D:82'],
                    issuer=fuzzy_issuer,
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),


        dict(
            desc='Add an illegal MAC address to %r' % fqdn1,
            command=('host_mod', [fqdn1], dict(macaddress=[u'xx'])),
            expected=errors.ValidationError(name='macaddress',
                error=u'Must be of the form HH:HH:HH:HH:HH:HH, where ' +
                    u'each H is a hexadecimal character.'),
        ),


        dict(
            desc='Add SSH public key to %r' % fqdn1,
            command=('host_mod', [fqdn1], dict(ipasshpubkey=[sshpubkey])),
            expected=dict(
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
                    subject=DN(('CN',api.env.host),x509.subject_base()),
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
            ),
        ),


        dict(
            desc='Add an illegal SSH public key to %r' % fqdn1,
            command=('host_mod', [fqdn1], dict(ipasshpubkey=[u'no-pty %s' % sshpubkey])),
            expected=errors.ValidationError(name='sshpubkey',
                error=u'options are not allowed'),
        ),


        dict(
            desc='Delete %r' % fqdn1,
            command=('host_del', [fqdn1], {}),
            expected=dict(
                value=[fqdn1],
                summary=u'Deleted host "%s"' % fqdn1,
                result=dict(failed=[]),
            ),
        ),


        dict(
            desc='Try to retrieve non-existent %r' % fqdn1,
            command=('host_show', [fqdn1], {}),
            expected=errors.NotFound(reason=u'%s: host not found' % fqdn1),
        ),


        dict(
            desc='Try to update non-existent %r' % fqdn1,
            command=('host_mod', [fqdn1], dict(description=u'Nope')),
            expected=errors.NotFound(reason=u'%s: host not found' % fqdn1),
        ),


        dict(
            desc='Try to delete non-existent %r' % fqdn1,
            command=('host_del', [fqdn1], {}),
            expected=errors.NotFound(reason=u'%s: host not found' % fqdn1),
        ),

        # Test deletion using a non-fully-qualified hostname. Services
        # associated with this host should also be removed.
        dict(
            desc='Re-create %r' % fqdn1,
            command=('host_add', [fqdn1],
                dict(
                    description=u'Test host 1',
                    l=u'Undisclosed location 1',
                    force=True,
                ),
            ),
            expected=dict(
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
                    managedby_host=[u'%s' % fqdn1],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),

        dict(
            desc='Add a service to host %r' % fqdn1,
            command=('service_add', [service1], {'force': True}),
            expected=dict(
                value=service1,
                summary=u'Added service "%s"' % service1,
                result=dict(
                    dn=service1dn,
                    krbprincipalname=[service1],
                    objectclass=objectclasses.service,
                    managedby_host=[fqdn1],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),

        dict(
            desc='Delete using host name %r' % short1,
            command=('host_del', [short1], {}),
            expected=dict(
                value=[short1],
                summary=u'Deleted host "%s"' % short1,
                result=dict(failed=[]),
            ),
        ),

        dict(
            desc='Search for services for %r' % fqdn1,
            command=('service_find', [fqdn1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 services matched',
                result=[
                ],
            ),
        ),


        dict(
            desc='Try to add host not in DNS %r without force' % fqdn2,
            command=('host_add', [fqdn2], {}),
            expected=errors.DNSNotARecordError(
                reason=u'Host does not have corresponding DNS A/AAAA record'),
        ),


        dict(
            desc='Try to add host not in DNS %r with force' % fqdn2,
            command=('host_add', [fqdn2],
                dict(
                    description=u'Test host 2',
                    l=u'Undisclosed location 2',
                    userclass=[u'webserver', u'mailserver'],
                    force=True,
                ),
            ),
            expected=dict(
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
            ),
        ),


        dict(
            desc='Retrieve %r' % fqdn2,
            command=('host_show', [fqdn2], {}),
            expected=dict(
                value=fqdn2,
                summary=None,
                result=dict(
                    dn=dn2,
                    fqdn=[fqdn2],
                    description=[u'Test host 2'],
                    l=[u'Undisclosed location 2'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn2, api.env.realm)],
                    has_keytab=False,
                    has_password=False,
                    managedby_host=[fqdn2],
                    userclass=[u'webserver', u'mailserver'],
                ),
            ),
        ),


        # This test will only succeed when running against lite-server.py
        # on same box as IPA install.
        dict(
            desc='Delete the current host (master?) %s should be caught' % api.env.host,
            command=('host_del', [api.env.host], {}),
            expected=errors.ValidationError(name='hostname',
                error=u'An IPA master host cannot be deleted or disabled'),
        ),


        dict(
            desc='Disable the current host (master?) %s should be caught' % api.env.host,
            command=('host_disable', [api.env.host], {}),
            expected=errors.ValidationError(name='hostname',
                error=u'An IPA master host cannot be deleted or disabled'),
        ),


        dict(
            desc='Test that validation is enabled on adds',
            command=('host_add', [invalidfqdn1], {}),
            expected=errors.ValidationError(name='hostname',
                error=u"invalid domain-name: only letters, numbers, '-' " +
                u"are allowed. DNS label may not start or end with '-'"),
        ),


        # The assumption on these next 4 tests is that if we don't get a
        # validation error then the request was processed normally.
        dict(
            desc='Test that validation is disabled on mods',
            command=('host_mod', [invalidfqdn1], {}),
            expected=errors.NotFound(
                reason=u'%s: host not found' % invalidfqdn1),
        ),


        dict(
            desc='Test that validation is disabled on deletes',
            command=('host_del', [invalidfqdn1], {}),
            expected=errors.NotFound(
                reason=u'%s: host not found' % invalidfqdn1),
        ),


        dict(
            desc='Test that validation is disabled on show',
            command=('host_show', [invalidfqdn1], {}),
            expected=errors.NotFound(
                reason=u'%s: host not found' % invalidfqdn1),
        ),


        dict(
            desc='Test that validation is disabled on find',
            command=('host_find', [invalidfqdn1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 hosts matched',
                result=[],
            ),
        ),


        dict(
            desc='Add managedby_host %r to %r' % (fqdn3, fqdn4),
            command=('host_add_managedby', [fqdn4], dict(host=fqdn3,),
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    managedby = dict(
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
            ),
        ),


        dict(
            desc='Delete %r' % fqdn3,
            command=('host_del', [fqdn3], {}),
            expected=dict(
                value=[fqdn3],
                summary=u'Deleted host "%s"' % fqdn3,
                result=dict(failed=[]),
            ),
        ),


        dict(
            desc='Retrieve %r to verify that %r is gone from managedBy' % (fqdn4, fqdn3),
            command=('host_show', [fqdn4], {}),
            expected=dict(
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
            ),
        ),


        dict(
            desc='Create a host with a NULL password',
            command=('host_add', [fqdn3],
                dict(
                    description=u'Test host 3',
                    force=True,
                    userpassword=None,
                ),
            ),
            expected=dict(
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
            ),
        ),

    ]

class test_host_false_pwd_change(XMLRPC_test):

    fqdn1 = u'testhost1.%s' % api.env.domain
    short1 = u'testhost1'
    new_pass = u'pass_123'
    command = "ipa-client/ipa-join"

    @classmethod
    def setUpClass(cls):
        [cls.keytabfd,cls.keytabname] = tempfile.mkstemp()
        os.close(cls.keytabfd)

        does_command_exist = os.path.isfile(cls.command)

        if not does_command_exist:
            raise SkipTest("Command '%s' not found" % cls.command)

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
        random_pass = api.Command['host_add'](self.fqdn1, random=True, force=True)['result']['randompassword']

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
        except ipautil.CalledProcessError, e:
            pass
        finally:
            self.host_joined()

    @raises(errors.ValidationError)
    def test_b_try_password(self):
        """
        Try to change the password of enrolled host with specified password
        """
        api.Command['host_mod'](self.fqdn1, userpassword=self.new_pass)

    @raises(errors.ValidationError)
    def test_c_try_random(self):
        """
        Try to change the password of enrolled host with random password
        """
        api.Command['host_mod'](self.fqdn1, random=True)

    def test_d_cleanup(self):
        """
        Clean up test data
        """
        os.unlink(self.keytabname)
        api.Command['host_del'](self.fqdn1)
        # verify that it's gone
        with assert_raises(errors.NotFound):
            api.Command['host_show'](self.fqdn1)


class test_host_dns(Declarative):

    cleanup_commands = [
        ('host_del', [ipv6only_host_fqdn], {}),
        ('host_del', [ipv4only_host_fqdn], {}),
        ('host_del', [ipv46both_host_fqdn], {}),
        ('host_del', [ipv4_fromip_host_fqdn], {}),
        ('host_del', [ipv6_fromip_host_fqdn], {}),
        ('dnszone_del', [dnszone], {}),
        ('dnszone_del', [revzone], {}),
        ('dnszone_del', [revipv6zone], {}),
    ]

    tests = [
        dict(
            desc='Create zone %r' % dnszone,
            command=(
                'dnszone_add', [dnszone], {
                    'idnssoarname': dnszone_rname,
                }
            ),
            expected={
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
                                         u'grant %(realm)s krb5-self * SSHFP;'
                                         % dict(realm=api.env.realm)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),


        dict(
            desc='Create reverse zone %r' % revzone,
            command=(
                'dnszone_add', [revzone], {
                    'idnssoarname': dnszone_rname,
                }
            ),
            expected={
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
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-subdomain %(zone)s PTR;'
                                         % dict(realm=api.env.realm, zone=revzone)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),


        dict(
            desc='Create reverse zone %r' % revipv6zone,
            command=(
                'dnszone_add', [revipv6zone], {
                    'idnssoarname': dnszone_rname,
                }
            ),
            expected={
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
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-subdomain %(zone)s PTR;'
                                         % dict(realm=api.env.realm, zone=revipv6zone)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),


        dict(
            desc='Add A record to %r in zone %r' % (ipv6only, dnszone),
            command=('dnsrecord_add', [dnszone, ipv6only], {'arecord': arec}),
            expected={
                'value': ipv6only_dnsname,
                'summary': None,
                'result': {
                    'dn': ipv6only_dn,
                    'idnsname': [ipv6only_dnsname],
                    'arecord': [arec],
                    'objectclass': objectclasses.dnsrecord,
                },
            },
        ),


        dict(
            desc='Add A record to %r in zone %r' % (ipv4only, dnszone),
            command=('dnsrecord_add', [dnszone, ipv4only], {'aaaarecord': aaaarec}),
            expected={
                'value': ipv4only_dnsname,
                'summary': None,
                'result': {
                    'dn': ipv4only_dn,
                    'idnsname': [ipv4only_dnsname],
                    'aaaarecord': [aaaarec],
                    'objectclass': objectclasses.dnsrecord,
                },
            },
        ),


        dict(
            desc='Add A record to %r in zone %r' % (ipv46both, dnszone),
            command=('dnsrecord_add', [dnszone, ipv46both], {'arecord': arec2,
                                                    'aaaarecord': aaaarec}
                     ),
            expected={
                'value': ipv46both_dnsname,
                'summary': None,
                'result': {
                    'dn': ipv46both_dn,
                    'idnsname': [ipv46both_dnsname],
                    'arecord': [arec2],
                    'aaaarecord': [aaaarec],
                    'objectclass': objectclasses.dnsrecord,
                },
            },
        ),


        dict(
            desc='Create %r (AAAA record exists)' % ipv6only_host_fqdn,
            command=('host_add', [ipv6only_host_fqdn],
                dict(
                    description=u'Test host 5',
                    l=u'Undisclosed location 5',
                ),
            ),
            expected=dict(
                value=ipv6only_host_fqdn,
                summary=u'Added host "%s"' % ipv6only_host_fqdn,
                result=dict(
                    dn=ipv6only_host_dn,
                    fqdn=[ipv6only_host_fqdn],
                    description=[u'Test host 5'],
                    l=[u'Undisclosed location 5'],
                    krbprincipalname=[u'host/%s@%s' % (ipv6only_host_fqdn, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[ipv6only_host_fqdn],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),


        dict(
            desc='Create %r (A record exists)' % ipv4only_host_fqdn,
            command=('host_add', [ipv4only_host_fqdn],
                dict(
                    description=u'Test host 6',
                    l=u'Undisclosed location 6',
                ),
            ),
            expected=dict(
                value=ipv4only_host_fqdn,
                summary=u'Added host "%s"' % ipv4only_host_fqdn,
                result=dict(
                    dn=ipv4only_host_dn,
                    fqdn=[ipv4only_host_fqdn],
                    description=[u'Test host 6'],
                    l=[u'Undisclosed location 6'],
                    krbprincipalname=[u'host/%s@%s' % (ipv4only_host_fqdn, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[ipv4only_host_fqdn],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),


        dict(
            desc='Create %r (A and AAAA records exist)' % ipv46both_host_fqdn,
            command=('host_add', [ipv46both_host_fqdn],
                dict(
                    description=u'Test host 7',
                    l=u'Undisclosed location 7',
                ),
            ),
            expected=dict(
                value=ipv46both_host_fqdn,
                summary=u'Added host "%s"' % ipv46both_host_fqdn,
                result=dict(
                    dn=ipv46both_host_dn,
                    fqdn=[ipv46both_host_fqdn],
                    description=[u'Test host 7'],
                    l=[u'Undisclosed location 7'],
                    krbprincipalname=[u'host/%s@%s' % (ipv46both_host_fqdn, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[ipv46both_host_fqdn],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),


        dict(
            desc='Create %r with --from-ip option' % ipv4_fromip_host_fqdn,
            command=('host_add', [ipv4_fromip_host_fqdn],
                dict(
                    description=u'Test host 8',
                    l=u'Undisclosed location 8',
                    ip_address=ipv4_fromip_ip,
                ),
            ),
            expected=dict(
                value=ipv4_fromip_host_fqdn,
                summary=u'Added host "%s"' % ipv4_fromip_host_fqdn,
                result=dict(
                    dn=ipv4_fromip_host_dn,
                    fqdn=[ipv4_fromip_host_fqdn],
                    description=[u'Test host 8'],
                    l=[u'Undisclosed location 8'],
                    krbprincipalname=[u'host/%s@%s' % (ipv4_fromip_host_fqdn, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[ipv4_fromip_host_fqdn],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),


        dict(
            desc='Check if A record was created for host %r' % ipv4_fromip_host_fqdn,
            command=('dnsrecord_show', [dnszone, ipv4_fromip], {}
            ),
            expected=dict(
                value=ipv4_fromip_dnsname,
                summary=None,
                result=dict(
                    dn=ipv4_fromip_dn,
                    idnsname=[ipv4_fromip_dnsname],
                    arecord=[ipv4_fromip_arec],
                ),
            ),
        ),


        dict(
            desc='Check if PTR record was created for host %r' % ipv4_fromip_host_fqdn,
            command=('dnsrecord_show', [revzone, ipv4_fromip_ptr], {}
            ),
            expected=dict(
                value=ipv4_fromip_ptr_dnsname,
                summary=None,
                result=dict(
                    dn=ipv4_fromip_ptr_dn,
                    idnsname=[ipv4_fromip_ptr_dnsname],
                    ptrrecord=[ipv4_fromip_ptrrec],
                ),
            ),
        ),

        dict(
            desc='Create %r with --from-ip option (IPv6)' % ipv6_fromip_host_fqdn,
            command=('host_add', [ipv6_fromip_host_fqdn],
                dict(
                    description=u'Test host 9',
                    l=u'Undisclosed location 9',
                    ip_address=ipv6_fromip_ipv6,
                ),
            ),
            expected=dict(
                value=ipv6_fromip_host_fqdn,
                summary=u'Added host "%s"' % ipv6_fromip_host_fqdn,
                result=dict(
                    dn=ipv6_fromip_host_dn,
                    fqdn=[ipv6_fromip_host_fqdn],
                    description=[u'Test host 9'],
                    l=[u'Undisclosed location 9'],
                    krbprincipalname=[u'host/%s@%s' % (ipv6_fromip_host_fqdn, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[ipv6_fromip_host_fqdn],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),


        dict(
            desc='Check if AAAA record was created for host %r' % ipv6_fromip_host_fqdn,
            command=('dnsrecord_show', [dnszone, ipv6_fromip], {}
            ),
            expected=dict(
                value=ipv6_fromip_dnsname,
                summary=None,
                result=dict(
                    dn=ipv6_fromip_dn,
                    idnsname=[ipv6_fromip_dnsname],
                    aaaarecord=[ipv6_fromip_aaaarec],
                ),
            ),
        ),


        dict(
            desc='Check if PTR record was created for host %r' % ipv6_fromip_host_fqdn,
            command=('dnsrecord_show', [revipv6zone, ipv6_fromip_ptr], {}
            ),
            expected=dict(
                value=ipv6_fromip_ptr_dnsname,
                summary=None,
                result=dict(
                    dn=ipv6_fromip_ptr_dn,
                    idnsname=[ipv6_fromip_ptr_dnsname],
                    ptrrecord=[ipv6_fromip_ptrrec],
                ),
            ),
        ),
    ]


class test_host_allowed_to(Declarative):
    cleanup_commands = [
        ('user_del', [user1], {}),
        ('user_del', [user2], {}),
        ('group_del', [group1], {}),
        ('group_del', [group2], {}),
        ('host_del', [fqdn1], {}),
        ('host_del', [fqdn3], {}),
        ('hostgroup_del', [hostgroup1], {}),
    ]

    tests = [
        # prepare entries
        dict(
            desc='Create %r' % user1,
            command=(
                'user_add', [], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=get_user_result(user1, u'Test', u'User1', 'add'),
            ),
        ),
        dict(
            desc='Create %r' % user2,
            command=(
                'user_add', [], dict(givenname=u'Test', sn=u'User2')
            ),
            expected=dict(
                value=user2,
                summary=u'Added user "%s"' % user2,
                result=get_user_result(user2, u'Test', u'User2', 'add'),
            ),
        ),
        dict(
            desc='Create group: %r' % group1,
            command=(
                'group_add', [group1], dict()
            ),
            expected=dict(
                value=group1,
                summary=u'Added group "%s"' % group1,
                result=dict(
                    cn=[group1],
                    objectclass=objectclasses.group + [u'posixgroup'],
                    ipauniqueid=[fuzzy_uuid],
                    gidnumber=[fuzzy_digits],
                    dn=group1_dn
                ),
            ),
        ),
        dict(
            desc='Create group: %r' % group2,
            command=(
                'group_add', [group2], dict()
            ),
            expected=dict(
                value=group2,
                summary=u'Added group "%s"' % group2,
                result=dict(
                    cn=[group2],
                    objectclass=objectclasses.group + [u'posixgroup'],
                    ipauniqueid=[fuzzy_uuid],
                    gidnumber=[fuzzy_digits],
                    dn=group2_dn
                ),
            ),
        ),
        dict(
            desc='Create %r' % fqdn1,
            command=(
                'host_add', [fqdn1],
                dict(
                    force=True,
                ),
            ),
            expected=dict(
                value=fqdn1,
                summary=u'Added host "%s"' % fqdn1,
                result=dict(
                    dn=dn1,
                    fqdn=[fqdn1],
                    krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[fqdn1],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),
        dict(
            desc='Create %r' % fqdn3,
            command=(
                'host_add', [fqdn3],
                dict(
                    force=True,
                ),
            ),
            expected=dict(
                value=fqdn3,
                summary=u'Added host "%s"' % fqdn3,
                result=dict(
                    dn=dn3,
                    fqdn=[fqdn3],
                    krbprincipalname=[u'host/%s@%s' % (fqdn3, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[fqdn3],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),

        dict(
            desc='Create %r' % hostgroup1,
            command=('hostgroup_add', [hostgroup1],
                dict(description=u'Test hostgroup 1')
            ),
            expected=dict(
                value=hostgroup1,
                summary=u'Added hostgroup "testhostgroup1"',
                result=dict(
                    dn=hostgroup1_dn,
                    cn=[hostgroup1],
                    objectclass=objectclasses.hostgroup,
                    description=[u'Test hostgroup 1'],
                    ipauniqueid=[fuzzy_uuid],
                    mepmanagedentry=[DN(('cn',hostgroup1),('cn','ng'),('cn','alt'),
                                        api.env.basedn)],
                ),
            ),
        ),

        # verify
        dict(
            desc='Allow %r to a retrieve keytab of %r' % (user1, fqdn1),
            command=('host_allow_retrieve_keytab', [fqdn1],
                     dict(user=user1)),
            expected=dict(
                failed=dict(
                    ipaallowedtoperform_read_keys=dict(
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
                    krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                    managedby_host=[fqdn1],
                ),
            ),
        ),

        dict(
            desc='Duplicate add: user %r' % (user1),
            command=('host_allow_retrieve_keytab', [fqdn1],
                     dict(user=user1)),
            expected=dict(
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
            ),
        ),

        dict(
            desc='Allow %r, %r to a retrieve keytab of %r' % (
                group1, group2, fqdn1),
            command=('host_allow_retrieve_keytab', [fqdn1],
                     dict(group=[group1, group2], host=[fqdn3],
                          hostgroup=[hostgroup1])),
            expected=dict(
                failed=dict(
                    ipaallowedtoperform_read_keys=dict(
                        group=[],
                        host=[],
                        hostgroup=[],
                        user=[],
                    ),
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
            ),
        ),

        dict(
            desc='Invalid removal of retrieve keytab %r' % (user2),
            command=('host_disallow_retrieve_keytab', [fqdn1],
                     dict(user=[user2])),
            expected=dict(
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
            ),
        ),

        dict(
            desc='Removal of retrieve keytab %r' % (group2),
            command=('host_disallow_retrieve_keytab', [fqdn1],
                     dict(group=[group2])),
            expected=dict(
                failed=dict(
                    ipaallowedtoperform_read_keys=dict(
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
                    krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                    managedby_host=[fqdn1],
                ),
            ),
        ),

        dict(
            desc='Allow %r, %r to a create keytab of %r' % (
                group1, user1, fqdn1),
            command=('host_allow_create_keytab', [fqdn1],
                     dict(group=[group1, group2], user=[user1], host=[fqdn3],
                          hostgroup=[hostgroup1])),
            expected=dict(
                failed=dict(
                    ipaallowedtoperform_write_keys=dict(
                        group=[],
                        host=[],
                        hostgroup=[],
                        user=[],
                    ),
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
            ),
        ),

        dict(
            desc='Duplicate add: %r, %r' % (user1, group1),
            command=('host_allow_create_keytab', [fqdn1],
                     dict(group=[group1], user=[user1], host=[fqdn3],
                          hostgroup=[hostgroup1])),
            expected=dict(
                failed=dict(
                    ipaallowedtoperform_write_keys=dict(
                        group=[[group1, u'This entry is already a member']],
                        host=[[fqdn3, u'This entry is already a member']],
                        user=[[user1, u'This entry is already a member']],
                        hostgroup=[[hostgroup1, u'This entry is already a member']],
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
            ),
        ),

        dict(
            desc='Invalid removal of create keytab %r' % (user2),
            command=('host_disallow_create_keytab', [fqdn1],
                     dict(user=[user2])),
            expected=dict(
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
            ),
        ),

        dict(
            desc='Removal of create keytab %r' % (group2),
            command=('host_disallow_create_keytab', [fqdn1],
                     dict(group=[group2])),
            expected=dict(
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
            ),
        ),

        dict(
            desc='Presence of ipaallowedtoperform in show output',
            command=('host_show', [fqdn1], {}),
            expected=dict(
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
            ),
        ),

        dict(
            desc='Presence of ipaallowedtoperform in mod output',
            command=(
                'host_mod', [fqdn1],
                dict(description=u"desc")),
            expected=dict(
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
            ),
        ),
    ]
