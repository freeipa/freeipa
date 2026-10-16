# Authors:
#   Ana Krivokapic <akrivoka@redhat.com>
#
# Copyright (C) 2013  Red Hat
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
Test integration of DNS and realmdomains.
1. dnszone_{add,del} should create/delete appropriate entry in realmdomains.
2. realmdomains_mod should add a _kerberos TXT record in the DNS zone.
"""


from ipalib import api, errors
from ipalib.util import normalize_zone
from ipapython.dn import DN
from ipapython.dnsutil import DNSName
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import Declarative, fuzzy_digits
import pytest


cn = 'Realm Domains'
dn = DN(('cn', cn), ('cn', 'ipa'), ('cn', 'etc'), api.env.basedn)
our_domain = api.env.domain
dnszone_1 = 'dnszone.test'
dnszone_1_absolute = '%s.' % dnszone_1
dnszone_1_dn = DN(('idnsname', dnszone_1_absolute), api.env.container_dns,
                  api.env.basedn)
idnssoamname = 'ns1.%s.' % dnszone_1
idnssoarname = 'root.%s.' % dnszone_1
dnszone_2 = 'dnszone2.test'
dnszone_2_absolute = "%s." % dnszone_2
dnszone_2_dn = DN(('idnsname', dnszone_2_absolute), api.env.container_dns,
                  api.env.basedn)

self_server_ns = normalize_zone(api.env.host)
self_server_ns_dnsname = DNSName(self_server_ns)

def assert_realmdomain_and_txt_record_present(response):
    zone = response['value']
    if isinstance(zone, (tuple, list)):
        zone = zone[0]
    zone = str(zone)
    if zone.endswith('.'):
        #realmdomains are without end dot
        zone = zone[:-1]

    r = api.Command['realmdomains_show']()
    assert zone in r['result']['associateddomain']

    r = api.Command['dnsrecord_show'](zone, '_kerberos')
    assert api.env.realm in r['result']['txtrecord']

    return True


def assert_realmdomain_and_txt_record_not_present(response):
    zone = response['value']
    if isinstance(zone, (tuple, list)):
        zone = zone[0]
    zone = str(zone)
    if zone.endswith('.'):
        #realmdomains are without end dot
        zone = zone[:-1]

    r = api.Command['realmdomains_show']()
    assert zone not in r['result']['associateddomain']

    try:
        api.Command['dnsrecord_show'](zone, '_kerberos')
    except errors.NotFound:
        return True
    else:
        return False


@pytest.mark.tier1
class test_dns_realmdomains_integration(Declarative):
    cleanup_commands = [
        ('realmdomains_mod', [], {'associateddomain': [our_domain]}),
        ('dnszone_del', [dnszone_1, dnszone_2], {'continue': True}),
    ]

    tests = [
        dict(
            desc='Check realmdomain and TXT record get created '
                 'during dnszone_add',
            command=(
                'dnszone_add', [dnszone_1], {
                    'idnssoarname': idnssoarname,
                }
            ),
            expected={
                'value':DNSName(dnszone_1_absolute),
                'summary': None,
                'result': {
                    'dn': dnszone_1_dn,
                    'idnsname': [DNSName(dnszone_1_absolute)],
                    'idnszoneactive': [True],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': lambda x: True,
                    'idnssoarname': [DNSName(idnssoarname)],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [False],
                    'idnsupdatepolicy': ['grant %(realm)s krb5-self * A; '
                                         'grant %(realm)s krb5-self * AAAA; '
                                         'grant %(realm)s krb5-self * SSHFP;'
                                         % dict(realm=api.env.realm)],
                    'idnsallowtransfer': ['none;'],
                    'idnsallowquery': ['any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
            extra_check=assert_realmdomain_and_txt_record_present,
        ),

        dict(
            desc='Check realmdomain and TXT record gets created '
                 'during dnszone_add for master zone with a forwarder',
            command=(
                'dnszone_add', [dnszone_2], {
                    'idnssoarname': idnssoarname,
                    'idnsforwarders': '198.18.19.20',
                    'idnsforwardpolicy': 'only',
                }
            ),
            expected={
                'value': DNSName(dnszone_2_absolute),
                'summary': None,
                'messages': (
                    {
                        'message': 'DNS forwarder semantics changed since '
                        'IPA 4.0.\nYou may want to use forward zones '
                        '(dnsforwardzone-*) instead.\nFor more details read '
                        'the docs.',
                        'code': 13002,
                        'type': 'warning',
                        'name': 'ForwardersWarning',
                        'data': {}
                    },),
                'result': {
                    'dn': dnszone_2_dn,
                    'idnsname': [DNSName(dnszone_2_absolute)],
                    'idnszoneactive': [True],
                    'idnssoamname': [self_server_ns_dnsname],
                    'idnsforwarders': ['198.18.19.20'],
                    'idnsforwardpolicy': ['only'],
                    'nsrecord': lambda x: True,
                    'idnssoarname': [DNSName(idnssoarname)],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [False],
                    'idnsupdatepolicy': ['grant %(realm)s krb5-self * A; '
                                         'grant %(realm)s krb5-self * AAAA; '
                                         'grant %(realm)s krb5-self * SSHFP;'
                                         % dict(realm=api.env.realm)],
                    'idnsallowtransfer': ['none;'],
                    'idnsallowquery': ['any;'],
                    'objectclass': objectclasses.dnszone,

                },
            },
            extra_check=assert_realmdomain_and_txt_record_present,
        ),

        dict(
            desc='Check realmdomain and TXT record get deleted '
                 'during dnszone_del',
            command=('dnszone_del', [dnszone_1], {}),
            expected={
                'value': [DNSName(dnszone_1_absolute)],
                'summary': 'Deleted DNS zone "%s"' % dnszone_1_absolute,
                'result': {'failed': []},
            },
            extra_check=assert_realmdomain_and_txt_record_not_present,
        ),
    ]
