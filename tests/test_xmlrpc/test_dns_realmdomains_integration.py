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
from ipapython.dn import DN
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits


cn = u'Realm Domains'
dn = DN(('cn', cn), ('cn', 'ipa'), ('cn', 'etc'), api.env.basedn)
our_domain = api.env.domain
dnszone_1 = u'dnszone.test'
dnszone_1_dn = DN(('idnsname', dnszone_1), api.env.container_dns,
                  api.env.basedn)
idnssoamname = u'ns1.%s.' % dnszone_1
idnssoarname = u'root.%s.' % dnszone_1
dnszone_2 = u'dnszone2.test'
dnszone_2_dn = DN(('idnsname', dnszone_2), api.env.container_dns,
                  api.env.basedn)


def assert_realmdomain_and_txt_record_present(response):
    zone = response['value']

    r = api.Command['realmdomains_show']()
    assert zone in r['result']['associateddomain']

    r = api.Command['dnsrecord_show'](zone, u'_kerberos')
    assert api.env.realm in r['result']['txtrecord']

    return True


def assert_realmdomain_and_txt_record_not_present(response):
    zone = response['value']

    r = api.Command['realmdomains_show']()
    assert zone not in r['result']['associateddomain']

    try:
        api.Command['dnsrecord_show'](zone, u'_kerberos')
    except errors.NotFound:
        return True


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
                    'idnssoamname': idnssoamname,
                    'idnssoarname': idnssoarname,
                    'ip_address': u'1.2.3.4',
                }
            ),
            expected={
                'value': dnszone_1,
                'summary': None,
                'result': {
                    'dn': dnszone_1_dn,
                    'idnsname': [dnszone_1],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [idnssoamname],
                    'nsrecord': [idnssoamname],
                    'idnssoarname': [idnssoarname],
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
            extra_check=assert_realmdomain_and_txt_record_present,
        ),

        dict(
            desc='Check realmdomain and TXT record do not get created '
                 'during dnszone_add for forwarded zone',
            command=(
                'dnszone_add', [dnszone_2], {
                    'idnssoamname': idnssoamname,
                    'idnssoarname': idnssoarname,
                    'idnsforwarders': u'1.2.3.4',
                    'idnsforwardpolicy': u'only',
                    'force': True,
                }
            ),
            expected={
                'value': dnszone_2,
                'summary': None,
                'result': {
                    'dn': dnszone_2_dn,
                    'idnsname': [dnszone_2],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [idnssoamname],
                    'idnsforwarders': [u'1.2.3.4'],
                    'idnsforwardpolicy': [u'only'],
                    'nsrecord': [idnssoamname],
                    'idnssoarname': [idnssoarname],
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
            extra_check=assert_realmdomain_and_txt_record_not_present,
        ),

        dict(
            desc='Check realmdomain and TXT record get deleted '
                 'during dnszone_del',
            command=('dnszone_del', [dnszone_1], {}),
            expected={
                'value': dnszone_1,
                'summary': u'Deleted DNS zone "%s"' % dnszone_1,
                'result': {'failed': u''},
            },
            extra_check=assert_realmdomain_and_txt_record_not_present,
        ),
    ]
