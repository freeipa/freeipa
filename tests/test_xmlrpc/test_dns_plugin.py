# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2010  Red Hat
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
Test the `ipalib/plugins/dns.py` module.
"""

import nose
from ipalib import api, errors
from ipapython.dn import DN
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid

dnszone1 = u'dnszone.test'
dnszone1_dn = DN(('idnsname',dnszone1), api.env.container_dns, api.env.basedn)
dnszone1_mname = u'ns1.%s.' % dnszone1
dnszone1_mname_dn = DN(('idnsname','ns1'), dnszone1_dn)
dnszone1_rname = u'root.%s.' % dnszone1
dnszone1_permission = u'Manage DNS zone %s' % dnszone1
dnszone1_permission_dn = DN(('cn',dnszone1_permission),
                            api.env.container_permission,api.env.basedn)
dnszone2 = u'dnszone2.test'
dnszone2_dn = DN(('idnsname', dnszone2), api.env.container_dns, api.env.basedn)
dnszone2_mname = u'ns1.%s.' % dnszone2
dnszone2_rname = u'root.%s.' % dnszone2
revdnszone1 = u'15.142.80.in-addr.arpa.'
revdnszone1_ip = u'80.142.15.0/24'
revdnszone1_dn = DN(('idnsname', revdnszone1), api.env.container_dns, api.env.basedn)
revdnszone2 = u'16.142.80.in-addr.arpa.'
revdnszone2_ip = u'80.142.16.0'
revdnszone2_dn = DN(('idnsname',revdnszone2), api.env.container_dns, api.env.basedn)
dnsres1 = u'testdnsres'
dnsres1_dn = DN(('idnsname',dnsres1), dnszone1_dn)
dnsres1_renamed = u'testdnsres-renamed'
dnsrev1 = u'80'
dnsrev1_dn = DN(('idnsname',dnsrev1), revdnszone1_dn)
dnsrev2 = u'81'
dnsrev2_dn = DN(('idnsname',dnsrev2), revdnszone1_dn)
dnsrescname = u'testcnamerec'
dnsrescname_dn = DN(('idnsname',dnsrescname), dnszone1_dn)

class test_dns(Declarative):

    @classmethod
    def setUpClass(cls):
        super(test_dns, cls).setUpClass()

        if not api.Backend.xmlclient.isconnected():
            api.Backend.xmlclient.connect(fallback=False)
        try:
           api.Command['dnszone_add'](dnszone1,
               idnssoamname = dnszone1_mname,
               idnssoarname = dnszone1_rname,
               force = True,
           )
           api.Command['dnszone_del'](dnszone1)
        except errors.NotFound:
            raise nose.SkipTest('DNS is not configured')
        except errors.DuplicateEntry:
            pass

    cleanup_commands = [
        ('dnszone_del', [dnszone1, dnszone2, revdnszone1, revdnszone2],
            {'continue': True}),
        ('dnsconfig_mod', [], {'idnsforwarders' : None,
                               'idnsforwardpolicy' : None,
                               'idnsallowsyncptr' : None,
                               'idnszonerefresh' : None,
                               }),
        ('permission_del', [dnszone1_permission], {'force': True}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent zone %r' % dnszone1,
            command=('dnszone_show', [dnszone1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS zone not found' % dnszone1),
        ),


        dict(
            desc='Try to update non-existent zone %r' % dnszone1,
            command=('dnszone_mod', [dnszone1], {'idnssoamname': u'foobar'}),
            expected=errors.NotFound(
                reason=u'%s: DNS zone not found' % dnszone1),
        ),


        dict(
            desc='Try to delete non-existent zone %r' % dnszone1,
            command=('dnszone_del', [dnszone1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS zone not found' % dnszone1),
        ),


        dict(
            desc='Try to create zone with invalid name',
            command=(
                'dnszone_add', [u'invalid zone'], {
                    'idnssoamname': dnszone1_mname,
                    'idnssoarname': dnszone1_rname,
                    'ip_address' : u'1.2.3.4',
                }
            ),
            expected=errors.ValidationError(name='name',
                error=u'only letters, numbers, and - are allowed. ' +
                    u'DNS label may not start or end with -'),
        ),


        dict(
            desc='Create zone %r' % dnszone1,
            command=(
                'dnszone_add', [dnszone1], {
                    'idnssoamname': dnszone1_mname,
                    'idnssoarname': dnszone1_rname,
                    'ip_address' : u'1.2.3.4',
                }
            ),
            expected={
                'value': dnszone1,
                'summary': None,
                'result': {
                    'dn': dnszone1_dn,
                    'idnsname': [dnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [dnszone1_mname],
                    'nsrecord': [dnszone1_mname],
                    'idnssoarname': [dnszone1_rname],
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
            desc='Try to create duplicate zone %r' % dnszone1,
            command=(
                'dnszone_add', [dnszone1], {
                    'idnssoamname': dnszone1_mname,
                    'idnssoarname': dnszone1_rname,
                    'ip_address' : u'1.2.3.4',
                }
            ),
            expected=errors.DuplicateEntry(
                message=u'DNS zone with name "%s" already exists' % dnszone1),
        ),

        dict(
            desc='Try to create a zone with nonexistent NS entry',
            command=(
                'dnszone_add', [dnszone2], {
                    'idnssoamname': dnszone2_mname,
                    'idnssoarname': dnszone2_rname,
                }
            ),
            expected=errors.NotFound(reason='Nameserver \'%s\' does not have a corresponding A/AAAA record' % (dnszone2_mname)),
        ),

        dict(
            desc='Create a zone with nonexistent NS entry with --force',
            command=(
                'dnszone_add', [dnszone2], {
                    'idnssoamname': dnszone2_mname,
                    'idnssoarname': dnszone2_rname,
                    'force'       : True,
                }
            ),
            expected={
                'value': dnszone2,
                'summary': None,
                'result': {
                    'dn': dnszone2_dn,
                    'idnsname': [dnszone2],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [dnszone2_mname],
                    'nsrecord': [dnszone2_mname],
                    'idnssoarname': [dnszone2_rname],
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
            desc='Delete zone %r' % dnszone2,
            command=('dnszone_del', [dnszone2], {}),
            expected={
                'value': dnszone2,
                'summary': None,
                'result': {'failed': u''},
            },
        ),

        dict(
            desc='Retrieve zone %r' % dnszone1,
            command=('dnszone_show', [dnszone1], {}),
            expected={
                'value': dnszone1,
                'summary': None,
                'result': {
                    'dn': dnszone1_dn,
                    'idnsname': [dnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': [dnszone1_mname],
                    'idnssoamname': [dnszone1_mname],
                    'idnssoarname': [dnszone1_rname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
            },
        ),


        dict(
            desc='Update zone %r' % dnszone1,
            command=('dnszone_mod', [dnszone1], {'idnssoarefresh': 5478}),
            expected={
                'value': dnszone1,
                'summary': None,
                'result': {
                    'idnsname': [dnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': [dnszone1_mname],
                    'idnssoamname': [dnszone1_mname],
                    'idnssoarname': [dnszone1_rname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
            },
        ),


        dict(
            desc='Create reverse zone %r' % revdnszone1,
            command=(
                'dnszone_add', [revdnszone1], {
                    'idnssoamname': dnszone1_mname,
                    'idnssoarname': dnszone1_rname,
                    'ip_address' : u'1.2.3.4',
                }
            ),
            expected={
                'value': revdnszone1,
                'summary': None,
                'result': {
                    'dn': revdnszone1_dn,
                    'idnsname': [revdnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [dnszone1_mname],
                    'nsrecord': [dnszone1_mname],
                    'idnssoarname': [dnszone1_rname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-subdomain %(zone)s PTR;'
                                         % dict(realm=api.env.realm, zone=revdnszone1)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),


        dict(
            desc='Search for zones with name server %r' % (dnszone1_mname),
            command=('dnszone_find', [], {'idnssoamname': dnszone1_mname}),
            expected={
                'summary': None,
                'count': 2,
                'truncated': False,
                'result': [{
                    'dn': revdnszone1_dn,
                    'idnsname': [revdnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': [dnszone1_mname],
                    'idnssoamname': [dnszone1_mname],
                    'idnssoarname': [dnszone1_rname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
                {
                    'dn': dnszone1_dn,
                    'idnsname': [dnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': [dnszone1_mname],
                    'idnssoamname': [dnszone1_mname],
                    'idnssoarname': [dnszone1_rname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                }],
            },
        ),


        dict(
            desc='Search for zones with name server %r with --forward-only' % dnszone1_mname,
            command=('dnszone_find', [], {'idnssoamname': dnszone1_mname, 'forward_only' : True}),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [{
                    'dn': dnszone1_dn,
                    'idnsname': [dnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': [dnszone1_mname],
                    'idnssoamname': [dnszone1_mname],
                    'idnssoarname': [dnszone1_rname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                }],
            },
        ),


        dict(
            desc='Delete reverse zone %r' % revdnszone1,
            command=('dnszone_del', [revdnszone1], {}),
            expected={
                'value': revdnszone1,
                'summary': None,
                'result': {'failed': u''},
            },
        ),


        dict(
            desc='Disable zone %r' % dnszone1,
            command=('dnszone_disable', [dnszone1], {}),
            expected={
                'value': dnszone1,
                'summary': u'Disabled DNS zone "%s"' % dnszone1,
                'result': True,
            },
        ),


        dict(
            desc='Check if zone %r is really disabled' % dnszone1,
            command=('dnszone_show', [dnszone1], {}),
            expected={
                'value': dnszone1,
                'summary': None,
                'result': {
                    'dn': dnszone1_dn,
                    'idnsname': [dnszone1],
                    'idnszoneactive': [u'FALSE'],
                    'nsrecord': [dnszone1_mname],
                    'idnssoamname': [dnszone1_mname],
                    'idnssoarname': [dnszone1_rname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
            },
        ),


        dict(
            desc='Enable zone %r' % dnszone1,
            command=('dnszone_enable', [dnszone1], {}),
            expected={
                'value': dnszone1,
                'summary': u'Enabled DNS zone "%s"' % dnszone1,
                'result': True,
            },
        ),


        dict(
            desc='Check if zone %r is really enabled' % dnszone1,
            command=('dnszone_show', [dnszone1], {}),
            expected={
                'value': dnszone1,
                'summary': None,
                'result': {
                    'dn': dnszone1_dn,
                    'idnsname': [dnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': [dnszone1_mname],
                    'idnssoamname': [dnszone1_mname],
                    'idnssoarname': [dnszone1_rname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
            },
        ),


        dict(
            desc='Try to retrieve non-existent record %r in zone %r' % (dnsres1, dnszone1),
            command=('dnsrecord_show', [dnszone1, dnsres1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS resource record not found' % dnsres1),
        ),


        dict(
            desc='Try to delete non-existent record %r in zone %r' % (dnsres1, dnszone1),
            command=('dnsrecord_del', [dnszone1, dnsres1], {'del_all' : True}),
            expected=errors.NotFound(
                reason=u'%s: DNS resource record not found' % dnsres1),
        ),


        dict(
            desc='Try to delete root zone record \'@\' in %r' % (dnszone1),
            command=('dnsrecord_del', [dnszone1, u'@'], {'del_all' : True}),
            expected=errors.ValidationError(name='del_all',
                error=u"Zone record '@' cannot be deleted"),
        ),


        dict(
            desc='Try to create record with invalid name in zone %r' % dnszone1,
            command=('dnsrecord_add', [dnszone1, u'invalid record'], {'arecord': u'127.0.0.1'}),
            expected=errors.ValidationError(name='name',
                error=u'only letters, numbers, _, and - are allowed. ' +
                    u'DNS label may not start or end with -'),
        ),


        dict(
            desc='Create record %r in zone %r' % (dnszone1, dnsres1),
            command=('dnsrecord_add', [dnszone1, dnsres1], {'arecord': u'127.0.0.1'}),
            expected={
                'value': dnsres1,
                'summary': None,
                'result': {
                    'dn': dnsres1_dn,
                    'idnsname': [dnsres1],
                    'objectclass': objectclasses.dnsrecord,
                    'arecord': [u'127.0.0.1'],
                },
            },
        ),


        dict(
            desc='Search for all records in zone %r' % dnszone1,
            command=('dnsrecord_find', [dnszone1], {}),
            expected={
                'summary': None,
                'count': 3,
                'truncated': False,
                'result': [
                    {
                        'dn': dnszone1_dn,
                        'nsrecord': (dnszone1_mname,),
                        'idnsname': [u'@'],
                    },
                    {
                        'dn': dnszone1_mname_dn,
                        'idnsname': [u'ns1'],
                        'arecord': [u'1.2.3.4'],
                    },
                    {
                        'dn': dnsres1_dn,
                        'idnsname': [dnsres1],
                        'arecord': [u'127.0.0.1'],
                    },
                ],
            },
        ),


        dict(
            desc='Add A record to %r in zone %r' % (dnsres1, dnszone1),
            command=('dnsrecord_add', [dnszone1, dnsres1], {'arecord': u'10.10.0.1'}),
            expected={
                'value': dnsres1,
                'summary': None,
                'result': {
                    'dn': dnsres1_dn,
                    'idnsname': [dnsres1],
                    'arecord': [u'127.0.0.1', u'10.10.0.1'],
                    'objectclass': objectclasses.dnsrecord,
                },
            },
        ),


        dict(
            desc='Remove A record from %r in zone %r' % (dnsres1, dnszone1),
            command=('dnsrecord_del', [dnszone1, dnsres1], {'arecord': u'127.0.0.1'}),
            expected={
                'value': dnsres1,
                'summary': None,
                'result': {
                    'idnsname': [dnsres1],
                    'arecord': [u'10.10.0.1'],
                },
            },
        ),


        dict(
            desc='Add AAAA record to %r in zone %r using dnsrecord_mod' % (dnsres1, dnszone1),
            command=('dnsrecord_mod', [dnszone1, dnsres1], {'aaaarecord': u'::1'}),
            expected={
                'value': dnsres1,
                'summary': None,
                'result': {
                    'idnsname': [dnsres1],
                    'arecord': [u'10.10.0.1'],
                    'aaaarecord': [u'::1'],
                },
            },
        ),


        dict(
            desc='Try to modify nonexistent record in zone %r' % dnszone1,
            command=('dnsrecord_mod',
                [dnszone1, u'ghostname'],
                {'aaaarecord': u'f001:baad::1'}),
            expected=errors.NotFound(
                reason=u'ghostname: DNS resource record not found'),
        ),


        dict(
            desc='Modify AAAA record in %r in zone %r' % (dnsres1, dnszone1),
            command=('dnsrecord_mod', [dnszone1, dnsres1], {'aaaarecord': u'ff02::1'}),
            expected={
                'value': dnsres1,
                'summary': None,
                'result': {
                    'idnsname': [dnsres1],
                    'arecord': [u'10.10.0.1'],
                    'aaaarecord': [u'ff02::1'],
                },
            },
        ),


        dict(
            desc='Remove AAAA record from %r in zone %r using dnsrecord_mod' % (dnsres1, dnszone1),
            command=('dnsrecord_mod', [dnszone1, dnsres1], {'aaaarecord': u''}),
            expected={
                'value': dnsres1,
                'summary': None,
                'result': {
                    'idnsname': [dnsres1],
                    'arecord': [u'10.10.0.1'],
                },
            },
        ),

        dict(
            desc='Try to add invalid MX record to zone %r using dnsrecord_add' % (dnszone1),
            command=('dnsrecord_add', [dnszone1, u'@'], {'mxrecord': dnszone1_mname }),
            expected=errors.ValidationError(name='mx_rec',
                error=u'format must be specified as "PREFERENCE EXCHANGER" ' +
                    u' (see RFC 1035 for details)'),
        ),

        dict(
            desc='Add MX record to zone %r using dnsrecord_add' % (dnszone1),
            command=('dnsrecord_add', [dnszone1, u'@'], {'mxrecord': u"0 %s" % dnszone1_mname }),
            expected={
                'value': u'@',
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnszone,
                    'dn': dnszone1_dn,
                    'idnsname': [u'@'],
                    'mxrecord': [u"0 %s" % dnszone1_mname],
                    'nsrecord': [dnszone1_mname],
                },
            },
        ),

        dict(
            desc='Try to add invalid SRV record to zone %r using dnsrecord_add' % (dnszone1),
            command=('dnsrecord_add', [dnszone1, u'_foo._tcp'], {'srvrecord': dnszone1_mname}),
            expected=errors.ValidationError(name='srv_rec',
                error=u'format must be specified as "PRIORITY WEIGHT PORT TARGET" ' +
                    u' (see RFC 2782 for details)'),
        ),

        dict(
            desc='Try to add invalid SRV record via parts to zone %r using dnsrecord_add' % (dnszone1),
            command=('dnsrecord_add', [dnszone1, u'_foo._tcp'], {'srv_part_priority': 0,
                                                                 'srv_part_weight' : 0,
                                                                 'srv_part_port' : 123,
                                                                 'srv_part_target' : u'foo bar'}),
            expected=errors.ValidationError(name='srv_target',
                error=u'invalid domain-name: only letters, numbers, and - ' +
                    u'are allowed. DNS label may not start or end with -'),
        ),

        dict(
            desc='Try to add SRV record to zone %r both via parts and a raw value' % (dnszone1),
            command=('dnsrecord_add', [dnszone1, u'_foo._tcp'], {'srv_part_priority': 0,
                                                                 'srv_part_weight' : 0,
                                                                 'srv_part_port' : 123,
                                                                 'srv_part_target' : u'foo.bar.',
                                                                 'srvrecord': [u"1 100 1234 %s" \
                                                                     % dnszone1_mname]}),
            expected=errors.ValidationError(name='srv_target',
                error=u'Raw value of a DNS record was already set by ' +
                    u'"srv_rec" option'),
        ),

        dict(
            desc='Add SRV record to zone %r using dnsrecord_add' % (dnszone1),
            command=('dnsrecord_add', [dnszone1, u'_foo._tcp'], {'srvrecord': u"0 100 1234 %s" % dnszone1_mname}),
            expected={
                'value': u'_foo._tcp',
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': DN(('idnsname', u'_foo._tcp'), dnszone1_dn),
                    'idnsname': [u'_foo._tcp'],
                    'srvrecord': [u"0 100 1234 %s" % dnszone1_mname],
                },
            },
        ),

        dict(
            desc='Try to modify SRV record in zone %r without specifying modified value' % (dnszone1),
            command=('dnsrecord_mod', [dnszone1, u'_foo._tcp'], {'srv_part_priority': 1,}),
            expected=errors.RequirementError(name='srvrecord'),
        ),

        dict(
            desc='Try to modify SRV record in zone %r with non-existent modified value' % (dnszone1),
            command=('dnsrecord_mod', [dnszone1, u'_foo._tcp'], {'srv_part_priority': 1,
                                                  'srvrecord' : [u"0 100 1234 does.not.exist."] }),
            expected=errors.AttrValueNotFound(attr='SRV record',
                value=u'0 100 1234 does.not.exist.'),
        ),

        dict(
            desc='Try to modify SRV record in zone %r with invalid part value' % (dnszone1),
            command=('dnsrecord_mod', [dnszone1, u'_foo._tcp'], {'srv_part_priority': 100000,
                                                  'srvrecord' : [u"0 100 1234 %s" % dnszone1_mname] }),
            expected=errors.ValidationError(name='srv_priority', error=u'can be at most 65535'),
        ),

        dict(
            desc='Modify SRV record in zone %r using parts' % (dnszone1),
            command=('dnsrecord_mod', [dnszone1, u'_foo._tcp'], {'srv_part_priority': 1,
                                                  'srvrecord' : [u"0 100 1234 %s" % dnszone1_mname] }),
            expected={
                'value': u'_foo._tcp',
                'summary': None,
                'result': {
                    'idnsname': [u'_foo._tcp'],
                    'srvrecord': [u"1 100 1234 %s" % dnszone1_mname],
                },
            },
        ),

        dict(
            desc='Try to add invalid LOC record to zone %r using dnsrecord_add' % (dnszone1),
            command=('dnsrecord_add', [dnszone1, u'@'], {'locrecord': u"91 11 42.4 N 16 36 29.6 E 227.64" }),
            expected=errors.ValidationError(name='lat_deg',
                error=u'can be at most 90'),
        ),

        dict(
            desc='Add LOC record to zone %r using dnsrecord_add' % (dnszone1),
            command=('dnsrecord_add', [dnszone1, u'@'], {'locrecord': u"49 11 42.4 N 16 36 29.6 E 227.64" }),
            expected={
                'value': u'@',
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnszone,
                    'dn': dnszone1_dn,
                    'idnsname': [u'@'],
                    'mxrecord': [u"0 %s" % dnszone1_mname],
                    'nsrecord': [dnszone1_mname],
                    'locrecord': [u"49 11 42.400 N 16 36 29.600 E 227.64"],
                },
            },
        ),

        dict(
            desc='Try to add CNAME record to %r using dnsrecord_add' % (dnsres1),
            command=('dnsrecord_add', [dnszone1, dnsres1], {'cnamerecord': u'foo-1.example.com.'}),
            expected=errors.ValidationError(name='cnamerecord',
                error=u'CNAME record is not allowed to coexist with any other records except PTR'),
        ),

        dict(
            desc='Try to add invalid CNAME record %r using dnsrecord_add' % (dnsrescname),
            command=('dnsrecord_add', [dnszone1, dnsrescname], {'cnamerecord': u'-.example.com'}),
            expected=errors.ValidationError(name='hostname',
                error=u'invalid domain-name: only letters, numbers, and - ' +
                    u'are allowed. DNS label may not start or end with -'),
        ),

        dict(
            desc='Add CNAME record to %r using dnsrecord_add' % (dnsrescname),
            command=('dnsrecord_add', [dnszone1, dnsrescname], {'cnamerecord': u'foo-1.example.com.'}),
            expected={
                'value': dnsrescname,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': dnsrescname_dn,
                    'idnsname': [dnsrescname],
                    'cnamerecord': [u'foo-1.example.com.'],
                },
            },
        ),

        dict(
            desc='Try to add other record to CNAME record %r using dnsrecord_add' % (dnsrescname),
            command=('dnsrecord_add', [dnszone1, dnsrescname], {'arecord': u'10.0.0.1'}),
            expected=errors.ValidationError(name='cnamerecord',
                error=u'CNAME record is not allowed to coexist with any other records except PTR'),
        ),

        dict(
            desc='Try to add other record to CNAME record %r using dnsrecord_mod' % (dnsrescname),
            command=('dnsrecord_mod', [dnszone1, dnsrescname], {'arecord': u'10.0.0.1'}),
            expected=errors.ValidationError(name='cnamerecord',
                error=u'CNAME record is not allowed to coexist with any other records except PTR'),
        ),

        dict(
            desc='Add A record and delete CNAME record in %r with dnsrecord_mod' % (dnsrescname),
            command=('dnsrecord_mod', [dnszone1, dnsrescname], {'arecord': u'10.0.0.1',
                                                                'cnamerecord': None}),
            expected={
                'value': dnsrescname,
                'summary': None,
                'result': {
                    'idnsname': [dnsrescname],
                    'arecord': [u'10.0.0.1'],
                },
            },
        ),

        dict(
            desc='Try to add invalid KX record %r using dnsrecord_add' % (dnsres1),
            command=('dnsrecord_add', [dnszone1, dnsres1], {'kxrecord': u'foo-1.example.com' }),
            expected=errors.ValidationError(name='kx_rec',
                error=u'format must be specified as "PREFERENCE EXCHANGER" ' +
                    u' (see RFC 2230 for details)'),
        ),

        dict(
            desc='Add KX record to %r using dnsrecord_add' % (dnsres1),
            command=('dnsrecord_add', [dnszone1, dnsres1], {'kxrecord': u'1 foo-1' }),
            expected={
                'value': dnsres1,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': dnsres1_dn,
                    'idnsname': [dnsres1],
                    'arecord': [u'10.10.0.1'],
                    'kxrecord': [u'1 foo-1'],
                },
            },
        ),

        dict(
            desc='Add TXT record to %r using dnsrecord_add' % (dnsres1),
            command=('dnsrecord_add', [dnszone1, dnsres1], {'txtrecord': u'foo bar' }),
            expected={
                'value': dnsres1,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': dnsres1_dn,
                    'idnsname': [dnsres1],
                    'arecord': [u'10.10.0.1'],
                    'kxrecord': [u'1 foo-1'],
                    'txtrecord': [u'foo bar'],
                },
            },
        ),

        dict(
            desc='Add NSEC record to %r using dnsrecord_add' % (dnsres1),
            command=('dnsrecord_add', [dnszone1, dnsres1], {
                'nsec_part_next': dnszone1,
                'nsec_part_types' : [u'TXT', u'A']}),
            expected={
                'value': dnsres1,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': dnsres1_dn,
                    'idnsname': [dnsres1],
                    'arecord': [u'10.10.0.1'],
                    'kxrecord': [u'1 foo-1'],
                    'txtrecord': [u'foo bar'],
                    'nsecrecord': [dnszone1 + u' TXT A'],
                },
            },
        ),

        dict(
            desc='Try to add unresolvable absolute NS record to %r using dnsrecord_add' % (dnsres1),
            command=('dnsrecord_add', [dnszone1, dnsres1], {'nsrecord': u'does.not.exist.'}),
            expected=errors.NotFound(reason=u"Nameserver 'does.not.exist.' does not have a corresponding A/AAAA record"),
        ),

        dict(
            desc='Try to add unresolvable relative NS record to %r using dnsrecord_add' % (dnsres1),
            command=('dnsrecord_add', [dnszone1, dnsres1], {'nsrecord': u'does.not.exist'}),
            expected=errors.NotFound(reason=u"Nameserver 'does.not.exist.%s.' does not have a corresponding A/AAAA record" % dnszone1),
        ),

        dict(
            desc='Add unresolvable NS record with --force to %r using dnsrecord_add' % (dnsres1),
            command=('dnsrecord_add', [dnszone1, dnsres1], {'nsrecord': u'does.not.exist.',
                                                            'force' : True}),
            expected={
                'value': dnsres1,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': dnsres1_dn,
                    'idnsname': [dnsres1],
                    'arecord': [u'10.10.0.1'],
                    'kxrecord': [u'1 foo-1'],
                    'txtrecord': [u'foo bar'],
                    'nsecrecord': [dnszone1 + u' TXT A'],
                    'nsrecord': [u'does.not.exist.'],
                },
            },
        ),

        dict(
            desc='Try to to rename DNS zone %r root record' % (dnszone1),
            command=('dnsrecord_mod', [dnszone1, u'@'], {'rename': dnsres1_renamed,}),
            expected=errors.ValidationError(name='rename',
                           error=u'DNS zone root record cannot be renamed')
        ),

        dict(
            desc='Rename DNS record %r to %r' % (dnsres1, dnsres1_renamed),
            command=('dnsrecord_mod', [dnszone1, dnsres1], {'rename': dnsres1_renamed,}),
            expected={
                'value': dnsres1,
                'summary': None,
                'result': {
                    'idnsname': [dnsres1_renamed],
                    'arecord': [u'10.10.0.1'],
                    'kxrecord': [u'1 foo-1'],
                    'txtrecord': [u'foo bar'],
                    'nsecrecord': [dnszone1 + u' TXT A'],
                    'nsrecord': [u'does.not.exist.'],
                },
            },
        ),


        dict(
            desc='Delete record %r in zone %r' % (dnsres1_renamed, dnszone1),
            command=('dnsrecord_del', [dnszone1, dnsres1_renamed], {'del_all': True }),
            expected={
                'value': dnsres1_renamed,
                'summary': u'Deleted record "%s"' % dnsres1_renamed,
                'result': {'failed': u''},
            },
        ),


        dict(
            desc='Try to create a reverse zone from invalid IP',
            command=(
                'dnszone_add', [], {
                    'name_from_ip': u'foo',
                    'idnssoamname': dnszone1_mname,
                    'idnssoarname': dnszone1_rname,
                    'ip_address' : u'1.2.3.4',
                }
            ),
            expected=errors.ValidationError(name='name_from_ip',
                error=u'invalid IP network format'),
        ),

        dict(
            desc='Create reverse zone from IP/netmask %r using name_from_ip option' % revdnszone1_ip,
            command=(
                'dnszone_add', [], {
                    'name_from_ip': revdnszone1_ip,
                    'idnssoamname': dnszone1_mname,
                    'idnssoarname': dnszone1_rname,
                    'ip_address' : u'1.2.3.4',
                }
            ),
            expected={
                'value': revdnszone1,
                'summary': None,
                'result': {
                    'dn': revdnszone1_dn,
                    'idnsname': [revdnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [dnszone1_mname],
                    'nsrecord': [dnszone1_mname],
                    'idnssoarname': [dnszone1_rname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-subdomain %(zone)s PTR;'
                                         % dict(realm=api.env.realm, zone=revdnszone1)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),


        dict(
            desc='Create reverse zone from IP %r using name_from_ip option' % revdnszone2_ip,
            command=(
                'dnszone_add', [], {
                    'name_from_ip': revdnszone2_ip,
                    'idnssoamname': dnszone1_mname,
                    'idnssoarname': dnszone1_rname,
                    'ip_address' : u'1.2.3.4',
                }
            ),
            expected={
                'value': revdnszone2,
                'summary': None,
                'result': {
                    'dn': revdnszone2_dn,
                    'idnsname': [revdnszone2],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [dnszone1_mname],
                    'nsrecord': [dnszone1_mname],
                    'idnssoarname': [dnszone1_rname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-subdomain %(zone)s PTR;'
                                         % dict(realm=api.env.realm, zone=revdnszone2)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),


        dict(
            desc='Try to add invalid PTR %r to %r using dnsrecord_add' % (dnsrev1, revdnszone1),
            command=('dnsrecord_add', [revdnszone1, dnsrev1], {'ptrrecord': u'-.example.com' }),
            expected=errors.ValidationError(name='hostname',
                error=u'invalid domain-name: only letters, numbers, and - ' +
                    u'are allowed. DNS label may not start or end with -'),
        ),

        dict(
            desc='Add PTR record %r to %r using dnsrecord_add' % (dnsrev1, revdnszone1),
            command=('dnsrecord_add', [revdnszone1, dnsrev1], {'ptrrecord': u'foo-1.example.com' }),
            expected={
                'value': dnsrev1,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': dnsrev1_dn,
                    'idnsname': [dnsrev1],
                    'ptrrecord': [u'foo-1.example.com.'],
                },
            },
        ),

        dict(
            desc='Test that CNAME/PTR record type combination in record %r is allowed' % (dnsrev1),
            command=('dnsrecord_add', [revdnszone1, dnsrev1], {'cnamerecord': u'foo-1.example.com.' }),
            expected={
                'value': dnsrev1,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': dnsrev1_dn,
                    'idnsname': [dnsrev1],
                    'ptrrecord': [u'foo-1.example.com.'],
                    'cnamerecord': [u'foo-1.example.com.'],
                },
            },
        ),

        dict(
            desc='Update global DNS settings',
            command=('dnsconfig_mod', [], {'idnsforwarders' : [u'80.142.15.80'],}),
            expected={
                'value': u'',
                'summary': None,
                'result': {
                    'idnsforwarders': [u'80.142.15.80'],
                },
            },
        ),


        dict(
            desc='Try to add invalid allow-query to zone %r' % dnszone1,
            command=('dnszone_mod', [dnszone1], {'idnsallowquery': u'foo'}),
            expected=errors.ValidationError(name='allow_query',
                error=u"failed to detect a valid IP address from u'foo'"),
        ),

        dict(
            desc='Add allow-query ACL to zone %r' % dnszone1,
            command=('dnszone_mod', [dnszone1], {'idnsallowquery': u'!10/8;any'}),
            expected={
                'value': dnszone1,
                'summary': None,
                'result': {
                    'idnsname': [dnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': [dnszone1_mname],
                    'mxrecord': [u'0 ns1.dnszone.test.'],
                    'locrecord': [u"49 11 42.400 N 16 36 29.600 E 227.64"],
                    'idnssoamname': [dnszone1_mname],
                    'idnssoarname': [dnszone1_rname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowquery': [u'!10.0.0.0/8;any;'],
                    'idnsallowtransfer': [u'none;'],
                },
            },
        ),


        dict(
            desc='Try to add invalid allow-transfer to zone %r' % dnszone1,
            command=('dnszone_mod', [dnszone1], {'idnsallowtransfer': u'10.'}),
            expected=errors.ValidationError(name='allow_transfer',
                error=u"failed to detect a valid IP address from u'10.'"),
        ),

        dict(
            desc='Add allow-transer ACL to zone %r' % dnszone1,
            command=('dnszone_mod', [dnszone1], {'idnsallowtransfer': u'80.142.15.80'}),
            expected={
                'value': dnszone1,
                'summary': None,
                'result': {
                    'idnsname': [dnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': [dnszone1_mname],
                    'mxrecord': [u'0 ns1.dnszone.test.'],
                    'locrecord': [u"49 11 42.400 N 16 36 29.600 E 227.64"],
                    'idnssoamname': [dnszone1_mname],
                    'idnssoarname': [dnszone1_rname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowquery': [u'!10.0.0.0/8;any;'],
                    'idnsallowtransfer': [u'80.142.15.80;'],
                },
            },
        ),


        dict(
            desc='Set SOA serial of zone %r to high number' % dnszone1,
            command=('dnszone_mod', [dnszone1], {'idnssoaserial': 4294967295}),
            expected={
                'value': dnszone1,
                'summary': None,
                'result': {
                    'idnsname': [dnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': [dnszone1_mname],
                    'mxrecord': [u'0 ns1.dnszone.test.'],
                    'locrecord': [u"49 11 42.400 N 16 36 29.600 E 227.64"],
                    'idnssoamname': [dnszone1_mname],
                    'idnssoarname': [dnszone1_rname],
                    'idnssoaserial': [u'4294967295'],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowquery': [u'!10.0.0.0/8;any;'],
                    'idnsallowtransfer': [u'80.142.15.80;'],
                },
            },
        ),


        dict(
            desc='Try to create duplicate PTR record for %r with --a-create-reverse' % dnsres1,
            command=('dnsrecord_add', [dnszone1, dnsres1], {'arecord': u'80.142.15.80',
                                                            'a_extra_create_reverse' : True}),
            expected=errors.DuplicateEntry(message=u'Reverse record for IP ' +
                u'address 80.142.15.80 already exists in reverse zone ' +
                u'15.142.80.in-addr.arpa..'),
        ),


        dict(
            desc='Create A record %r in zone %r with --a-create-reverse' % (dnsres1, dnszone1),
            command=('dnsrecord_add', [dnszone1, dnsres1], {'arecord': u'80.142.15.81',
                                                            'a_extra_create_reverse' : True}),
            expected={
                'value': dnsres1,
                'summary': None,
                'result': {
                    'dn': dnsres1_dn,
                    'idnsname': [dnsres1],
                    'objectclass': objectclasses.dnsrecord,
                    'arecord': [u'80.142.15.81'],
                },
            },
        ),


        dict(
            desc='Check reverse record for %r created via --a-create-reverse' % dnsres1,
            command=('dnsrecord_show', [revdnszone1, dnsrev2], {}),
            expected={
                'value': dnsrev2,
                'summary': None,
                'result': {
                    'dn': dnsrev2_dn,
                    'idnsname': [dnsrev2],
                    'ptrrecord': [dnsres1 + '.' + dnszone1 + '.'],
                },
            },
        ),


        dict(
            desc='Try to add per-zone permission for unknown zone',
            command=('dnszone_add_permission', [u'does.not.exist'], {}),
            expected=errors.NotFound(reason=u'does.not.exist: DNS zone not found')
        ),


        dict(
            desc='Add per-zone permission for zone %r' % dnszone1,
            command=(
                'dnszone_add_permission', [dnszone1], {}
            ),
            expected=dict(
                result=True,
                value=dnszone1_permission,
                summary=u'Added system permission "%s"' % dnszone1_permission,
            ),
        ),


        dict(
            desc='Try to add duplicate per-zone permission for zone %r' % dnszone1,
            command=(
                'dnszone_add_permission', [dnszone1], {}
            ),
            expected=errors.DuplicateEntry(message=u'permission with name '
                '"%s" already exists' % dnszone1_permission)
        ),


        dict(
            desc='Make sure the permission was created %r' % dnszone1,
            command=(
                'permission_show', [dnszone1_permission], {}
            ),
            expected=dict(
                value=dnszone1_permission,
                summary=None,
                result={
                    'dn': dnszone1_permission_dn,
                    'cn': [dnszone1_permission],
                    'ipapermissiontype': [u'SYSTEM'],
                },
            ),
        ),


        dict(
            desc='Try to remove per-zone permission for unknown zone',
            command=('dnszone_remove_permission', [u'does.not.exist'], {}),
            expected=errors.NotFound(reason=u'does.not.exist: DNS zone not found')
        ),


        dict(
            desc='Remove per-zone permission for zone %r' % dnszone1,
            command=(
                'dnszone_remove_permission', [dnszone1], {}
            ),
            expected=dict(
                result=True,
                value=dnszone1_permission,
                summary=u'Removed system permission "%s"' % dnszone1_permission,
            ),
        ),


        dict(
            desc='Make sure the permission for zone %r was deleted' % dnszone1,
            command=(
                'permission_show', [dnszone1_permission], {}
            ),
            expected=errors.NotFound(reason=u'%s: permission not found'
                                     % dnszone1_permission)
        ),


        dict(
            desc='Delete zone %r' % dnszone1,
            command=('dnszone_del', [dnszone1], {}),
            expected={
                'value': dnszone1,
                'summary': None,
                'result': {'failed': u''},
            },
        ),

    ]
