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
from ipalib.dn import *
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid

dnszone1 = u'dnszone.test'
dnszone2 = u'dnszone2.test'
revdnszone1 = u'15.142.80.in-addr.arpa.'
dnsres1 = u'testdnsres'

class test_dns(Declarative):

    def setUp(self):
        super(test_dns, self).setUp()
        try:
           api.Command['dnszone_add'](dnszone1,
               idnssoamname = u'ns1.%s' % dnszone1,
               idnssoarname = u'root.%s' % dnszone1,
               force = True,
           )
           api.Command['dnszone_del'](dnszone1)
        except errors.NotFound:
            raise nose.SkipTest('DNS is not configured')
        except errors.DuplicateEntry:
            pass

    cleanup_commands = [
        ('dnszone_del', [dnszone1], {}),
        ('dnsrecord_del', [dnszone1, dnsres1], {'del_all' : True}),
        ('dnszone_del', [dnszone2], {}),
        ('dnszone_del', [revdnszone1], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent zone %r' % dnszone1,
            command=('dnszone_show', [dnszone1], {}),
            expected=errors.NotFound(reason='DNS zone not found'),
        ),


        dict(
            desc='Try to update non-existent zone %r' % dnszone1,
            command=('dnszone_mod', [dnszone1], {'idnssoamname': u'foobar'}),
            expected=errors.NotFound(reason='DNS zone not found'),
        ),


        dict(
            desc='Try to delete non-existent zone %r' % dnszone1,
            command=('dnszone_del', [dnszone1], {}),
            expected=errors.NotFound(reason='DNS zone not found'),
        ),


        dict(
            desc='Create zone %r' % dnszone1,
            command=(
                'dnszone_add', [dnszone1], {
                    'idnssoamname': u'ns1.%s' % dnszone1,
                    'idnssoarname': u'root.%s' % dnszone1,
                    'ip_address' : u'1.2.3.4',
                }
            ),
            expected={
                'value': dnszone1,
                'summary': None,
                'result': {
                    'dn': lambda x: DN(x) == \
                        DN(('idnsname',dnszone1),('cn','dns'),api.env.basedn),
                    'idnsname': [dnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [u'ns1.%s.' % dnszone1],
                    'nsrecord': [u'ns1.%s.' % dnszone1],
                    'idnssoarname': [u'root.%s.' % dnszone1],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'objectclass': [u'top', u'idnsrecord', u'idnszone'],
                },
            },
        ),


        dict(
            desc='Try to create duplicate zone %r' % dnszone1,
            command=(
                'dnszone_add', [dnszone1], {
                    'idnssoamname': u'ns1.%s' % dnszone1,
                    'idnssoarname': u'root.%s' % dnszone1,
                    'ip_address' : u'1.2.3.4',
                }
            ),
            expected=errors.DuplicateEntry(),
        ),

        dict(
            desc='Try to create a zone with nonexistent NS entry',
            command=(
                'dnszone_add', [dnszone2], {
                    'idnssoamname': u'ns1.%s' % dnszone2,
                    'idnssoarname': u'root.%s' % dnszone2,
                }
            ),
            expected=errors.NotFound(reason='Nameserver \'ns1.%s\' does not have a corresponding A/AAAA record' % (dnszone2)),
        ),

        dict(
            desc='Create a zone with nonexistent NS entry with --force',
            command=(
                'dnszone_add', [dnszone2], {
                    'idnssoamname': u'ns1.%s' % dnszone2,
                    'idnssoarname': u'root.%s' % dnszone2,
                    'force'       : True,
                }
            ),
            expected={
                'value': dnszone2,
                'summary': None,
                'result': {
                    'dn': lambda x: DN(x) == \
                        DN(('idnsname',dnszone2),('cn','dns'),api.env.basedn),
                    'idnsname': [dnszone2],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [u'ns1.%s.' % dnszone2],
                    'nsrecord': [u'ns1.%s.' % dnszone2],
                    'idnssoarname': [u'root.%s.' % dnszone2],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'objectclass': [u'top', u'idnsrecord', u'idnszone'],
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
                    'dn': lambda x: DN(x) == \
                        DN(('idnsname',dnszone1),('cn','dns'),api.env.basedn),
                    'idnsname': [dnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': [u'ns1.%s.' % dnszone1],
                    'idnssoamname': [u'ns1.%s.' % dnszone1],
                    'idnssoarname': [u'root.%s.' % dnszone1],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
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
                    'nsrecord': [u'ns1.%s.' % dnszone1],
                    'idnssoamname': [u'ns1.%s.' % dnszone1],
                    'idnssoarname': [u'root.%s.' % dnszone1],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                },
            },
        ),


        dict(
            desc='Create reverse zone %r' % revdnszone1,
            command=(
                'dnszone_add', [revdnszone1], {
                    'idnssoamname': u'ns1.%s' % dnszone1,
                    'idnssoarname': u'root.%s' % dnszone1,
                    'ip_address' : u'1.2.3.4',
                }
            ),
            expected={
                'value': revdnszone1,
                'summary': None,
                'result': {
                    'dn': lambda x: DN(x) == \
                        DN(('idnsname',revdnszone1),('cn','dns'),api.env.basedn),
                    'idnsname': [revdnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [u'ns1.%s.' % dnszone1],
                    'nsrecord': [u'ns1.%s.' % dnszone1],
                    'idnssoarname': [u'root.%s.' % dnszone1],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'objectclass': [u'top', u'idnsrecord', u'idnszone'],
                },
            },
        ),


        dict(
            desc='Search for zones with name server %r' % (u'ns1.%s.' % dnszone1),
            command=('dnszone_find', [], {'idnssoamname': u'ns1.%s.' % dnszone1}),
            expected={
                'summary': None,
                'count': 2,
                'truncated': False,
                'result': [{
                    'dn': lambda x: DN(x) == \
                        DN(('idnsname',revdnszone1),('cn','dns'),api.env.basedn),
                    'idnsname': [revdnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': [u'ns1.%s.' % dnszone1],
                    'idnssoamname': [u'ns1.%s.' % dnszone1],
                    'idnssoarname': [u'root.%s.' % dnszone1],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                },
                {
                    'dn': lambda x: DN(x) == \
                        DN(('idnsname',dnszone1),('cn','dns'),api.env.basedn),
                    'idnsname': [dnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': [u'ns1.%s.' % dnszone1],
                    'idnssoamname': [u'ns1.%s.' % dnszone1],
                    'idnssoarname': [u'root.%s.' % dnszone1],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                }],
            },
        ),


        dict(
            desc='Search for zones with name server %r with --forward-only' % (u'ns1.%s.' % dnszone1),
            command=('dnszone_find', [], {'idnssoamname': u'ns1.%s.' % dnszone1, 'forward_only' : True}),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [{
                    'dn': lambda x: DN(x) == \
                        DN(('idnsname',dnszone1),('cn','dns'),api.env.basedn),
                    'idnsname': [dnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': [u'ns1.%s.' % dnszone1],
                    'idnssoamname': [u'ns1.%s.' % dnszone1],
                    'idnssoarname': [u'root.%s.' % dnszone1],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
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
                    'dn': lambda x: DN(x) == \
                        DN(('idnsname',dnszone1),('cn','dns'),api.env.basedn),
                    'idnsname': [dnszone1],
                    'idnszoneactive': [u'FALSE'],
                    'nsrecord': [u'ns1.%s.' % dnszone1],
                    'idnssoamname': [u'ns1.%s.' % dnszone1],
                    'idnssoarname': [u'root.%s.' % dnszone1],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
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
                    'dn': lambda x: DN(x) == \
                        DN(('idnsname',dnszone1),('cn','dns'),api.env.basedn),
                    'idnsname': [dnszone1],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': [u'ns1.%s.' % dnszone1],
                    'idnssoamname': [u'ns1.%s.' % dnszone1],
                    'idnssoarname': [u'root.%s.' % dnszone1],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                },
            },
        ),


        dict(
            desc='Try to retrieve non-existent record %r in zone %r' % (dnsres1, dnszone1),
            command=('dnsrecord_show', [dnszone1, dnsres1], {}),
            expected=errors.NotFound(reason='DNS resource record not found'),
        ),


        dict(
            desc='Try to delete non-existent record %r in zone %r' % (dnsres1, dnszone1),
            command=('dnsrecord_del', [dnszone1, dnsres1], {'del_all' : True}),
            expected=errors.NotFound(reason='DNS resource record not found'),
        ),


        dict(
            desc='Create record %r in zone %r' % (dnszone1, dnsres1),
            command=('dnsrecord_add', [dnszone1, dnsres1], {'arecord': u'127.0.0.1'}),
            expected={
                'value': dnsres1,
                'summary': None,
                'result': {
                    'dn': lambda x: DN(x) == \
                        DN(('idnsname',dnsres1),('idnsname',dnszone1),
                           ('cn','dns'),api.env.basedn),
                    'idnsname': [dnsres1],
                    'objectclass': [u'top', u'idnsrecord'],
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
                        'dn': lambda x: DN(x) == \
                            DN(('idnsname',dnszone1),('cn','dns'),
                               api.env.basedn),
                        'nsrecord': (u'ns1.dnszone.test.',),
                        'idnsname': [u'@'],
                    },
                    {
                        'dn': lambda x: DN(x) == \
                            DN(('idnsname','ns1'),('idnsname',dnszone1),
                               ('cn','dns'),api.env.basedn),
                        'idnsname': [u'ns1'],
                        'arecord': [u'1.2.3.4'],
                    },
                    {
                        'dn': lambda x: DN(x) == \
                            DN(('idnsname',dnsres1),('idnsname',dnszone1),
                               ('cn','dns'),api.env.basedn),
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
                    'dn': lambda x: DN(x) == \
                        DN(('idnsname',dnsres1),('idnsname',dnszone1),
                           ('cn','dns'),api.env.basedn),
                    'idnsname': [dnsres1],
                    'arecord': [u'127.0.0.1', u'10.10.0.1'],
                    'objectclass': [u'top', u'idnsrecord'],
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
            desc='Delete record %r in zone %r' % (dnsres1, dnszone1),
            command=('dnsrecord_del', [dnszone1, dnsres1], {'del_all': True }),
            expected={
                'value': dnsres1,
                'summary': u'Deleted record "%s"' % dnsres1,
                'result': {'failed': u''},
            },
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

