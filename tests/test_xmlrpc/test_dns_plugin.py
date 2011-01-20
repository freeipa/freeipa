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
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid

dnszone1 = u'dnszone.test'
dnsres1 = u'testdnsres'

class test_dns(Declarative):

    def setUp(self):
        super(test_dns, self).setUp()
        try:
           api.Command['dnszone_add'](dnszone1,
               idnssoamname = u'ns1.%s' % dnszone1,
               idnssoarname = u'root.%s' % dnszone1,
           )
           api.Command['dnszone_del'](dnszone1)
        except errors.NotFound:
            raise nose.SkipTest('DNS is not configured')
        except errors.DuplicateEntry:
            pass

    cleanup_commands = [
        ('dnszone_del', [dnszone1], {}),
        ('dnsrecord_del', [dnszone1, dnsres1], {'del_all' : True}),
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
                }
            ),
            expected={
                'value': dnszone1,
                'summary': None,
                'result': {
                    'dn': u'idnsname=%s,cn=dns,%s' % (dnszone1, api.env.basedn),
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
                }
            ),
            expected=errors.DuplicateEntry(),
        ),


        dict(
            desc='Retrieve zone %r' % dnszone1,
            command=('dnszone_show', [dnszone1], {}),
            expected={
                'value': dnszone1,
                'summary': None,
                'result': {
                    'dn': u'idnsname=%s,cn=dns,%s' % (dnszone1, api.env.basedn),
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
            desc='Search for zones with name server %r' % (u'ns1.%s.' % dnszone1),
            command=('dnszone_find', [], {'idnssoamname': u'ns1.%s.' % dnszone1}),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [{
                    'dn': u'idnsname=%s,cn=dns,%s' % (dnszone1, api.env.basedn),
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
                    'dn': u'idnsname=%s,cn=dns,%s' % (dnszone1, api.env.basedn),
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
                    'dn': u'idnsname=%s,cn=dns,%s' % (dnszone1, api.env.basedn),
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
                    'dn': u'idnsname=%s,idnsname=%s,cn=dns,%s' % (dnsres1, dnszone1, api.env.basedn),
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
                'count': 2,
                'truncated': False,
                'result': [
                    {
                        'dn': u'idnsname=%s,cn=dns,%s' % (dnszone1, api.env.basedn),
                        'nsrecord': (u'ns1.dnszone.test.',),
                        'idnsname': [u'@'],
                    },
                    {
                        'dn': u'idnsname=%s,idnsname=%s,cn=dns,%s' % (dnsres1, dnszone1, api.env.basedn),
                        'idnsname': [dnsres1],
                        'arecord': [u'127.0.0.1'],
                    },
                ],
            },
        ),


        dict(
            desc='Add A record to %r in zone %r' % (dnszone1, dnsres1),
            command=('dnsrecord_add', [dnszone1, dnsres1], {'arecord': u'10.10.0.1'}),
            expected={
                'value': dnsres1,
                'summary': None,
                'result': {
                    'dn': u'idnsname=%s,idnsname=%s,cn=dns,%s' % (dnsres1, dnszone1, api.env.basedn),
                    'idnsname': [dnsres1],
                    'arecord': [u'127.0.0.1', u'10.10.0.1'],
                    'objectclass': [u'top', u'idnsrecord'],
                },
            },
        ),


        dict(
            desc='Remove A record from %r in zone %r' % (dnszone1, dnsres1),
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

