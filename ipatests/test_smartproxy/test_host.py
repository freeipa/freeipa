# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2014  Red Hat
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

from ipalib import api
from ipapython.dn import DN
from resttest import REST_test, fuzzy_uuid, fuzzy_password
from ipatests.test_xmlrpc import objectclasses
import requests

fqdn1 = u'testhost.example.com'
dn1 = DN(('fqdn',fqdn1),('cn','computers'),('cn','accounts'),
         api.env.basedn)
fqdn2 = u'testhost2.example.com'
dn2 = DN(('fqdn',fqdn2),('cn','computers'),('cn','accounts'),
         api.env.basedn)

class test_host(REST_test):

    cleanup = [
        ('/ipa/smartproxy/host/%s' % fqdn1, {}),
        ('/ipa/smartproxy/host/%s' % fqdn2, {}),
    ]

    tests = [

        dict(
            desc='Get a non-existent host',
            request=('/ipa/smartproxy/host/notfound', {}),
            method=requests.get,
            expected_status=404,
            expected={},
        ),

        dict(
            desc='Create a host',
            request=('/ipa/smartproxy/host', {'hostname': fqdn1,
                                              'description': 'test',
                                              'macaddress': '00:50:56:30:F6:5F'}),
            method=requests.post,
            expected_status=201,
            expected=dict(
                dn=dn1,
                has_keytab=False,
                objectclass=[u'ipasshhost', u'ipaSshGroupOfPubKeys',
                             u'ieee802device', u'ipaobject',
                             u'nshost', u'ipahost', u'pkiuser',
                             u'ipaservice', u'top',],
                description=[u'test'],
                macaddress=[u'00:50:56:30:F6:5F'],
                fqdn=[fqdn1],
                has_password=True,
                randompassword=fuzzy_password,
                ipauniqueid=[fuzzy_uuid],
                managedby_host=[fqdn1],
            ),
        ),

        dict(
            desc='Get the host',
            request=('/ipa/smartproxy/host/%s' % fqdn1, {}),
            method=requests.get,
            expected_status=200,
            expected=dict(
                dn=dn1,
                description=[u'test'],
                macaddress=[u'00:50:56:30:F6:5F'],
                has_keytab=False,
                fqdn=[u'testhost.example.com'],
                has_password=True,
                managedby_host=[fqdn1],
            ),
        ),

        # Note that this has the side-effect of confirming that description,
        # macaddress, etc. doesn't get wiped on update.
        dict(
            desc='Update the host',
            request=('/ipa/smartproxy/host/%s' % fqdn1, {'userclass': 'test'}),
            method=requests.post,
            expected_status=200,
            expected=dict(
                has_keytab=False,
                description=[u'test'],
                macaddress=[u'00:50:56:30:F6:5F'],
                fqdn=[u'testhost.example.com'],
                has_password=True,
                managedby_host=[fqdn1],
                randompassword=fuzzy_password,
                userclass=[u'test']

            ),
        ),

        dict(
            desc='Remove the host',
            request=('/ipa/smartproxy/host/%s' % fqdn1, {}),
            method=requests.delete,
            expected_status=200,
            expected=dict(failed=[]),
        ),

        dict(
            desc='Create a host with a fixed password',
            request=('/ipa/smartproxy/host', {'hostname': fqdn2, 'password': 'Secret123'}),
            method=requests.post,
            expected_status=201,
            expected=dict(
                dn=dn2,
                has_keytab=False,
                objectclass=[u'ipasshhost', u'ipaSshGroupOfPubKeys',
                             u'ieee802device', u'ipaobject',
                             u'nshost', u'ipahost', u'pkiuser',
                             u'ipaservice', u'top',],
                fqdn=[fqdn2],
                has_password=True,
                ipauniqueid=[fuzzy_uuid],
                managedby_host=[fqdn2],
            ),
        ),

        dict(
            desc='Remove a non-existent host',
            request=('/ipa/smartproxy/host/notfound', {}),
            method=requests.delete,
            expected_status=404,
            expected={},
        ),

    ]
