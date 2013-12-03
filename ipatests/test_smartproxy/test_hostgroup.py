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
from resttest import REST_test, fuzzy_uuid
from ipatests.test_xmlrpc import objectclasses
import requests

hostgroup1 = u'testhostgroup'
dn1 = DN(('cn', hostgroup1),('cn','hostgroups'),('cn','accounts'),
         api.env.basedn)

class test_hostgroup(REST_test):

    cleanup = [
        ('/ipa/smartproxy/hostgroup/%s' % hostgroup1, {}),
    ]

    tests = [

        dict(
            desc='Get a non-existent hostgroup',
            request=('/ipa/smartproxy/hostgroup/notfound', {}),
            method=requests.get,
            expected_status=404,
            expected={},
        ),

        dict(
            desc='Create a hostgroup',
            request=('/ipa/smartproxy/hostgroup', {'name': hostgroup1, 'description': u'test'}),
            method=requests.post,
            expected_status=201,
            expected=dict(
                dn=dn1,
                cn=[hostgroup1],
                objectclass=objectclasses.hostgroup,
                description=[u'test'],
                mepmanagedentry=[DN(('cn',hostgroup1),('cn','ng'),('cn','alt'),
                                        api.env.basedn)],
                ipauniqueid=[fuzzy_uuid],
            ),
        ),

        dict(
            desc='Get the hostgroup',
            request=('/ipa/smartproxy/hostgroup/%s' % hostgroup1, {}),
            method=requests.get,
            expected_status=200,
            expected=dict(
                dn=dn1,
                cn=[u'testhostgroup'],
                description=[u'test'],
            ),
        ),

        dict(
            desc='Add a duplicate hostgroup',
            request=('/ipa/smartproxy/hostgroup', {'name': hostgroup1, 'description': u'test'}),
            method=requests.post,
            expected_status=400,
            expected={},
        ),

        dict(
            desc='Remove the hostgroup',
            request=('/ipa/smartproxy/hostgroup/%s' % hostgroup1, {}),
            method=requests.delete,
            expected_status=200,
            expected=dict(failed=[]),
        ),

        dict(
            desc='Remove a non-existent hostgroup',
            request=('/ipa/smartproxy/hostgroup/%s' % hostgroup1, {}),
            method=requests.delete,
            expected_status=404,
            expected={},
        ),
    ]
