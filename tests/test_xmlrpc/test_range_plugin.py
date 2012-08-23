# Authors:
#    Alexander Bokovoy <abokovoy@redhat.com>
#
# Copyright (C) 2012  Red Hat
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
Test the `ipalib/plugins/idrange.py` module, and XML-RPC in general.
"""

from ipalib import api, errors, _
from tests.util import assert_equal, Fuzzy
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid
from tests.test_xmlrpc import objectclasses
from ipapython.dn import *

testrange1 = u't-range-1'
testrange1_base_id = 900000
testrange1_size = 99999

user1=u'tuser1'
user1_uid = 900000
group1=u'group1'
group1_gid = 900100

class test_range(Declarative):
    cleanup_commands = [
        ('idrange_del', [testrange1], {}),
        ('user_del', [user1], {}),
        ('group_del', [group1], {}),
    ]

    tests = [
        dict(
            desc='Create ID range %r' % (testrange1),
            command=('idrange_add', [testrange1],
                      dict(ipabaseid=testrange1_base_id, ipaidrangesize=testrange1_size,
                           ipabaserid=1000, ipasecondarybaserid=20000)),
            expected=dict(
                result=dict(
                    dn=DN(('cn',testrange1),('cn','ranges'),('cn','etc'),
                          api.env.basedn),
                    cn=[testrange1],
                    objectclass=[u'ipaIDrange', u'ipadomainidrange'],
                    ipabaseid=[unicode(testrange1_base_id)],
                    ipabaserid=[u'1000'],
                    ipasecondarybaserid=[u'20000'],
                    ipaidrangesize=[unicode(testrange1_size)],
                    iparangetype=[u'local domain range'],
                ),
                value=testrange1,
                summary=u'Added ID range "%s"' % (testrange1),
            ),
        ),

        dict(
            desc='Retrieve ID range %r' % (testrange1),
            command=('idrange_show', [testrange1], dict()),
            expected=dict(
                result=dict(
                    dn=DN(('cn',testrange1),('cn','ranges'),('cn','etc'),
                          api.env.basedn),
                    cn=[testrange1],
                    ipabaseid=[unicode(testrange1_base_id)],
                    ipabaserid=[u'1000'],
                    ipasecondarybaserid=[u'20000'],
                    ipaidrangesize=[unicode(testrange1_size)],
                    iparangetype=[u'local domain range'],
                ),
                value=testrange1,
                summary=None,
            ),
        ),


        dict(
            desc='Create user %r in ID range %r' % (user1, testrange1),
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1',
                                          uidnumber=user1_uid)
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=dict(
                    gecos=[u'Test User1'],
                    givenname=[u'Test'],
                    homedirectory=[u'/home/tuser1'],
                    krbprincipalname=[u'tuser1@' + api.env.realm],
                    loginshell=[u'/bin/sh'],
                    objectclass=objectclasses.user,
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[unicode(user1_uid)],
                    gidnumber=[unicode(user1_uid)],
                    displayname=[u'Test User1'],
                    cn=[u'Test User1'],
                    initials=[u'TU'],
                    mail=[u'%s@%s' % (user1, api.env.domain)],
                    ipauniqueid=[fuzzy_uuid],
                    krbpwdpolicyreference=[DN(('cn','global_policy'),('cn',api.env.realm),
                                              ('cn','kerberos'),api.env.basedn)],
                    mepmanagedentry=[DN(('cn',user1),('cn','groups'),('cn','accounts'),
                                        api.env.basedn)],
                    memberof_group=[u'ipausers'],
                    has_keytab=False,
                    has_password=False,
                    dn=DN(('uid',user1),('cn','users'),('cn','accounts'), api.env.basedn)
                ),
            ),
        ),


        dict(
            desc='Create group %r in ID range %r' % (group1, testrange1),
            command=(
                'group_add', [group1], dict(description=u'Test desc 1',
                                            gidnumber=group1_gid)
            ),
            expected=dict(
                value=group1,
                summary=u'Added group "%s"' % group1,
                result=dict(
                    cn=[group1],
                    description=[u'Test desc 1'],
                    gidnumber=[unicode(group1_gid)],
                    objectclass=objectclasses.group + [u'posixgroup'],
                    ipauniqueid=[fuzzy_uuid],
                    dn=DN(('cn',group1),('cn','groups'),('cn','accounts'), api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Try to modify ID range %r to get out bounds object #1' % (testrange1),
            command=('idrange_mod', [testrange1], dict(ipabaseid=90001)),
            expected=errors.ValidationError(name='ipabaseid,ipaidrangesize',
                error=u'range modification leaving objects with ID out of the'
                      u' defined range is not allowed'),
        ),


        dict(
            desc='Try to modify ID range %r to get out bounds object #2' % (testrange1),
            command=('idrange_mod', [testrange1], dict(ipaidrangesize=100)),
            expected=errors.ValidationError(name='ipabaseid,ipaidrangesize',
                error=u'range modification leaving objects with ID out of the'
                      u' defined range is not allowed'),
        ),


        dict(
            desc='Try to modify ID range %r to get out bounds object #3' % (testrange1),
            command=('idrange_mod', [testrange1], dict(ipabaseid=100, ipaidrangesize=100)),
            expected=errors.ValidationError(name='ipabaseid,ipaidrangesize',
                error=u'range modification leaving objects with ID out of the'
                      u' defined range is not allowed'),
        ),


        dict(
            desc='Modify ID range %r' % (testrange1),
            command=('idrange_mod', [testrange1], dict(ipaidrangesize=90000)),
            expected=dict(
                result=dict(
                    cn=[testrange1],
                    ipabaseid=[unicode(testrange1_base_id)],
                    ipabaserid=[u'1000'],
                    ipasecondarybaserid=[u'20000'],
                    ipaidrangesize=[u'90000'],
                    iparangetype=[u'local domain range'],
                ),
                value=testrange1,
                summary=u'Modified ID range "%s"' % (testrange1),
            ),
        ),


        dict(
            desc='Try to delete ID range %r with active IDs inside it' % testrange1,
            command=('idrange_del', [testrange1], {}),
            expected=errors.ValidationError(name='ipabaseid,ipaidrangesize',
                error=u'range modification leaving objects with ID out of the'
                      u' defined range is not allowed'),
        ),


        dict(
            desc='Delete user %r' % user1,
            command=('user_del', [user1], {}),
            expected=dict(
                result=dict(failed=u''),
                value=user1,
                summary=u'Deleted user "%s"' % user1,
            ),
        ),


        dict(
            desc='Delete group %r' % group1,
            command=('group_del', [group1], {}),
            expected=dict(
                result=dict(failed=u''),
                value=group1,
                summary=u'Deleted group "%s"' % group1,
            ),
        ),


        dict(
            desc='Delete ID range %r' % testrange1,
            command=('idrange_del', [testrange1], {}),
            expected=dict(
                result=dict(failed=u''),
                value=testrange1,
                summary=u'Deleted ID range "%s"' % testrange1,
            ),
        ),

    ]
