# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#   Lenka Doudova <ldoudova@redhat.com>
#
# Copyright (C) 2010, 2016  Red Hat
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
Test the `ipaserver/plugins/config.py` module.
"""

from ipalib import api, errors
from ipatests.test_xmlrpc.xmlrpc_test import Declarative
import pytest

domain = api.env.domain
sl_domain = 'singlelabeldomain'

@pytest.mark.tier1
class test_config(Declarative):

    cleanup_commands = [
    ]

    tests = [

        dict(
            desc='Try to add an unrelated objectclass to ipauserobjectclasses',
            command=('config_mod', [],
                dict(addattr=u'ipauserobjectclasses=ipahost')),
            expected=dict(
                    result=lambda d: 'ipahost' in d['ipauserobjectclasses'],
                    value=None,
                    summary=None,
                ),
        ),

        dict(
            desc='Remove the unrelated objectclass from ipauserobjectclasses',
            command=('config_mod', [],
                dict(delattr=u'ipauserobjectclasses=ipahost')),
            expected=dict(
                    result=lambda d: 'ipahost' not in d['ipauserobjectclasses'],
                    value=None,
                    summary=None,
                ),
        ),

        dict(
            desc='Try to remove ipausersearchfields',
            command=('config_mod', [],
                dict(delattr=u'ipausersearchfields=uid,givenname,sn,telephonenumber,ou,title')),
            expected=errors.RequirementError(name='usersearch'),
        ),

        dict(
            desc='Add uppercased attribute to ipausersearchfields',
            command=('config_mod', [], dict(
                ipausersearchfields=
                u'uid,givenname,sn,telephonenumber,ou,title,Description')
            ),
            expected=dict(
                result=lambda d: (
                    d['ipausersearchfields'] ==
                    (u'uid,givenname,sn,telephonenumber,ou,title,description',)
                ),
                value=None,
                summary=None,
                ),
        ),

        dict(
            desc='Remove uppercased attribute from ipausersearchfields',
            command=('config_mod', [], dict(
                     ipausersearchfields=
                     u'uid,givenname,sn,telephonenumber,ou,title',)),
            expected=dict(
                result=lambda d: (
                    d['ipausersearchfields'] ==
                    (u'uid,givenname,sn,telephonenumber,ou,title',)
                ),
                value=None,
                summary=None,
                ),
        ),

        dict(
            desc='Try to set ipaselinuxusermapdefault not in selinux order list',
            command=('config_mod', [],
                dict(ipaselinuxusermapdefault=u'unknown_u:s0')),
            expected=errors.ValidationError(name='ipaselinuxusermapdefault',
                error='SELinux user map default user not in order list'),
        ),

        dict(
            desc='Try to set invalid ipaselinuxusermapdefault',
            command=('config_mod', [],
                dict(ipaselinuxusermapdefault=u'foo')),
            expected=errors.ValidationError(name='ipaselinuxusermapdefault',
                error='Invalid MLS value, must match s[0-15](-s[0-15])'),
        ),

        dict(
            desc='Try to set invalid ipaselinuxusermapdefault with setattr',
            command=('config_mod', [],
                dict(setattr=u'ipaselinuxusermapdefault=unknown_u:s0')),
            expected=errors.ValidationError(name='ipaselinuxusermapdefault',
                error='SELinux user map default user not in order list'),
        ),

        dict(
            desc='Try to set ipaselinuxusermaporder without ipaselinuxusermapdefault out of it',
            command=('config_mod', [],
                dict(ipaselinuxusermaporder=u'notfound_u:s0')),
            expected=errors.ValidationError(name='ipaselinuxusermaporder',
                error='SELinux user map default user not in order list'),
        ),

        dict(
            desc='Try to set invalid ipaselinuxusermaporder',
            command=('config_mod', [],
                dict(ipaselinuxusermaporder=u'$')),
            expected=errors.ValidationError(name='ipaselinuxusermaporder',
                error='A list of SELinux users delimited by $ expected'),
        ),

        dict(
            desc='Try to set invalid selinux user in ipaselinuxusermaporder',
            command=('config_mod', [],
                dict(ipaselinuxusermaporder=u'unconfined_u:s0-s0:c0.c1023$baduser$guest_u:s0')),
            expected=errors.ValidationError(name='ipaselinuxusermaporder',
                error='SELinux user \'baduser\' is not valid: Invalid MLS '
                      'value, must match s[0-15](-s[0-15])'),
        ),

        dict(
            desc='Try to set new selinux order and invalid default user',
            command=(
                'config_mod', [],
                dict(
                    ipaselinuxusermaporder=u'xguest_u:s0$guest_u:s0'
                    u'$user_u:s0-s0:c0.c1023$staff_u:s0-s0:c0.c1023'
                    u'$sysadm_u:s0-s0:c0.c1023$unconfined_u:s0-s0:c0.c1023',
                    ipaselinuxusermapdefault=u'unknown_u:s0')),
            expected=errors.ValidationError(name='ipaselinuxusermapdefault',
                error='SELinux user map default user not in order list'),
        ),

        dict(
            desc='Set user auth type',
            command=('config_mod', [], dict(ipauserauthtype=u'password')),
            expected=dict(
                    result=lambda d: d['ipauserauthtype'] == (u'password',),
                    value=None,
                    summary=None,
                ),
        ),

        dict(
            desc='Check user auth type',
            command=('config_show', [], {}),
            expected=dict(
                    result=lambda d: d['ipauserauthtype'] == (u'password',),
                    value=None,
                    summary=None,
                ),
        ),

        dict(
            desc='Unset user auth type',
            command=('config_mod', [], dict(ipauserauthtype=None)),
            expected=dict(
                    result=lambda d: 'ipauserauthtype' not in d,
                    value=None,
                    summary=None,
                ),
        ),

        dict(
            desc='Set maximum username length higher than limit of 255',
            command=('config_mod', [], dict(ipamaxusernamelength=256)),
            expected=errors.ValidationError(
                name='maxusername',
                error='can be at most 255'),
        ),

        dict(
            desc='Set maximum username length equal to limit 255',
            command=('config_mod', [], dict(ipamaxusernamelength=255)),
            expected=dict(
                result=lambda d: d['ipamaxusernamelength'] == (u'255',),
                value=None,
                summary=None,
                ),
        ),

        # Cleanup after previous test - returns max username length to 32
        dict(
            desc='Return maximum username length to default value',
            command=('config_mod', [], dict(ipamaxusernamelength=32)),
            expected=dict(
                result=lambda d: d['ipamaxusernamelength'] == (u'32',),
                value=None,
                summary=None,
                ),
        ),
        dict(
            desc='Check if domain resolution order does not accept SLD',
            command=(
                'config_mod', [], {
                    'ipadomainresolutionorder': u'{domain}:{sl_domain}'.format(
                        domain=domain, sl_domain=sl_domain)}),
            expected=errors.ValidationError(
                name=u'ipadomainresolutionorder',
                error=(
                    u"Invalid domain name '{}': "
                    "single label domains are not supported").format(
                        sl_domain),
            ),
        ),
        dict(
            desc='Set the number of search records to -1 (unlimited)',
            command=(
                'config_mod', [], {
                    'ipasearchrecordslimit': u'-1',
                },
            ),
            expected={
                'result': lambda d: d['ipasearchrecordslimit'] == (u'-1',),
                'summary': None,
                'value': None,
            },
        ),
        dict(
            desc='Set the number of search records to greater than 10',
            command=(
                'config_mod', [], {
                    'ipasearchrecordslimit': u'100',
                },
            ),
            expected={
                'result': lambda d: d['ipasearchrecordslimit'] == (u'100',),
                'summary': None,
                'value': None,
            },
        ),
        dict(
            desc='Set the number of search records to lower than -1',
            command=(
                'config_mod', [], {
                    'ipasearchrecordslimit': u'-10',
                },
            ),
            expected=errors.ValidationError(
                name=u'searchrecordslimit',
                error=u'must be at least 10',
            ),
        ),
        dict(
            desc='Set the number of search records to lower than 10',
            command=(
                'config_mod', [], {
                    'ipasearchrecordslimit': u'1',
                },
            ),
            expected=errors.ValidationError(
                name=u'searchrecordslimit',
                error=u'must be at least 10',
            ),
        ),
        dict(
            desc='Set the number of search records to zero (unlimited)',
            command=(
                'config_mod', [], {
                    'ipasearchrecordslimit': u'0',
                },
            ),
            expected={
                'result': lambda d: d['ipasearchrecordslimit'] == (u'-1',),
                'summary': None,
                'value': None,
            },
        ),
        dict(
            desc='Set the number of search records back to 100',
            command=(
                'config_mod', [], {
                    'ipasearchrecordslimit': u'100',
                },
            ),
            expected={
                'result': lambda d: d['ipasearchrecordslimit'] == (u'100',),
                'summary': None,
                'value': None,
            },
        ),
    ]
