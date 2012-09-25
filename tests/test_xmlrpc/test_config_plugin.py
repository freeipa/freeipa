# Authors:
#   Petr Viktorin <pviktori@redhat.com>
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
Test the `ipalib/plugins/config.py` module.
"""

from ipalib import errors
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid

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
                    value=u'',
                    summary=None,
                ),
        ),

        dict(
            desc='Remove the unrelated objectclass from ipauserobjectclasses',
            command=('config_mod', [],
                dict(delattr=u'ipauserobjectclasses=ipahost')),
            expected=dict(
                    result=lambda d: 'ipahost' not in d['ipauserobjectclasses'],
                    value=u'',
                    summary=None,
                ),
        ),

        dict(
            desc='Try to remove ipausersearchfields',
            command=('config_mod', [],
                dict(delattr=u'ipausersearchfields=uid,givenname,sn,telephonenumber,ou,title')),
            expected=errors.RequirementError(name='ipausersearchfields'),
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
            command=('config_mod', [],
                dict(ipaselinuxusermaporder=u'xguest_u:s0$guest_u:s0$user_u:s0-s0:c0.c1023$staff_u:s0-s0:c0.c1023$unconfined_u:s0-s0:c0.c1023',
                    ipaselinuxusermapdefault=u'unknown_u:s0')),
            expected=errors.ValidationError(name='ipaselinuxusermapdefault',
                error='SELinux user map default user not in order list'),
        ),

    ]
