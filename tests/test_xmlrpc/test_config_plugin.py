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

    ]
