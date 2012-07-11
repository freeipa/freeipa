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
Test the `ipalib/plugins/range.py` module, and XML-RPC in general.
"""

from ipalib import api, errors, _
from tests.util import assert_equal, Fuzzy
from xmlrpc_test import Declarative
from ipalib.dn import *

testrange1 = u't-range-1'

class test_range(Declarative):
    cleanup_commands = [
        ('range_del', [testrange1], {}),
    ]

    tests = [
        dict(
            desc='Create range %r' % (testrange1),
            command=('range_add', [testrange1],
                      dict(ipabaseid=900000, ipaidrangesize=99999,
                           ipabaserid=1000, ipasecondarybaserid=20000)),
            expected=dict(
                result=dict(
                    dn=lambda x: DN(x) == \
                        DN(('cn',testrange1),('cn','ranges'),('cn','etc'),
                           api.env.basedn),
                    cn=[testrange1],
                    objectclass=[u'ipaIDrange', u'ipadomainidrange'],
                    ipabaseid=[u'900000'],
                    ipabaserid=[u'1000'],
                    ipasecondarybaserid=[u'20000'],
                    ipaidrangesize=[u'99999'],
                    iparangetype=[u'local domain range'],
                ),
                value=testrange1,
                summary=u'Added ID range "%s"' % (testrange1),
            ),
        ),

        dict(
            desc='Retrieve range %r' % (testrange1),
            command=('range_show', [testrange1], dict()),
            expected=dict(
                result=dict(
                    dn=lambda x: DN(x) == \
                        DN(('cn',testrange1),('cn','ranges'),('cn','etc'),
                           api.env.basedn),
                    cn=[testrange1],
                    ipabaseid=[u'900000'],
                    ipabaserid=[u'1000'],
                    ipasecondarybaserid=[u'20000'],
                    ipaidrangesize=[u'99999'],
                    iparangetype=[u'local domain range'],
                ),
                value=testrange1,
                summary=None,
            ),
        ),


        dict(
            desc='Modify range %r' % (testrange1),
            command=('range_mod', [testrange1], dict(ipaidrangesize=90000)),
            expected=dict(
                result=dict(
                    cn=[testrange1],
                    ipabaseid=[u'900000'],
                    ipabaserid=[u'1000'],
                    ipasecondarybaserid=[u'20000'],
                    ipaidrangesize=[u'90000'],
                    iparangetype=[u'local domain range'],
                ),
                value=testrange1,
                summary=u'Modified ID range "%s"' % (testrange1),
            ),
        ),

    ]
