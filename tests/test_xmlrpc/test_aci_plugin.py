# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
"""
Test the `ipalib/plugins/aci.py` module.
"""

import sys
from xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipalib import api
from ipalib import errors


class test_aci(XMLRPC_test):
    """
    Test the `aci` plugin.
    """
    aciname = u'acitest'
    taskgroup = u'testtaskgroup'
    kw = {'permissions': u'add', 'type': u'user', 'taskgroup': taskgroup }
    aci = u'(target = "ldap:///uid=*,cn=users,cn=accounts,%s")(version 3.0;acl "acitest";allow (add) groupdn = "ldap:///cn=testtaskgroup,cn=taskgroups,cn=accounts,%s";)' % (api.env.basedn, api.env.basedn)

    def test_1_aci_add(self):
        """
        Test adding an aci using the `xmlrpc.aci_add` method.
        """
        result = api.Command['aci_add'](self.aciname, **self.kw)['result']

        assert result == self.aci

    def test_2_aci_show(self):
        """
        Test showing an aci using the `xmlrpc.aci_show` method.
        """
        result = api.Command['aci_show'](self.aciname)['result']

        assert result == self.aci

    def test_3_aci_find(self):
        """
        Test showing an aci using the `xmlrpc.aci_show` method.
        """
        outcome = api.Command['aci_find'](self.aciname)
        result = outcome['result']
        count = outcome['count']

        assert count == 1
        assert result[0] == self.aci

    def test_4_aci_del(self):
        """
        Remove the second test policy with `xmlrpc.aci_del`.
        """
        assert api.Command['aci_del'](self.aciname)['result'] is True

        # Verify that it is gone
        try:
            api.Command['aci_show'](self.aciname)
        except errors.NotFound:
            pass
        else:
            assert False
