# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
Test the `ipalib/plugins/hostgroup.py` module.
"""

import sys
from xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipalib import api
from ipalib import errors


class test_hostgroup(XMLRPC_test):
    """
    Test the `hostgroup` plugin.
    """
    cn = u'testgroup'
    description = u'Test host group'
    kw = {'cn': cn, 'description': description, 'raw': True}

    host_fqdn = u'ipatesthost.%s' % api.env.domain
    host_description = u'Test host'
    host_localityname = u'Undisclosed location'

    def test_1_hostgroup_add(self):
        """
        Test the `xmlrpc.hostgroup_add` method.
        """
        entry = api.Command['hostgroup_add'](**self.kw)['result']
        assert_attr_equal(entry, 'description', self.description)
        assert_attr_equal(entry, 'cn', self.cn)
        assert_attr_equal(entry, 'objectclass', 'ipaobject')

    def test_2_host_add(self):
        """
        Add a host to test add/remove member.
        """
        kw = {'fqdn': self.host_fqdn, 'description': self.host_description, 'localityname': self.host_localityname, 'raw': True}
        entry = api.Command['host_add'](**kw)['result']
        assert_attr_equal(entry, 'description', self.host_description)
        assert_attr_equal(entry, 'fqdn', self.host_fqdn)

    def test_3_hostgroup_add_member(self):
        """
        Test the `xmlrpc.hostgroup_add_member` method.
        """
        kw = {'raw': True}
        kw['host'] = self.host_fqdn
        ret = api.Command['hostgroup_add_member'](self.cn, **kw)
        assert ret['result']['member'] != []
        assert ret['completed'] == 1

    def test_4_hostgroup_show(self):
        """
        Test the `xmlrpc.hostgroup_show` method.
        """
        entry = api.Command['hostgroup_show'](self.cn, raw=True)['result']
        assert_attr_equal(entry, 'description', self.description)
        assert_attr_equal(entry, 'cn', self.cn)

    def test_5_hostgroup_find(self):
        """
        Test the `xmlrpc.hostgroup_find` method.
        """
        ret = api.Command['hostgroup_find'](cn=self.cn, raw=True)
        assert ret['truncated'] is False
        entries = ret['result']
        assert_attr_equal(entries[0], 'description', self.description)
        assert_attr_equal(entries[0], 'cn', self.cn)

    def test_6_hostgroup_mod(self):
        """
        Test the `xmlrpc.hostgroup_mod` method.
        """
        newdesc = u'Updated host group'
        modkw = {'cn': self.cn, 'description': newdesc, 'raw': True}
        entry = api.Command['hostgroup_mod'](**modkw)['result']
        assert_attr_equal(entry, 'description', newdesc)

        # Ok, double-check that it was changed
        entry = api.Command['hostgroup_show'](self.cn, raw=True)['result']
        assert_attr_equal(entry, 'description', newdesc)
        assert_attr_equal(entry, 'cn', self.cn)

    def test_7_hostgroup_remove_member(self):
        """
        Test the `xmlrpc.hostgroup_remove_member` method.
        """
        kw = {'raw': True}
        kw['host'] = self.host_fqdn
        ret = api.Command['hostgroup_remove_member'](self.cn, **kw)
        assert ret['completed'] == 1

    def test_8_hostgroup_del(self):
        """
        Test the `xmlrpc.hostgroup_del` method.
        """
        assert api.Command['hostgroup_del'](self.cn)['result'] is True

        # Verify that it is gone
        try:
            api.Command['hostgroup_show'](self.cn)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_9_host_del(self):
        """
        Test the `xmlrpc.host_del` method.
        """
        assert api.Command['host_del'](self.host_fqdn)['result'] is True

        # Verify that it is gone
        try:
            api.Command['host_show'](self.host_fqdn)
        except errors.NotFound:
            pass
        else:
            assert False
