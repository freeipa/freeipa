# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
Test the `ipalib/plugins/automount.py' module.
"""

import sys
from xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipalib import api
from ipalib import errors


class test_automount(XMLRPC_test):
    """
    Test the `automount` plugin.
    """
    locname = u'testlocation'
    mapname = u'testmap'
    keyname = u'testkey'
    keyname2 = u'testkey2'
    description = u'description of map'
    info = u'ro'
    map_kw = {'automountmapname': mapname, 'description': description, 'raw': True}
    key_kw = {'automountkey': keyname, 'automountinformation': info, 'raw': True}
    key_kw2 = {'automountkey': keyname2, 'automountinformation': info, 'raw': True}

    def test_0_automountlocation_add(self):
        """
        Test adding a location `xmlrpc.automountlocation_add` method.
        """
        ret = self.failsafe_add(
            api.Object.automountlocation, self.locname
        )
        entry = ret['result']
        assert_attr_equal(entry, 'cn', self.locname)

    def test_1_automountmap_add(self):
        """
        Test adding a map `xmlrpc.automountmap_add` method.
        """
        res = api.Command['automountmap_add'](self.locname, **self.map_kw)['result']
        assert res
        assert_attr_equal(res, 'automountmapname', self.mapname)

    def test_2_automountkey_add(self):
        """
        Test adding a key using `xmlrpc.automountkey_add` method.
        """
        res = api.Command['automountkey_add'](self.locname, self.mapname, **self.key_kw2)['result']
        assert res
        assert_attr_equal(res, 'automountkey', self.keyname2)

    def test_3_automountkey_add(self):
        """
        Test adding a key using `xmlrpc.automountkey_add` method.
        """
        res = api.Command['automountkey_add'](self.locname, self.mapname, **self.key_kw)['result']
        assert res
        assert_attr_equal(res, 'automountkey', self.keyname)

    def test_4_automountkey_add(self):
        """
        Test adding a duplicate key using `xmlrpc.automountkey_add` method.
        """
        try:
            api.Command['automountkey_add'](self.locname, self.mapname, **self.key_kw)
        except errors.DuplicateEntry:
            pass
        else:
            assert False

    def test_5_automountmap_show(self):
        """
        Test the `xmlrpc.automountmap_show` method.
        """
        res = api.Command['automountmap_show'](self.locname, self.mapname, raw=True)['result']
        assert res
        assert_attr_equal(res, 'automountmapname', self.mapname)

    def test_6_automountmap_find(self):
        """
        Test the `xmlrpc.automountmap_find` method.
        """
        res = api.Command['automountmap_find'](self.locname, self.mapname, raw=True)['result']
        assert_attr_equal(res[0], 'automountmapname', self.mapname)

    def test_7_automountkey_show(self):
        """
        Test the `xmlrpc.automountkey_show` method.
        """
        showkey_kw={'automountkey': self.keyname, 'raw': True}
        res = api.Command['automountkey_show'](self.locname, self.mapname, **showkey_kw)['result']
        assert res
        assert_attr_equal(res, 'automountkey', self.keyname)
        assert_attr_equal(res, 'automountinformation', self.info)

    def test_8_automountkey_find(self):
        """
        Test the `xmlrpc.automountkey_find` method.
        """
        res = api.Command['automountkey_find'](self.locname, self.mapname, raw=True)['result']
        assert res
        assert len(res) == 2
        assert_attr_equal(res[1], 'automountkey', self.keyname)
        assert_attr_equal(res[1], 'automountinformation', self.info)

    def test_9_automountkey_mod(self):
        """
        Test the `xmlrpc.automountkey_mod` method.
        """
        self.key_kw['automountinformation'] = u'rw'
        self.key_kw['description'] = u'new description'
        res = api.Command['automountkey_mod'](self.locname, self.mapname, **self.key_kw)['result']
        assert res
        assert_attr_equal(res, 'automountinformation', 'rw')
        assert_attr_equal(res, 'description', 'new description')

    def test_a_automountmap_mod(self):
        """
        Test the `xmlrpc.automountmap_mod` method.
        """
        mod_kw = {'description': u'new description'}
        res = api.Command['automountmap_mod'](self.locname, self.mapname, **mod_kw)['result']
        assert res
        assert_attr_equal(res, 'description', 'new description')

    def test_b_automountkey_del(self):
        """
        Test the `xmlrpc.automountkey_del` method.
        """
        delkey_kw={'automountkey': self.keyname, 'raw': True}
        res = api.Command['automountkey_del'](self.locname, self.mapname, **delkey_kw)['result']
        assert res == True

        # Verify that it is gone
        try:
            api.Command['automountkey_show'](self.locname, self.mapname, **delkey_kw)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_c_automountlocation_del(self):
        """
        Test the `xmlrpc.automountlocation_del` method.
        """
        res = api.Command['automountlocation_del'](self.locname)['result']
        assert res == True

        # Verify that it is gone
        try:
            api.Command['automountlocation_show'](self.locname)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_d_automountmap_del(self):
        """
        Test that the `xmlrpc.automountlocation_del` method removes all maps and keys
        """
        # Verify that the second key we added is gone
        key_kw = {'automountkey': self.keyname2, 'raw': True}
        try:
            api.Command['automountkey_show'](self.locname, self.mapname, **key_kw)
        except errors.NotFound:
            pass
        else:
            assert False


class test_automount_indirect(XMLRPC_test):
    """
    Test the `automount` plugin indirect map functionality.
    """
    locname = u'testlocation'
    mapname = u'auto.home'
    keyname = u'/home'
    parentmap = u'auto.master'
    description = u'Home directories'
    map_kw = {'key': keyname, 'parentmap': parentmap, 'description': description, 'raw': True}

    def test_0_automountlocation_add(self):
        """
        Test adding a location.
        """
        res = api.Command['automountlocation_add'](self.locname, raw=True)['result']
        assert res
        assert_attr_equal(res, 'cn', self.locname)

    def test_1_automountmap_add_indirect(self):
        """
        Test adding an indirect map.
        """
        res = api.Command['automountmap_add_indirect'](self.locname, self.mapname, **self.map_kw)['result']
        assert res
        assert_attr_equal(res, 'automountmapname', self.mapname)

    def test_2_automountmap_show(self):
        """
        Test the `xmlrpc.automountmap_show` method.
        """
        res = api.Command['automountkey_show'](self.locname, self.parentmap, self.keyname, raw=True)['result']
        assert res
        assert_attr_equal(res, 'automountkey', self.keyname)

    def test_3_automountkey_del(self):
        """
        Remove the indirect key /home.
        """
        delkey_kw = {'automountkey': self.keyname}
        res = api.Command['automountkey_del'](self.locname, self.parentmap, **delkey_kw)['result']
        assert res == True

        # Verify that it is gone
        try:
            api.Command['automountkey_show'](self.locname, self.parentmap, **delkey_kw)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_4_automountmap_del(self):
        """
        Remove the indirect map for auto.home.
        """
        res = api.Command['automountmap_del'](self.locname, self.mapname)['result']
        assert res == True

        # Verify that it is gone
        try:
            api.Command['automountmap_show'](self.locname, self.mapname)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_5_automountlocation_del(self):
        """
        Remove the location.
        """
        res = api.Command['automountlocation_del'](self.locname)['result']
        assert res == True

        # Verity that it is gone
        try:
            api.Command['automountlocation_show'](self.locname)
        except errors.NotFound:
            pass
        else:
            assert False


class test_automount_indirect_no_parent(XMLRPC_test):
    """
    Test the `automount` plugin Indirect map function.
    """
    locname = u'testlocation'
    mapname = u'auto.home'
    keyname = u'/home'
    parentmap = u'auto.master'
    description = u'Home directories'
    map_kw = {'key': keyname, 'description': description, 'raw': True}

    def test_0_automountlocation_add(self):
        """
        Test adding a location.
        """
        res = api.Command['automountlocation_add'](self.locname, raw=True)['result']
        assert res
        assert_attr_equal(res, 'cn', self.locname)

    def test_1_automountmap_add_indirect(self):
        """
        Test adding an indirect map with default parent.
        """
        res = api.Command['automountmap_add_indirect'](self.locname, self.mapname, **self.map_kw)['result']
        assert res
        assert_attr_equal(res, 'automountmapname', self.mapname)

    def test_2_automountkey_show(self):
        """
        Test the `xmlrpc.automountkey_show` method with default parent.
        """
        showkey_kw = {'automountkey': self.keyname, 'raw': True}
        res = api.Command['automountkey_show'](self.locname, self.parentmap, **showkey_kw)['result']
        assert res
        assert_attr_equal(res, 'automountkey', self.keyname)

    def test_3_automountkey_del(self):
        """
        Remove the indirect key /home.
        """
        delkey_kw={'automountkey': self.keyname}
        res = api.Command['automountkey_del'](self.locname, self.parentmap, **delkey_kw)['result']
        assert res == True

        # Verify that it is gone
        try:
            api.Command['automountkey_show'](self.locname, self.parentmap, **delkey_kw)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_4_automountmap_del(self):
        """
        Remove the indirect map for auto.home.
        """
        res = api.Command['automountmap_del'](self.locname, self.mapname)['result']
        assert res == True

        # Verify that it is gone
        try:
            api.Command['automountmap_show'](self.locname, self.mapname)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_5_automountlocation_del(self):
        """
        Remove the location.
        """
        res = api.Command['automountlocation_del'](self.locname)['result']
        assert res == True

        # Verity that it is gone
        try:
            api.Command['automountlocation_show'](self.locname)
        except errors.NotFound:
            pass
        else:
            assert False
