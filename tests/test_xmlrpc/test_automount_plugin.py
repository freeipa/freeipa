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
    mapname = u'testmap'
    keyname = u'testkey'
    keyname2 = u'testkey2'
    description = u'description of map'
    info = u'ro'
    map_kw = {'automountmapname': mapname, 'description': description}
    key_kw = {'automountmapname': mapname, 'automountkey': keyname, 'automountinformation': info}
    key_kw2 = {'automountmapname': mapname, 'automountkey': keyname2, 'automountinformation': info}

    def test_1_automountmap_add(self):
        """
        Test adding a map `xmlrpc.automountmap_add` method.
        """
        (dn, res) = api.Command['automountmap_add'](**self.map_kw)
        assert res
        assert_attr_equal(res, 'automountmapname', self.mapname)

    def test_2_automountkey_add(self):
        """
        Test adding a key using `xmlrpc.automountkey_add` method.
        """
        (dn, res) = api.Command['automountkey_add'](**self.key_kw2)
        assert res
        assert_attr_equal(res, 'automountkey', self.keyname2)

    def test_3_automountkey_add(self):
        """
        Test adding a key using `xmlrpc.automountkey_add` method.
        """
        (dn, res) = api.Command['automountkey_add'](**self.key_kw)
        assert res
        assert_attr_equal(res, 'automountkey', self.keyname)

    def test_4_automountkey_add(self):
        """
        Test adding a duplicate key using `xmlrpc.automountkey_add` method.
        """
        try:
            api.Command['automountkey_add'](**self.key_kw)
        except errors.DuplicateEntry:
            pass
        else:
            assert False

    def test_5_automountmap_show(self):
        """
        Test the `xmlrpc.automountmap_show` method.
        """
        (dn, res) = api.Command['automountmap_show'](self.mapname)
        assert res
        assert_attr_equal(res, 'automountmapname', self.mapname)

    def test_6_automountmap_find(self):
        """
        Test the `xmlrpc.automountmap_find` method.
        """
        (res, truncated) = api.Command['automountmap_find'](self.mapname)
        assert res
        assert_attr_equal(res[0][1], 'automountmapname', self.mapname)

    def test_7_automountkey_show(self):
        """
        Test the `xmlrpc.automountkey_show` method.
        """
        showkey_kw={'automountmapname': self.mapname, 'automountkey': self.keyname}
        (dn, res) = api.Command['automountkey_show'](**showkey_kw)
        assert res
        assert_attr_equal(res, 'automountkey', self.keyname)
        assert_attr_equal(res, 'automountinformation', self.info)

    def test_8_automountkey_find(self):
        """
        Test the `xmlrpc.automountkey_find` method.
        """
        (res, truncated) = api.Command['automountkey_find'](self.mapname)
        assert res
        assert len(res) == 2
        assert_attr_equal(res[1][1], 'automountkey', self.keyname)
        assert_attr_equal(res[1][1], 'automountinformation', self.info)

    def test_9_automountkey_mod(self):
        """
        Test the `xmlrpc.automountkey_mod` method.
        """
        self.key_kw['automountinformation'] = u'rw'
        self.key_kw['description'] = u'new description'
        (dn, res) = api.Command['automountkey_mod'](**self.key_kw)
        assert res
        assert_attr_equal(res, 'automountinformation', 'rw')
        assert_attr_equal(res, 'description', 'new description')

    def test_a_automountmap_mod(self):
        """
        Test the `xmlrpc.automountmap_mod` method.
        """
        self.map_kw['description'] = u'new description'
        (dn, res) = api.Command['automountmap_mod'](**self.map_kw)
        assert res
        assert_attr_equal(res, 'description', 'new description')

    def test_b_automountkey_del(self):
        """
        Test the `xmlrpc.automountkey_del` method.
        """
        delkey_kw={'automountmapname': self.mapname, 'automountkey': self.keyname}
        res = api.Command['automountkey_del'](**delkey_kw)
        assert res == True

        # Verify that it is gone
        try:
            api.Command['automountkey_show'](**delkey_kw)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_c_automountmap_del(self):
        """
        Test the `xmlrpc.automountmap_del` method.
        """
        res = api.Command['automountmap_del'](self.mapname)
        assert res == True

        # Verify that it is gone
        try:
            api.Command['automountmap_show'](self.mapname)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_d_automountmap_del(self):
        """
        Test that the `xmlrpc.automountmap_del` method removes all keys
        """
        # Verify that the second key we added is gone
        key_kw = {'automountmapname': self.mapname, 'automountkey': self.keyname2}
        try:
            api.Command['automountkey_show'](**key_kw)
        except errors.NotFound:
            pass
        else:
            assert False


class test_automount_indirect(XMLRPC_test):
    """
    Test the `automount` plugin indirect map functionality.
    """
    mapname = u'auto.home'
    keyname = u'/home'
    parentmap = u'auto.master'
    description = u'Home directories'
    map_kw = {'key': keyname, 'parentmap': parentmap, 'description': description}

    def test_1_automountmap_add_indirect(self):
        """
        Test adding an indirect map.
        """
        (dn, res) = api.Command['automountmap_add_indirect'](self.mapname, **self.map_kw)
        assert res
        assert_attr_equal(res, 'automountinformation', self.mapname)

    def test_2_automountmap_show(self):
        """
        Test the `xmlrpc.automountmap_show` method.
        """
        showkey_kw = {'automountmapname': self.parentmap, 'automountkey': self.keyname}
        (dn, res) = api.Command['automountkey_show'](**showkey_kw)
        assert res
        assert_attr_equal(res, 'automountkey', self.keyname)

    def test_3_automountkey_del(self):
        """
        Remove the indirect key /home.
        """
        delkey_kw = {'automountmapname': self.parentmap, 'automountkey': self.keyname}
        res = api.Command['automountkey_del'](**delkey_kw)
        assert res == True

        # Verify that it is gone
        try:
            api.Command['automountkey_show'](**delkey_kw)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_4_automountmap_del(self):
        """
        Remove the indirect map for auto.home.
        """
        res = api.Command['automountmap_del'](self.mapname)
        assert res == True

        # Verify that it is gone
        try:
            api.Command['automountmap_show'](self.mapname)
        except errors.NotFound:
            pass
        else:
            assert False


class test_automount_indirect_no_parent(XMLRPC_test):
    """
    Test the `automount` plugin Indirect map function.
    """
    mapname = u'auto.home'
    keyname = u'/home'
    parentmap = u'auto.master'
    description = u'Home directories'
    map_kw = {'key': keyname, 'description': description}

    def test_1_automountmap_add_indirect(self):
        """
        Test adding an indirect map with default parent.
        """
        (dn, res) = api.Command['automountmap_add_indirect'](self.mapname, **self.map_kw)
        assert res
        assert_attr_equal(res, 'automountinformation', self.mapname)

    def test_2_automountkey_show(self):
        """
        Test the `xmlrpc.automountkey_show` method with default parent.
        """
        showkey_kw = {'automountmapname': self.parentmap, 'automountkey': self.keyname}
        (dn, res) = api.Command['automountkey_show'](**showkey_kw)
        assert res
        assert_attr_equal(res, 'automountkey', self.keyname)

    def test_3_automountkey_del(self):
        """
        Remove the indirect key /home.
        """
        delkey_kw={'automountmapname': self.parentmap, 'automountkey': self.keyname}
        res = api.Command['automountkey_del'](**delkey_kw)
        assert res == True

        # Verify that it is gone
        try:
            api.Command['automountkey_show'](**delkey_kw)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_4_automountmap_del(self):
        """
        Remove the indirect map for auto.home.
        """
        res = api.Command['automountmap_del'](self.mapname)
        assert res == True

        # Verify that it is gone
        try:
            api.Command['automountmap_show'](self.mapname)
        except errors.NotFound:
            pass
        else:
            assert False

