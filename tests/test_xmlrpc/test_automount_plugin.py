# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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
Test the `ipalib/plugins/f_automount' module.
"""

import sys
from xmlrpc_test import XMLRPC_test
from ipalib import api
from ipalib import errors


class test_Service(XMLRPC_test):
    """
    Test the `f_automount` plugin.
    """
    mapname='testmap'
    keyname='testkey'
    keyname2='secondkey'
    description='description of map'
    info='ro'
    map_kw={'automountmapname': mapname, 'description': description}
    key_kw={'automountmapname': mapname, 'automountkey': keyname, 'automountinformation': info}
    key_kw2={'automountmapname': mapname, 'automountkey': keyname2, 'automountinformation': info}

    def test_add_1map(self):
        """
        Test adding a map `xmlrpc.automount_addmap` method.
        """
        res = api.Command['automount_addmap'](**self.map_kw)
        assert res
        assert res.get('automountmapname','') == self.mapname

    def test_add_2key(self):
        """
        Test adding a key using `xmlrpc.automount_addkey` method.
        """
        res = api.Command['automount_addkey'](**self.key_kw2)
        assert res
        assert res.get('automountkey','') == self.keyname2

    def test_add_3key(self):
        """
        Test adding a key using `xmlrpc.automount_addkey` method.
        """
        res = api.Command['automount_addkey'](**self.key_kw)
        assert res
        assert res.get('automountkey','') == self.keyname

    def test_add_4key(self):
        """
        Test adding a duplicate key using `xmlrpc.automount_addkey` method.
        """
        try:
            res = api.Command['automount_addkey'](**self.key_kw)
        except errors.DuplicateEntry:
            pass
        else:
            assert False

    def test_doshowmap(self):
        """
        Test the `xmlrpc.automount_showmap` method.
        """
        res = api.Command['automount_showmap'](self.mapname)
        assert res
        assert res.get('automountmapname','') == self.mapname

    def test_findmap(self):
        """
        Test the `xmlrpc.automount_findmap` method.
        """
        res = api.Command['automount_findmap'](self.mapname)
        assert res
        assert len(res) == 2
        assert res[1].get('automountmapname','') == self.mapname

    def test_doshowkey(self):
        """
        Test the `xmlrpc.automount_showkey` method.
        """
        showkey_kw={'automountmapname': self.mapname, 'automountkey': self.keyname}
        res = api.Command['automount_showkey'](**showkey_kw)
        assert res
        assert res.get('automountkey','') == self.keyname
        assert res.get('automountinformation','') == self.info

    def test_findkey(self):
        """
        Test the `xmlrpc.automount_findkey` method.
        """
        res = api.Command['automount_findkey'](self.keyname)
        assert res
        assert len(res) == 2
        assert res[1].get('automountkey','') == self.keyname
        assert res[1].get('automountinformation','') == self.info

    def test_modkey(self):
        """
        Test the `xmlrpc.automount_modkey` method.
        """
        self.key_kw['automountinformation'] = 'rw'
        self.key_kw['description'] = 'new description'
        res = api.Command['automount_modkey'](**self.key_kw)
        assert res
        assert res.get('automountkey','') == self.keyname
        assert res.get('automountinformation','') == 'rw'
        assert res.get('description','') == 'new description'

    def test_modmap(self):
        """
        Test the `xmlrpc.automount_modmap` method.
        """
        self.map_kw['description'] = 'new description'
        res = api.Command['automount_modmap'](**self.map_kw)
        assert res
        assert res.get('automountmapname','') == self.mapname
        assert res.get('description','') == 'new description'

    def test_remove1key(self):
        """
        Test the `xmlrpc.automount_delkey` method.
        """
        delkey_kw={'automountmapname': self.mapname, 'automountkey': self.keyname}
        res = api.Command['automount_delkey'](**delkey_kw)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['automount_showkey'](**delkey_kw)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_remove2map(self):
        """
        Test the `xmlrpc.automount_delmap` method.
        """
        res = api.Command['automount_delmap'](self.mapname)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['automount_showmap'](self.mapname)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_remove3map(self):
        """
        Test that the `xmlrpc.automount_delmap` method removes all keys
        """
        # Verify that the second key we added is gone
        key_kw={'automountmapname': self.mapname, 'automountkey': self.keyname2}
        try:
            res = api.Command['automount_showkey'](**key_kw)
        except errors.NotFound:
            pass
        else:
            assert False

class test_Indirect(XMLRPC_test):
    """
    Test the `f_automount` plugin Indirect map function.
    """
    mapname='auto.home'
    keyname='/home'
    parentmap='auto.master'
    description='Home directories'
    map_kw={'automountkey': keyname, 'parentmap': parentmap, 'description': description}

    def test_add_indirect(self):
        """
        Test adding an indirect map.
        """
        res = api.Command['automount_addindirectmap'](self.mapname, **self.map_kw)
        assert res
        assert res.get('automountinformation','') == self.mapname

    def test_doshowkey(self):
        """
        Test the `xmlrpc.automount_showkey` method.
        """
        showkey_kw={'automountmapname': self.parentmap, 'automountkey': self.keyname}
        res = api.Command['automount_showkey'](**showkey_kw)
        assert res
        assert res.get('automountkey','') == self.keyname

    def test_remove_key(self):
        """
        Remove the indirect key /home
        """
        delkey_kw={'automountmapname': self.parentmap, 'automountkey': self.keyname}
        res = api.Command['automount_delkey'](**delkey_kw)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['automount_showkey'](**delkey_kw)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_remove_map(self):
        """
        Remove the indirect map for auto.home
        """
        res = api.Command['automount_delmap'](self.mapname)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['automount_showmap'](self.mapname)
        except errors.NotFound:
            pass
        else:
            assert False
