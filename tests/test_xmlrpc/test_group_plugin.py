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
Test the `ipalib/plugins/f_group` module.
"""

import sys
from xmlrpc_test import XMLRPC_test
from ipalib import api
from ipalib import errors


class test_Group(XMLRPC_test):
    """
    Test the `f_group` plugin.
    """
    cn = u'testgroup'
    cn2 = u'testgroup2'
    cnposix = u'posixgroup'
    description = u'This is a test'
    kw={'description':description,'cn':cn}

    def test_add(self):
        """
        Test the `xmlrpc.group_add` method: testgroup.
        """
        res = api.Command['group_add'](**self.kw)
        assert res
        assert res.get('description','') == self.description
        assert res.get('cn','') == self.cn

    def test_add2(self):
        """
        Test the `xmlrpc.group_add` method duplicate detection.
        """
        try:
            res = api.Command['group_add'](**self.kw)
        except errors.DuplicateEntry:
            pass

    def test_add3(self):
        """
        Test the `xmlrpc.group_add` method: testgroup2.
        """
        self.kw['cn'] = self.cn2
        res = api.Command['group_add'](**self.kw)
        assert res
        assert res.get('description','') == self.description
        assert res.get('cn','') == self.cn2

    def test_addposix(self):
        """
        Test the `xmlrpc.group_add` method: posixgroup
        """
        posixkw = {}
        posixkw['cn'] = self.cnposix
        posixkw['description'] = self.description
        posixkw['posix'] = True
        res = api.Command['group_add'](**posixkw)
        assert res
        assert res.get('description','') == self.description
        assert res.get('cn','') == self.cnposix

    def test_add_member(self):
        """
        Test the `xmlrpc.group_add_member` method.
        """
        kw={}
        kw['groups'] = self.cn2
        res = api.Command['group_add_member'](self.cn, **kw)
        assert res == tuple()

    def test_add_member2(self):
        """
        Test the `xmlrpc.group_add_member` with a non-existent member
        """
        kw={}
        kw['groups'] = u"notfound"
        res = api.Command['group_add_member'](self.cn, **kw)
        # an error isn't thrown, the list of failed members is returned
        assert res != []

    def test_doshow(self):
        """
        Test the `xmlrpc.group_show` method.
        """
        res = api.Command['group_show'](self.cn)
        assert res
        assert res.get('description','') == self.description
        assert res.get('cn','') == self.cn
        assert res.get('member','').startswith('cn=%s' % self.cn2)

    def test_doshowposix(self):
        """
        Test the `xmlrpc.group_show` method for a posix group.
        """
        res = api.Command['group_show'](self.cnposix)
        assert res
        assert res.get('description','') == self.description
        assert res.get('cn','') == self.cnposix
        assert res.get('gidnumber',None)

    def test_find(self):
        """
        Test the `xmlrpc.group_find` method.
        """
        res = api.Command['group_find'](self.cn)
        assert res
        assert len(res) == 3
        assert res[1].get('description','') == self.description
        assert res[1].get('cn','') == self.cn

    def test_mod(self):
        """
        Test the `xmlrpc.group_mod` method.
        """
        modkw = self.kw
        modkw['cn'] = self.cn
        modkw['description'] = u'New description'
        res = api.Command['group_mod'](**modkw)
        assert res
        assert res.get('description','') == 'New description'

        # Ok, double-check that it was changed
        res = api.Command['group_show'](self.cn)
        assert res
        assert res.get('description','') == 'New description'
        assert res.get('cn','') == self.cn

    def test_mod2(self):
        """
        Test the `xmlrpc.group_mod` method, promote a posix group
        """
        modkw = self.kw
        modkw['cn'] = self.cn
        modkw['posix'] = True
        res = api.Command['group_mod'](**modkw)
        assert res
        assert res.get('description','') == 'New description'
        assert res.get('gidnumber','')

        # Ok, double-check that it was changed
        res = api.Command['group_show'](self.cn)
        assert res
        assert res.get('description','') == 'New description'
        assert res.get('cn','') == self.cn
        assert res.get('gidnumber','')

    def test_remove_member(self):
        """
        Test the `xmlrpc.group_remove_member` method.
        """
        kw={}
        kw['groups'] = self.cn2
        res = api.Command['group_remove_member'](self.cn, **kw)

        res = api.Command['group_show'](self.cn)
        assert res
        assert res.get('member','') == ''

    def test_remove_member2(self):
        """
        Test the `xmlrpc.group_remove_member` method with non-member
        """
        kw={}
        kw['groups'] = u"notfound"
        # an error isn't thrown, the list of failed members is returned
        res = api.Command['group_remove_member'](self.cn, **kw)
        assert res != []

    def test_remove_x(self):
        """
        Test the `xmlrpc.group_del` method: testgroup.
        """
        res = api.Command['group_del'](self.cn)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['group_show'](self.cn)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_remove_x2(self):
        """
        Test the `xmlrpc.group_del` method: testgroup2.
        """
        res = api.Command['group_del'](self.cn2)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['group_show'](self.cn2)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_remove_x3(self):
        """
        Test the `xmlrpc.group_del` method: posixgroup.
        """
        res = api.Command['group_del'](self.cnposix)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['group_show'](self.cnposix)
        except errors.NotFound:
            pass
        else:
            assert False
