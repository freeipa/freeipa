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
Test the `ipalib/plugins/f_user` module.
"""

import sys
from xmlrpc_test import XMLRPC_test
from ipalib import api
from ipalib import errors


class test_User(XMLRPC_test):
    """
    Test the `f_user` plugin.
    """
    uid=u'jexample'
    givenname=u'Jim'
    sn=u'Example'
    home=u'/home/%s' % uid
    principalname=u'%s@%s' % (uid, api.env.realm)
    kw={'givenname':givenname,'sn':sn,'uid':uid,'homedirectory':home}

    def test_add(self):
        """
        Test the `xmlrpc.user_add` method.
        """
        res = api.Command['user_add'](**self.kw)
        assert res
        assert res.get('givenname','') == self.givenname
        assert res.get('sn','') == self.sn
        assert res.get('uid','') == self.uid
        assert res.get('homedirectory','') == self.home

    def test_add2(self):
        """
        Test the `xmlrpc.user_add` method duplicate detection.
        """
        try:
            res = api.Command['user_add'](**self.kw)
        except errors.DuplicateEntry:
            pass

    def test_doshow(self):
        """
        Test the `xmlrpc.user_show` method.
        """
        kw={'uid':self.uid, 'all': True}
        res = api.Command['user_show'](**kw)
        assert res
        assert res.get('givenname','') == self.givenname
        assert res.get('sn','') == self.sn
        assert res.get('uid','') == self.uid
        assert res.get('homedirectory','') == self.home
        assert res.get('krbprincipalname','') == self.principalname

    def test_find_all(self):
        """
        Test the `xmlrpc.user_find` method with all attributes.
        """
        kw={'all': True}
        res = api.Command['user_find'](self.uid, **kw)
        assert res
        assert len(res) == 2
        assert res[1].get('givenname','') == self.givenname
        assert res[1].get('sn','') == self.sn
        assert res[1].get('uid','') == self.uid
        assert res[1].get('homedirectory','') == self.home
        assert res[1].get('krbprincipalname','') == self.principalname

    def test_find_minimal(self):
        """
        Test the `xmlrpc.user_find` method with minimal attributes.
        """
        res = api.Command['user_find'](self.uid)
        assert res
        assert len(res) == 2
        assert res[1].get('givenname','') == self.givenname
        assert res[1].get('sn','') == self.sn
        assert res[1].get('uid','') == self.uid
        assert res[1].get('homedirectory','') == self.home
        assert res[1].get('krbprincipalname', None) == None

    def test_lock(self):
        """
        Test the `xmlrpc.user_lock` method.
        """
        res = api.Command['user_lock'](self.uid)
        assert res == True

    def test_lockoff(self):
        """
        Test the `xmlrpc.user_unlock` method.
        """
        res = api.Command['user_unlock'](self.uid)
        assert res == True

    def test_mod(self):
        """
        Test the `xmlrpc.user_mod` method.
        """
        modkw = self.kw
        modkw['givenname'] = u'Finkle'
        res = api.Command['user_mod'](**modkw)
        assert res
        assert res.get('givenname','') == 'Finkle'
        assert res.get('sn','') == self.sn

        # Ok, double-check that it was changed
        res = api.Command['user_show'](self.uid)
        assert res
        assert res.get('givenname','') == u'Finkle'
        assert res.get('sn','') == self.sn
        assert res.get('uid','') == self.uid

    def test_remove(self):
        """
        Test the `xmlrpc.user_del` method.
        """
        res = api.Command['user_del'](self.uid)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['user_show'](self.uid)
        except errors.NotFound:
            pass
        else:
            assert False
