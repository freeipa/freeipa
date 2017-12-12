# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
Test the `ipaserver/plugins/passwd.py` module.
"""
import pytest

from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipalib import api
from ipalib import errors


@pytest.mark.tier1
class test_passwd(XMLRPC_test):
    """
    Test the `passwd` plugin.
    """
    uid = u'pwexample'
    givenname = u'Jim'
    sn = u'Example'
    home = u'/home/%s' % uid
    principalname = u'%s@%s' % (uid, api.env.realm)
    kw = {'givenname': givenname, 'sn': sn, 'uid': uid, 'homedirectory': home}

    def test_1_user_add(self):
        """
        Create a test user
        """
        entry = api.Command['user_add'](**self.kw)['result']
        assert_attr_equal(entry, 'givenname', self.givenname)
        assert_attr_equal(entry, 'sn', self.sn)
        assert_attr_equal(entry, 'uid', self.uid)
        assert_attr_equal(entry, 'homedirectory', self.home)
        assert_attr_equal(entry, 'objectclass', 'ipaobject')

    def test_2_set_passwd(self):
        """
        Test the `xmlrpc.passwd` method.
        """
        out = api.Command['passwd'](self.uid, password=u'password1')
        assert out['result'] is True

    def test_3_user_del(self):
        """
        Remove the test user
        """
        api.Command['user_del'](self.uid)

        # Verify that it is gone
        with pytest.raises(errors.NotFound):
            api.Command['user_show'](self.uid)
