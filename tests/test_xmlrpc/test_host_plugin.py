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
Test the `ipalib/plugins/host.py` module.
"""

import sys
from xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipalib import api
from ipalib import errors


class test_host(XMLRPC_test):
    """
    Test the `host` plugin.
    """
    fqdn = u'ipatesthost.%s' % api.env.domain
    description = u'Test host'
    localityname = u'Undisclosed location'
    kw = {'fqdn': fqdn, 'description': description, 'localityname': localityname, 'raw': True}

    def test_1_host_add(self):
        """
        Test the `xmlrpc.host_add` method.
        """
        res = api.Command['host_add'](**self.kw)['result']
        assert type(res) is dict
        assert_attr_equal(res, 'description', self.description)
        assert_attr_equal(res, 'fqdn', self.fqdn)
        assert_attr_equal(res, 'localityname', self.localityname)
        assert_attr_equal(res, 'objectclass', 'ipaobject')

    def test_2_host_show(self):
        """
        Test the `xmlrpc.host_show` method with all attributes.
        """
        kw = {'fqdn': self.fqdn, 'all': True, 'raw': True}
        res = api.Command['host_show'](**kw)['result']
        assert res
        assert_attr_equal(res, 'description', self.description)
        assert_attr_equal(res, 'fqdn', self.fqdn)
        assert_attr_equal(res, 'l', self.localityname)

    def test_3_host_show(self):
        """
        Test the `xmlrpc.host_show` method with default attributes.
        """
        kw = {'fqdn': self.fqdn, 'raw': True}
        res = api.Command['host_show'](**kw)['result']
        assert res
        assert_attr_equal(res, 'description', self.description)
        assert_attr_equal(res, 'fqdn', self.fqdn)
        assert_attr_equal(res, 'localityname', self.localityname)

    def test_4_host_find(self):
        """
        Test the `xmlrpc.host_find` method with all attributes.
        """
        kw = {'fqdn': self.fqdn, 'all': True, 'raw': True}
        res = api.Command['host_find'](**kw)['result']
        assert res
        assert_attr_equal(res[0], 'description', self.description)
        assert_attr_equal(res[0], 'fqdn', self.fqdn)
        assert_attr_equal(res[0], 'l', self.localityname)

    def test_5_host_find(self):
        """
        Test the `xmlrpc.host_find` method with default attributes.
        """
        res = api.Command['host_find'](self.fqdn, raw=True)['result']
        assert res
        assert_attr_equal(res[0], 'description', self.description)
        assert_attr_equal(res[0], 'fqdn', self.fqdn)
        assert_attr_equal(res[0], 'localityname', self.localityname)

    def test_6_host_mod(self):
        """
        Test the `xmlrpc.host_mod` method.
        """
        newdesc = u'Updated host'
        modkw = {'fqdn': self.fqdn, 'description': newdesc, 'raw': True}
        res = api.Command['host_mod'](**modkw)['result']
        assert res
        assert_attr_equal(res, 'description', newdesc)

        # Ok, double-check that it was changed
        res = api.Command['host_show'](self.fqdn, raw=True)['result']
        assert res
        assert_attr_equal(res, 'description', newdesc)
        assert_attr_equal(res, 'fqdn', self.fqdn)

    def test_7_host_del(self):
        """
        Test the `xmlrpc.host_del` method.
        """
        assert api.Command['host_del'](self.fqdn)['result'] is True

        # Verify that it is gone
        try:
            api.Command['host_show'](self.fqdn)
        except errors.NotFound:
            pass
        else:
            assert False
