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
Test the `ipalib/plugins/f_host` module.
"""

import sys
from xmlrpc_test import XMLRPC_test
from ipalib import api
from ipalib import errors
from ipalib.cli import CLI

try:
    api.finalize()
except StandardError:
    pass

class test_Host(XMLRPC_test):
    """
    Test the `f_host` plugin.
    """
    cn='ipaexample.%s' % api.env.domain
    description='Test host'
    localityname='Undisclosed location'
    kw={'cn': cn, 'description': description, 'localityname': localityname}

    def test_add(self):
        """
        Test the `xmlrpc.host_add` method.
        """
        res = api.Command['host_add'](**self.kw)
        assert res
        assert res.get('description','') == self.description
        assert res.get('cn','') == self.cn
        assert res.get('l','') == self.localityname

    def test_doshow_all(self):
        """
        Test the `xmlrpc.host_show` method with all attributes.
        """
        kw={'cn':self.cn, 'all': True}
        res = api.Command['host_show'](**kw)
        assert res
        assert res.get('description','') == self.description
        assert res.get('cn','') == self.cn
        assert res.get('l','') == self.localityname

    def test_doshow_minimal(self):
        """
        Test the `xmlrpc.host_show` method with default attributes.
        """
        kw={'cn':self.cn}
        res = api.Command['host_show'](**kw)
        assert res
        assert res.get('description','') == self.description
        assert res.get('cn','') == self.cn
        assert res.get('localityname','') == self.localityname

    def test_find_all(self):
        """
        Test the `xmlrpc.host_find` method with all attributes.
        """
        kw={'cn':self.cn, 'all': True}
        res = api.Command['host_find'](**kw)
        assert res
        assert len(res) == 2
        assert res[1].get('description','') == self.description
        assert res[1].get('cn','') == self.cn
        assert res[1].get('l','') == self.localityname

    def test_find_minimal(self):
        """
        Test the `xmlrpc.host_find` method with default attributes.
        """
        res = api.Command['host_find'](self.cn)
        assert res
        assert len(res) == 2
        assert res[1].get('description','') == self.description
        assert res[1].get('cn','') == self.cn
        assert res[1].get('localityname','') == self.localityname

    def test_mod(self):
        """
        Test the `xmlrpc.host_mod` method.
        """
        newdesc='Updated host'
        modkw={'cn': self.cn, 'description': newdesc}
        res = api.Command['host_mod'](**modkw)
        assert res
        assert res.get('description','') == newdesc

        # Ok, double-check that it was changed
        res = api.Command['host_show'](self.cn)
        assert res
        assert res.get('description','') == newdesc
        assert res.get('cn','') == self.cn

    def test_remove(self):
        """
        Test the `xmlrpc.host_del` method.
        """
        res = api.Command['host_del'](self.cn)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['host_show'](self.cn)
        except errors.NotFound:
            pass
        else:
            assert False
