# Authors:
#   Jakub Hrozek <jhrozek@redhat.com>
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
Test the `ipalib/plugins/f_application` module.
"""

from xmlrpc_test import XMLRPC_test
from ipalib import api

class test_Application(XMLRPC_test):
    """
    Test the `f_application` plugin.
    """
    app_cn=u"sudo"
    app_description=u"a sudo test app"
    kw={'cn':app_cn,'description':app_description}

    def test_create_config(self):
        """
        Test the `xmlrpc.application_create` method - create a config application
        """
        create_kw = dict(self.kw)
        create_kw.update({'type':u'config'})
        res = api.Command['application_create'](**create_kw)
        assert res
        assert res.get('description','') == self.app_description
        assert res.get('cn','') == self.app_cn
        assert res.get('dn','').startswith("cn=%s,%s" % (self.app_cn,api.env.container_applications))
    
    def test_create_role(self):
        """
        Test the `xmlrpc.application_create` method - create a role application
        """
        create_kw = dict(self.kw)
        create_kw.update({'type':u'role'})
        res = api.Command['application_create'](**create_kw)
        assert res
        assert res.get('description','') == self.app_description
        assert res.get('cn','') == self.app_cn
        assert res.get('dn','').startswith("cn=%s,%s" % (self.app_cn,api.env.container_roles))
    
    def test_do_show_config(self):
        """
        Test the `xmlrpc.application_show` method - show a role application
        """
        showkw = {'cn':self.app_cn, 'type':u'config'}
        res = api.Command['application_show'](**showkw)
        assert res
        assert res.get('description','') == self.app_description
        assert res.get('cn','') == self.app_cn

    def test_do_show_role(self):
        """
        Test the `xmlrpc.application_show` method - show a role application
        """
        showkw = {'cn':self.app_cn, 'type':u'role'}
        res = api.Command['application_show'](**showkw)
        assert res
        assert res.get('description','') == self.app_description
        assert res.get('cn','') == self.app_cn

    def test_do_find_config(self):
        """
        Test the `xmlrpc.application_find` method - find all config applications
        """
        kw = {'type':u'config'}
        res = api.Command['application_find'](self.app_cn, **kw)
        assert res
        assert len(res) == 2
        assert res[1].get('cn') == self.app_cn

    def test_do_find_role(self):
        """
        Test the `xmlrpc.application_find` method - find all role applications
        """
        kw = {'type':u'role'}
        res = api.Command['application_find'](self.app_cn, **kw)
        assert res
        assert len(res) == 2
        assert res[1].get('cn') == self.app_cn

    def test_edit_config(self):
        """
        Test the `xmlrpc.application_edit` method - edit a config application
        """
        modkw = dict(self.kw)
        modkw['description'] = u'foobar'
        modkw['type'] = u'config'
        res = api.Command['application_edit'](**modkw)
        assert res
        assert res.get('description','') == 'foobar'

    def test_edit_role(self):
        """
        Test the `xmlrpc.application_edit` method - edit a role application
        """
        modkw = dict(self.kw)
        modkw['description'] = u'foobar'
        modkw['type'] = u'role'
        res = api.Command['application_edit'](**modkw)
        assert res
        assert res.get('description','') == 'foobar'

    def test_remove_config(self):
        """
        Test the `xmlrpc.application_delete` method - delete a config application
        """
        delkw = {'cn':self.app_cn, 'type':u'config'}
        res = api.Command['application_delete'](**delkw)
        assert res == True

        # try to search for the app, should really be gone
        kw = {'type':u'config'}
        res = api.Command['application_find'](self.app_cn, **kw)
        assert res
        assert len(res) == 1

    def test_remove_role(self):
        """
        Test the `xmlrpc.application_delete` method - delete a role application
        """
        delkw = {'cn':self.app_cn, 'type':u'role'}
        res = api.Command['application_delete'](**delkw)
        assert res == True

        # try to search for the app, should really be gone
        kw = {'type':u'role'}
        res = api.Command['application_find'](self.app_cn, **kw)
        assert res
        assert len(res) == 1

