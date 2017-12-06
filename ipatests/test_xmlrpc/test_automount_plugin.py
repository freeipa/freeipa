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
Test the `ipaserver/plugins/automount.py' module.
"""

import textwrap
import tempfile
import shutil

from ipalib import api
from ipalib import errors
from ipapython.dn import DN

import pytest
import six

from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipatests.util import assert_deepequal

if six.PY3:
    unicode = str


class MockTextui(list):
    """Collects output lines"""
    # Extend the mock object if other textui methods are called
    def print_plain(self, line):
        self.append(unicode(line))


class AutomountTest(XMLRPC_test):
    """Provides common functionality for automount tests"""

    locname = u'testlocation'
    tofiles_output = ''  # To be overridden

    def check_tofiles(self):
        """Check automountlocation_tofiles output against self.tofiles_output
        """
        res = api.Command['automountlocation_tofiles'](self.locname)

        mock_ui = MockTextui()
        command = api.Command['automountlocation_tofiles']
        command.output_for_cli(mock_ui, res, self.locname, version=u'2.88')
        expected_output = self.tofiles_output
        assert_deepequal(expected_output, u'\n'.join(mock_ui))

    def check_import_roundtrip(self):
        """Check automountlocation_tofiles/automountlocation_import roundtrip

        Loads self.tofiles_output (which should correspond to
        automountlocation_tofiles output), then checks the resulting map
        against tofiles_output again.
        Do not use this if the test creates maps that aren't connected to
        auto.master -- these can't be imported successfully.
        """
        conf_directory = tempfile.mkdtemp()

        # Parse the tofiles_output into individual files, replace /etc/ by
        # our temporary directory name
        current_file = None
        for line in self.tofiles_output.splitlines():
            line = line.replace('/etc/',  '%s/' % conf_directory)
            if line.startswith(conf_directory) and line.endswith(':'):
                current_file = open(line.rstrip(':'), 'w')
            elif '--------' in line:
                current_file.close()
            elif line.startswith('maps not connected to '):
                break
            else:
                current_file.write(line + '\n')
        assert current_file is not None, ('The input file does not contain any'
                                          'records of files to be opened.')
        current_file.close()

        self.failsafe_add(api.Object.automountlocation, self.locname)

        try:
            # Feed the files to automountlocation_import & check
            master_file = u'%s/auto.master' % conf_directory
            automountlocation_import = api.Command['automountlocation_import']
            res = automountlocation_import(self.locname, master_file,
                                           version=u'2.88')
            assert_deepequal(dict(
                result=dict(
                    keys=lambda k: k,
                    maps=lambda m: m,
                    skipped=(),
                    duplicatemaps=(),
                    duplicatekeys=(),
                )), res)  # pylint: disable=used-before-assignment
            self.check_tofiles()
        finally:
            res = api.Command['automountlocation_del'](self.locname)['result']
            assert res
            assert not res['failed']

        # Success; delete the temporary directory
        shutil.rmtree(conf_directory)


@pytest.mark.tier1
class test_automount(AutomountTest):
    """
    Test the `automount` plugin.
    """
    mapname = u'testmap'
    keyname = u'testkey'
    keyname_rename = u'testkey_rename'
    keyname2 = u'testkey2'
    description = u'description of map'
    info = u'ro'
    newinfo = u'rw'
    map_kw = {'automountmapname': mapname, 'description': description, 'raw': True}
    key_kw = {'automountkey': keyname, 'automountinformation': info, 'raw': True}
    key_kw2 = {'automountkey': keyname2, 'automountinformation': info, 'raw': True}

    tofiles_output = textwrap.dedent(u"""
        /etc/auto.master:
        /-\t/etc/auto.direct
        ---------------------------
        /etc/auto.direct:

        maps not connected to /etc/auto.master:
        ---------------------------
        /etc/testmap:
        testkey2\tro
        """).strip()

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
        with pytest.raises(errors.DuplicateEntry):
            api.Command['automountkey_add'](
                self.locname, self.mapname, **self.key_kw)

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
        showkey_kw={'automountkey': self.keyname, 'automountinformation' : self.info, 'raw': True}
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
        assert_attr_equal(res[0], 'automountkey', self.keyname)
        assert_attr_equal(res[0], 'automountinformation', self.info)

    def test_9_automountkey_mod(self):
        """
        Test the `xmlrpc.automountkey_mod` method.
        """
        self.key_kw['newautomountinformation'] = self.newinfo
        self.key_kw['rename'] = self.keyname_rename
        res = api.Command['automountkey_mod'](self.locname, self.mapname, **self.key_kw)['result']
        assert res
        assert_attr_equal(res, 'automountinformation', self.newinfo)
        assert_attr_equal(res, 'automountkey', self.keyname_rename)

    def test_a1_automountmap_mod(self):
        """
        Test the `xmlrpc.automountmap_mod` method.
        """
        mod_kw = {'description': u'new description'}
        res = api.Command['automountmap_mod'](self.locname, self.mapname, **mod_kw)['result']
        assert res
        assert_attr_equal(res, 'description', 'new description')

    def test_a2_automountmap_tofiles(self):
        """
        Test the `automountlocation_tofiles` command.
        """
        res = api.Command['automountlocation_tofiles'](self.locname,
                                                       version=u'2.88')
        assert_deepequal(dict(
            result=dict(
                keys={'auto.direct': ()},
                orphanmaps=(dict(
                    dn=DN(('automountmapname', self.mapname),
                          ('cn', self.locname),
                          ('cn', 'automount'), api.env.basedn),
                    description=(u'new description',),
                    automountmapname=(u'testmap',)),),
                orphankeys=[(
                    dict(
                        dn=DN(('description', self.keyname2),
                              ('automountmapname', 'testmap'),
                              ('cn', self.locname),
                              ('cn', 'automount'), api.env.basedn),
                        automountkey=(self.keyname2,),
                        description=(self.keyname2,),
                        automountinformation=(u'ro',),
                    ),
                    dict(
                        dn=DN(('description', self.keyname_rename),
                              ('automountmapname', 'testmap'),
                              ('cn', self.locname),
                              ('cn', 'automount'), api.env.basedn),
                        automountkey=(self.keyname_rename,),
                        description=(self.keyname_rename,),
                        automountinformation=(u'rw',),
                    ))],
                maps=(
                    dict(
                        dn=DN(('description', '/- auto.direct'),
                              ('automountmapname', 'auto.master'),
                              ('cn', self.locname),
                              ('cn', 'automount'), api.env.basedn),
                        automountkey=(u'/-',),
                        description=(u'/- auto.direct',),
                        automountinformation=(u'auto.direct',)
                    ),
            ))), res)

        # Also check the CLI output

        self.check_tofiles()

    def test_b_automountkey_del(self):
        """
        Test the `xmlrpc.automountkey_del` method.
        """
        delkey_kw={'automountkey': self.keyname_rename, 'automountinformation' : self.newinfo}
        res = api.Command['automountkey_del'](self.locname, self.mapname, **delkey_kw)['result']
        assert res
        assert not res['failed']

        # Verify that it is gone
        with pytest.raises(errors.NotFound):
            api.Command['automountkey_show'](self.locname, self.mapname, **delkey_kw)

    def test_c_automountlocation_del(self):
        """
        Test the `xmlrpc.automountlocation_del` method.
        """
        res = api.Command['automountlocation_del'](self.locname)['result']
        assert res
        assert not res['failed']

        # Verify that it is gone
        with pytest.raises(errors.NotFound):
            api.Command['automountlocation_show'](self.locname)

    def test_d_automountmap_del(self):
        """
        Test that the `xmlrpc.automountlocation_del` method removes all maps and keys
        """
        # Verify that the second key we added is gone
        key_kw = {'automountkey': self.keyname2, 'automountinformation': self.info, 'raw': True}
        with pytest.raises(errors.NotFound):
            api.Command['automountkey_show'](self.locname, self.mapname, **key_kw)


@pytest.mark.tier1
class test_automount_direct(AutomountTest):
    """
    Test the `automount` plugin indirect map functionality.
    """
    mapname = u'auto.direct2'
    keyname = u'/-'
    direct_kw = { 'key' : keyname }

    tofiles_output = textwrap.dedent(u"""
        /etc/auto.master:
        /-\t/etc/auto.direct
        /-\t/etc/auto.direct2
        ---------------------------
        /etc/auto.direct:
        ---------------------------
        /etc/auto.direct2:

        maps not connected to /etc/auto.master:
        """).strip()

    def test_0_automountlocation_add(self):
        """
        Test adding a location.
        """
        res = api.Command['automountlocation_add'](self.locname, raw=True)['result']
        assert res
        assert_attr_equal(res, 'cn', self.locname)

    def test_1_automountmap_add_direct(self):
        """
        Test adding a second direct map with a different info
        """
        res = api.Command['automountmap_add_indirect'](self.locname, self.mapname, **self.direct_kw)['result']
        assert res
        assert_attr_equal(res, 'automountmapname', self.mapname)

    def test_2_automountmap_add_duplicate(self):
        """
        Test adding a duplicate direct map.
        """
        with pytest.raises(errors.DuplicateEntry):
            api.Command['automountmap_add_indirect'](
                self.locname, self.mapname, **self.direct_kw)

    def test_2a_automountmap_tofiles(self):
        """Test the `automountmap_tofiles` command"""
        self.check_tofiles()

    def test_3_automountlocation_del(self):
        """
        Remove the location.
        """
        res = api.Command['automountlocation_del'](self.locname)['result']
        assert res
        assert not res['failed']

        # Verity that it is gone
        with pytest.raises(errors.NotFound):
            api.Command['automountlocation_show'](self.locname)

    def test_z_import_roundtrip(self):
        """Check automountlocation_tofiles/automountlocation_import roundtrip
        """
        self.check_import_roundtrip()


@pytest.mark.tier1
class test_automount_indirect(AutomountTest):
    """
    Test the `automount` plugin indirect map functionality.
    """
    mapname = u'auto.home'
    keyname = u'/home'
    parentmap = u'auto.master'
    map_kw = {'key': keyname, 'parentmap': parentmap, 'raw': True}
    key_kw = {'automountkey': keyname, 'automountinformation': mapname}

    tofiles_output = textwrap.dedent(u"""
        /etc/auto.master:
        /-\t/etc/auto.direct
        /home\t/etc/auto.home
        ---------------------------
        /etc/auto.direct:
        ---------------------------
        /etc/auto.home:

        maps not connected to /etc/auto.master:
        """).strip()

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

    def test_1a_automountmap_add_indirect(self):
        """
        Test adding a duplicate indirect map.
        """
        with pytest.raises(errors.DuplicateEntry):
            api.Command['automountmap_add_indirect'](
                self.locname, self.mapname, **self.map_kw
            )

    def test_2_automountmap_show(self):
        """
        Test the `xmlrpc.automountmap_show` method.
        """
        res = api.Command['automountmap_show'](self.locname, self.mapname, raw=True)['result']
        assert res
        assert_attr_equal(res, 'automountmapname', self.mapname)

    def test_2a_automountmap_tofiles(self):
        """Test the `automountmap_tofiles` command"""
        self.check_tofiles()

    def test_3_automountkey_del(self):
        """
        Remove the indirect key /home.
        """
        res = api.Command['automountkey_del'](self.locname, self.parentmap, **self.key_kw)['result']
        assert res
        assert not res['failed']

        # Verify that it is gone
        with pytest.raises(errors.NotFound):
            api.Command['automountkey_show'](self.locname, self.parentmap, **self.key_kw)

    def test_4_automountmap_del(self):
        """
        Remove the indirect map for auto.home.
        """
        res = api.Command['automountmap_del'](self.locname, self.mapname)['result']
        assert res
        assert not res['failed']

        # Verify that it is gone
        with pytest.raises(errors.NotFound):
            api.Command['automountmap_show'](self.locname, self.mapname)

    def test_5_automountlocation_del(self):
        """
        Remove the location.
        """
        res = api.Command['automountlocation_del'](self.locname)['result']
        assert res
        assert not res['failed']

        # Verity that it is gone
        with pytest.raises(errors.NotFound):
            api.Command['automountlocation_show'](self.locname)

    def test_z_import_roundtrip(self):
        """Check automountlocation_tofiles/automountlocation_import roundtrip
        """
        self.check_import_roundtrip()


@pytest.mark.tier1
class test_automount_indirect_no_parent(AutomountTest):
    """
    Test the `automount` plugin Indirect map function.
    """
    mapname = u'auto.home'
    keyname = u'/home'
    mapname2 = u'auto.direct2'
    keyname2 = u'direct2'
    parentmap = u'auto.master'
    map_kw = {'key': keyname, 'raw': True}
    map_kw2 = {'key': keyname2, 'raw': True}

    tofiles_output = textwrap.dedent(u"""
        /etc/auto.master:
        /-\t/etc/auto.direct
        /home\t/etc/auto.home
        ---------------------------
        /etc/auto.direct:
        ---------------------------
        /etc/auto.home:
        direct2\t-fstype=autofs ldap:auto.direct2

        maps not connected to /etc/auto.master:
        ---------------------------
        /etc/auto.direct2:
        """).strip()

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
        showkey_kw = {'automountkey': self.keyname, 'automountinformation': self.mapname, 'raw': True}
        res = api.Command['automountkey_show'](self.locname, self.parentmap, **showkey_kw)['result']
        assert res
        assert_attr_equal(res, 'automountkey', self.keyname)

    def test_2a_automountmap_add_indirect(self):
        """
        Test adding an indirect map with default parent.
        """
        res = api.Command['automountmap_add_indirect'](self.locname,
            u'auto.direct2', parentmap=self.mapname, **self.map_kw2)['result']
        assert res
        assert_attr_equal(res, 'automountmapname', self.mapname2)

    def test_2b_automountmap_tofiles(self):
        """Test the `automountmap_tofiles` command"""
        self.check_tofiles()

    def test_3_automountkey_del(self):
        """
        Remove the indirect key /home.
        """
        delkey_kw={'automountkey': self.keyname, 'automountinformation': self.mapname}
        res = api.Command['automountkey_del'](self.locname, self.parentmap, **delkey_kw)['result']
        assert res
        assert not res['failed']

        # Verify that it is gone
        with pytest.raises(errors.NotFound):
            api.Command['automountkey_show'](self.locname, self.parentmap, **delkey_kw)

    def test_4_automountmap_del(self):
        """
        Remove the indirect map for auto.home.
        """
        res = api.Command['automountmap_del'](self.locname, self.mapname)['result']
        assert res
        assert not res['failed']

        # Verify that it is gone
        with pytest.raises(errors.NotFound):
            api.Command['automountmap_show'](self.locname, self.mapname)

    def test_5_automountlocation_del(self):
        """
        Remove the location.
        """
        res = api.Command['automountlocation_del'](self.locname)['result']
        assert res
        assert not res['failed']

        # Verity that it is gone
        with pytest.raises(errors.NotFound):
            api.Command['automountlocation_show'](self.locname)
