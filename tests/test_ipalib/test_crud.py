# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
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
Test the `ipalib.crud` module.
"""

from tests.util import read_only, raises, get_api, ClassChecker
from ipalib import crud, frontend, plugable, config


class CrudChecker(ClassChecker):
    """
    Class for testing base classes in `ipalib.crud`.
    """

    def get_api(self, args=tuple(), options={}):
        """
        Return a finalized `ipalib.plugable.API` instance.
        """
        assert self.cls.__bases__ == (frontend.Method,)
        (api, home) = get_api()
        class user(frontend.Object):
            takes_params = (
                'givenname',
                'sn',
                frontend.Param('uid', primary_key=True),
                'initials',
            )
        class user_verb(self.cls):
            takes_args = args
            takes_options = options
        api.register(user)
        api.register(user_verb)
        api.finalize()
        return api


class test_Add(CrudChecker):
    """
    Test the `ipalib.crud.Add` class.
    """

    _cls = crud.Add

    def test_get_args(self):
        """
        Test the `ipalib.crud.Add.get_args` method.
        """
        api = self.get_api()
        assert list(api.Method.user_verb.args) == ['uid']
        assert api.Method.user_verb.args.uid.required is True
        api = self.get_api(args=('extra?',))
        assert list(api.Method.user_verb.args) == ['uid', 'extra']
        assert api.Method.user_verb.args.uid.required is True
        assert api.Method.user_verb.args.extra.required is False

    def test_get_options(self):
        """
        Test the `ipalib.crud.Add.get_options` method.
        """
        api = self.get_api()
        assert list(api.Method.user_verb.options) == \
            ['givenname', 'sn', 'initials']
        for param in api.Method.user_verb.options():
            assert param.required is True
        api = self.get_api(options=('extra?',))
        assert list(api.Method.user_verb.options) == \
            ['givenname', 'sn', 'initials', 'extra']
        assert api.Method.user_verb.options.extra.required is False


class test_Get(CrudChecker):
    """
    Test the `ipalib.crud.Get` class.
    """

    _cls = crud.Get

    def test_get_args(self):
        """
        Test the `ipalib.crud.Get.get_args` method.
        """
        api = self.get_api()
        assert list(api.Method.user_verb.args) == ['uid']
        assert api.Method.user_verb.args.uid.required is True

    def test_get_options(self):
        """
        Test the `ipalib.crud.Get.get_options` method.
        """
        api = self.get_api()
        assert list(api.Method.user_verb.options) == []
        assert len(api.Method.user_verb.options) == 0


class test_Del(CrudChecker):
    """
    Test the `ipalib.crud.Del` class.
    """

    _cls = crud.Del

    def test_get_args(self):
        """
        Test the `ipalib.crud.Del.get_args` method.
        """
        api = self.get_api()
        assert list(api.Method.user_verb.args) == ['uid']
        assert api.Method.user_verb.args.uid.required is True

    def test_get_options(self):
        """
        Test the `ipalib.crud.Del.get_options` method.
        """
        api = self.get_api()
        assert list(api.Method.user_verb.options) == []
        assert len(api.Method.user_verb.options) == 0


class test_Mod(CrudChecker):
    """
    Test the `ipalib.crud.Mod` class.
    """

    _cls = crud.Mod

    def test_get_args(self):
        """
        Test the `ipalib.crud.Mod.get_args` method.
        """
        api = self.get_api()
        assert list(api.Method.user_verb.args) == ['uid']
        assert api.Method.user_verb.args.uid.required is True

    def test_get_options(self):
        """
        Test the `ipalib.crud.Mod.get_options` method.
        """
        api = self.get_api()
        assert list(api.Method.user_verb.options) == \
            ['givenname', 'sn', 'initials']
        for param in api.Method.user_verb.options():
            assert param.required is False


class test_Find(CrudChecker):
    """
    Test the `ipalib.crud.Find` class.
    """

    _cls = crud.Find

    def test_get_args(self):
        """
        Test the `ipalib.crud.Find.get_args` method.
        """
        api = self.get_api()
        assert list(api.Method.user_verb.args) == ['uid']
        assert api.Method.user_verb.args.uid.required is True

    def test_get_options(self):
        """
        Test the `ipalib.crud.Find.get_options` method.
        """
        api = self.get_api()
        assert list(api.Method.user_verb.options) == \
            ['givenname', 'sn', 'initials']
        for param in api.Method.user_verb.options():
            assert param.required is False


class test_CrudBackend(ClassChecker):
    """
    Test the `ipalib.crud.CrudBackend` class.
    """

    _cls = crud.CrudBackend

    def get_subcls(self):
        class ldap(self.cls):
            pass
        return ldap

    def check_method(self, name, *args):
        o = self.cls()
        e = raises(NotImplementedError, getattr(o, name), *args)
        assert str(e) == 'CrudBackend.%s()' % name
        sub = self.subcls()
        e = raises(NotImplementedError, getattr(sub, name), *args)
        assert str(e) == 'ldap.%s()' % name

    def test_create(self):
        """
        Test the `ipalib.crud.CrudBackend.create` method.
        """
        self.check_method('create')

    def test_retrieve(self):
        """
        Test the `ipalib.crud.CrudBackend.retrieve` method.
        """
        self.check_method('retrieve', 'primary key', 'attribute')

    def test_update(self):
        """
        Test the `ipalib.crud.CrudBackend.update` method.
        """
        self.check_method('update', 'primary key')

    def test_delete(self):
        """
        Test the `ipalib.crud.CrudBackend.delete` method.
        """
        self.check_method('delete', 'primary key')

    def test_search(self):
        """
        Test the `ipalib.crud.CrudBackend.search` method.
        """
        self.check_method('search')
