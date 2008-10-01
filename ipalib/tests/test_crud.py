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
Unit tests for `ipalib.crud` module.
"""

from tstutil import read_only, raises, ClassChecker
from ipalib import crud, frontend, plugable, config

def get_api():
    api = plugable.API(
        config.default_environment(),
        frontend.Object,
        frontend.Method,
        frontend.Property,
    )
    class user(frontend.Object):
        takes_params = (
            'givenname',
            'sn',
            frontend.Param('uid', primary_key=True),
            'initials',
        )
    api.register(user)
    return api


class test_Add(ClassChecker):
    """
    Test the `crud.Add` class.
    """

    _cls = crud.Add

    def test_class(self):
        assert self.cls.__bases__ == (frontend.Method,)

    def test_options_args(self):
        """
        Test `crud.Add.get_args` and `crud.Add.get_options` methods.
        """
        api = get_api()
        class user_add(self.cls):
            pass
        api.register(user_add)
        api.finalize()
        assert list(api.Method.user_add.args) == ['uid']
        assert list(api.Method.user_add.options) == \
            ['givenname', 'sn', 'initials']
        for param in api.Method.user_add.options():
            assert param.required is True


class test_Get(ClassChecker):
    """
    Test the `crud.Get` class.
    """

    _cls = crud.Get

    def test_class(self):
        assert self.cls.__bases__ == (frontend.Method,)

    def test_options_args(self):
        """
        Test `crud.Get.get_args` and `crud.Get.get_options` methods.
        """
        api = get_api()
        class user_get(self.cls):
            pass
        api.register(user_get)
        api.finalize()
        assert list(api.Method.user_get.args) == ['uid']
        assert list(api.Method.user_get.options) == []


class test_Del(ClassChecker):
    """
    Test the `crud.Del` class.
    """

    _cls = crud.Del

    def test_class(self):
        assert self.cls.__bases__ == (frontend.Method,)

    def test_options_args(self):
        """
        Test `crud.Del.get_args` and `crud.Del.get_options` methods.
        """
        api = get_api()
        class user_del(self.cls):
            pass
        api.register(user_del)
        api.finalize()
        assert list(api.Method.user_del.args) == ['uid']
        assert list(api.Method.user_del.options) == []


class test_Mod(ClassChecker):
    """
    Test the `crud.Mod` class.
    """

    _cls = crud.Mod

    def test_class(self):
        assert self.cls.__bases__ == (frontend.Method,)

    def test_options_args(self):
        """
        Test `crud.Mod.get_args` and `crud.Mod.get_options` methods.
        """
        api = get_api()
        class user_mod(self.cls):
            pass
        api.register(user_mod)
        api.finalize()
        assert list(api.Method.user_mod.args) == ['uid']
        assert api.Method.user_mod.args[0].required is True
        assert list(api.Method.user_mod.options) == \
            ['givenname', 'sn', 'initials']
        for param in api.Method.user_mod.options():
            assert param.required is False


class test_Find(ClassChecker):
    """
    Test the `crud.Find` class.
    """

    _cls = crud.Find

    def test_class(self):
        assert self.cls.__bases__ == (frontend.Method,)

    def test_options_args(self):
        """
        Test `crud.Find.get_args` and `crud.Find.get_options` methods.
        """
        api = get_api()
        class user_find(self.cls):
            pass
        api.register(user_find)
        api.finalize()
        assert list(api.Method.user_find.args) == ['uid']
        assert api.Method.user_find.args[0].required is True
        assert list(api.Method.user_find.options) == \
            ['givenname', 'sn', 'initials']
        for param in api.Method.user_find.options():
            assert param.required is False
