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
from ipalib import crud, frontend, plugable

def get_api():
    api = plugable.API(
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

    def test_get_options(self):
        """
        Test the `crud.Add.get_options` method.
        """
        api = get_api()
        class user_add(self.cls):
            pass
        api.register(user_add)
        api.finalize()
        assert list(api.Method.user_add.args) == []
        assert list(api.Method.user_add.options) == \
            ['givenname', 'sn', 'uid', 'initials']



class test_Get(ClassChecker):
    """
    Test the `crud.Get` class.
    """

    _cls = crud.Get

    def test_class(self):
        assert self.cls.__bases__ == (frontend.Method,)


class test_Del(ClassChecker):
    """
    Test the `crud.Del` class.
    """

    _cls = crud.Del

    def test_class(self):
        assert self.cls.__bases__ == (frontend.Method,)


class test_Mod(ClassChecker):
    """
    Test the `crud.Mod` class.
    """

    _cls = crud.Mod

    def test_class(self):
        assert self.cls.__bases__ == (frontend.Method,)


class test_Find(ClassChecker):
    """
    Test the `crud.Find` class.
    """

    _cls = crud.Find

    def test_class(self):
        assert self.cls.__bases__ == (frontend.Method,)
