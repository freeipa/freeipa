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
Common utility functions and classes for unit tests.
"""

import inspect
import os
from os import path
import tempfile
import shutil
import ipalib



class TempDir(object):
    def __init__(self):
        self.__path = tempfile.mkdtemp(prefix='ipa.tests.')
        assert self.path == self.__path

    def __get_path(self):
        assert path.abspath(self.__path) == self.__path
        assert self.__path.startswith('/tmp/ipa.tests.')
        assert path.isdir(self.__path) and not path.islink(self.__path)
        return self.__path
    path = property(__get_path)

    def rmtree(self):
        if self.__path is not None:
            shutil.rmtree(self.path)
            self.__path = None

    def makedirs(self, *parts):
        d = self.join(*parts)
        if not path.exists(d):
            os.makedirs(d)
        assert path.isdir(d) and not path.islink(d)
        return d

    def touch(self, *parts):
        d = self.makedirs(*parts[:-1])
        f = path.join(d, parts[-1])
        assert not path.exists(f)
        open(f, 'w').close()
        assert path.isfile(f) and not path.islink(f)
        return f

    def write(self, content, *parts):
        d = self.makedirs(*parts[:-1])
        f = path.join(d, parts[-1])
        assert not path.exists(f)
        open(f, 'w').write(content)
        assert path.isfile(f) and not path.islink(f)
        return f

    def join(self, *parts):
        return path.join(self.path, *parts)

    def __del__(self):
        self.rmtree()


class TempHome(TempDir):
    def __init__(self):
        super(TempHome, self).__init__()
        self.__home = os.environ['HOME']
        os.environ['HOME'] = self.path

    def rmtree(self):
        os.environ['HOME'] = self.__home
        super(TempHome, self).rmtree()


class ExceptionNotRaised(Exception):
    """
    Exception raised when an *expected* exception is *not* raised during a
    unit test.
    """
    msg = 'expected %s'

    def __init__(self, expected):
        self.expected = expected

    def __str__(self):
        return self.msg % self.expected.__name__


def raises(exception, callback, *args, **kw):
    """
    Tests that the expected exception is raised; raises ExceptionNotRaised
    if test fails.
    """
    raised = False
    try:
        callback(*args, **kw)
    except exception, e:
        raised = True
    if not raised:
        raise ExceptionNotRaised(exception)
    return e


def getitem(obj, key):
    """
    Works like getattr but for dictionary interface. Use this in combination
    with raises() to test that, for example, KeyError is raised.
    """
    return obj[key]


def setitem(obj, key, value):
    """
    Works like setattr but for dictionary interface. Use this in combination
    with raises() to test that, for example, TypeError is raised.
    """
    obj[key] = value


def delitem(obj, key):
    """
    Works like delattr but for dictionary interface. Use this in combination
    with raises() to test that, for example, TypeError is raised.
    """
    del obj[key]


def no_set(obj, name, value='some_new_obj'):
    """
    Tests that attribute cannot be set.
    """
    raises(AttributeError, setattr, obj, name, value)


def no_del(obj, name):
    """
    Tests that attribute cannot be deleted.
    """
    raises(AttributeError, delattr, obj, name)


def read_only(obj, name, value='some_new_obj'):
    """
    Tests that attribute is read-only. Returns attribute.
    """
    # Test that it cannot be set:
    no_set(obj, name, value)

    # Test that it cannot be deleted:
    no_del(obj, name)

    # Return the attribute
    return getattr(obj, name)


def is_prop(prop):
    return type(prop) is property


class ClassChecker(object):
    __cls = None
    __subcls = None

    def __get_cls(self):
        if self.__cls is None:
            self.__cls = self._cls
        assert inspect.isclass(self.__cls)
        return self.__cls
    cls = property(__get_cls)

    def __get_subcls(self):
        if self.__subcls is None:
            self.__subcls = self.get_subcls()
        assert inspect.isclass(self.__subcls)
        return self.__subcls
    subcls = property(__get_subcls)

    def get_subcls(self):
        raise NotImplementedError(
            self.__class__.__name__,
            'get_subcls()'
        )


def check_TypeError(value, type_, name, callback, *args, **kw):
    """
    Tests a standard TypeError raised with `errors.raise_TypeError`.
    """
    e = raises(TypeError, callback, *args, **kw)
    assert e.value is value
    assert e.type is type_
    assert e.name == name
    assert type(e.name) is str
    assert str(e) == ipalib.errors.TYPE_FORMAT % (name, type_, value)
    return e


def get_api(**kw):
    """
    Returns (api, home) tuple.

    This function returns a tuple containing an `ipalib.plugable.API`
    instance and a `TempHome` instance.
    """
    home = TempHome()
    api = ipalib.create_api(mode='unit_test')
    api.env.in_tree = True
    for (key, value) in kw.iteritems():
        api.env[key] = value
    return (api, home)
