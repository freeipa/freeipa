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
Test the `tests.util` module.
"""

import util


class Prop(object):
    def __init__(self, *ops):
        self.__ops = frozenset(ops)
        self.__prop = 'prop value'

    def __get_prop(self):
        if 'get' not in self.__ops:
            raise AttributeError('get prop')
        return self.__prop

    def __set_prop(self, value):
        if 'set' not in self.__ops:
            raise AttributeError('set prop')
        self.__prop = value

    def __del_prop(self):
        if 'del' not in self.__ops:
            raise AttributeError('del prop')
        self.__prop = None

    prop = property(__get_prop, __set_prop, __del_prop)


def test_yes_raised():
    f = util.raises

    class SomeError(Exception):
        pass

    class AnotherError(Exception):
        pass

    def callback1():
        'raises correct exception'
        raise SomeError()

    def callback2():
        'raises wrong exception'
        raise AnotherError()

    def callback3():
        'raises no exception'

    f(SomeError, callback1)

    raised = False
    try:
        f(SomeError, callback2)
    except AnotherError:
        raised = True
    assert raised

    raised = False
    try:
        f(SomeError, callback3)
    except util.ExceptionNotRaised:
        raised = True
    assert raised


def test_no_set():
    # Tests that it works when prop cannot be set:
    util.no_set(Prop('get', 'del'), 'prop')

    # Tests that ExceptionNotRaised is raised when prop *can* be set:
    raised = False
    try:
        util.no_set(Prop('set'), 'prop')
    except util.ExceptionNotRaised:
        raised = True
    assert raised


def test_no_del():
    # Tests that it works when prop cannot be deleted:
    util.no_del(Prop('get', 'set'), 'prop')

    # Tests that ExceptionNotRaised is raised when prop *can* be set:
    raised = False
    try:
        util.no_del(Prop('del'), 'prop')
    except util.ExceptionNotRaised:
        raised = True
    assert raised


def test_read_only():
    # Test that it works when prop is read only:
    assert util.read_only(Prop('get'), 'prop') == 'prop value'

    # Test that ExceptionNotRaised is raised when prop can be set:
    raised = False
    try:
        util.read_only(Prop('get', 'set'), 'prop')
    except util.ExceptionNotRaised:
        raised = True
    assert raised

    # Test that ExceptionNotRaised is raised when prop can be deleted:
    raised = False
    try:
        util.read_only(Prop('get', 'del'), 'prop')
    except util.ExceptionNotRaised:
        raised = True
    assert raised

    # Test that ExceptionNotRaised is raised when prop can be both set and
    # deleted:
    raised = False
    try:
        util.read_only(Prop('get', 'del'), 'prop')
    except util.ExceptionNotRaised:
        raised = True
    assert raised

    # Test that AttributeError is raised when prop can't be read:
    raised = False
    try:
        util.read_only(Prop(), 'prop')
    except AttributeError:
        raised = True
    assert raised
