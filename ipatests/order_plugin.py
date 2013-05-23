# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2013  Red Hat
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

"""A Nose plugin that allows ordered test cases"""

import os
import unittest
import inspect

from nose.plugins import Plugin
import nose.loader


def ordered(cls):
    """Decorator that marks a test class as ordered"""
    cls._order_plugin__ordered = True
    assert not isinstance(cls, unittest.TestCase), (
        "A unittest.TestCase may not be ordered.")
    return cls


class OrderTests(Plugin):
    name = 'ordered-tests'

    def options(self, parser, env=os.environ):
        super(OrderTests, self).options(parser, env=env)

    def configure(self, options, conf):
        super(OrderTests, self).configure(options, conf)
        if not self.enabled:
            return

    def loadTestsFromTestClass(self, cls):
        """Sort methods of ordered test cases by co_firstlineno"""
        if not getattr(cls, '_order_plugin__ordered', False):
            return
        loader = nose.loader.TestLoader()

        def wanted(attr):
            item = getattr(cls, attr, None)
            if not inspect.ismethod(item):
                return False
            return loader.selector.wantMethod(item)

        methods = [getattr(cls, case) for case in dir(cls) if wanted(case)]
        methods.sort(key=lambda m: m.func_code.co_firstlineno)
        cases = [loader.makeTest(m, cls) for m in methods]
        return cases

    def wantMethod(self, method):
        """Hide non-TestCase methods from the normal loader"""
        im_class = getattr(method, 'im_class', None)
        if im_class and getattr(im_class, '_order_plugin__ordered', False):
            return False
