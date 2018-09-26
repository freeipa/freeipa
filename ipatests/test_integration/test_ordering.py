# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2014  Red Hat
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

"""Test the ordering of tests

IPA integration tests, marked with `@ordered`, require tests to be run
in a specific order:
- Base classes first
- Within a class, test methods are ordered according to source line
"""

from pytest_sourceorder import ordered


@ordered
class TestBase:
    @classmethod
    def setup_class(cls):
        cls.value = 'unchanged'

    def test_d_first(self):
        type(self).value = 'changed once'


class TestChild(TestBase):
    def test_b_third(self):
        assert type(self).value == 'changed twice'
        type(self).value = 'changed thrice'

    def test_a_fourth(self):
        assert type(self).value == 'changed thrice'


def test_c_second(self):
    assert type(self).value == 'changed once'
    type(self).value = 'changed twice'
TestBase.test_c_second = test_c_second
del test_c_second
