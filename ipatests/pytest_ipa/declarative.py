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

"""Pytest plugin for Declarative tests"""


def pytest_generate_tests(metafunc):
    """Generates Declarative tests"""
    if 'declarative_test_definition' in metafunc.fixturenames:
        tests = []
        descriptions = []
        for i, test in enumerate(metafunc.cls.tests):
            if callable(test):
                description = '%s: %s' % (
                    str(i).zfill(4),
                    test.__name__,  # test is not a dict. pylint: disable=E1103
                )
            else:
                description = '%s: %s: %s' % (str(i).zfill(4),
                                              test['command'][0],
                                              test.get('desc', ''))
                test = dict(test)
                test['nice'] = description
            tests.append(test)
            descriptions.append(description)
        metafunc.parametrize(
            ['index', 'declarative_test_definition'],
            enumerate(tests),
            ids=descriptions,
        )
