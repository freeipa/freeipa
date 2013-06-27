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

from ipatests.test_integration import tasks


def test_topology_star():
    topo = tasks.get_topo('star')
    assert topo == tasks.star_topo
    assert list(topo('M', [1, 2, 3, 4, 5])) == [
        ('M', 1),
        ('M', 2),
        ('M', 3),
        ('M', 4),
        ('M', 5),
    ]
    assert list(topo('M', [])) == []


def test_topology_line():
    topo = tasks.get_topo('line')
    assert topo == tasks.line_topo
    assert list(topo('M', [1, 2, 3, 4, 5])) == [
        ('M', 1),
        (1, 2),
        (2, 3),
        (3, 4),
        (4, 5),
    ]
    assert list(topo('M', [])) == []


def test_topology_tree():
    topo = tasks.get_topo('tree')
    assert topo == tasks.tree_topo
    assert list(topo('M', [1, 2, 3, 4, 5])) == [
        ('M', 1),
        ('M', 2),
        (1, 3),
        (1, 4),
        (2, 5),
    ]
    assert list(topo('M', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])) == [
        ('M', 1),
        ('M', 2),
        (1, 3),
        (1, 4),
        (2, 5),
        (2, 6),
        (3, 7),
        (3, 8),
        (4, 9),
        (4, 10),
    ]
    assert list(topo('M', [])) == []


def test_topology_tree2():
    topo = tasks.get_topo('tree2')
    assert topo == tasks.tree2_topo
    assert list(topo('M', [1, 2, 3, 4, 5])) == [
        ('M', 1),
        ('M', 2),
        (2, 3),
        (3, 4),
        (4, 5),
    ]
    assert list(topo('M', [])) == []


def test_topology_complete():
    topo = tasks.get_topo('complete')
    assert topo == tasks.complete_topo
    assert list(topo('M', [1, 2, 3])) == [
        ('M', 1),
        ('M', 2),
        ('M', 3),
        (1, 2),
        (1, 3),
        (2, 3),
    ]
    assert list(topo('M', [])) == []
