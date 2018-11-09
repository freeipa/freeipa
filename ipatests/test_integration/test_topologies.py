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

from ipatests.pytest_ipa.integration import tasks


def test_topology_star():
    topo = tasks.get_topo('star')
    assert topo is tasks.star_topo
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
    assert topo is tasks.line_topo
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
    assert topo is tasks.tree_topo
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
    assert topo is tasks.tree2_topo
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
    assert topo is tasks.complete_topo
    assert list(topo('M', [1, 2, 3])) == [
        ('M', 1),
        ('M', 2),
        ('M', 3),
        (1, 2),
        (1, 3),
        (2, 3),
    ]
    assert list(topo('M', [])) == []


def test_topology_two_connected():
    topo = tasks.get_topo('2-connected')
    assert topo is tasks.two_connected_topo
    assert list(topo('M', [1, 2, 3, 4, 5, 6, 7, 8])) == [
        ('M', 1),
        ('M', 2),
        (2, 3),
        (1, 3),
        ('M', 4),
        ('M', 5),
        (4, 6),
        (5, 6),
        (2, 4),
        (2, 7),
        (4, 8),
        (7, 8),
    ]
    assert list(topo('M', [])) == []


def test_topology_double_circle_topo():
    topo = tasks.get_topo('double-circle')
    assert topo is tasks.double_circle_topo
    assert list(topo('M', list(range(1, 30)))) == [
        ('M', 1),
        (1, 6),
        (1, 12),
        (6, 7),
        (7, 12),
        (7, 18),
        (12, 13),
        (13, 18),
        (13, 24),
        (18, 19),
        (19, 24),
        (19, 'M'),
        (24, 25),
        (25, 'M'),
        (25, 6),
        ('M', 2),
        (2, 3),
        (2, 4),
        (2, 5),
        (3, 4),
        (3, 5),
        (4, 5),
        (1, 5),
        (6, 8),
        (8, 9),
        (8, 10),
        (8, 11),
        (9, 10),
        (9, 11),
        (10, 11),
        (7, 11),
        (12, 14),
        (14, 15),
        (14, 16),
        (14, 17),
        (15, 16),
        (15, 17),
        (16, 17),
        (13, 17),
        (18, 20),
        (20, 21),
        (20, 22),
        (20, 23),
        (21, 22),
        (21, 23),
        (22, 23),
        (19, 23),
        (24, 26),
        (26, 27),
        (26, 28),
        (26, 29),
        (27, 28),
        (27, 29),
        (28, 29),
        (25, 29),
    ]
    assert list(topo('M', [])) == []
