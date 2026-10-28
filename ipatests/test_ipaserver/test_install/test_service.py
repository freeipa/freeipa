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

"""
Tests for the `ipaserver.service` module.
"""

from ipaserver.install import service
import pytest


@pytest.mark.tier0
def test_format_seconds():
    assert service.format_seconds(0) == '0 seconds'
    assert service.format_seconds(1) == '1 second'
    assert service.format_seconds(2) == '2 seconds'
    assert service.format_seconds(11) == '11 seconds'
    assert service.format_seconds(60) == '1 minute'
    assert service.format_seconds(61) == '1 minute 1 second'
    assert service.format_seconds(62) == '1 minute 2 seconds'
    assert service.format_seconds(120) == '2 minutes'
    assert service.format_seconds(125) == '2 minutes 5 seconds'
