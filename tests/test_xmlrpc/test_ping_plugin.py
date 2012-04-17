# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2012  Red Hat
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
Test the `ipalib/plugins/ping.py` module, and XML-RPC in general.
"""

from ipalib import api, errors, _
from tests.util import assert_equal, Fuzzy
from xmlrpc_test import Declarative


class test_ping(Declarative):

    tests = [
        dict(
            desc='Ping the server',
            command=('ping', [], {}),
            expected=dict(
                summary=Fuzzy('IPA server version .*. API version .*')),
        ),

        dict(
            desc='Try to ping with an argument',
            command=('ping', ['bad_arg'], {}),
            expected=errors.ZeroArgumentError(name='ping'),
        ),

        dict(
            desc='Try to ping with an option',
            command=('ping', [], dict(bad_arg=True)),
            expected=errors.OptionError(_('Unknown option: %(option)s'),
                option='bad_arg'),
        ),

    ]
