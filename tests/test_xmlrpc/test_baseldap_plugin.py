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
Test the `ipalib.plugins.baseldap` module.
"""

from ipalib import errors
from ipalib.plugins import baseldap

def test_exc_wrapper():
    """Test the CallbackInterface._exc_wrapper helper method"""
    handled_exceptions = []

    class test_callback(baseldap.CallbackInterface):
        """Fake IPA method"""
        def test_fail(self):
            self._exc_wrapper([], {}, self.fail)(1, 2, a=1, b=2)

        def fail(self, *args, **kwargs):
            assert args == (1, 2)
            assert kwargs == dict(a=1, b=2)
            raise errors.ExecutionError('failure')

    instance = test_callback()

    # Test with one callback first

    @test_callback.register_exc_callback
    def handle_exception(self, keys, options, e, call_func, *args, **kwargs):
        assert args == (1, 2)
        assert kwargs == dict(a=1, b=2)
        handled_exceptions.append(type(e))

    instance.test_fail()
    assert handled_exceptions == [errors.ExecutionError]

    # Test with another callback added

    handled_exceptions = []

    def dont_handle(self, keys, options, e, call_func, *args, **kwargs):
        assert args == (1, 2)
        assert kwargs == dict(a=1, b=2)
        handled_exceptions.append(None)
        raise e
    test_callback.register_exc_callback(dont_handle, first=True)

    instance.test_fail()
    assert handled_exceptions == [None, errors.ExecutionError]
