# encoding: utf-8
# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
Test the `ipalib.encoder` module.
"""

import string

from tests.util import ClassChecker, assert_equal
from ipalib.encoder import Encoder, encode_args, decode_retval

_test_str_d = u'ěščřžýáíé'
_test_str_e = u'ěščřžýáíé'.encode(Encoder.encode_to)

class test_Encoder(ClassChecker):
    """
    Test the `ipalib.encoder.Encoder` class.
    """
    _cls = Encoder

    def test_encode(self):
        """
        Test the `ipalib.encoder.Encoder.encode` method.
        """
        o = self.cls()
        o.encode_postprocessor = lambda x: x
        # strings
        assert_equal(o.encode('ahoj'), 'ahoj'.encode(o.encode_to))
        assert_equal(o.encode(_test_str_d), _test_str_e)
        # bool, float, int, long
        assert_equal(o.encode(True), str(True).encode(o.encode_to))
        assert_equal(o.encode(1.01), str(1.01).encode(o.encode_to))
        assert_equal(o.encode(1000), str(1000).encode(o.encode_to))
        assert_equal(o.encode(long(1)), str(long(1)).encode(o.encode_to))
        # lists
        expected = [_test_str_e, '1']
        assert_equal(o.encode([_test_str_d, 1]), expected)
        expected = ['1', ['1', '2', '3']]
        assert_equal(o.encode([1, [1, 2, 3]]), expected)
        # tuples
        expected = (_test_str_e, '1')
        assert_equal(o.encode((_test_str_d, 1)), expected)
        expected = ('1', ('1', '2', '3'))
        assert_equal(o.encode((1, (1, 2, 3))), expected)
        # dicts: only values, no postprocessing
        o.encode_dict_keys = False
        o.encode_dict_keys_postprocess = False
        o.encode_dict_vals = True
        o.encode_dict_vals_postprocess = False
        expected = {_test_str_d: _test_str_e}
        assert_equal(o.encode({_test_str_d: _test_str_d}), expected)
        # dicts: only keys, no postprocessing
        o.encode_dict_keys = True
        o.encode_dict_vals = False
        expected = {_test_str_e: _test_str_d}
        assert_equal(o.encode({_test_str_d: _test_str_d}), expected)
        # dicts: both keys and values, no postprocessing
        o.encode_dict_vals = True
        expected = {_test_str_e: _test_str_e}
        assert_equal(o.encode({_test_str_d: _test_str_d}), expected)
        # dicts: both keys and values, postprocessing on keys only
        o.encode_dict_keys = True
        o.encode_dict_keys_postprocess = True
        o.encode_postprocessor = string.upper
        expected = {_test_str_e.upper(): _test_str_e}
        assert_equal(o.encode({u'ěščřžýáíé': u'ěščřžýáíé'}), expected)
        # None
        o.encode_postprocessor = lambda x: x
        o.encode_none = False
        assert_equal(o.encode(None), None)
        o.encode_none = True
        assert_equal(o.encode(None), str(None).encode(o.encode_to))

    def test_decode(self):
        """
        Test the `ipalib.encoder.Encoder.decode` method.
        """
        o = self.cls()
        o.decode_postprocessor = lambda x: x
        # strings
        assert_equal(o.decode('ahoj'), 'ahoj'.decode(o.decode_from))
        assert_equal(o.decode(_test_str_e), _test_str_d)
        # bool, float, int, long
        assert_equal(o.decode('True'), str(True).decode(o.decode_from))
        assert_equal(o.decode('1.01'), str(1.01).decode(o.decode_from))
        assert_equal(o.decode('1000'), str(1000).decode(o.decode_from))
        assert_equal(o.decode('1'), str(long(1)).decode(o.decode_from))
        # lists
        expected = [_test_str_d, '1']
        assert_equal(o.decode([_test_str_e, '1']), expected)
        expected = [u'1', [u'1', u'2', u'3']]
        assert_equal(o.decode(['1', ['1', '2', '3']]), expected)
        # tuples
        expected = (_test_str_d, '1')
        assert_equal(o.decode((_test_str_e, 1)), expected)
        expected = (u'1', (u'1', u'2', u'3'))
        assert_equal(o.decode(('1', ('1', '2', '3'))), expected)
        # dicts: only values, no postprocessing
        o.decode_dict_keys = False
        o.decode_dict_keys_postprocess = False
        o.decode_dict_vals = True
        o.decode_dict_vals_postprocess = False
        expected = {_test_str_e: _test_str_d}
        assert_equal(o.decode({_test_str_e: _test_str_e}), expected)
        # dicts: only keys, no postprocessing
        o.decode_dict_keys = True
        o.decode_dict_vals = False
        expected = {_test_str_d: _test_str_e}
        assert_equal(o.decode({_test_str_e: _test_str_e}), expected)
        # dicts: both keys and values, no postprocessing
        o.decode_dict_vals = True
        expected = {_test_str_d: _test_str_d}
        assert_equal(o.decode({_test_str_e: _test_str_e}), expected)
        # dicts: both keys and values, postprocessing on keys only
        o.decode_dict_keys = True
        o.decode_dict_keys_postprocess = True
        o.decode_postprocessor = string.upper
        expected = {_test_str_d.upper(): _test_str_d}
        assert_equal(o.decode({_test_str_e: _test_str_e}), expected)
        # TODO: dict decoding using a table
        # None
        o.decode_postprocessor = lambda x: x
        o.decode_none = False
        assert_equal(o.decode(None), None)
        o.decode_none = True
        assert_equal(o.decode(None), str(None).decode(o.encode_to))

