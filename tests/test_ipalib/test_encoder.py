# encoding: utf-8
# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
Test the `ipalib.encoder` module.
"""

import string

from tests.util import ClassChecker, assert_equal
from ipalib.encoder import Encoder, EncoderSettings, encode_args, decode_retval

_encoder_settings = EncoderSettings()

_test_str_d = u'ěščřžýáíé'
_test_str_e = u'ěščřžýáíé'.encode(_encoder_settings.encode_to)


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
        encode_to = o.encoder_settings.encode_to
        o.encoder_settings.encode_postprocessor = lambda x: x
        # strings
        assert_equal(o.encode('ahoj'), 'ahoj'.encode(encode_to))
        assert_equal(o.encode(_test_str_d), _test_str_e)
        # bool, float, int, long
        assert_equal(o.encode(True), str(True).encode(encode_to))
        assert_equal(o.encode(1.01), str(1.01).encode(encode_to))
        assert_equal(o.encode(1000), str(1000).encode(encode_to))
        assert_equal(o.encode(long(1)), str(long(1)).encode(encode_to))
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
        o.encoder_settings.encode_dict_keys = False
        o.encoder_settings.encode_dict_keys_postprocess = False
        o.encoder_settings.encode_dict_vals = True
        o.encoder_settings.encode_dict_vals_postprocess = False
        expected = {_test_str_d: _test_str_e}
        assert_equal(o.encode({_test_str_d: _test_str_d}), expected)
        # dicts: only keys, no postprocessing
        o.encoder_settings.encode_dict_keys = True
        o.encoder_settings.encode_dict_vals = False
        expected = {_test_str_e: _test_str_d}
        assert_equal(o.encode({_test_str_d: _test_str_d}), expected)
        # dicts: both keys and values, no postprocessing
        o.encoder_settings.encode_dict_vals = True
        expected = {_test_str_e: _test_str_e}
        assert_equal(o.encode({_test_str_d: _test_str_d}), expected)
        # dicts: both keys and values, postprocessing on keys only
        o.encoder_settings.encode_dict_keys = True
        o.encoder_settings.encode_dict_keys_postprocess = True
        o.encoder_settings.encode_postprocessor = string.upper
        expected = {_test_str_e.upper(): _test_str_e}
        assert_equal(o.encode({u'ěščřžýáíé': u'ěščřžýáíé'}), expected)
        # None
        o.encoder_settings.encode_postprocessor = lambda x: x
        o.encoder_settings.encode_none = False
        assert_equal(o.encode(None), None)
        o.encoder_settings.encode_none = True
        assert_equal(o.encode(None), str(None).encode(encode_to))

    def test_decode(self):
        """
        Test the `ipalib.encoder.Encoder.decode` method.
        """
        o = self.cls()
        decode_from = o.encoder_settings.decode_from
        o.encoder_settings.decode_postprocessor = lambda x: x
        # strings
        assert_equal(o.decode('ahoj'), 'ahoj'.decode(decode_from))
        assert_equal(o.decode(_test_str_e), _test_str_d)
        # bool, float, int, long
        assert_equal(o.decode('True'), str(True).decode(decode_from))
        assert_equal(o.decode('1.01'), str(1.01).decode(decode_from))
        assert_equal(o.decode('1000'), str(1000).decode(decode_from))
        assert_equal(o.decode('1'), str(long(1)).decode(decode_from))
        # lists
        expected = [_test_str_d, '1']
        assert_equal(o.decode([_test_str_e, '1']), expected)
        expected = [u'1', [u'1', u'2', u'3']]
        assert_equal(o.decode(['1', ['1', '2', '3']]), expected)
        # tuples
        expected = (_test_str_d, 1)
        assert_equal(o.decode((_test_str_e, 1)), expected)
        expected = (u'1', (u'1', u'2', u'3'))
        assert_equal(o.decode(('1', ('1', '2', '3'))), expected)
        # dicts: only values, no postprocessing
        o.encoder_settings.decode_dict_keys = False
        o.encoder_settings.decode_dict_keys_postprocess = False
        o.encoder_settings.decode_dict_vals = True
        o.encoder_settings.decode_dict_vals_postprocess = False
        expected = {_test_str_e: _test_str_d}
        assert_equal(o.decode({_test_str_e: _test_str_e}), expected)
        # dicts: only keys, no postprocessing
        o.encoder_settings.decode_dict_keys = True
        o.encoder_settings.decode_dict_vals = False
        expected = {_test_str_d: _test_str_e}
        assert_equal(o.decode({_test_str_e: _test_str_e}), expected)
        # dicts: both keys and values, no postprocessing
        o.encoder_settings.decode_dict_vals = True
        expected = {_test_str_d: _test_str_d}
        assert_equal(o.decode({_test_str_e: _test_str_e}), expected)
        # dicts: both keys and values, postprocessing on keys only
        o.encoder_settings.decode_dict_keys = True
        o.encoder_settings.decode_dict_keys_postprocess = True
        o.encoder_settings.decode_postprocessor = string.upper
        expected = {_test_str_d.upper(): _test_str_d}
        assert_equal(o.decode({_test_str_e: _test_str_e}), expected)
        # TODO: dict decoding using a table
        # None
        o.encoder_settings.decode_postprocessor = lambda x: x
        o.encoder_settings.decode_none = False
        assert_equal(o.decode(None), None)
        o.encoder_settings.decode_none = True
        assert_equal(o.decode(None), str(None).decode(decode_from))

