# Authors:
#   Nathaniel McCallum <npmccallum@redhat.com>
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

import codecs
import os
import pytest

from ipaserver.install.ipa_otptoken_import import (
    PSKCDocument, CSVDocument, ValidationError)
from ipaserver.install.ipa_otptoken_import import convertHashName

basename = os.path.join(os.path.dirname(__file__), "data")

@pytest.mark.tier1
class test_otptoken_import(object):
    def test_figure3(self):
        doc = PSKCDocument(os.path.join(basename, "pskc-figure3.xml"))
        assert doc.keyname is None
        assert [(t.id, t.options) for t in doc.getKeyPackages()] == \
            [(u'12345678', {
                'ipatokenotpkey': u'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
                'ipatokenvendor': u'Manufacturer',
                'ipatokenserial': u'987654321',
                'ipatokenhotpcounter': 0,
                'ipatokenotpdigits': 8,
                'type': u'hotp',
                })]

    def test_figure4(self):
        doc = PSKCDocument(os.path.join(basename, "pskc-figure4.xml"))
        assert doc.keyname is None
        try:
            [(t.id, t.options) for t in doc.getKeyPackages()]
        except ValidationError: # Referenced keys are not supported.
            pass
        else:
            assert False

    def test_figure5(self):
        doc = PSKCDocument(os.path.join(basename, "pskc-figure5.xml"))
        assert doc.keyname is None
        try:
            [(t.id, t.options) for t in doc.getKeyPackages()]
        except ValidationError: # PIN Policy is not supported.
            pass
        else:
            assert False

    def test_figure6(self):
        doc = PSKCDocument(os.path.join(basename, "pskc-figure6.xml"))
        assert doc.keyname == 'Pre-shared-key'
        doc.setKey(codecs.decode('12345678901234567890123456789012', 'hex'))
        assert [(t.id, t.options) for t in doc.getKeyPackages()] == \
            [(u'12345678', {
                'ipatokenotpkey': u'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
                'ipatokenvendor': u'Manufacturer',
                'ipatokenserial': u'987654321',
                'ipatokenhotpcounter': 0,
                'ipatokenotpdigits': 8,
                'type': u'hotp'})]

    def test_figure7(self):
        doc = PSKCDocument(os.path.join(basename, "pskc-figure7.xml"))
        assert doc.keyname == 'My Password 1'
        doc.setKey(b'qwerty')
        assert [(t.id, t.options) for t in doc.getKeyPackages()] == \
            [(u'123456', {
                'ipatokenotpkey': u'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
                'ipatokenvendor': u'TokenVendorAcme',
                'ipatokenserial': u'987654321',
                'ipatokenotpdigits': 8,
                'type': u'hotp'})]

    def test_figure8(self):
        try:
            PSKCDocument(os.path.join(basename, "pskc-figure8.xml"))
        except NotImplementedError: # X.509 is not supported.
            pass
        else:
            assert False

    def test_invalid(self):
        try:
            PSKCDocument(os.path.join(basename, "pskc-invalid.xml"))
        except ValueError: # File is invalid.
            pass
        else:
            assert False

    def test_mini(self):
        try:
            doc = PSKCDocument(os.path.join(basename, "pskc-mini.xml"))
            for t in doc.getKeyPackages():
                t._PSKCKeyPackage__process()
        except ValidationError: # Unsupported token type.
            pass
        else:
            assert False

    def test_full(self):
        doc = PSKCDocument(os.path.join(basename, "full.xml"))
        assert [(t.id, t.options) for t in doc.getKeyPackages()] == \
            [(u'KID1', {
                'ipatokenotpkey': u'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
                'ipatokennotafter': u'20060531000000Z',
                'ipatokennotbefore': u'20060501000000Z',
                'ipatokenserial': u'SerialNo-IssueNo',
                'ipatokentotpclockoffset': 60000,
                'ipatokenotpalgorithm': u'sha1',
                'ipatokenvendor': u'iana.dummy',
                'description': u'FriendlyName',
                'ipatokentotptimestep': 200,
                'ipatokenhotpcounter': 0,
                'ipatokenmodel': u'Model',
                'ipatokenotpdigits': 8,
                'type': u'hotp',
            })]

    def test_csv(self):
        doc = CSVDocument(os.path.join(basename, "tokens.csv"))
        assert [(t.id, t.options) for t in doc.getKeyPackages()] == \
            [('GALT10280114',
              {'ipatokenotpdigits': '6',
               'ipatokenotpkey':
               '4OT3Y7P5HDS22NL7TX6GXH33N7O3274NTPU4P6TVXW2HL3XV',
               'ipatokenserial': 'GALT10280114',
               'ipatokentotptimestep': '30',
               'type': 'totp'}),
             ('GALT10280115',
              {'ipatokenotpdigits': '6',
               'ipatokenotpkey':
               '2H3VXW2XGTRV2PDLK5P5L3Y6PGTJ3225DTTU4PDZ55PPD7VW',
               'ipatokenserial': 'GALT10280115',
               'ipatokentotptimestep': '30',
               'type': 'totp'}),
             ('GALT10280123',
              {'ipatokenotpdigits': '6',
               'ipatokenotpkey':
               '4N7FXU55PNY646WV5U4X7BW2PO7XNV45G7W5P6DPTXNOTR75',
               'ipatokenserial': 'GALT10280123',
               'ipatokentotptimestep': '30',
               'type': 'totp'}),
             ('GALT10280118',
              {'ipatokenotpdigits': '6',
               'ipatokenotpkey':
               '2XL7T25NLTRX2OOTJU27PVVZNNDN7W6O37ZZOOD7325OLTPX',
               'ipatokenserial': 'GALT10280118',
               'ipatokentotptimestep': '30',
               'type': 'totp'}),
             ('GALT10280122',
              {'ipatokenotpdigits': '6',
               'ipatokenotpkey':
               '36XPJ53O3TJVOPGRXXOHDV555OXFU247HDI72HD3X2567HS7',
               'ipatokenserial': 'GALT10280122',
               'ipatokentotptimestep': '30',
               'type': 'totp'}),
             ('GALT10280119',
              {'ipatokenotpdigits': '6',
               'ipatokenotpkey':
               'POPXLX3HWRX23O3J54N5G55U67DZ5U4OHDS33HLJW356XDLW',
               'ipatokenserial': 'GALT10280119',
               'ipatokentotptimestep': '30',
               'type': 'totp'}),
             ('GALT10280127',
              {'ipatokenotpdigits': '6',
               'ipatokenotpkey':
               '4NTLQ63XW7Z266HF3WPHXHY74NO7I76GXH3X57PFU62HDZVW',
               'ipatokenserial': 'GALT10280127',
               'ipatokentotptimestep': '30',
               'type': 'totp'}),
             ('GALT10280131',
              {'ipatokenotpdigits': '6',
               'ipatokenotpkey':
               '67LN625PO3XYOGTTP4NGXJU2N56XZVOH3PX25XHF245X3PY7',
               'ipatokenserial': 'GALT10280131',
               'ipatokentotptimestep': '30',
               'type': 'totp'}),
             ('GALT10280130',
              {'ipatokenotpdigits': '6',
               'ipatokenotpkey':
               '6NHN33357H245N3R5UN5DV5Y3PPPLYNNPF473NDR446OXNV4',
               'ipatokenserial': 'GALT10280130',
               'ipatokentotptimestep': '30',
               'type': 'totp'}),
             ('GALT10280126',
              {'ipatokenotpdigits': '6',
               'ipatokenotpkey':
               '6PGRZ44HO5732XLLPVO5W5Y336PLK6OO3TV2N5WTXX65O3Z2',
               'ipatokenserial': 'GALT10280126',
               'ipatokentotptimestep': '30',
               'type': 'totp'})]

    def test_invalid_csv(self):
        try:
            doc = CSVDocument(os.path.join(basename, "invalid-tokens.csv"))
            assert len([(t.id, t.options) for t in doc.getKeyPackages()]) == 0
        except ValidationError:  # Reading the file threw an exception
            pass
        else:
            assert False


    def test_valid_tokens(self):
        assert convertHashName('sha1') == u'sha1'
        assert convertHashName('hmac-sha1') == u'sha1'
        assert convertHashName('sha224') == u'sha224'
        assert convertHashName('hmac-sha224') == u'sha224'
        assert convertHashName('sha256') == u'sha256'
        assert convertHashName('hmac-sha256') == u'sha256'
        assert convertHashName('sha384') == u'sha384'
        assert convertHashName('hmac-sha384') == u'sha384'
        assert convertHashName('sha512') == u'sha512'
        assert convertHashName('hmac-sha512') == u'sha512'

    def test_invalid_tokens(self):
        """The conversion defaults to sha1 on unknown hashing"""
        assert convertHashName('something-sha256') == u'sha1'
        assert convertHashName('') == u'sha1'
        assert convertHashName(None) == u'sha1'
