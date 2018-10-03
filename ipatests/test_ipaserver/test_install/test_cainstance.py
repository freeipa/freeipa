#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

from binascii import hexlify
from io import StringIO
import pickle
from configparser import RawConfigParser
import pytest
from ipaserver.install import cainstance

pytestmark = pytest.mark.tier0


class test_ExternalCAProfile:
    def test_MSCSTemplateV1_good(self):
        o = cainstance.MSCSTemplateV1("MySubCA")
        assert hexlify(o.get_ext_data()) == b'1e0e004d007900530075006200430041'

    def test_MSCSTemplateV1_bad(self):
        with pytest.raises(ValueError):
            cainstance.MSCSTemplateV1("MySubCA:1")

    def test_MSCSTemplateV1_pickle_roundtrip(self):
        o = cainstance.MSCSTemplateV1("MySubCA")
        s = pickle.dumps(o)
        assert o.get_ext_data() == pickle.loads(s).get_ext_data()

    def test_MSCSTemplateV2_too_few_parts(self):
        with pytest.raises(ValueError):
            cainstance.MSCSTemplateV2("1.2.3.4")

    def test_MSCSTemplateV2_too_many_parts(self):
        with pytest.raises(ValueError):
            cainstance.MSCSTemplateV2("1.2.3.4:100:200:300")

    def test_MSCSTemplateV2_bad_oid(self):
        with pytest.raises(ValueError):
            cainstance.MSCSTemplateV2("not_an_oid:1")

    def test_MSCSTemplateV2_non_numeric_major_version(self):
        with pytest.raises(ValueError):
            cainstance.MSCSTemplateV2("1.2.3.4:major:200")

    def test_MSCSTemplateV2_non_numeric_minor_version(self):
        with pytest.raises(ValueError):
            cainstance.MSCSTemplateV2("1.2.3.4:100:minor")

    def test_MSCSTemplateV2_major_version_lt_zero(self):
        with pytest.raises(ValueError):
            cainstance.MSCSTemplateV2("1.2.3.4:-1:200")

    def test_MSCSTemplateV2_minor_version_lt_zero(self):
        with pytest.raises(ValueError):
            cainstance.MSCSTemplateV2("1.2.3.4:100:-1")

    def test_MSCSTemplateV2_major_version_gt_max(self):
        with pytest.raises(ValueError):
            cainstance.MSCSTemplateV2("1.2.3.4:4294967296:200")

    def test_MSCSTemplateV2_minor_version_gt_max(self):
        with pytest.raises(ValueError):
            cainstance.MSCSTemplateV2("1.2.3.4:100:4294967296")

    def test_MSCSTemplateV2_good_major(self):
        o = cainstance.MSCSTemplateV2("1.2.3.4:4294967295")
        assert hexlify(o.get_ext_data()) == b'300c06032a0304020500ffffffff'

    def test_MSCSTemplateV2_good_major_minor(self):
        o = cainstance.MSCSTemplateV2("1.2.3.4:4294967295:0")
        assert hexlify(o.get_ext_data()) \
            == b'300f06032a0304020500ffffffff020100'

    def test_MSCSTemplateV2_pickle_roundtrip(self):
        o = cainstance.MSCSTemplateV2("1.2.3.4:4294967295:0")
        s = pickle.dumps(o)
        assert o.get_ext_data() == pickle.loads(s).get_ext_data()

    def test_ExternalCAProfile_dispatch(self):
        """
        Test that constructing ExternalCAProfile actually returns an
        instance of the appropriate subclass.
        """
        assert isinstance(
            cainstance.ExternalCAProfile("MySubCA"),
            cainstance.MSCSTemplateV1)
        assert isinstance(
            cainstance.ExternalCAProfile("1.2.3.4:100"),
            cainstance.MSCSTemplateV2)

    def test_write_pkispawn_config_file_MSCSTemplateV1(self):
        template = cainstance.MSCSTemplateV1(u"SubCA")
        expected = (
            '[CA]\n'
            'pki_req_ext_oid = 1.3.6.1.4.1.311.20.2\n'
            'pki_req_ext_data = 1e0a00530075006200430041\n\n'
        )
        self._test_write_pkispawn_config_file(template, expected)

    def test_write_pkispawn_config_file_MSCSTemplateV2(self):
        template = cainstance.MSCSTemplateV2(u"1.2.3.4:4294967295")
        expected = (
            '[CA]\n'
            'pki_req_ext_oid = 1.3.6.1.4.1.311.21.7\n'
            'pki_req_ext_data = 300c06032a0304020500ffffffff\n\n'
        )
        self._test_write_pkispawn_config_file(template, expected)

    def _test_write_pkispawn_config_file(self, template, expected):
        """
        Test that the values we read from an ExternalCAProfile
        object can be used to produce a reasonable-looking pkispawn
        configuration.
        """
        config = RawConfigParser()
        config.optionxform = str
        config.add_section("CA")
        config.set("CA", "pki_req_ext_oid", template.ext_oid)
        config.set("CA", "pki_req_ext_data",
                   hexlify(template.get_ext_data()).decode('ascii'))
        out = StringIO()
        config.write(out)
        assert out.getvalue() == expected
