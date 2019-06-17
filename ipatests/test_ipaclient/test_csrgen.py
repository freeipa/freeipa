#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import os
import pytest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509

from ipaclient import csrgen, csrgen_ffi
from ipalib import errors

BASE_DIR = os.path.dirname(__file__)
CSR_DATA_DIR = os.path.join(BASE_DIR, 'data', 'test_csrgen')


@pytest.fixture
def formatter():
    return csrgen.Formatter(csr_data_dir=CSR_DATA_DIR)


@pytest.fixture
def rule_provider():
    return csrgen.FileRuleProvider(csr_data_dir=CSR_DATA_DIR)


@pytest.fixture
def generator():
    return csrgen.CSRGenerator(csrgen.FileRuleProvider())


class StubRuleProvider(csrgen.RuleProvider):
    def __init__(self):
        self.syntax_rule = csrgen.Rule(
            'syntax', '{{datarules|join(",")}}', {})
        self.data_rule = csrgen.Rule('data', 'data_template', {})
        self.field_mapping = csrgen.FieldMapping(
            'example', self.syntax_rule, [self.data_rule])
        self.rules = [self.field_mapping]

    def rules_for_profile(self, profile_id):
        return self.rules


class IdentityFormatter(csrgen.Formatter):
    base_template_name = 'identity_base.tmpl'

    def __init__(self):
        super(IdentityFormatter, self).__init__(csr_data_dir=CSR_DATA_DIR)

    def _get_template_params(self, syntax_rules):
        return {'options': syntax_rules}


class test_Formatter:
    def test_prepare_data_rule_with_data_source(self, formatter):
        data_rule = csrgen.Rule('uid', '{{subject.uid.0}}',
                                {'data_source': 'subject.uid.0'})
        prepared = formatter._prepare_data_rule(data_rule)
        assert prepared == '{% if subject.uid.0 %}{{subject.uid.0}}{% endif %}'

    def test_prepare_data_rule_no_data_source(self, formatter):
        """Not a normal case, but we should handle it anyway"""
        data_rule = csrgen.Rule('uid', 'static_text', {})
        prepared = formatter._prepare_data_rule(data_rule)
        assert prepared == 'static_text'

    def test_prepare_syntax_rule_with_data_sources(self, formatter):
        syntax_rule = csrgen.Rule(
            'example', '{{datarules|join(",")}}', {})
        data_rules = ['{{subject.field1}}', '{{subject.field2}}']
        data_sources = ['subject.field1', 'subject.field2']
        prepared = formatter._prepare_syntax_rule(
            syntax_rule, data_rules, 'example', data_sources)

        assert prepared == (
            '{% if subject.field1 or subject.field2 %}{{subject.field1}},'
            '{{subject.field2}}{% endif %}')

    def test_prepare_syntax_rule_with_combinator(self, formatter):
        syntax_rule = csrgen.Rule('example', '{{datarules|join(",")}}',
                                  {'data_source_combinator': 'and'})
        data_rules = ['{{subject.field1}}', '{{subject.field2}}']
        data_sources = ['subject.field1', 'subject.field2']
        prepared = formatter._prepare_syntax_rule(
            syntax_rule, data_rules, 'example', data_sources)

        assert prepared == (
            '{% if subject.field1 and subject.field2 %}{{subject.field1}},'
            '{{subject.field2}}{% endif %}')

    def test_prepare_syntax_rule_required(self, formatter):
        syntax_rule = csrgen.Rule('example', '{{datarules|join(",")}}',
                                  {'required': True})
        data_rules = ['{{subject.field1}}']
        data_sources = ['subject.field1']
        prepared = formatter._prepare_syntax_rule(
            syntax_rule, data_rules, 'example', data_sources)

        assert prepared == (
            '{% filter required("example") %}{% if subject.field1 %}'
            '{{subject.field1}}{% endif %}{% endfilter %}')

    def test_prepare_syntax_rule_passthrough(self, formatter):
        """
        Calls to macros defined as passthrough are still call tags in the final
        template.
        """
        formatter._define_passthrough('example.macro')

        syntax_rule = csrgen.Rule(
            'example',
            '{% call example.macro() %}{{datarules|join(",")}}{% endcall %}',
            {})
        data_rules = ['{{subject.field1}}']
        data_sources = ['subject.field1']
        prepared = formatter._prepare_syntax_rule(
            syntax_rule, data_rules, 'example', data_sources)

        assert prepared == (
            '{% if subject.field1 %}{% call example.macro() %}'
            '{{subject.field1}}{% endcall %}{% endif %}')

    def test_prepare_syntax_rule_no_data_sources(self, formatter):
        """Not a normal case, but we should handle it anyway"""
        syntax_rule = csrgen.Rule(
            'example', '{{datarules|join(",")}}', {})
        data_rules = ['rule1', 'rule2']
        data_sources = []
        prepared = formatter._prepare_syntax_rule(
            syntax_rule, data_rules, 'example', data_sources)

        assert prepared == 'rule1,rule2'


class test_FileRuleProvider:
    def test_rule_basic(self, rule_provider):
        rule_name = 'basic'

        rule = rule_provider._rule(rule_name)

        assert rule.template == 'openssl_rule'

    def test_rule_global_options(self, rule_provider):
        rule_name = 'options'

        rule = rule_provider._rule(rule_name)

        assert rule.options['rule_option'] is True

    def test_rule_nosuchrule(self, rule_provider):
        with pytest.raises(errors.NotFound):
            rule_provider._rule('nosuchrule')

    def test_rules_for_profile_success(self, rule_provider):
        rules = rule_provider.rules_for_profile('profile')

        assert len(rules) == 1
        field_mapping = rules[0]
        assert field_mapping.syntax_rule.name == 'basic'
        assert len(field_mapping.data_rules) == 1
        assert field_mapping.data_rules[0].name == 'options'

    def test_rules_for_profile_nosuchprofile(self, rule_provider):
        with pytest.raises(errors.NotFound):
            rule_provider.rules_for_profile('nosuchprofile')


class test_CSRGenerator:
    def test_userCert_OpenSSL(self, generator):
        principal = {
            'uid': ['testuser'],
            'mail': ['testuser@example.com'],
        }
        config = {
            'ipacertificatesubjectbase': [
                'O=DOMAIN.EXAMPLE.COM'
            ],
        }

        script = generator.csr_config(principal, config, 'userCert')
        with open(os.path.join(
                CSR_DATA_DIR, 'configs', 'userCert.conf')) as f:
            expected_script = f.read()
        assert script == expected_script

    def test_caIPAserviceCert_OpenSSL(self, generator):
        principal = {
            'krbprincipalname': [
                'HTTP/machine.example.com@DOMAIN.EXAMPLE.COM'
            ],
        }
        config = {
            'ipacertificatesubjectbase': [
                'O=DOMAIN.EXAMPLE.COM'
            ],
        }

        script = generator.csr_config(
            principal, config, 'caIPAserviceCert')
        with open(os.path.join(
                CSR_DATA_DIR, 'configs', 'caIPAserviceCert.conf')) as f:
            expected_script = f.read()
        assert script == expected_script

    def test_works_with_lowercase_attr_type_shortname(self, generator):
        principal = {
            'uid': ['testuser'],
            'mail': ['testuser@example.com'],
        }
        template_env = {
            'ipacertificatesubjectbase': [
                'o=DOMAIN.EXAMPLE.COM'  # lower-case attr type shortname
            ],
        }
        config = generator.csr_config(principal, template_env, 'userCert')

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        adaptor = csrgen.OpenSSLAdaptor(key=key)

        reqinfo = bytes(csrgen_ffi.build_requestinfo(
            config.encode('utf-8'), adaptor.get_subject_public_key_info()))
        csr_der = adaptor.sign_csr(reqinfo)
        csr = x509.load_der_x509_csr(csr_der, default_backend())
        assert (
            csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            == [x509.NameAttribute(x509.NameOID.COMMON_NAME, u'testuser')]
        )
        assert (
            csr.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
            == [x509.NameAttribute(
                x509.NameOID.ORGANIZATION_NAME, u'DOMAIN.EXAMPLE.COM')]
        )

    def test_unrecognised_attr_type_raises(self, generator):
        principal = {
            'uid': ['testuser'],
            'mail': ['testuser@example.com'],
        }
        template_env = {
            'ipacertificatesubjectbase': [
                'X=DOMAIN.EXAMPLE.COM'  # unrecognised attr type
            ],
        }
        config = generator.csr_config(principal, template_env, 'userCert')

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        adaptor = csrgen.OpenSSLAdaptor(key=key)

        with pytest.raises(
                errors.CSRTemplateError,
                match=r'^unrecognised attribute type: X$'):
            csrgen_ffi.build_requestinfo(
                config.encode('utf-8'), adaptor.get_subject_public_key_info())


class test_rule_handling:
    def test_optionalAttributeMissing(self, generator):
        principal = {'uid': 'testuser'}
        rule_provider = StubRuleProvider()
        rule_provider.data_rule.template = '{{subject.mail}}'
        rule_provider.data_rule.options = {'data_source': 'subject.mail'}
        generator = csrgen.CSRGenerator(
            rule_provider, formatter_class=IdentityFormatter)

        script = generator.csr_config(
            principal, {}, 'example')
        assert script == '\n'

    def test_twoDataRulesOneMissing(self, generator):
        principal = {'uid': 'testuser'}
        rule_provider = StubRuleProvider()
        rule_provider.data_rule.template = '{{subject.mail}}'
        rule_provider.data_rule.options = {'data_source': 'subject.mail'}
        rule_provider.field_mapping.data_rules.append(csrgen.Rule(
            'data2', '{{subject.uid}}', {'data_source': 'subject.uid'}))
        generator = csrgen.CSRGenerator(
            rule_provider, formatter_class=IdentityFormatter)

        script = generator.csr_config(principal, {}, 'example')
        assert script == ',testuser\n'

    def test_requiredAttributeMissing(self):
        principal = {'uid': 'testuser'}
        rule_provider = StubRuleProvider()
        rule_provider.data_rule.template = '{{subject.mail}}'
        rule_provider.data_rule.options = {'data_source': 'subject.mail'}
        rule_provider.syntax_rule.options = {'required': True}
        generator = csrgen.CSRGenerator(
            rule_provider, formatter_class=IdentityFormatter)

        with pytest.raises(errors.CSRTemplateError):
            _script = generator.csr_config(
                principal, {}, 'example')
