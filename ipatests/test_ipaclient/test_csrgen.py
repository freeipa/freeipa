#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import os
import pytest

from ipaclient import csrgen
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

    def rules_for_profile(self, profile_id, helper):
        return self.rules


class IdentityFormatter(csrgen.Formatter):
    base_template_name = 'identity_base.tmpl'

    def __init__(self):
        super(IdentityFormatter, self).__init__(csr_data_dir=CSR_DATA_DIR)

    def _get_template_params(self, syntax_rules):
        return {'options': syntax_rules}


class IdentityCSRGenerator(csrgen.CSRGenerator):
    FORMATTERS = {'identity': IdentityFormatter}


class test_Formatter(object):
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


class test_FileRuleProvider(object):
    def test_rule_basic(self, rule_provider):
        rule_name = 'basic'

        rule1 = rule_provider._rule(rule_name, 'openssl')
        rule2 = rule_provider._rule(rule_name, 'certutil')

        assert rule1.template == 'openssl_rule'
        assert rule2.template == 'certutil_rule'

    def test_rule_global_options(self, rule_provider):
        rule_name = 'options'

        rule1 = rule_provider._rule(rule_name, 'openssl')
        rule2 = rule_provider._rule(rule_name, 'certutil')

        assert rule1.options['global_option'] is True
        assert rule2.options['global_option'] is True

    def test_rule_helper_options(self, rule_provider):
        rule_name = 'options'

        rule1 = rule_provider._rule(rule_name, 'openssl')
        rule2 = rule_provider._rule(rule_name, 'certutil')

        assert rule1.options['helper_option'] is True
        assert 'helper_option' not in rule2.options

    def test_rule_nosuchrule(self, rule_provider):
        with pytest.raises(errors.NotFound):
            rule_provider._rule('nosuchrule', 'openssl')

    def test_rule_nosuchhelper(self, rule_provider):
        with pytest.raises(errors.EmptyResult):
            rule_provider._rule('basic', 'nosuchhelper')

    def test_rules_for_profile_success(self, rule_provider):
        rules = rule_provider.rules_for_profile('profile', 'certutil')

        assert len(rules) == 1
        field_mapping = rules[0]
        assert field_mapping.syntax_rule.name == 'basic'
        assert len(field_mapping.data_rules) == 1
        assert field_mapping.data_rules[0].name == 'options'

    def test_rules_for_profile_nosuchprofile(self, rule_provider):
        with pytest.raises(errors.NotFound):
            rule_provider.rules_for_profile('nosuchprofile', 'certutil')


class test_CSRGenerator(object):
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

        script = generator.csr_script(principal, config, 'userCert', 'openssl')
        with open(os.path.join(
                CSR_DATA_DIR, 'scripts', 'userCert_openssl.sh')) as f:
            expected_script = f.read()
        assert script == expected_script

    def test_userCert_Certutil(self, generator):
        principal = {
            'uid': ['testuser'],
            'mail': ['testuser@example.com'],
        }
        config = {
            'ipacertificatesubjectbase': [
                'O=DOMAIN.EXAMPLE.COM'
            ],
        }

        script = generator.csr_script(
            principal, config, 'userCert', 'certutil')

        with open(os.path.join(
                CSR_DATA_DIR, 'scripts', 'userCert_certutil.sh')) as f:
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

        script = generator.csr_script(
            principal, config, 'caIPAserviceCert', 'openssl')
        with open(os.path.join(
                CSR_DATA_DIR, 'scripts', 'caIPAserviceCert_openssl.sh')) as f:
            expected_script = f.read()
        assert script == expected_script

    def test_caIPAserviceCert_Certutil(self, generator):
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

        script = generator.csr_script(
            principal, config, 'caIPAserviceCert', 'certutil')
        with open(os.path.join(
                CSR_DATA_DIR, 'scripts', 'caIPAserviceCert_certutil.sh')) as f:
            expected_script = f.read()
        assert script == expected_script


class test_rule_handling(object):
    def test_optionalAttributeMissing(self, generator):
        principal = {'uid': 'testuser'}
        rule_provider = StubRuleProvider()
        rule_provider.data_rule.template = '{{subject.mail}}'
        rule_provider.data_rule.options = {'data_source': 'subject.mail'}
        generator = IdentityCSRGenerator(rule_provider)

        script = generator.csr_script(
            principal, {}, 'example', 'identity')
        assert script == '\n'

    def test_twoDataRulesOneMissing(self, generator):
        principal = {'uid': 'testuser'}
        rule_provider = StubRuleProvider()
        rule_provider.data_rule.template = '{{subject.mail}}'
        rule_provider.data_rule.options = {'data_source': 'subject.mail'}
        rule_provider.field_mapping.data_rules.append(csrgen.Rule(
            'data2', '{{subject.uid}}', {'data_source': 'subject.uid'}))
        generator = IdentityCSRGenerator(rule_provider)

        script = generator.csr_script(principal, {}, 'example', 'identity')
        assert script == ',testuser\n'

    def test_requiredAttributeMissing(self):
        principal = {'uid': 'testuser'}
        rule_provider = StubRuleProvider()
        rule_provider.data_rule.template = '{{subject.mail}}'
        rule_provider.data_rule.options = {'data_source': 'subject.mail'}
        rule_provider.syntax_rule.options = {'required': True}
        generator = IdentityCSRGenerator(rule_provider)

        with pytest.raises(errors.CSRTemplateError):
            script = generator.csr_script(
                principal, {}, 'example', 'identity')
