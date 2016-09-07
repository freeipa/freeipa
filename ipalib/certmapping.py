#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import collections
import jinja2
import jinja2.ext
import jinja2.sandbox
import json
import os.path
import traceback

from ipalib import api
from ipalib import errors
from ipalib.text import _
from ipapython.ipa_log_manager import root_logger
from ipapython.templating import IPAExtension

import six

if six.PY3:
    unicode = str

__doc__ = _("""
Routines for constructing certificate signing requests using IPA data and
stored mapping rules.
""")

CSR_DATA_DIR = '/usr/share/ipa/csr'


class IndexableUndefined(jinja2.Undefined):
    def __getitem__(self, key):
        return jinja2.Undefined(
            hint=self._undefined_hint, obj=self._undefined_obj,
            name=self._undefined_name, exc=self._undefined_exception)


class Formatter(object):
    """
    Class for processing a set of mapping rules into a template.

    The template can be rendered with user and database data to produce a
    script, which generates a CSR when run.

    Subclasses of Formatter should set the value of base_template_name to the
    filename of a base template with spaces for the processed rules.
    Additionally, they should override the _get_template_params method to
    produce the correct output for the base template.
    """
    base_template_name = None

    def __init__(self):
        self.jinja2 = jinja2.sandbox.SandboxedEnvironment(
            loader=jinja2.FileSystemLoader(
                os.path.join(CSR_DATA_DIR, 'templates')),
            extensions=[jinja2.ext.ExprStmtExtension, IPAExtension],
            keep_trailing_newline=True, undefined=IndexableUndefined)

        self.passthrough_globals = {}

    def _define_passthrough(self, call):

        def passthrough(caller):
            return u'{%% call %s() %%}%s{%% endcall %%}' % (call, caller())

        parts = call.split('.')
        current_level = self.passthrough_globals
        for part in parts[:-1]:
            if part not in current_level:
                current_level[part] = {}
            current_level = current_level[part]
        current_level[parts[-1]] = passthrough

    def build_template(self, rules):
        """
        Construct a template that can produce CSR generator strings.

        :param rules: list of MappingRuleset to use to populate the template.

        :returns: jinja2.Template that can be rendered to produce the CSR data.
        """
        syntax_rules = []
        for description, syntax_rule, data_rules in rules:
            data_rules_prepared = [
                self._prepare_data_rule(rule) for rule in data_rules]

            data_sources = []
            for rule in data_rules:
                data_source = rule.options.get('data_source')
                if data_source:
                    data_sources.append(data_source)

            syntax_rules.append(self._prepare_syntax_rule(
                syntax_rule, data_rules_prepared, description, data_sources))

        template_params = self._get_template_params(syntax_rules)
        base_template = self.jinja2.get_template(
            self.base_template_name, globals=self.passthrough_globals)

        try:
            combined_template_source = base_template.render(**template_params)
        except jinja2.UndefinedError:
            root_logger.debug(traceback.format_exc())
            raise errors.CertificateMappingError(reason=_(
                'Template error when formatting certificate data'))

        root_logger.debug(
            'Formatting with template: %s' % combined_template_source)
        combined_template = self.jinja2.from_string(combined_template_source)

        return combined_template

    def _wrap_conditional(self, rule, condition):
        rule = '{%% if %s %%}%s{%% endif %%}' % (condition, rule)
        return rule

    def _wrap_required(self, rule, description):
        template = '{%% filter required("%s") %%}%s{%% endfilter %%}' % (
            description, rule)

        return template

    def _prepare_data_rule(self, data_rule):
        template = data_rule.template

        data_source = data_rule.options.get('data_source')
        if data_source:
            template = self._wrap_conditional(template, data_source)

        return template

    def _prepare_syntax_rule(self, syntax_rule, data_rules, description, data_sources):
        root_logger.debug('Syntax rule template: %s' % syntax_rule.template)
        template = self.jinja2.from_string(
            syntax_rule.template, globals=self.passthrough_globals)
        is_required = syntax_rule.options.get('required', False)
        try:
            rendered = template.render(datarules=data_rules)
        except jinja2.UndefinedError:
            root_logger.debug(traceback.format_exc())
            raise errors.CertificateMappingError(reason=_(
                'Template error when formatting certificate data'))

        combinator = ' %s ' % syntax_rule.options.get(
            'data_source_combinator', 'or')
        condition = combinator.join(data_sources)
        prepared_template = self._wrap_conditional(rendered, condition)
        if is_required:
            prepared_template = self._wrap_required(
                prepared_template, description)

        return prepared_template

    def _get_template_params(self, syntax_rules):
        """
        Package the syntax rules into fields expected by the base template.

        :param syntax_rules: list of prepared syntax rules to be included in
            the template.

        :returns: dict of values needed to render the base template.
        """
        raise NotImplementedError('Formatter class must be subclassed')


class OpenSSLFormatter(Formatter):
    """Formatter class supporting the openssl command-line tool."""

    base_template_name = 'openssl_base.tmpl'

    # Syntax rules are wrapped in this data structure, to keep track of whether
    # each goes in the extension or the root section
    SyntaxRule = collections.namedtuple(
        'SyntaxRule', ['template', 'is_extension'])

    def __init__(self):
        super(OpenSSLFormatter, self).__init__()
        self._define_passthrough('openssl.section')

    def _get_template_params(self, syntax_rules):
        parameters = [rule.template for rule in syntax_rules
                      if not rule.is_extension]
        extensions = [rule.template for rule in syntax_rules
                      if rule.is_extension]

        return {'parameters': parameters, 'extensions': extensions}

    def _prepare_syntax_rule(self, syntax_rule, data_rules, description, data_sources):
        """Overrides method to pull out whether rule is an extension or not."""
        prepared_template = super(OpenSSLFormatter, self)._prepare_syntax_rule(
            syntax_rule, data_rules, description, data_sources)
        is_extension = syntax_rule.options.get('extension', False)
        return self.SyntaxRule(prepared_template, is_extension)


class CertutilFormatter(Formatter):
    base_template_name = 'certutil_base.tmpl'

    def _get_template_params(self, syntax_rules):
        return {'options': syntax_rules}


# FieldMapping - representation of the rules needed to construct a complete
# certificate field.
# - description: str, a name or description of this field, to be used in
#   messages
# - syntax_rule: Rule, the rule defining the syntax of this field
# - data_rules: list of Rule, the rules that produce data to be stored in this
#   field
FieldMapping = collections.namedtuple(
    'FieldMapping', ['description', 'syntax_rule', 'data_rules'])
Rule = collections.namedtuple(
    'Rule', ['name', 'template', 'options'])


class RuleProvider(object):
    def rules_for_profile(self, profile_id, helper):
        """
        Return the rules needed to build a CSR for the given certificate
        profile.

        :param profile_id: str, name of the certificate profile to use
        :param helper: str, name of tool (e.g. openssl, certutil) that will be
            used to create CSR

        :returns: list of FieldMapping, filled out with the appropriate rules
        """
        raise NotImplementedError('RuleProvider class must be subclassed')


class FileRuleProvider(RuleProvider):
    def __init__(self):
        self.rules = {}

    def _rule(self, rule_name, helper):
        if (rule_name, helper) not in self.rules:
            rule_path = os.path.join(CSR_DATA_DIR, 'rules',
                                     '%s.json' % rule_name)
            with open(rule_path) as rule_file:
                ruleset = json.load(rule_file)
            try:
                rule = [r for r in ruleset['rules']
                        if r['helper'] == helper][0]
            except IndexError:
                raise errors.NotFound(
                    reason=_('No transformation in "%(ruleset)s" rule supports'
                             ' helper "%(helper)s"') %
                    {'ruleset': rule_name, 'helper': helper})

            options = {}
            if 'options' in ruleset:
                options.update(ruleset['options'])
            if 'options' in rule:
                options.update(rule['options'])
            self.rules[(rule_name, helper)] = Rule(
                rule_name, rule['template'], options)
        return self.rules[(rule_name, helper)]

    def rules_for_profile(self, profile_id, helper):
        profile_path = os.path.join(CSR_DATA_DIR, 'profiles',
                                    '%s.json' % profile_id)
        with open(profile_path) as profile_file:
            profile = json.load(profile_file)

        field_mappings = []
        for field in profile:
            syntax_rule = self._rule(field['syntax'], helper)
            data_rules = [self._rule(name, helper) for name in field['data']]
            field_mappings.append(FieldMapping(
                syntax_rule.name, syntax_rule, data_rules))
        return field_mappings


class CSRGenerator(object):
    FORMATTERS = {
        'openssl': OpenSSLFormatter,
        'certutil': CertutilFormatter,
    }

    def __init__(self, rule_provider):
        self.rule_provider = rule_provider

    def csr_script(self, principal, profile_id, helper):
        config = api.Command.config_show()['result']
        render_data = {'subject': principal, 'config': config}

        formatter = self.FORMATTERS[helper]()
        rules = self.rule_provider.rules_for_profile(profile_id, helper)
        template = formatter.build_template(rules)

        try:
            script = template.render(render_data)
        except jinja2.UndefinedError:
            root_logger.debug(traceback.format_exc())
            raise errors.CertificateMappingError(reason=_(
                'Template error when formatting certificate data'))

        return script
