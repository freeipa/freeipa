#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import collections
import errno
import json
import os.path
import pipes
import traceback

import pkg_resources

import jinja2
import jinja2.ext
import jinja2.sandbox
import six

from ipalib import api
from ipalib import errors
from ipalib.text import _
from ipapython.ipa_log_manager import log_mgr

if six.PY3:
    unicode = str

__doc__ = _("""
Routines for constructing certificate signing requests using IPA data and
stored templates.
""")

logger = log_mgr.get_logger(__name__)


class IndexableUndefined(jinja2.Undefined):
    def __getitem__(self, key):
        return jinja2.Undefined(
            hint=self._undefined_hint, obj=self._undefined_obj,
            name=self._undefined_name, exc=self._undefined_exception)


class IPAExtension(jinja2.ext.Extension):
    """Jinja2 extension providing useful features for CSR generation rules."""

    def __init__(self, environment):
        super(IPAExtension, self).__init__(environment)

        environment.filters.update(
            quote=self.quote,
            required=self.required,
        )

    def quote(self, data):
        return pipes.quote(data)

    def required(self, data, name):
        if not data:
            raise errors.CSRTemplateError(
                reason=_('Required CSR generation rule %(name)s is missing data') %
                {'name': name})
        return data


class Formatter(object):
    """
    Class for processing a set of CSR generation rules into a template.

    The template can be rendered with user and database data to produce a
    script, which generates a CSR when run.

    Subclasses of Formatter should set the value of base_template_name to the
    filename of a base template with spaces for the processed rules.
    Additionally, they should override the _get_template_params method to
    produce the correct output for the base template.
    """
    base_template_name = None

    def __init__(self, csr_data_dir=None):
        # chain loaders:
        # 1) csr_data_dir/templates
        # 2) /etc/ipa/csrgen/templates
        # 3) ipaclient/csrgen/templates
        loaders = []
        if csr_data_dir is not None:
            loaders.append(jinja2.FileSystemLoader(
                os.path.join(csr_data_dir, 'templates'))
            )
        loaders.append(jinja2.FileSystemLoader(
            os.path.join(api.env.confdir, 'csrgen/templates'))
        )
        loaders.append(jinja2.PackageLoader('ipaclient', 'csrgen/templates'))

        self.jinja2 = jinja2.sandbox.SandboxedEnvironment(
            loader=jinja2.ChoiceLoader(loaders),
            extensions=[jinja2.ext.ExprStmtExtension, IPAExtension],
            keep_trailing_newline=True, undefined=IndexableUndefined)

        self.passthrough_globals = {}

    def _define_passthrough(self, call):
        """Some macros are meant to be interpreted during the final render, not
        when data rules are interpolated into syntax rules. This method allows
        those macros to be registered so that calls to them are passed through
        to the prepared rule rather than interpreted.
        """

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

        :param rules: list of FieldMapping to use to populate the template.

        :returns: jinja2.Template that can be rendered to produce the CSR data.
        """
        syntax_rules = []
        for field_mapping in rules:
            data_rules_prepared = [
                self._prepare_data_rule(rule)
                for rule in field_mapping.data_rules]

            data_sources = []
            for rule in field_mapping.data_rules:
                data_source = rule.options.get('data_source')
                if data_source:
                    data_sources.append(data_source)

            syntax_rules.append(self._prepare_syntax_rule(
                field_mapping.syntax_rule, data_rules_prepared,
                field_mapping.description, data_sources))

        template_params = self._get_template_params(syntax_rules)
        base_template = self.jinja2.get_template(
            self.base_template_name, globals=self.passthrough_globals)

        try:
            combined_template_source = base_template.render(**template_params)
        except jinja2.UndefinedError:
            logger.debug(traceback.format_exc())
            raise errors.CSRTemplateError(reason=_(
                'Template error when formatting certificate data'))

        logger.debug(
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

    def _prepare_syntax_rule(
            self, syntax_rule, data_rules, description, data_sources):
        logger.debug('Syntax rule template: %s' % syntax_rule.template)
        template = self.jinja2.from_string(
            syntax_rule.template, globals=self.passthrough_globals)
        is_required = syntax_rule.options.get('required', False)
        try:
            prepared_template = template.render(datarules=data_rules)
        except jinja2.UndefinedError:
            logger.debug(traceback.format_exc())
            raise errors.CSRTemplateError(reason=_(
                'Template error when formatting certificate data'))

        if data_sources:
            combinator = ' %s ' % syntax_rule.options.get(
                'data_source_combinator', 'or')
            condition = combinator.join(data_sources)
            prepared_template = self._wrap_conditional(
                prepared_template, condition)

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

    def __init__(self, *args, **kwargs):
        super(OpenSSLFormatter, self).__init__(*args, **kwargs)
        self._define_passthrough('openssl.section')

    def _get_template_params(self, syntax_rules):
        parameters = [rule.template for rule in syntax_rules
                      if not rule.is_extension]
        extensions = [rule.template for rule in syntax_rules
                      if rule.is_extension]

        return {'parameters': parameters, 'extensions': extensions}

    def _prepare_syntax_rule(
            self, syntax_rule, data_rules, description, data_sources):
        """Overrides method to pull out whether rule is an extension or not."""
        prepared_template = super(OpenSSLFormatter, self)._prepare_syntax_rule(
            syntax_rule, data_rules, description, data_sources)
        is_extension = syntax_rule.options.get('extension', False)
        return self.SyntaxRule(prepared_template, is_extension)


class CertutilFormatter(Formatter):
    base_template_name = 'certutil_base.tmpl'

    def _get_template_params(self, syntax_rules):
        return {'options': syntax_rules}


class FieldMapping(object):
    """Representation of the rules needed to construct a complete cert field.

    Attributes:
        description: str, a name or description of this field, to be used in
            messages
        syntax_rule: Rule, the rule defining the syntax of this field
        data_rules: list of Rule, the rules that produce data to be stored in
            this field
    """
    __slots__ = ['description', 'syntax_rule', 'data_rules']

    def __init__(self, description, syntax_rule, data_rules):
        self.description = description
        self.syntax_rule = syntax_rule
        self.data_rules = data_rules


class Rule(object):
    __slots__ = ['name', 'template', 'options']

    def __init__(self, name, template, options):
        self.name = name
        self.template = template
        self.options = options


class RuleProvider(object):
    def rules_for_profile(self, profile_id, helper):
        """
        Return the rules needed to build a CSR using the given profile.

        :param profile_id: str, name of the CSR generation profile to use
        :param helper: str, name of tool (e.g. openssl, certutil) that will be
            used to create CSR

        :returns: list of FieldMapping, filled out with the appropriate rules
        """
        raise NotImplementedError('RuleProvider class must be subclassed')


class FileRuleProvider(RuleProvider):
    def __init__(self, csr_data_dir=None):
        self.rules = {}
        self._csrgen_data_dirs = []
        if csr_data_dir is not None:
            self._csrgen_data_dirs.append(csr_data_dir)
        self._csrgen_data_dirs.append(
            os.path.join(api.env.confdir, 'csrgen')
        )
        self._csrgen_data_dirs.append(
            pkg_resources.resource_filename('ipaclient', 'csrgen')
        )

    def _open(self, subdir, filename):
        for data_dir in self._csrgen_data_dirs:
            path = os.path.join(data_dir, subdir, filename)
            try:
                return open(path)
            except IOError as e:
                if e.errno != errno.ENOENT:
                    raise
        raise IOError(
            errno.ENOENT,
            "'{}' not found in {}".format(
                os.path.join(subdir, filename),
                ", ".join(self._csrgen_data_dirs)
            )
        )

    def _rule(self, rule_name, helper):
        if (rule_name, helper) not in self.rules:
            try:
                with self._open('rules', '%s.json' % rule_name) as f:
                    ruleset = json.load(f)
            except IOError:
                raise errors.NotFound(
                    reason=_('Ruleset %(ruleset)s does not exist.') %
                    {'ruleset': rule_name})

            matching_rules = [r for r in ruleset['rules']
                              if r['helper'] == helper]
            if len(matching_rules) == 0:
                raise errors.EmptyResult(
                    reason=_('No transformation in "%(ruleset)s" rule supports'
                             ' helper "%(helper)s"') %
                    {'ruleset': rule_name, 'helper': helper})
            elif len(matching_rules) > 1:
                raise errors.RedundantMappingRule(
                    ruleset=rule_name, helper=helper)
            rule = matching_rules[0]

            options = {}
            if 'options' in ruleset:
                options.update(ruleset['options'])
            if 'options' in rule:
                options.update(rule['options'])

            self.rules[(rule_name, helper)] = Rule(
                rule_name, rule['template'], options)

        return self.rules[(rule_name, helper)]

    def rules_for_profile(self, profile_id, helper):
        try:
            with self._open('profiles', '%s.json' % profile_id) as f:
                profile = json.load(f)
        except IOError:
            raise errors.NotFound(
                reason=_('No CSR generation rules are defined for profile'
                         ' %(profile_id)s') % {'profile_id': profile_id})

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

    def csr_script(self, principal, config, profile_id, helper):
        render_data = {'subject': principal, 'config': config}

        formatter = self.FORMATTERS[helper]()
        rules = self.rule_provider.rules_for_profile(profile_id, helper)
        template = formatter.build_template(rules)

        try:
            script = template.render(render_data)
        except jinja2.UndefinedError:
            logger.debug(traceback.format_exc())
            raise errors.CSRTemplateError(reason=_(
                'Template error when formatting certificate data'))

        return script
