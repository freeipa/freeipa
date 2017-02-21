#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function

import copy
import os.path
import sys
import textwrap

from astroid import MANAGER, register_module_extender
from astroid import scoped_nodes
from pylint.checkers import BaseChecker
from pylint.checkers.utils import check_messages
from pylint.interfaces import IAstroidChecker
from astroid.builder import AstroidBuilder


def register(linter):
    linter.register_checker(IPAChecker(linter))


def _warning_already_exists(cls, member):
    print(
        "WARNING: member '{member}' in '{cls}' already exists".format(
            cls="{}.{}".format(cls.root().name, cls.name), member=member),
        file=sys.stderr
    )


def fake_class(name_or_class_obj, members=()):
    if isinstance(name_or_class_obj, scoped_nodes.Class):
        cl = name_or_class_obj
    else:
        cl = scoped_nodes.Class(name_or_class_obj, None)

    for m in members:
        if isinstance(m, str):
            if m in cl.locals:
                _warning_already_exists(cl, m)
            else:
                cl.locals[m] = [scoped_nodes.Class(m, None)]
        elif isinstance(m, dict):
            for key, val in m.items():
                assert isinstance(key, str), "key must be string"
                if key in cl.locals:
                    _warning_already_exists(cl, key)
                    fake_class(cl.locals[key], val)
                else:
                    cl.locals[key] = [fake_class(key, val)]
        else:
            # here can be used any astroid type
            if m.name in cl.locals:
                _warning_already_exists(cl, m.name)
            else:
                cl.locals[m.name] = [copy.copy(m)]
    return cl


fake_backend = {'Backend': [
    {'wsgi_dispatch': ['mount']},
]}

NAMESPACE_ATTRS = ['Command', 'Object', 'Method', fake_backend, 'Updater',
                   'Advice']
fake_api_env = {'env': [
    'host',
    'realm',
    'session_auth_duration',
    'session_duration_type',
    'kinit_lifetime',
]}

# this is due ipaserver.rpcserver.KerberosSession where api is undefined
fake_api = {'api': [fake_api_env] + NAMESPACE_ATTRS}

_LOGGING_ATTRS = ['debug', 'info', 'warning', 'error', 'exception',
                  'critical']
LOGGING_ATTRS = [
    {'log': _LOGGING_ATTRS},
] + _LOGGING_ATTRS

# 'class': ['generated', 'properties']
ipa_class_members = {
    # Python standard library & 3rd party classes
    'socket._socketobject': ['sendall'],

    # IPA classes
    'ipalib.base.NameSpace': [
        'add',
        'mod',
        'del',
        'show',
        'find'
    ],
    'ipalib.cli.Collector': ['__options'],
    'ipalib.config.Env': [
        {'__d': ['get']},
        {'__done': ['add']},
        'xmlrpc_uri',
        'validate_api',
        'startup_traceback',
        'verbose',
        'server',
        {'domain': dir(str)},
    ] + LOGGING_ATTRS,
    'ipalib.errors.ACIError': [
        'info',
    ],
    'ipalib.errors.ConversionError': [
        'error',
    ],
    'ipalib.errors.DatabaseError': [
        'desc',
    ],
    'ipalib.errors.NetworkError': [
        'error',
    ],
    'ipalib.errors.NotFound': [
        'reason',
    ],
    'ipalib.errors.PublicError': [
        'msg',
        'strerror',
        'kw',
    ],
    'ipalib.errors.SingleMatchExpected': [
        'found',
    ],
    'ipalib.errors.SkipPluginModule': [
        'reason',
    ],
    'ipalib.errors.ValidationError': [
        'error',
    ],
    'ipalib.errors.SchemaUpToDate': [
        'fingerprint',
        'ttl',
    ],
    'ipalib.messages.PublicMessage': [
        'msg',
        'strerror',
        'type',
        'kw',
    ],
    'ipalib.parameters.Param': [
        'cli_name',
        'cli_short_name',
        'label',
        'default',
        'doc',
        'required',
        'multivalue',
        'primary_key',
        'normalizer',
        'default_from',
        'autofill',
        'query',
        'attribute',
        'include',
        'exclude',
        'flags',
        'hint',
        'alwaysask',
        'sortorder',
        'option_group',
        'no_convert',
        'deprecated',
     ],
    'ipalib.parameters.Bool': [
        'truths',
        'falsehoods'],
    'ipalib.parameters.Data': [
        'minlength',
        'maxlength',
        'length',
        'pattern',
        'pattern_errmsg',
    ],
    'ipalib.parameters.Str': ['noextrawhitespace'],
    'ipalib.parameters.Password': ['confirm'],
    'ipalib.parameters.File': ['stdin_if_missing'],
    'ipalib.parameters.Enum': ['values'],
    'ipalib.parameters.Number': [
        'minvalue',
        'maxvalue',
    ],
    'ipalib.parameters.Decimal': [
        'precision',
        'exponential',
        'numberclass',
    ],
    'ipalib.parameters.DNSNameParam': [
        'only_absolute',
        'only_relative',
    ],
    'ipalib.parameters.Principal': [
        'require_service',
    ],
    'ipalib.plugable.API': [
        fake_api_env,
    ] + NAMESPACE_ATTRS + LOGGING_ATTRS,
    'ipalib.plugable.Plugin': [
        'Object',
        'Method',
        'Updater',
        'Advice',
    ] + LOGGING_ATTRS,
    'ipalib.util.ForwarderValidationError': [
        'msg',
    ],
    'ipaserver.install.ldapupdate.LDAPUpdate': LOGGING_ATTRS,
    'ipaserver.plugins.dns.DNSRecord': [
        'validatedns',
        'normalizedns',
    ],
    'ipaserver.rpcserver.KerberosSession': [
        fake_api,
    ] + LOGGING_ATTRS,
    'ipatests.test_integration.base.IntegrationTest': [
        'domain',
        {'master': [
            {'config': [
                {'dirman_password': dir(str)},
                {'admin_password': dir(str)},
                {'admin_name': dir(str)},
                {'dns_forwarder': dir(str)},
                {'test_dir': dir(str)},
                {'ad_admin_name': dir(str)},
                {'ad_admin_password': dir(str)},
                {'domain_level': dir(str)},
            ]},
            {'domain': [
                {'realm': dir(str)},
                {'name': dir(str)},
            ]},
            'hostname',
            'ip',
            'collect_log',
            {'run_command': [
                {'stdout_text': dir(str)},
                'stderr_text',
                'returncode',
            ]},
            {'transport': ['put_file', 'file_exists']},
            'put_file_contents',
            'get_file_contents',
            'ldap_connect',
        ]},
        'replicas',
        'clients',
        'ad_domains',
    ]
}


def fix_ipa_classes(cls):
    class_name_with_module = "{}.{}".format(cls.root().name, cls.name)
    if class_name_with_module in ipa_class_members:
        fake_class(cls, ipa_class_members[class_name_with_module])

MANAGER.register_transform(scoped_nodes.Class, fix_ipa_classes)


def pytest_config_transform():
    """pylint.config attribute
    """
    return AstroidBuilder(MANAGER).string_build(textwrap.dedent('''
    from _pytest.config import get_config
    config = get_config()
    '''))


register_module_extender(MANAGER, 'pytest', pytest_config_transform)


class IPAChecker(BaseChecker):
    __implements__ = IAstroidChecker

    name = 'ipa'
    msgs = {
        'W9901': (
            'Forbidden import %s (can\'t import from %s in %s)',
            'ipa-forbidden-import',
            'Used when an forbidden import is detected.',
        ),
    }
    options = (
        (
            'forbidden-imports',
            {
                'default': '',
                'type': 'csv',
                'metavar': '<path>[:<module>[:<module>...]][,<path>...]',
                'help': 'Modules which are forbidden to be imported in the '
                        'given paths',
            },
        ),
    )
    priority = -1

    def open(self):
        self._dir = os.path.abspath(os.path.dirname(__file__))

        self._forbidden_imports = {self._dir: []}
        for forbidden_import in self.config.forbidden_imports:
            forbidden_import = forbidden_import.split(':')
            path = os.path.join(self._dir, forbidden_import[0])
            path = os.path.abspath(path)
            modules = forbidden_import[1:]
            self._forbidden_imports[path] = modules

        self._forbidden_imports_stack = []

    def _get_forbidden_import_rule(self, node):
        path = node.path
        if path:
            path = os.path.abspath(path)
            while path.startswith(self._dir):
                if path in self._forbidden_imports:
                    return path
                path = os.path.dirname(path)
        return self._dir

    def visit_module(self, node):
        self._forbidden_imports_stack.append(
            self._get_forbidden_import_rule(node))

    def leave_module(self, node):
        self._forbidden_imports_stack.pop()

    def _check_forbidden_imports(self, node, names):
        path = self._forbidden_imports_stack[-1]
        relpath = os.path.relpath(path, self._dir)
        modules = self._forbidden_imports[path]
        for module in modules:
            module_prefix = module + '.'
            for name in names:
                if name == module or name.startswith(module_prefix):
                    self.add_message('ipa-forbidden-import',
                                     args=(name, module, relpath), node=node)

    @check_messages('ipa-forbidden-import')
    def visit_import(self, node):
        names = [n[0] for n in node.names]
        self._check_forbidden_imports(node, names)

    @check_messages('ipa-forbidden-import')
    def visit_importfrom(self, node):
        names = ['{}.{}'.format(node.modname, n[0]) for n in node.names]
        self._check_forbidden_imports(node, names)
