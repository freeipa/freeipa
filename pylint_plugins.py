#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function

import copy
import sys

from astroid import MANAGER
from astroid import scoped_nodes
from pylint.checkers import BaseChecker
from pylint.checkers.utils import check_messages
from pylint.interfaces import IAstroidChecker


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
        'verbose'
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
    'ipaserver.session.AuthManager': LOGGING_ATTRS,
    'ipaserver.session.SessionAuthManager': LOGGING_ATTRS,
    'ipaserver.session.SessionManager': LOGGING_ATTRS,
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


# prefix match is used for all values specified here --> all submodules are
# matched
# module names must be specified in absolute path
FORBIDDEN_IMPORTS = (
    # ( checked module, [# forbidden.import.1, # forbidden.import.2])
    ('ipapython', ('ipalib',)),
)


def fix_ipa_classes(cls):
    class_name_with_module = "{}.{}".format(cls.root().name, cls.name)
    if class_name_with_module in ipa_class_members:
        fake_class(cls, ipa_class_members[class_name_with_module])


class IPAImportChecker(BaseChecker):
    """Check for specified imports from FORBIDDEN_IMPORTS and return
    warning when module is not allowed ot be imported
    into the particular module"""

    __implements__ = IAstroidChecker

    name = 'ipa-imports'
    msgs = {
        'W9999': (
            'IPA: forbidden import "%s" ("%s" should not import "%s")',
            'ipa-forbidden-import',
            'Used when import of module is not '
            'allowed in the particular module.'
        ),
    }
    priority = -2

    def _check_imports(self, node, import_abs_name):
        # name of the module where import statement is
        current = node.root().name
        for importer, imports in FORBIDDEN_IMPORTS:
            if current.startswith(importer):
                # current node is listed in rules
                for imprt in imports:
                    if import_abs_name.startswith(imprt):
                        self.add_message(
                            'ipa-forbidden-import',
                            args=(import_abs_name, importer, imprt),
                            node=node)
                        break
                break

    @check_messages('ipa-forbidden-import')
    def visit_import(self, node):
        """triggered when an import statement is seen"""
        modnode = [name for name, _obj in node.names]
        for m in modnode:
            self._check_imports(node, m)

    @check_messages('ipa-forbidden-import')
    def visit_importfrom(self, node):
        """triggered when a from statement is seen"""
        basename = node.modname
        self._check_imports(node, basename)


def register(linter):
    linter.register_checker(IPAImportChecker(linter))


MANAGER.register_transform(scoped_nodes.Class, fix_ipa_classes)
