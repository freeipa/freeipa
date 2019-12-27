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
    if isinstance(name_or_class_obj, scoped_nodes.ClassDef):
        cl = name_or_class_obj
    else:
        cl = scoped_nodes.ClassDef(name_or_class_obj, None)

    for m in members:
        if isinstance(m, str):
            if m in cl.locals:
                _warning_already_exists(cl, m)
            else:
                cl.locals[m] = [scoped_nodes.ClassDef(m, None)]
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
    'ipalib.config.Env': [  # somehow needed for pylint on Python 2
        'debug',
        'startup_traceback',
        'server',
        'validate_api',
        'verbose',
    ],
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
        'Advice',
    ],
    'ipalib.util.ForwarderValidationError': [
        'msg',
    ],
    'ipaserver.plugins.dns.DNSRecord': [
        'validatedns',
        'normalizedns',
    ],
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
                {'fips_mode': dir(bool)},
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


MANAGER.register_transform(scoped_nodes.ClassDef, fix_ipa_classes)


def pytest_config_transform():
    """pylint.config attribute
    """
    return AstroidBuilder(MANAGER).string_build(textwrap.dedent('''
    from _pytest.config import get_config
    config = get_config()
    '''))


register_module_extender(MANAGER, 'pytest', pytest_config_transform)


def ipaplatform_constants_transform():
    return AstroidBuilder(MANAGER).string_build(textwrap.dedent('''
    from ipaplatform.base.constants import constants
    __all__ = ('constants',)
    '''))


def ipaplatform_paths_transform():
    return AstroidBuilder(MANAGER).string_build(textwrap.dedent('''
    from ipaplatform.base.paths import paths
    __all__ = ('paths',)
    '''))


def ipaplatform_services_transform():
    return AstroidBuilder(MANAGER).string_build(textwrap.dedent('''
    from ipaplatform.base.services import knownservices
    from ipaplatform.base.services import timedate_services
    from ipaplatform.base.services import service
    from ipaplatform.base.services import wellknownservices
    from ipaplatform.base.services import wellknownports
    __all__ = ('knownservices', 'timedate_services', 'service',
               'wellknownservices', 'wellknownports')
    '''))


def ipaplatform_tasks_transform():
    return AstroidBuilder(MANAGER).string_build(textwrap.dedent('''
    from ipaplatform.base.tasks import tasks
    __all__ = ('tasks',)
    '''))


register_module_extender(MANAGER, 'ipaplatform.constants',
                         ipaplatform_constants_transform)
register_module_extender(MANAGER, 'ipaplatform.paths',
                         ipaplatform_paths_transform)
register_module_extender(MANAGER, 'ipaplatform.services',
                         ipaplatform_services_transform)
register_module_extender(MANAGER, 'ipaplatform.tasks',
                         ipaplatform_tasks_transform)


def ipalib_request_transform():
    """ipalib.request.context attribute
    """
    return AstroidBuilder(MANAGER).string_build(textwrap.dedent('''
    from ipalib.request import context
    context._pylint_attr = Connection("_pylint", lambda: None)
    '''))


register_module_extender(MANAGER, 'ipalib.request', ipalib_request_transform)


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
        if path and isinstance(path, list):
            # In pylint 2.0, path is a list with one element. Namespace
            # packages may contain more than one element, but we can safely
            # ignore them, as they don't contain code.
            path = path[0]
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


#
# Teach pylint how api object works
#
# ipalib uses some tricks to create api.env members and api objects. pylint
# is not able to infer member names and types from code. The explict
# assignments inside the string builder templates are good enough to show
# pylint, how the api is created. Additional transformations are not
# required.
#

AstroidBuilder(MANAGER).string_build(textwrap.dedent(
    """
    from ipalib import api
    from ipalib import cli, plugable, rpc
    from ipalib.base import NameSpace
    from ipaclient.plugins import rpcclient
    try:
        from ipaserver.plugins import dogtag, ldap2, serverroles
    except ImportError:
        HAS_SERVER = False
    else:
        HAS_SERVER = True

    def wildcard(*args, **kwargs):
        return None

    # ipalib.api members
    api.Backend = plugable.APINameSpace(api, None)
    api.Command = plugable.APINameSpace(api, None)
    api.Method = plugable.APINameSpace(api, None)
    api.Object = plugable.APINameSpace(api, None)
    api.Updater = plugable.APINameSpace(api, None)
    # ipalib.api.Backend members
    api.Backend.cli = cli.cli(api)
    api.Backend.textui = cli.textui(api)
    api.Backend.jsonclient = rpc.jsonclient(api)
    api.Backend.rpcclient = rpcclient.rpcclient(api)
    api.Backend.xmlclient = rpc.xmlclient(api)

    if HAS_SERVER:
        api.Backend.kra = dogtag.kra(api)
        api.Backend.ldap2 = ldap2.ldap2(api)
        api.Backend.ra = dogtag.ra(api)
        api.Backend.ra_certprofile = dogtag.ra_certprofile(api)
        api.Backend.ra_lightweight_ca = dogtag.ra_lightweight_ca(api)
        api.Backend.serverroles = serverroles.serverroles(api)

    # ipalib.base.NameSpace
    NameSpace.find = wildcard
    """
))


AstroidBuilder(MANAGER).string_build(textwrap.dedent(
    """
    from ipalib import api
    from ipapython.dn import DN

    api.env.api_version = ''
    api.env.bin = ''  # object
    api.env.ca_agent_install_port = None
    api.env.ca_agent_port = 0
    api.env.ca_ee_install_port = None
    api.env.ca_ee_port = 0
    api.env.ca_host = ''
    api.env.ca_install_port = None
    api.env.ca_port = 0
    api.env.certmonger_wait_timeout = 0
    api.env.conf = ''  # object
    api.env.conf_default = ''  # object
    api.env.confdir = ''  # object
    api.env.container_accounts = DN()
    api.env.container_adtrusts = DN()
    api.env.container_applications = DN()
    api.env.container_automember = DN()
    api.env.container_automount = DN()
    api.env.container_ca = DN()
    api.env.container_ca_renewal = DN()
    api.env.container_caacl = DN()
    api.env.container_certmap = DN()
    api.env.container_certmaprules = DN()
    api.env.container_certprofile = DN()
    api.env.container_cifsdomains = DN()
    api.env.container_configs = DN()
    api.env.container_custodia = DN()
    api.env.container_deleteuser = DN()
    api.env.container_dna = DN()
    api.env.container_dna_posix_ids = DN()
    api.env.container_dns = DN()
    api.env.container_dnsservers = DN()
    api.env.container_group = DN()
    api.env.container_hbac = DN()
    api.env.container_hbacservice = DN()
    api.env.container_hbacservicegroup = DN()
    api.env.container_host = DN()
    api.env.container_hostgroup = DN()
    api.env.container_locations = DN()
    api.env.container_masters = DN()
    api.env.container_netgroup = DN()
    api.env.container_otp = DN()
    api.env.container_permission = DN()
    api.env.container_policies = DN()
    api.env.container_policygroups = DN()
    api.env.container_policylinks = DN()
    api.env.container_privilege = DN()
    api.env.container_radiusproxy = DN()
    api.env.container_ranges = DN()
    api.env.container_realm_domains = DN()
    api.env.container_rolegroup = DN()
    api.env.container_roles = DN()
    api.env.container_s4u2proxy = DN()
    api.env.container_selinux = DN()
    api.env.container_service = DN()
    api.env.container_stageuser = DN()
    api.env.container_sudocmd = DN()
    api.env.container_sudocmdgroup = DN()
    api.env.container_sudorule = DN()
    api.env.container_sysaccounts = DN()
    api.env.container_topology = DN()
    api.env.container_trusts = DN()
    api.env.container_user = DN()
    api.env.container_vault = DN()
    api.env.container_views = DN()
    api.env.container_virtual = DN()
    api.env.context = ''  # object
    api.env.debug = False
    api.env.delegate = False
    api.env.dogtag_version = 0
    api.env.dot_ipa = ''  # object
    api.env.enable_ra = False
    api.env.env_confdir = None
    api.env.fallback = True
    api.env.force_schema_check = False
    api.env.home = ''  # object
    api.env.host = ''
    api.env.host_princ = ''
    api.env.http_timeout = 0
    api.env.in_server = False  # object
    api.env.in_tree = False  # object
    api.env.interactive = True
    api.env.ipalib = ''  # object
    api.env.kinit_lifetime = None
    api.env.lite_pem = ''
    api.env.lite_profiler = ''
    api.env.lite_host = ''
    api.env.lite_port = 0
    api.env.log = ''  # object
    api.env.logdir = ''  # object
    api.env.mode = ''
    api.env.mount_ipa = ''
    api.env.nss_dir = ''  # object
    api.env.plugins_on_demand = False  # object
    api.env.prompt_all = False
    api.env.ra_plugin = ''
    api.env.recommended_max_agmts = 0
    api.env.replication_wait_timeout = 0
    api.env.rpc_protocol = ''
    api.env.server = ''
    api.env.script = ''  # object
    api.env.site_packages = ''  # object
    api.env.skip_version_check = False
    api.env.smb_princ = ''
    api.env.startup_timeout = 0
    api.env.startup_traceback = False
    api.env.tls_ca_cert = ''  # object
    api.env.tls_version_max = ''
    api.env.tls_version_min = ''
    api.env.validate_api = False
    api.env.verbose = 0
    api.env.version = ''
    api.env.wait_for_dns = 0
    api.env.webui_prod = True
    """
))
