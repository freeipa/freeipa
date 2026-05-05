#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function

import copy
import os.path
import sys
import textwrap

from astroid import MANAGER, register_module_extender
from astroid.exceptions import AstroidImportError
from astroid.nodes import scoped_nodes
from pylint.checkers import BaseChecker
from pylint.checkers.utils import only_required_for_messages
from astroid.builder import AstroidBuilder


def register(linter):
    linter.register_checker(IPAChecker(linter))


def _warning_already_exists(cls, member):
    print(
        "WARNING: member '{member}' in '{cls}' already exists".format(
            cls="{}.{}".format(cls.root().name, cls.name), member=member),
        file=sys.stderr
    )


def fake_class(name_or_class_obj, members=(), parent=None):
    if isinstance(name_or_class_obj, scoped_nodes.ClassDef):
        cl = name_or_class_obj
    else:
        cl = scoped_nodes.ClassDef(
            name=name_or_class_obj, lineno=None, col_offset=None, parent=parent,
            end_lineno=None, end_col_offset=None)

    for m in members:
        if isinstance(m, str):
            if m in cl.locals:
                _warning_already_exists(cl, m)
            else:
                cl.locals[m] = [scoped_nodes.ClassDef(
                    name=m, lineno=None, col_offset=None, parent=cl,
                    end_lineno=None, end_col_offset=None)]
        elif isinstance(m, dict):
            for key, val in m.items():
                assert isinstance(key, str), "key must be string"
                if key in cl.locals:
                    _warning_already_exists(cl, key)
                    fake_class(cl.locals[key], val)
                else:
                    cl.locals[key] = [fake_class(key, val, parent=cl)]
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
}


def fix_ipa_classes(cls):
    class_name_with_module = "{}.{}".format(cls.root().name, cls.name)
    if class_name_with_module in ipa_class_members:
        fake_class(cls, ipa_class_members[class_name_with_module])


MANAGER.register_transform(scoped_nodes.ClassDef, fix_ipa_classes)


def ipaplatform_constants_transform():
    return AstroidBuilder(MANAGER).string_build(textwrap.dedent('''
    from ipaplatform.base.constants import constants, User, Group
    __all__ = ('constants', 'User', 'Group')
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


def _synta_failed_import_hook(modname):
    """Provide stubs for synta submodules that live in the Rust extension."""
    if modname == 'synta.general_name':
        return AstroidBuilder(MANAGER).string_build(
            textwrap.dedent('''\
                OTHER_NAME = 0
                RFC822_NAME = 1
                DNS_NAME = 2
                X400_ADDRESS = 3
                DIRECTORY_NAME = 4
                EDI_PARTY_NAME = 5
                URI = 6
                IP_ADDRESS = 7
                REGISTERED_ID = 8
                class OtherName:
                    type_id = None
                    value = b''
                class DNSName:
                    value = ''
                class RFC822Name:
                    value = ''
                class IPAddress:
                    value = None
                class DirectoryName:
                    value = b''
                class UniformResourceIdentifier:
                    value = ''
                class RegisteredID:
                    value = None
            '''),
            modname='synta.general_name')
    if modname == 'synta.oids':
        return AstroidBuilder(MANAGER).string_build(
            textwrap.dedent('''\
                class _OID:
                    def __str__(self):
                        return ''
                    def components(self):
                        return ()
                KP_SERVER_AUTH = _OID()
                KP_CLIENT_AUTH = _OID()
                KP_CODE_SIGNING = _OID()
                KP_EMAIL_PROTECTION = _OID()
                PKINIT_KP_CLIENT_AUTH = _OID()
                PKINIT_KP_KDC = _OID()
                ANY_EXTENDED_KEY_USAGE = _OID()
                MS_SAN_UPN = _OID()
                PKINIT_SAN = _OID()
                EXTENDED_KEY_USAGE = _OID()
                MS_CERTIFICATE_TEMPLATE_NAME = _OID()
                MS_CERTIFICATE_TEMPLATE = _OID()
                KEY_USAGE = _OID()
                BASIC_CONSTRAINTS = _OID()
                SUBJECT_KEY_IDENTIFIER = _OID()
                AUTHORITY_KEY_IDENTIFIER = _OID()
                SUBJECT_ALT_NAME = _OID()
                AUTHORITY_INFO_ACCESS = _OID()
                CRL_DISTRIBUTION_POINTS = _OID()
                SHA256_WITH_RSA = _OID()
                class attr:
                    class _Attr:
                        def __str__(self):
                            return ''
                    COMMON_NAME = _Attr()
                    COUNTRY = _Attr()
                    LOCALITY = _Attr()
                    STATE = _Attr()
                    ORGANIZATION = _Attr()
                    ORG_UNIT = _Attr()
                    SERIAL_NUMBER = _Attr()
                    SURNAME = _Attr()
                    GIVEN_NAME = _Attr()
                    TITLE = _Attr()
                    GENERATION_QUALIFIER = _Attr()
                    DN_QUALIFIER = _Attr()
                    PSEUDONYM = _Attr()
                    DOMAIN_COMPONENT = _Attr()
                    EMAIL_ADDRESS = _Attr()
                    JURISDICTION_COUNTRY = _Attr()
                    JURISDICTION_LOCALITY = _Attr()
                    JURISDICTION_STATE = _Attr()
                    BUSINESS_CATEGORY = _Attr()
                    STREET = _Attr()
                    POSTAL_CODE = _Attr()
                    USER_ID = _Attr()
                    ORG_IDENTIFIER = _Attr()
            '''),
            modname='synta.oids')
    if modname == 'synta.oids.attr':
        return AstroidBuilder(MANAGER).string_build(
            textwrap.dedent('''\
                class _Attr:
                    def __str__(self):
                        return ''
                COMMON_NAME = _Attr()
                COUNTRY = _Attr()
                LOCALITY = _Attr()
                STATE = _Attr()
                ORGANIZATION = _Attr()
                ORG_UNIT = _Attr()
                SERIAL_NUMBER = _Attr()
                SURNAME = _Attr()
                GIVEN_NAME = _Attr()
                TITLE = _Attr()
                GENERATION_QUALIFIER = _Attr()
                DN_QUALIFIER = _Attr()
                PSEUDONYM = _Attr()
                DOMAIN_COMPONENT = _Attr()
                EMAIL_ADDRESS = _Attr()
                JURISDICTION_COUNTRY = _Attr()
                JURISDICTION_LOCALITY = _Attr()
                JURISDICTION_STATE = _Attr()
                BUSINESS_CATEGORY = _Attr()
                STREET = _Attr()
                POSTAL_CODE = _Attr()
                USER_ID = _Attr()
                ORG_IDENTIFIER = _Attr()
            '''),
            modname='synta.oids.attr')
    if modname == 'synta.ext':
        return AstroidBuilder(MANAGER).string_build(
            textwrap.dedent('''\
                KU_DIGITAL_SIGNATURE = 0
                KU_NON_REPUDIATION = 1
                KU_KEY_ENCIPHERMENT = 2
                KU_DATA_ENCIPHERMENT = 3
                KU_KEY_AGREEMENT = 4
                KU_KEY_CERT_SIGN = 5
                KU_CRL_SIGN = 6
                KU_ENCIPHER_ONLY = 7
                KU_DECIPHER_ONLY = 8
                def key_usage(bits):
                    return b''
                def basic_constraints(ca=False, path_length=None):
                    return b''
                def subject_key_identifier(spki_der):
                    return b''
                def authority_key_identifier(spki_der):
                    return b''
                class SubjectAlternativeNameBuilder:
                    def dns_name(self, name):
                        return self
                    def other_name(self, der):
                        return self
                    def ip_address(self, addr):
                        return self
                    def rfc822_name(self, name):
                        return self
                    def build(self):
                        return b''
                SAN = SubjectAlternativeNameBuilder
                class CRLDistributionPointsBuilder:
                    def full_name_uri(self, uri):
                        return self
                    def full_name_dns(self, dns):
                        return self
                    def build(self):
                        return b''
                CDP = CRLDistributionPointsBuilder
                class ExtendedKeyUsageBuilder:
                    def server_auth(self):
                        return self
                    def client_auth(self):
                        return self
                    def add_oid(self, comps):
                        return self
                    def build(self):
                        return b''
            '''),
            modname='synta.ext')
    if modname == 'synta.crypto':
        return AstroidBuilder(MANAGER).string_build(
            textwrap.dedent('''\
                def hmac_sign(algorithm, key, data):
                    return b''
                def hmac_verify(algorithm, key, data, expected):
                    pass
                def pbkdf2_hmac(algorithm, password, salt, iterations, length):
                    return b''
                def symmetric_encrypt(algorithm, key, data, iv=None):
                    return b''
                def symmetric_decrypt(algorithm, key, data, iv=None):
                    return b''
                def generate_symmetric_key(algorithm):
                    return b''
                def wrap_aes_key_wrap(wrapping_key, key_to_wrap):
                    return b''
                def unwrap_aes_key_wrap(wrapping_key, wrapped_key):
                    return b''
                def rsa_oaep_encrypt(public_key, data, algorithm):
                    return b''
                def rsa_oaep_decrypt(private_key, data, algorithm):
                    return b''
                def triple_des_encrypt(key, data, iv=None):
                    return b''
                def triple_des_decrypt(key, data, iv=None):
                    return b''
            '''),
            modname='synta.crypto')
    if modname == 'synta.krb5':
        return AstroidBuilder(MANAGER).string_build(
            textwrap.dedent('''\
                NT_PRINCIPAL = 1
                NT_SRV_INST = 2
                NT_SRV_HST = 3
                NT_X500_PRINCIPAL = 6
                KRB5_PRINCIPAL_NAME_OID = '1.3.6.1.5.2.2'
                UPN_OID = '1.3.6.1.4.1.311.20.2.3'
                class Krb5PrincipalName:
                    realm = ''
                    name_type = 0
                    components = []
                    def __init__(self, realm, name_type, components):
                        pass
                    @classmethod
                    def from_der(cls, der):
                        return cls('', 0, [])
                    def to_der(self):
                        return b''
                    def to_othername_der(self):
                        return b''
                class UPN:
                    name = ''
                    @classmethod
                    def from_der(cls, der):
                        return cls()
                class ExternalPrincipalIdentifier:
                    pass
                class PrincipalName:
                    pass
            '''),
            modname='synta.krb5')
    raise AstroidImportError(modname)


MANAGER.register_failed_import_hook(_synta_failed_import_hook)


def synta_krb5_transform():
    """Provide symbols for synta.krb5 that live in the Rust _krb5 extension.

    The synta/krb5.py stub is documentation-only; the real module is
    populated by the Rust initialiser.  Pylint sees only the empty .py file
    so we inject the Rust-backed classes here.
    """
    return AstroidBuilder(MANAGER).string_build(
        textwrap.dedent('''\
            NT_UNKNOWN = 0
            NT_PRINCIPAL = 1
            NT_SRV_INST = 2
            NT_SRV_HST = 3
            NT_SRV_XHST = 4
            NT_UID = 5
            NT_X500_PRINCIPAL = 6
            NT_SMTP_NAME = 7
            NT_ENTERPRISE = 10
            NT_WELLKNOWN = 11
            NT_SRV_HST_DOMAIN = 12
            KRB5_PRINCIPAL_NAME_OID = '1.3.6.1.5.2.2'
            UPN_OID = '1.3.6.1.4.1.311.20.2.3'
            class Krb5PrincipalName:
                realm = ''
                name_type = 0
                components = []
                def __init__(self, realm, name_type, components):
                    pass
                @classmethod
                def from_der(cls, der):
                    return cls('', 0, [])
                def to_der(self):
                    return b''
                def to_othername_der(self):
                    return b''
            class UPN:
                name = ''
                @classmethod
                def from_der(cls, der):
                    return cls()
            class ExternalPrincipalIdentifier:
                pass
            class PrincipalName:
                pass
        '''))


register_module_extender(MANAGER, 'synta.krb5', synta_krb5_transform)


def ipalib_request_transform():
    """ipalib.request.context attribute
    """
    return AstroidBuilder(MANAGER).string_build(textwrap.dedent('''
    from ipalib.request import context
    context._pylint_attr = Connection("_pylint", lambda: None)
    '''))


register_module_extender(MANAGER, 'ipalib.request', ipalib_request_transform)


class IPAChecker(BaseChecker):

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
        for forbidden_import in self.linter.config.forbidden_imports:
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

    @only_required_for_messages('ipa-forbidden-import')
    def visit_import(self, node):
        names = [n[0] for n in node.names]
        self._check_forbidden_imports(node, names)

    @only_required_for_messages('ipa-forbidden-import')
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
    api.env.ca_agent_port = 0
    api.env.ca_host = ''
    api.env.ca_install_port = None
    api.env.ca_port = 0
    api.env.cache_dir = ''  # object
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
    api.env.container_subids = DN()
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
    api.env.container_passkey = DN()
    api.env.container_group = DN()
    api.env.container_hbac = DN()
    api.env.container_hbacservice = DN()
    api.env.container_hbacservicegroup = DN()
    api.env.container_host = DN()
    api.env.container_hostgroup = DN()
    api.env.container_idp = DN()
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
    api.env.key_type_size = 'rsa:2048'
    api.env.kinit_lifetime = None
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

    # defined in ipaclient/install/ipa_epn.py
    api.env.smtp_server = ""
    api.env.smtp_port = 0
    api.env.smtp_user = None
    api.env.smtp_password = None
    api.env.smtp_client_cert = None
    api.env.smtp_client_key = None
    api.env.smtp_client_key_pass = None
    api.env.smtp_timeout = 0
    api.env.smtp_security = ""
    api.env.smtp_admin = ""
    api.env.smtp_delay = None
    api.env.mail_from = None
    api.env.mail_from_name = None
    api.env.notify_ttls = ""
    api.env.msg_charset = ""
    api.env.msg_subtype = ""
    api.env.msg_subject = ""

    # defined in contrib/lite-server.py
    api.env.lite_pem = ''
    api.env.lite_profiler = ''
    api.env.lite_host = ''
    api.env.lite_port = 0
    api.env.lite_tracemalloc = False

    """
))

# dnspython 2.x introduces enums and creates module level globals from them
# pylint does not understand the trick
AstroidBuilder(MANAGER).string_build(textwrap.dedent(
    """
    import dns.flags
    import dns.rdataclass
    import dns.rdatatype

    dns.flags.AD = 0
    dns.flags.CD = 0
    dns.flags.DO = 0
    dns.flags.RD = 0

    dns.rdataclass.IN = 0

    dns.rdatatype.A = 0
    dns.rdatatype.AAAA = 0
    dns.rdatatype.CNAME = 0
    dns.rdatatype.DNSKEY = 0
    dns.rdatatype.MX = 0
    dns.rdatatype.NS = 0
    dns.rdatatype.PTR = 0
    dns.rdatatype.RRSIG = 0
    dns.rdatatype.SOA = 0
    dns.rdatatype.SRV = 0
    dns.rdatatype.TXT = 0
    dns.rdatatype.URI = 0
    """
))

AstroidBuilder(MANAGER).string_build(
    textwrap.dedent(
        """\
    from ipatests.test_integration.base import IntegrationTest
    from ipatests.test_integration.base import MultiDomainIntegrationTest
    from ipatests.pytest_ipa.integration.host import Host, WinHost
    from ipatests.pytest_ipa.integration.config import Config, Domain


    class PylintIPAHosts:
        def __getitem__(self, key):
            return Host()


    class PylintWinHosts:
        def __getitem__(self, key):
            return WinHost()


    class PylintADDomains:
        def __getitem__(self, key):
            return Domain()

    class PylintTrustedDomains:
        def __getitem__(self, key):
            return Domain()

    Host.config = Config()
    Host.domain = Domain()

    IntegrationTest.domain = Domain()
    IntegrationTest.master = Host()
    IntegrationTest.replicas = PylintIPAHosts()
    IntegrationTest.clients = PylintIPAHosts()
    IntegrationTest.ads = PylintWinHosts()
    IntegrationTest.ad_treedomains = PylintWinHosts()
    IntegrationTest.ad_subdomains = PylintWinHosts()
    IntegrationTest.ad_domains = PylintADDomains()
    MultiDomainIntegrationTest.domain = Domain()
    MultiDomainIntegrationTest.master = Host()
    MultiDomainIntegrationTest.replicas = PylintIPAHosts()
    MultiDomainIntegrationTest.clients = PylintIPAHosts()
    MultiDomainIntegrationTest.trusted_master = Host()
    MultiDomainIntegrationTest.trusted_replicas = PylintIPAHosts()
    MultiDomainIntegrationTest.trusted_clients = PylintIPAHosts()
    MultiDomainIntegrationTest.trusted_domains = PylintTrustedDomains()
    """
    )
)
