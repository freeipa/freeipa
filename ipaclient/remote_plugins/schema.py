#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import collections
import errno
import fcntl
import glob
import json
import os
import re
import sys
import time
import types
import zipfile

import six

from ipaclient.plugins.rpcclient import rpcclient
from ipalib import errors, parameters, plugable
from ipalib.frontend import Command, Method, Object
from ipalib.output import Output
from ipalib.parameters import DefaultFrom, Flag, Password, Str
from ipalib.text import _
from ipapython.dn import DN
from ipapython.dnsutil import DNSName
from ipapython.ipa_log_manager import log_mgr

if six.PY3:
    unicode = str

_TYPES = {
    'DN': DN,
    'DNSName': DNSName,
    'NoneType': type(None),
    'Sequence': collections.Sequence,
    'bool': bool,
    'dict': dict,
    'int': int,
    'list': list,
    'tuple': tuple,
    'unicode': unicode,
}

_PARAMS = {
    'Decimal': parameters.Decimal,
    'DN': parameters.DNParam,
    'DNSName': parameters.DNSNameParam,
    'bool': parameters.Bool,
    'bytes': parameters.Bytes,
    'datetime': parameters.DateTime,
    'dict': parameters.Dict,
    'int': parameters.Int,
    'str': parameters.Str,
}

USER_CACHE_PATH = (
    os.environ.get('XDG_CACHE_HOME') or
    os.path.join(
        os.environ.get(
            'HOME',
            os.path.expanduser('~')
        ),
        '.cache'
    )
)
SCHEMA_DIR = os.path.join(USER_CACHE_PATH, 'ipa', 'schema')
SERVERS_DIR = os.path.join(USER_CACHE_PATH, 'ipa', 'servers')

logger = log_mgr.get_logger(__name__)


class _SchemaCommand(Command):
    def get_options(self):
        skip = set()
        for option in super(_SchemaCommand, self).get_options():
            if option.name in skip:
                continue
            if option.name in ('all', 'raw'):
                skip.add(option.name)
            yield option


class _SchemaMethod(Method, _SchemaCommand):
    _failed_member_output_params = (
        # baseldap
        Str(
            'member',
            label=_("Failed members"),
        ),
        Str(
            'sourcehost',
            label=_("Failed source hosts/hostgroups"),
        ),
        Str(
            'memberhost',
            label=_("Failed hosts/hostgroups"),
        ),
        Str(
            'memberuser',
            label=_("Failed users/groups"),
        ),
        Str(
            'memberservice',
            label=_("Failed service/service groups"),
        ),
        Str(
            'failed',
            label=_("Failed to remove"),
            flags=['suppress_empty'],
        ),
        Str(
            'ipasudorunas',
            label=_("Failed RunAs"),
        ),
        Str(
            'ipasudorunasgroup',
            label=_("Failed RunAsGroup"),
        ),
        # caacl
        Str(
            'ipamembercertprofile',
            label=_("Failed profiles"),
        ),
        Str(
            'ipamemberca',
            label=_("Failed CAs"),
        ),
        # host
        Str(
            'managedby',
            label=_("Failed managedby"),
        ),
        # service
        Str(
            'ipaallowedtoperform_read_keys',
            label=_("Failed allowed to retrieve keytab"),
        ),
        Str(
            'ipaallowedtoperform_write_keys',
            label=_("Failed allowed to create keytab"),
        ),
        # servicedelegation
        Str(
            'failed_memberprincipal',
            label=_("Failed members"),
        ),
        Str(
            'ipaallowedtarget',
            label=_("Failed targets"),
        ),
        # vault
        Str(
            'owner?',
            label=_("Failed owners"),
        ),
    )

    @property
    def obj_name(self):
        return self.api.Object[self.obj_full_name].name

    @property
    def obj_version(self):
        return self.api.Object[self.obj_full_name].version

    def get_output_params(self):
        seen = set()
        for output_param in super(_SchemaMethod, self).get_output_params():
            seen.add(output_param.name)
            yield output_param
        for output_param in self._failed_member_output_params:
            if output_param.name not in seen:
                yield output_param


class _SchemaObject(Object):
    pass


class _SchemaPlugin(object):
    bases = None
    schema_key = None

    def __init__(self, full_name):
        self.name, _slash, self.version = full_name.partition('/')
        self.full_name = full_name
        self.__class = None

    def _create_default_from(self, api, name, keys):
        cmd_name = self.full_name

        def get_default(*args):
            kw = dict(zip(keys, args))
            result = api.Command.command_defaults(
                unicode(cmd_name),
                params=[unicode(name)],
                kw=kw,
            )['result']
            return result.get(name)

        if keys:
            def callback(*args):
                return get_default(*args)
        else:
            def callback():
                return get_default()

        callback.__name__ = '{0}_{1}_default'.format(self.name, name)

        return DefaultFrom(callback, *keys)

    def _create_param(self, api, schema):
        name = str(schema['name'])
        type_name = str(schema['type'])
        sensitive = schema.get('sensitive', False)

        if type_name == 'str' and sensitive:
            cls = Password
            sensitive = False
        elif (type_name == 'bool' and
                'default' in schema and
                schema['default'] == [u'False']):
            cls = Flag
            del schema['default']
        else:
            try:
                cls = _PARAMS[type_name]
            except KeyError:
                cls = Str

        kwargs = {}
        default = None

        for key, value in schema.items():
            if key in ('alwaysask',
                       'doc',
                       'label',
                       'multivalue',
                       'no_convert',
                       'option_group',
                       'required'):
                kwargs[key] = value
            elif key in ('cli_metavar',
                         'cli_name'):
                kwargs[key] = str(value)
            elif key == 'confirm' and issubclass(cls, Password):
                kwargs[key] = value
            elif key == 'default':
                default = value
            elif key == 'default_from_param':
                keys = tuple(str(k) for k in value)
                kwargs['default_from'] = (
                    self._create_default_from(api, name, keys))
            elif key in ('exclude',
                         'include'):
                kwargs[key] = tuple(str(v) for v in value)

        if default is not None:
            tmp = cls(name, **dict(kwargs, no_convert=False))
            if tmp.multivalue:
                default = tuple(tmp._convert_scalar(d) for d in default)
            else:
                default = tmp._convert_scalar(default[0])
            kwargs['default'] = default

        if 'default' in kwargs or 'default_from' in kwargs:
            kwargs['autofill'] = not kwargs.pop('alwaysask', False)

        param = cls(name, **kwargs)

        if sensitive:
            object.__setattr__(param, 'password', True)

        return param

    def _create_class(self, api, schema):
        class_dict = {}

        class_dict['name'] = str(schema['name'])
        class_dict['version'] = str(schema['version'])
        class_dict['full_name'] = str(schema['full_name'])
        if 'doc' in schema:
            class_dict['doc'] = schema['doc']
        if 'topic_topic' in schema:
            class_dict['topic'] = str(schema['topic_topic']).partition('/')[0]
        else:
            class_dict['topic'] = None

        class_dict['takes_params'] = tuple(self._create_param(api, s)
                                           for s in schema.get('params', []))

        return self.name, self.bases, class_dict

    def __call__(self, api):
        if self.__class is None:
            schema = api._schema[self.schema_key][self.full_name]
            name, bases, class_dict = self._create_class(api, schema)
            self.__class = type(name, bases, class_dict)

        return self.__class(api)


class _SchemaCommandPlugin(_SchemaPlugin):
    bases = (_SchemaCommand,)
    schema_key = 'commands'

    def _create_output(self, api, schema):
        if schema.get('multivalue', False):
            type_type = (tuple, list)
            if not schema.get('required', True):
                type_type = type_type + (type(None),)
        else:
            try:
                type_type = _TYPES[schema['type']]
            except KeyError:
                type_type = None
            else:
                if not schema.get('required', True):
                    type_type = (type_type, type(None))

        kwargs = {}
        kwargs['type'] = type_type

        if 'doc' in schema:
            kwargs['doc'] = schema['doc']

        if schema.get('no_display', False):
            kwargs['flags'] = ('no_display',)

        return Output(str(schema['name']), **kwargs)

    def _create_class(self, api, schema):
        name, bases, class_dict = (
            super(_SchemaCommandPlugin, self)._create_class(api, schema))

        if 'obj_class' in schema or 'attr_name' in schema:
            bases = (_SchemaMethod,)

        if 'obj_class' in schema:
            class_dict['obj_full_name'] = str(schema['obj_class'])
        if 'attr_name' in schema:
            class_dict['attr_name'] = str(schema['attr_name'])
        if 'exclude' in schema and u'cli' in schema['exclude']:
            class_dict['NO_CLI'] = True

        args = set(str(s['name']) for s in schema['params']
                   if s.get('positional', s.get('required', True)))
        class_dict['takes_args'] = tuple(
            p for p in class_dict['takes_params'] if p.name in args)
        class_dict['takes_options'] = tuple(
            p for p in class_dict['takes_params'] if p.name not in args)
        del class_dict['takes_params']

        class_dict['has_output'] = tuple(
            self._create_output(api, s) for s in schema['output'])

        return name, bases, class_dict


class _SchemaObjectPlugin(_SchemaPlugin):
    bases = (_SchemaObject,)
    schema_key = 'classes'


def _ensure_dir_created(d):
    try:
        os.makedirs(d)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise RuntimeError("Unable to create cache directory: {}"
                               "".format(e))


class _LockedZipFile(zipfile.ZipFile):
    """ Add locking to zipfile.ZipFile
    Shared lock is used with read mode, exclusive with write mode.
    """
    def __enter__(self):
        if 'r' in self.mode:
            fcntl.flock(self.fp, fcntl.LOCK_SH)
        elif 'w' in self.mode or 'a' in self.mode:
            fcntl.flock(self.fp, fcntl.LOCK_EX)

        return super(_LockedZipFile, self).__enter__()

    def __exit__(self, type_, value, traceback):
        fcntl.flock(self.fp, fcntl.LOCK_UN)

        return super(_LockedZipFile, self).__exit__(type_, value, traceback)


class _SchemaNameSpace(collections.Mapping):

    def __init__(self, schema, name):
        self.name = name
        self._schema = schema

    def __getitem__(self, key):
        return self._schema.read_namespace_member(self.name, key)

    def __iter__(self):
        for key in self._schema.iter_namespace(self.name):
            yield key

    def __len__(self):
        return len(list(self._schema.iter_namespace(self.name)))


class Schema(object):
    """
    Store and provide schema for commands and topics

    Create api instance
    >>> from ipalib import api
    >>> api.bootstrap(context='cli')
    >>> api.finalize()

    Get schema object
    >>> m = Schema(api)

    From now on we can access schema for commands stored in cache
    >>> m['commands'][u'ping'][u'doc']
    u'Ping a remote server.'

    >>> m['topics'][u'ping'][u'doc']
    u'Ping the remote IPA server to ...'

    """
    schema_path_template = os.path.join(SCHEMA_DIR, '{}')
    servers_path_template = os.path.join(SERVERS_DIR, '{}')
    ns_member_pattern_template = '^{}/(?P<name>.+)$'
    ns_member_path_template = '{}/{}'
    namespaces = {'classes', 'commands', 'topics'}
    schema_info_path = 'schema'

    @classmethod
    def _list(cls):
        for f in glob.glob(cls.schema_path_template.format('*')):
            yield os.path.splitext(os.path.basename(f))[0]

    @classmethod
    def _in_cache(cls, fingeprint):
        return os.path.exists(cls.schema_path_template.format(fingeprint))

    def __init__(self, api):
        self._api = api
        self._dict = {}

    def _open_server_info(self, hostname, mode):
        encoded_hostname = DNSName(hostname).ToASCII()
        path = self.servers_path_template.format(encoded_hostname)
        return open(path, mode)

    def _get_schema(self):
        client = rpcclient(self._api)
        client.finalize()
        client.connect(verbose=False)

        fps = [unicode(f) for f in Schema._list()]
        kwargs = {u'version': u'2.170'}
        if fps:
            kwargs[u'known_fingerprints'] = fps
        try:
            schema = client.forward(u'schema', **kwargs)['result']
        except errors.SchemaUpToDate as e:
            fp = e.fingerprint
            ttl = e.ttl
        else:
            fp = schema['fingerprint']
            ttl = schema['ttl']
            self._store(fp, schema)
        finally:
            client.disconnect()

        exp = ttl + time.time()
        return (fp, exp)

    def _ensure_cached(self):
        no_info = False
        try:
            # pylint: disable=access-member-before-definition
            fp = self._server_schema_fingerprint
            exp = self._server_schema_expiration
        except AttributeError:
            try:
                with self._open_server_info(self._api.env.server, 'r') as sc:
                    si = json.load(sc)

                fp = si['fingerprint']
                exp = si['expiration']
            except Exception as e:
                no_info = True
                if not (isinstance(e, EnvironmentError) and
                        e.errno == errno.ENOENT):  # pylint: disable=no-member
                    logger.warning('Failed to load server properties: {}'
                                   ''.format(e))

        if no_info or exp < time.time() or not Schema._in_cache(fp):
            (fp, exp) = self._get_schema()
            _ensure_dir_created(SERVERS_DIR)
            try:
                with self._open_server_info(self._api.env.server, 'w') as sc:
                    json.dump(dict(fingerprint=fp, expiration=exp), sc)
            except Exception as e:
                logger.warning('Failed to store server properties: {}'
                               ''.format(e))

        if not self._dict:
            self._dict['fingerprint'] = fp
            schema_info = self._read(self.schema_info_path)
            self._dict['version'] = schema_info['version']
            for ns in self.namespaces:
                self._dict[ns] = _SchemaNameSpace(self, ns)

        self._server_schema_fingerprintr = fp
        self._server_schema_expiration = exp

    def __getitem__(self, key):
        self._ensure_cached()
        return self._dict[key]

    def _open_archive(self, mode, fp=None):
        if not fp:
            fp = self['fingerprint']
        arch_path = self.schema_path_template.format(fp)
        return _LockedZipFile(arch_path, mode)

    def _store(self, fingerprint, schema={}):
        _ensure_dir_created(SCHEMA_DIR)

        schema_info = dict(version=schema['version'],
                           fingerprint=schema['fingerprint'])

        with self._open_archive('w', fingerprint) as zf:
            # store schema information
            zf.writestr(self.schema_info_path, json.dumps(schema_info))
            # store namespaces
            for namespace in self.namespaces:
                for member in schema[namespace]:
                    path = self.ns_member_path_template.format(
                        namespace,
                        member['full_name']
                    )
                    zf.writestr(path, json.dumps(member))

    def _read(self, path):
        with self._open_archive('r') as zf:
            return json.loads(zf.read(path))

    def read_namespace_member(self, namespace, member):
        path = self.ns_member_path_template.format(namespace, member)
        return self._read(path)

    def iter_namespace(self, namespace):
        pattern = self.ns_member_pattern_template.format(namespace)
        with self._open_archive('r') as zf:
            for name in zf.namelist():
                r = re.match(pattern, name)
                if r:
                    yield r.groups('name')[0]


def get_package(api):
    try:
        schema = api._schema
    except AttributeError:
        schema = Schema(api)
        object.__setattr__(api, '_schema', schema)

    fingerprint = str(schema['fingerprint'])
    package_name = '{}${}'.format(__name__, fingerprint)
    package_dir = '{}${}'.format(os.path.splitext(__file__)[0], fingerprint)

    try:
        return sys.modules[package_name]
    except KeyError:
        pass

    package = types.ModuleType(package_name)
    package.__file__ = os.path.join(package_dir, '__init__.py')
    package.modules = ['plugins']
    sys.modules[package_name] = package

    module_name = '.'.join((package_name, 'plugins'))
    module = types.ModuleType(module_name)
    module.__file__ = os.path.join(package_dir, 'plugins.py')
    module.register = plugable.Registry()
    for key, plugin_cls in (('commands', _SchemaCommandPlugin),
                            ('classes', _SchemaObjectPlugin)):
        for full_name in schema[key]:
            plugin = plugin_cls(full_name)
            plugin = module.register()(plugin)
    sys.modules[module_name] = module

    for full_name, topic in six.iteritems(schema['topics']):
        name = str(topic['name'])
        module_name = '.'.join((package_name, name))
        try:
            module = sys.modules[module_name]
        except KeyError:
            module = sys.modules[module_name] = types.ModuleType(module_name)
            module.__file__ = os.path.join(package_dir, '{}.py'.format(name))
        module.__doc__ = topic.get('doc')
        if 'topic_topic' in topic:
            module.topic = str(topic['topic_topic']).partition('/')[0]
        else:
            module.topic = None

    return package
