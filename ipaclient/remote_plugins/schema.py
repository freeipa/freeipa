#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import collections
import errno
import fcntl
import json
import os
import sys
import time
import types
import zipfile

import six

from ipaclient.frontend import ClientCommand, ClientMethod
from ipalib import errors, parameters, plugable
from ipalib.frontend import Object
from ipalib.output import Output
from ipalib.parameters import DefaultFrom, Flag, Password, Str
from ipapython.dn import DN
from ipapython.dnsutil import DNSName
from ipapython.ipa_log_manager import log_mgr

if six.PY3:
    unicode = str

_TYPES = {
    'DN': DN,
    'DNSName': DNSName,
    'Principal': unicode,
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
    'Principal': parameters.Principal,
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

logger = log_mgr.get_logger(__name__)


class _SchemaCommand(ClientCommand):
    pass


class _SchemaMethod(ClientMethod):
    @property
    def obj_name(self):
        return self.api.Object[self.obj_full_name].name

    @property
    def obj_version(self):
        return self.api.Object[self.obj_full_name].version


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
                'default' in schema and schema['default'][0] == u'False' and
                not schema.get('alwaysask', False)):
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
        try:
            return self._schema.read_namespace_member(self.name, key)
        except KeyError:
            raise KeyError(key)

    def __iter__(self):
        for key in self._schema.iter_namespace(self.name):
            yield key

    def __len__(self):
        return len(list(self._schema.iter_namespace(self.name)))


class NotAvailable(Exception):
    pass


class ServerInfo(collections.MutableMapping):
    _DIR = os.path.join(USER_CACHE_PATH, 'ipa', 'servers')

    def __init__(self, api):
        hostname = DNSName(api.env.server).ToASCII()
        self._path = os.path.join(self._DIR, hostname)
        self._dict = {}
        self._dirty = False

        self._read()

    def __enter__(self):
        return self

    def __exit__(self, *_exc_info):
        if self._dirty:
            self._write()

    def _read(self):
        try:
            with open(self._path, 'r') as sc:
                self._dict = json.load(sc)
        except EnvironmentError as e:
            if e.errno != errno.ENOENT:
                logger.warning('Failed to read server info: {}'.format(e))

    def _write(self):
        try:
            try:
                os.makedirs(self._DIR)
            except EnvironmentError as e:
                if e.errno != errno.EEXIST:
                    raise
            with open(self._path, 'w') as sc:
                json.dump(self._dict, sc)
        except EnvironmentError as e:
            logger.warning('Failed to write server info: {}'.format(e))

    def __getitem__(self, key):
        return self._dict[key]

    def __setitem__(self, key, value):
        self._dirty = key not in self._dict or self._dict[key] != value
        self._dict[key] = value

    def __delitem__(self, key):
        del self._dict[key]
        self._dirty = True

    def __iter__(self):
        return iter(self._dict)

    def __len__(self):
        return len(self._dict)


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
    namespaces = {'classes', 'commands', 'topics'}
    schema_info_path = 'schema'
    _DIR = os.path.join(USER_CACHE_PATH, 'ipa', 'schema')

    def __init__(self, api, server_info, client):
        self._dict = {}
        self._namespaces = {}
        self._help = None

        for ns in self.namespaces:
            self._dict[ns] = {}
            self._namespaces[ns] = _SchemaNameSpace(self, ns)

        is_known = False
        if not api.env.force_schema_check:
            try:
                self._fingerprint = server_info['fingerprint']
                self._expiration = server_info['expiration']
            except KeyError:
                pass
            else:
                is_known = True

        if is_known:
            try:
                self._read_schema()
            except Exception:
                pass
            else:
                return

        try:
            self._fetch(client)
        except NotAvailable:
            raise
        else:
            self._write_schema()
        finally:
            try:
                server_info['fingerprint'] = self._fingerprint
                server_info['expiration'] = self._expiration
            except AttributeError:
                pass

    def _open_schema(self, filename, mode):
        path = os.path.join(self._DIR, filename)
        return _LockedZipFile(path, mode)

    def _get_schema_fingerprint(self, schema):
        schema_info = json.loads(schema.read(self.schema_info_path))
        return schema_info['fingerprint']

    def _fetch(self, client):
        if not client.isconnected():
            client.connect(verbose=False)

        fps = []
        try:
            files = os.listdir(self._DIR)
        except EnvironmentError:
            pass
        else:
            for filename in files:
                try:
                    with self._open_schema(filename, 'r') as schema:
                        fps.append(
                            unicode(self._get_schema_fingerprint(schema)))
                except Exception:
                    continue

        kwargs = {u'version': u'2.170'}
        if fps:
            kwargs[u'known_fingerprints'] = fps
        try:
            schema = client.forward(u'schema', **kwargs)['result']
        except errors.CommandError:
            raise NotAvailable()
        except errors.SchemaUpToDate as e:
            fp = e.fingerprint
            ttl = e.ttl
        else:
            fp = schema['fingerprint']
            ttl = schema.pop('ttl', 0)

            for key, value in schema.items():
                if key in self.namespaces:
                    value = {m['full_name']: m for m in value}
                self._dict[key] = value

        self._fingerprint = fp
        self._expiration = ttl + time.time()

    def _read_schema(self):
        with self._open_schema(self._fingerprint, 'r') as schema:
            self._dict['fingerprint'] = self._get_schema_fingerprint(schema)
            schema_info = json.loads(schema.read(self.schema_info_path))
            self._dict['version'] = schema_info['version']

            for name in schema.namelist():
                ns, _slash, key = name.partition('/')
                if ns in self.namespaces:
                    self._dict[ns][key] = {}

    def __getitem__(self, key):
        try:
            return self._namespaces[key]
        except KeyError:
            return self._dict[key]

    def _write_schema(self):
        try:
            os.makedirs(self._DIR)
        except EnvironmentError as e:
            if e.errno != errno.EEXIST:
                logger.warning("Failed ti write schema: {}".format(e))
                return

        with self._open_schema(self._fingerprint, 'w') as schema:
            schema_info = {}
            for key, value in self._dict.items():
                if key in self.namespaces:
                    ns = value
                    for member in ns:
                        path = '{}/{}'.format(key, member)
                        schema.writestr(path, json.dumps(ns[member]))
                else:
                    schema_info[key] = value

            schema.writestr(self.schema_info_path, json.dumps(schema_info))

    def _read(self, path):
        with self._open_schema(self._fingerprint, 'r') as zf:
            return json.loads(zf.read(path))

    def read_namespace_member(self, namespace, member):
        value = self._dict[namespace][member]

        if (not value) or ('full_name' not in value):
            path = '{}/{}'.format(namespace, member)
            value = self._dict[namespace].setdefault(
                member, {}
            ).update(self._read(path))

        return value

    def iter_namespace(self, namespace):
        return iter(self._dict[namespace])


def get_package(api, client):
    try:
        schema = api._schema
    except AttributeError:
        with ServerInfo(api.env.hostname) as server_info:
            schema = Schema(api, server_info, client)
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
    for plugin_cls in (_SchemaCommandPlugin, _SchemaObjectPlugin):
        for full_name in schema[plugin_cls.schema_key]:
            plugin = plugin_cls(str(full_name))
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
