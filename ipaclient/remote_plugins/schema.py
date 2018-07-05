#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import errno
import json
import logging
import os
import sys
import tempfile
import types
import zipfile

from cryptography import x509 as crypto_x509

import six

from ipaclient.frontend import ClientCommand, ClientMethod
from ipalib import errors, parameters, plugable
from ipalib.constants import USER_CACHE_PATH
from ipalib.errors import SchemaUpToDate
from ipalib.frontend import Object
from ipalib.output import Output
from ipalib.parameters import DefaultFrom, Flag, Password, Str
from ipapython import ipautil
from ipapython.ipautil import fsdecode
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

# pylint: disable=no-name-in-module, import-error
if six.PY3:
    from collections.abc import Mapping, Sequence
else:
    from collections import Mapping, Sequence
# pylint: enable=no-name-in-module, import-error

logger = logging.getLogger(__name__)

FORMAT = '1'

if six.PY3:
    unicode = str

_TYPES = {
    'DN': DN,
    'DNSName': DNSName,
    'Principal': unicode,
    'NoneType': type(None),
    'Sequence': Sequence,
    'bool': bool,
    'dict': dict,
    'int': int,
    'list': list,
    'tuple': tuple,
    'unicode': unicode,
    'Certificate': crypto_x509.Certificate,
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
    'Certificate': parameters.Certificate,
}


def json_default(obj):
    if isinstance(obj, bytes):
        return obj.decode('utf-8')
    raise TypeError


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

    def __init__(self, schema, full_name):
        self.name, _slash, self.version = full_name.partition('/')
        self.full_name = full_name
        self._schema = schema
        self._class = None

    @property
    def doc(self):
        if self._class is not None:
            return self._class.doc
        else:
            schema = self._schema[self.schema_key][self.full_name]
            try:
                return schema['doc']
            except KeyError:
                return None

    @property
    def summary(self):
        if self._class is not None:
            return self._class.summary
        else:
            halp = self._schema[self.schema_key].get_help(self.full_name)
            try:
                return halp['summary']
            except KeyError:
                return u'<%s>' % self.full_name

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
            elif key == 'confirm':
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
        if self._class is None:
            schema = self._schema[self.schema_key][self.full_name]
            name, bases, class_dict = self._create_class(api, schema)
            self._class = type(name, bases, class_dict)

        return self._class(api)


class _SchemaCommandPlugin(_SchemaPlugin):
    bases = (_SchemaCommand,)
    schema_key = 'commands'

    @property
    def topic(self):
        if self._class is not None:
            return self._class.topic
        else:
            halp = self._schema[self.schema_key].get_help(self.full_name)
            try:
                return str(halp['topic_topic']).partition('/')[0]
            except KeyError:
                return None

    @property
    def NO_CLI(self):
        if self._class is not None:
            return self._class.NO_CLI
        else:
            halp = self._schema[self.schema_key].get_help(self.full_name)
            return 'cli' in halp.get('exclude', [])

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


class _SchemaNameSpace(Mapping):

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

    def get_help(self, key):
        try:
            return self._schema.get_help(self.name, key)
        except KeyError:
            raise KeyError(key)


class NotAvailable(Exception):
    pass


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
    _DIR = os.path.join(USER_CACHE_PATH, 'ipa', 'schema', FORMAT)

    def __init__(self, client, fingerprint=None):
        self._dict = {}
        self._namespaces = {}
        self._help = None

        for ns in self.namespaces:
            self._dict[ns] = {}
            self._namespaces[ns] = _SchemaNameSpace(self, ns)

        ttl = None
        read_failed = False

        if fingerprint is not None:
            try:
                self._read_schema(fingerprint)
            except Exception as e:
                # Failed to read the schema from cache. There may be a lot of
                # causes and not much we can do about it. Just ensure we will
                # ignore the cache and fetch the schema from server.
                logger.warning("Failed to read schema: %s", e)
                fingerprint = None
                read_failed = True

        if fingerprint is None:
            fingerprint, ttl = self._fetch(client, ignore_cache=read_failed)
            self._help = self._generate_help(self._dict)
            try:
                self._write_schema(fingerprint)
            except Exception as e:
                logger.warning("Failed to write schema: %s", e)

        self.fingerprint = fingerprint
        self.ttl = ttl

    def _fetch(self, client, ignore_cache=False):
        if not client.isconnected():
            client.connect(verbose=False)

        fps = []
        if not ignore_cache:
            try:
                fps = [fsdecode(f) for f in os.listdir(self._DIR)]
            except EnvironmentError:
                pass

        kwargs = {u'version': u'2.170'}
        if fps:
            kwargs[u'known_fingerprints'] = fps
        try:
            schema = client.forward(u'schema', **kwargs)['result']
        except errors.CommandError:
            raise NotAvailable()

        try:
            fp = schema['fingerprint']
            ttl = schema.pop('ttl')
            schema.pop('version')

            for key, value in schema.items():
                if key in self.namespaces:
                    value = {m['full_name']: m for m in value}
                self._dict[key] = value
        except KeyError as e:
            logger.warning("Failed to fetch schema: %s", e)
            raise NotAvailable()

        return (fp, ttl,)

    def _read_schema(self, fingerprint):
        # It's more efficient to read zip file members at once than to open
        # the zip file a couple of times, see #6690.
        filename = os.path.join(self._DIR, fingerprint)
        with zipfile.ZipFile(filename, 'r') as schema:
            for name in schema.namelist():
                ns, _slash, key = name.partition('/')
                if ns in self.namespaces:
                    self._dict[ns][key] = schema.read(name)
                elif name == '_help':
                    self._help = schema.read(name)

    def __getitem__(self, key):
        try:
            return self._namespaces[key]
        except KeyError:
            return self._dict[key]

    def _generate_help(self, schema):
        halp = {}

        for namespace in ('commands', 'topics'):
            halp[namespace] = {}

            for member_schema in schema[namespace].values():
                member_full_name = member_schema['full_name']

                topic = halp[namespace].setdefault(member_full_name, {})
                topic['name'] = member_schema['name']
                if 'doc' in member_schema:
                    topic['summary'] = (
                        member_schema['doc'].split('\n\n', 1)[0].strip())
                if 'topic_topic' in member_schema:
                    topic['topic_topic'] = member_schema['topic_topic']
                if 'exclude' in member_schema:
                    topic['exclude'] = member_schema['exclude']

        return halp

    def _write_schema(self, fingerprint):
        try:
            os.makedirs(self._DIR)
        except EnvironmentError as e:
            if e.errno != errno.EEXIST:
                raise

        with tempfile.NamedTemporaryFile('wb', prefix=fingerprint,
                                         dir=self._DIR, delete=False) as f:
            try:
                self._write_schema_data(f)
                ipautil.flush_sync(f)
                f.close()
            except Exception:
                os.unlink(f.name)
                raise
            else:
                os.rename(f.name, os.path.join(self._DIR, fingerprint))

    def _write_schema_data(self, fileobj):
        with zipfile.ZipFile(fileobj, 'w', zipfile.ZIP_DEFLATED) as schema:
            for key, value in self._dict.items():
                if key in self.namespaces:
                    ns = value
                    for member in ns:
                        path = '{}/{}'.format(key, member)
                        s = json.dumps(ns[member], default=json_default)
                        schema.writestr(path, s.encode('utf-8'))
                else:
                    schema.writestr(key, json.dumps(value).encode('utf-8'))

            schema.writestr(
                '_help',
                json.dumps(self._help, default=json_default).encode('utf-8')
            )

    def read_namespace_member(self, namespace, member):
        value = self._dict[namespace][member]

        if isinstance(value, bytes):
            value = json.loads(value.decode('utf-8'))
            self._dict[namespace][member] = value

        return value

    def iter_namespace(self, namespace):
        return iter(self._dict[namespace])

    def get_help(self, namespace, member):
        if isinstance(self._help, bytes):
            self._help = json.loads(
                self._help.decode('utf-8')  # pylint: disable=no-member
            )

        return self._help[namespace][member]


def get_package(server_info, client):
    NO_FINGERPRINT = object()

    fingerprint = NO_FINGERPRINT
    if server_info.is_valid():
        fingerprint = server_info.get('fingerprint', fingerprint)

    if fingerprint is not None:
        try:
            try:
                if fingerprint is NO_FINGERPRINT:
                    schema = Schema(client)
                else:
                    schema = Schema(client, fingerprint)
            except SchemaUpToDate as e:
                schema = Schema(client, e.fingerprint)
        except NotAvailable:
            fingerprint = None
            ttl = None
        except SchemaUpToDate as e:
            fingerprint = e.fingerprint
            ttl = e.ttl
        else:
            fingerprint = schema.fingerprint
            ttl = schema.ttl

        server_info['fingerprint'] = fingerprint
        server_info.update_validity(ttl)

    if fingerprint is None:
        raise NotAvailable()

    fingerprint = str(fingerprint)
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
            plugin = plugin_cls(schema, str(full_name))
            plugin = module.register()(plugin)  # pylint: disable=no-member
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
            s = topic['topic_topic']
            if isinstance(s, bytes):
                s = s.decode('utf-8')
            module.topic = s.partition('/')[0]
        else:
            module.topic = None

    return package
