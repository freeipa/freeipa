#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import collections
import os.path
import sys
import types

import six

from ipaclient.plugins.rpcclient import rpcclient
from ipalib import parameters, plugable
from ipalib.frontend import Command, Method, Object
from ipalib.output import Output
from ipalib.parameters import Bool, DefaultFrom, Flag, Password, Str
from ipalib.text import ConcatenatedLazyText, _
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

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


class _SchemaCommand(Command):
    def __fix_default_from(self, param):
        api = self.api
        name = unicode(self.name)
        param_name = unicode(param.name)
        keys = param.default_from.keys

        if keys:
            def callback(*args):
                kw = dict(zip(keys, args))
                result = api.Command.command_defaults(
                    name,
                    params=[param_name],
                    kw=kw,
                )['result']
                return result.get(param_name)
        else:
            def callback():
                result = api.Command.command_defaults(
                    name,
                    params=[param_name],
                )['result']
                return result.get(param_name)

        callback.__name__ = '{0}_{1}_default'.format(self.name, param.name)

        return param.clone(default_from=DefaultFrom(callback, *keys))

    def get_args(self):
        for arg in super(_SchemaCommand, self).get_args():
            if arg.default_from is not None:
                arg = self.__fix_default_from(arg)
            yield arg

    def get_options(self):
        skip = set()
        for option in super(_SchemaCommand, self).get_options():
            if option.name in skip:
                continue
            if option.name in ('all', 'raw'):
                skip.add(option.name)
            if option.default_from is not None:
                option = self.__fix_default_from(option)
            if (isinstance(option, Bool) and
                    option.autofill and
                    option.default is False):
                option = option.clone_retype(option.name, Flag)
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

    def get_output_params(self):
        seen = set()
        for output_param in super(_SchemaMethod, self).get_output_params():
            seen.add(output_param.name)
            yield output_param
        for output_param in self._failed_member_output_params:
            if output_param.name not in seen:
                yield output_param


def _nope():
    pass


def _create_param_convert_scalar(cls):
    def _convert_scalar(self, value, index=None):
        if isinstance(value, unicode):
            return value
        return super(cls, self)._convert_scalar(value)

    return _convert_scalar


def _create_param(meta):
    type_name = str(meta['type'])
    sensitive = meta.get('sensitive', False)

    if type_name == 'str' and sensitive:
        cls = Password
        sensitive = False
    else:
        try:
            cls = _PARAMS[type_name]
        except KeyError:
            cls = Str

    kwargs = {}
    default = None

    for key, value in meta.items():
        if key in ('alwaysask',
                   'doc',
                   'label',
                   'multivalue',
                   'no_convert',
                   'option_group',
                   'required',
                   'sortorder'):
            kwargs[key] = value
        elif key in ('cli_metavar',
                     'cli_name'):
            kwargs[key] = str(value)
        elif key == 'confirm' and issubclass(cls, parameters.Password):
            kwargs[key] = value
        elif key == 'default':
            default = value
        elif key == 'default_from_param':
            kwargs['default_from'] = DefaultFrom(_nope,
                                                 *(str(k) for k in value))
        elif key in ('exclude',
                     'include'):
            kwargs[key] = tuple(str(v) for v in value)

    if default is not None:
        tmp = cls(str(meta['name']), **dict(kwargs, no_convert=False))
        if tmp.multivalue:
            default = tuple(tmp._convert_scalar(d) for d in default)
        else:
            default = tmp._convert_scalar(default[0])
        kwargs['default'] = default

    if 'default' in kwargs or 'default_from' in kwargs:
        kwargs['autofill'] = not kwargs.pop('alwaysask', False)

    param = cls(str(meta['name']), **kwargs)

    if sensitive:
        object.__setattr__(param, 'password', True)

    return param


def _create_output(schema):
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


def _create_command(schema):
    command = {}
    command['name'] = str(schema['name'])
    if 'doc' in schema:
        command['doc'] = ConcatenatedLazyText(schema['doc'])
    if 'topic_topic' in schema:
        command['topic'] = str(schema['topic_topic'])
    else:
        command['topic'] = None
    if 'obj_class' in schema:
        command['obj_name'] = str(schema['obj_class'])
    if 'attr_name' in schema:
        command['attr_name'] = str(schema['attr_name'])
    if 'exclude' in schema and u'cli' in schema['exclude']:
        command['NO_CLI'] = True
    command['takes_args'] = tuple(
        _create_param(s) for s in schema['params']
        if s.get('positional', s.get('required', True)))
    command['takes_options'] = tuple(
        _create_param(s) for s in schema['params']
        if not s.get('positional', s.get('required', True)))
    command['has_output'] = tuple(
        _create_output(m) for m in schema['output'])

    return command


def _create_class(schema):
    cls = {}
    cls['name'] = str(schema['name'])
    if 'doc' in schema:
        cls['doc'] = ConcatenatedLazyText(schema['doc'])
    if 'topic_topic' in schema:
        cls['topic'] = str(schema['topic_topic'])
    else:
        cls['topic'] = None
    cls['takes_params'] = tuple(_create_param(s) for s in schema['params'])

    return cls


class _LazySchemaPlugin(object):
    def __init__(self, base, schema):
        self.__base = base
        self.__schema = schema
        self.__class = None
        self.__module__ = None

    @property
    def name(self):
        return str(self.__schema['name'])

    @property
    def bases(self):
        if self.__base is Command:
            if 'obj_class' in self.__schema:
                return (_SchemaMethod,)
            else:
                return (_SchemaCommand,)
        else:
            return (self.__base,)

    def __call__(self, api):
        if self.__class is None:
            if self.__base is Command:
                metaobject = _create_command(self.__schema)
            else:
                metaobject = _create_class(self.__schema)
            metaobject = type(self.name, self.bases, metaobject)
            metaobject.__module__ = self.__module__
            self.__class = metaobject

        return self.__class(api)


def _create_commands(schema):
    return [_LazySchemaPlugin(Command, s) for s in schema]


def _create_classes(schema):
    return [_LazySchemaPlugin(Object, s) for s in schema]


def _create_topic(schema):
    topic = {}
    topic['name'] = str(schema['name'])
    if 'doc' in schema:
        topic['doc'] = ConcatenatedLazyText(schema['doc'])
    if 'topic_topic' in schema:
        topic['topic'] = str(schema['topic_topic'])
    else:
        topic['topic'] = None

    return topic


def _create_topics(schema):
    return [_create_topic(s) for s in schema]


def get_package(api):
    package_name = '{}${}'.format(__name__, id(api))
    package_dir = '{}${}'.format(os.path.splitext(__file__)[0], id(api))

    try:
        return sys.modules[package_name]
    except KeyError:
        pass

    client = rpcclient(api)
    client.finalize()

    client.connect(verbose=False)
    try:
        schema = client.forward(u'schema', version=u'2.170')['result']
    finally:
        client.disconnect()

    commands = _create_commands(schema['commands'])
    classes = _create_classes(schema['classes'])
    topics = _create_topics(schema['topics'])

    package = types.ModuleType(package_name)
    package.__file__ = os.path.join(package_dir, '__init__.py')
    package.modules = []
    sys.modules[package_name] = package

    module_name = '.'.join((package_name, 'commands'))
    module = types.ModuleType(module_name)
    module.__file__ = os.path.join(package_dir, 'commands.py')
    module.register = plugable.Registry()
    package.modules.append('commands')
    sys.modules[module_name] = module

    for command in commands:
        command.__module__ = module_name
        command = module.register()(command)
        setattr(module, command.name, command)

    for cls in classes:
        cls.__module__ = module_name
        cls = module.register()(cls)
        setattr(module, cls.name, command)

    for topic in topics:
        name = topic.pop('name')
        module_name = '.'.join((package_name, name))
        try:
            module = sys.modules[module_name]
        except KeyError:
            module = sys.modules[module_name] = types.ModuleType(module_name)
            module.__file__ = os.path.join(package_dir, '{}.py'.format(name))
        module.__dict__.update(topic)
        try:
            module.__doc__ = module.doc
        except AttributeError:
            pass

    return package
