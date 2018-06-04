#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import importlib
import itertools
import sys

import six
import hashlib

from .baseldap import LDAPObject
from ipalib import errors
from ipalib.crud import PKQuery, Retrieve, Search
from ipalib.frontend import Command, Local, Method, Object
from ipalib.output import Entry, ListOfEntries, ListOfPrimaryKeys, PrimaryKey
from ipalib.parameters import Bool, Dict, Flag, Str
from ipalib.plugable import Registry
from ipalib.request import context
from ipalib.text import _
from ipapython.version import API_VERSION

# Schema TTL sent to clients in response to schema call.
# Number of seconds before client should check for schema update.
# This should be long enough to not slow down regular work or skripts
# but also short enough to ensure schema will be retvieved soon after
# it was updated
SCHEMA_TTL = 3600  # default: 1 hour

__doc__ = _("""
API Schema
""") + _("""
Provides API introspection capabilities.
""") + _("""
EXAMPLES:
""") + _("""
 Show user-find details:
   ipa command-show user-find
""") + _("""
 Find user-find parameters:
   ipa param-find user-find
""")

if six.PY3:
    unicode = str

register = Registry()


class BaseMetaObject(Object):
    takes_params = (
        Str(
            'name',
            label=_("Name"),
            normalizer=lambda name: name.replace(u'-', u'_'),
            flags={'no_search'},
        ),
        Str(
            'doc?',
            label=_("Documentation"),
            flags={'no_search'},
        ),
        Str(
            'exclude*',
            label=_("Exclude from"),
            flags={'no_search'},
        ),
        Str(
            'include*',
            label=_("Include in"),
            flags={'no_search'},
        ),
    )

    def _get_obj(self, obj, **kwargs):
        raise NotImplementedError()

    def _retrieve(self, *args, **kwargs):
        raise NotImplementedError()

    def retrieve(self, *args, **kwargs):
        obj = self._retrieve(*args, **kwargs)
        obj = self._get_obj(obj, **kwargs)
        return obj

    def _search(self, *args, **kwargs):
        raise NotImplementedError()

    def _split_search_args(self, criteria=None):
        return [], criteria

    def search(self, *args, **kwargs):
        args, criteria = self._split_search_args(*args)

        result = self._search(*args, **kwargs)
        if not result:
            return tuple()

        result = (self._get_obj(r, **kwargs) for r in result)

        if criteria:
            criteria = criteria.lower()
            result = (r for r in result
                      if (criteria in r['name'].lower() or
                          criteria in r.get('doc', u'').lower()))

        if not kwargs.get('all', False) and kwargs.get('pkey_only', False):
            key = self.primary_key.name
            result = ({key: r[key]} for r in result)

        return result


class BaseMetaRetrieve(Retrieve):
    def execute(self, *args, **options):
        obj = self.obj.retrieve(*args, **options)
        return dict(result=obj, value=args[-1])


class BaseMetaSearch(Search):
    def get_options(self):
        for option in super(BaseMetaSearch, self).get_options():
            yield option

        yield Flag(
            'pkey_only?',
            label=_("Primary key only"),
            doc=_("Results should contain primary key attribute only "
                  "(\"%s\")") % 'name',
        )

    def execute(self, command, criteria=None, **options):
        result = list(self.obj.search(command, criteria, **options))
        return dict(result=result, count=len(result), truncated=False)


class MetaObject(BaseMetaObject):
    takes_params = BaseMetaObject.takes_params + (
        Str(
            'topic_topic?',
            label=_("Help topic"),
            flags={'no_search'},
        ),
    )

    def get_params(self):
        for param in super(MetaObject, self).get_params():
            yield param

            if param.name == 'name':
                yield Str(
                    'version',
                    label=_("Version"),
                    flags={'no_search'},
                )
                yield Str(
                    'full_name',
                    label=_("Full name"),
                    primary_key=True,
                    normalizer=lambda name: name.replace(u'-', u'_'),
                    flags={'no_search'},
                )


class MetaRetrieve(BaseMetaRetrieve):
    pass


class MetaSearch(BaseMetaSearch):
    pass


@register()
class metaobject(MetaObject):
    takes_params = MetaObject.takes_params + (
        Str(
            'params_param*',
            label=_("Parameters"),
            flags={'no_search'},
        ),
    )

    def _iter_params(self, metaobj):
        raise NotImplementedError()

    def _get_obj(self, metaobj, all=False, **kwargs):
        obj = dict()
        obj['name'] = unicode(metaobj.name)
        obj['version'] = unicode(metaobj.version)
        obj['full_name'] = unicode(metaobj.full_name)

        if all:
            params = [unicode(p.name) for p in self._iter_params(metaobj)]
            if params:
                obj['params_param'] = params

        return obj


class metaobject_show(MetaRetrieve):
    pass


class metaobject_find(MetaSearch):
    pass


@register()
class command(metaobject):
    takes_params = metaobject.takes_params + (
        Str(
            'obj_class?',
            label=_("Method of"),
            flags={'no_search'},
        ),
        Str(
            'attr_name?',
            label=_("Method name"),
            flags={'no_search'},
        ),
    )

    def _iter_params(self, cmd):
        for arg in cmd.args():
            yield arg
        for option in cmd.options():
            if option.name == 'version':
                continue
            yield option

    def _get_obj(self, cmd, **kwargs):
        obj = super(command, self)._get_obj(cmd, **kwargs)

        if cmd.doc:
            obj['doc'] = unicode(cmd.doc)

        if cmd.topic:
            try:
                topic = self.api.Object.topic.retrieve(unicode(cmd.topic))
            except errors.NotFound:
                pass
            else:
                obj['topic_topic'] = topic['full_name']

        if isinstance(cmd, Method):
            obj['obj_class'] = unicode(cmd.obj_full_name)
            obj['attr_name'] = unicode(cmd.attr_name)

        if cmd.NO_CLI:
            obj['exclude'] = [u'cli']

        return obj

    def _retrieve(self, name, **kwargs):
        try:
            cmd = self.api.Command[name]
            if not isinstance(cmd, Local):
                return cmd
        except KeyError:
            pass

        raise errors.NotFound(
            reason=_("%(pkey)s: %(oname)s not found") % {
                'pkey': name, 'oname': self.name,
            }
        )

    def _search(self, **kwargs):
        for cmd in self.api.Command():
            if not isinstance(cmd, Local):
                yield cmd


@register()
class command_show(metaobject_show):
    __doc__ = _("Display information about a command.")


@register()
class command_find(metaobject_find):
    __doc__ = _("Search for commands.")


@register()
class command_defaults(PKQuery):
    __doc__ = _('Return command defaults')
    NO_CLI = True

    takes_options = (
        Str('params*'),
        Dict('kw?'),
    )

    def execute(self, name, **options):
        command = self.api.Command[name]

        params = options.get('params') or []
        kw = options.get('kw') or {}

        result = command.get_default(params, **kw)

        return dict(result=result)


@register()
class class_(metaobject):
    name = 'class'

    def _iter_params(self, metaobj):
        for param in metaobj.params():
            yield param

        if isinstance(metaobj, LDAPObject) and 'show' in metaobj.methods:
            members = (
                '{}_{}'.format(attr_name, obj_name)
                for attr_name, obj_names in metaobj.attribute_members.items()
                for obj_name in obj_names)
            passwords = (name for _, name in metaobj.password_attributes)

            names = set(itertools.chain(members, passwords))
            for param in metaobj.methods.show.output_params():
                if param.name in names and param.name not in metaobj.params:
                    yield param

    def _retrieve(self, name, **kwargs):
        try:
            return self.api.Object[name]
        except KeyError:
            pass

        raise errors.NotFound(
            reason=_("%(pkey)s: %(oname)s not found") % {
                'pkey': name, 'oname': self.name,
            }
        )

    def _search(self, **kwargs):
        return self.api.Object()


@register()
class class_show(metaobject_show):
    __doc__ = _("Display information about a class.")


@register()
class class_find(metaobject_find):
    __doc__ = _("Search for classes.")


@register()
class topic_(MetaObject):
    name = 'topic'

    def __init__(self, api):
        super(topic_, self).__init__(api)
        self.__topics = None
        self.__topics_by_key = None

    def __make_topics(self):
        if self.__topics is not None and self.__topics_by_key is not None:
            return

        object.__setattr__(self, '_topic___topics', [])
        topics = self.__topics
        object.__setattr__(self, '_topic___topics_by_key', {})
        topics_by_key = self.__topics_by_key

        for command in self.api.Command():
            topic_value = command.topic
            if topic_value is None:
                continue
            topic_name = unicode(topic_value)

            while topic_name not in topics_by_key:
                topic_version = u'1'
                topic_full_name = u'{}/{}'.format(topic_name,
                                                  topic_version)
                topic = {
                    'name': topic_name,
                    'version': topic_version,
                    'full_name': topic_full_name,
                }
                topics.append(topic)
                # pylint: disable=unsupported-assignment-operation
                topics_by_key[topic_name] = topic
                topics_by_key[topic_full_name] = topic
                # pylint: enable=unsupported-assignment-operation

                for package in self.api.packages:
                    module_name = '.'.join((package.__name__, topic_name))
                    try:
                        module = sys.modules[module_name]
                    except KeyError:
                        try:
                            module = importlib.import_module(module_name)
                        except ImportError:
                            continue

                    if module.__doc__ is not None:
                        topic['doc'] = unicode(module.__doc__).strip()

                    try:
                        topic_value = module.topic
                    except AttributeError:
                        continue
                    if topic_value is not None:
                        topic_name = unicode(topic_value)
                        topic['topic_topic'] = u'{}/{}'.format(topic_name,
                                                               topic_version)
                    else:
                        topic.pop('topic_topic', None)

    def _get_obj(self, topic, **kwargs):
        return topic

    def _retrieve(self, full_name, **kwargs):
        self.__make_topics()
        try:
            return self.__topics_by_key[full_name]
        except KeyError:
            raise errors.NotFound(
                reason=_("%(pkey)s: %(oname)s not found") % {
                    'pkey': full_name, 'oname': self.name,
                }
            )

    def _search(self, **kwargs):
        self.__make_topics()
        return iter(self.__topics)


@register()
class topic_show(MetaRetrieve):
    __doc__ = _("Display information about a help topic.")


@register()
class topic_find(MetaSearch):
    __doc__ = _("Search for help topics.")


class BaseParam(BaseMetaObject):
    takes_params = BaseMetaObject.takes_params + (
        Str(
            'type?',
            label=_("Type"),
            flags={'no_search'},
        ),
        Bool(
            'required?',
            label=_("Required"),
            flags={'no_search'},
        ),
        Bool(
            'multivalue?',
            label=_("Multi-value"),
            flags={'no_search'},
        ),
    )

    def get_params(self):
        for param in super(BaseParam, self).get_params():
            if param.name == 'name':
                param = param.clone(primary_key=True)
            yield param

    @property
    def parent(self):
        raise AttributeError('parent')

    def _split_search_args(self, parent_name, criteria=None):
        return [parent_name], criteria


class BaseParamMethod(Method):
    def get_args(self):
        parent = self.obj.parent
        parent_key = parent.primary_key
        yield parent_key.clone_rename(
            parent.name + parent_key.name,
            cli_name=parent.name,
            label=parent_key.label,
            required=True,
            query=True,
        )

        for arg in super(BaseParamMethod, self).get_args():
            yield arg


class BaseParamRetrieve(BaseParamMethod, BaseMetaRetrieve):
    pass


class BaseParamSearch(BaseParamMethod, BaseMetaSearch):
    pass


@register()
class param(BaseParam):
    takes_params = BaseParam.takes_params + (
        Bool(
            'alwaysask?',
            label=_("Always ask"),
            flags={'no_search'},
        ),
        Str(
            'cli_metavar?',
            label=_("CLI metavar"),
            flags={'no_search'},
        ),
        Str(
            'cli_name?',
            label=_("CLI name"),
            flags={'no_search'},
        ),
        Bool(
            'confirm',
            label=_("Confirm (password)"),
            flags={'no_search'},
        ),
        Str(
            'default*',
            label=_("Default"),
            flags={'no_search'},
        ),
        Str(
            'default_from_param*',
            label=_("Default from"),
            flags={'no_search'},
        ),
        Str(
            'label?',
            label=_("Label"),
            flags={'no_search'},
        ),
        Bool(
            'no_convert?',
            label=_("Convert on server"),
            flags={'no_search'},
        ),
        Str(
            'option_group?',
            label=_("Option group"),
            flags={'no_search'},
        ),
        Bool(
            'sensitive?',
            label=_("Sensitive"),
            flags={'no_search'},
        ),
        Bool(
            'positional?',
            label=_("Positional argument"),
            flags={'no_search'},
        ),
    )

    @property
    def parent(self):
        return self.api.Object.metaobject

    def _get_obj(self, metaobj_param, **kwargs):
        metaobj, param = metaobj_param

        obj = dict()
        obj['name'] = unicode(param.name)

        if param.type is unicode:
            obj['type'] = u'str'
        elif param.type is bytes:
            obj['type'] = u'bytes'
        elif param.type is not None:
            obj['type'] = unicode(param.type.__name__)

        if not param.required:
            obj['required'] = False
        if param.multivalue:
            obj['multivalue'] = True
        if param.password:
            obj['sensitive'] = True
        if isinstance(metaobj, Command):
            if param.required and param.name not in metaobj.args:
                obj['positional'] = False
            elif not param.required and param.name in metaobj.args:
                obj['positional'] = True

        for key, value in param._Param__clonekw.items():
            if key in ('doc',
                       'label'):
                obj[key] = unicode(value)
            elif key in ('exclude',
                         'include'):
                obj[key] = list(unicode(v) for v in value)
            if isinstance(metaobj, Command):
                if key == 'alwaysask':
                    obj.setdefault(key, value)
                elif key == 'confirm':
                    obj[key] = value
                elif key in ('cli_metavar',
                             'cli_name',
                             'option_group'):
                    obj[key] = unicode(value)
                elif key == 'default':
                    if param.multivalue:
                        obj[key] = [unicode(v) for v in value]
                    else:
                        obj[key] = [unicode(value)]
                    if not param.autofill:
                        obj['alwaysask'] = True
                elif key == 'default_from':
                    obj['default_from_param'] = list(unicode(k)
                                                     for k in value.keys)
                    if not param.autofill:
                        obj['alwaysask'] = True
                elif key in ('exponential',
                             'normalizer',
                             'only_absolute',
                             'precision'):
                    obj['no_convert'] = True

        if ((isinstance(metaobj, Command) and 'no_option' in param.flags) or
                (isinstance(metaobj, Object) and 'no_output' in param.flags)):
            value = obj.setdefault('exclude', [])
            if u'cli' not in value:
                value.append(u'cli')
            if u'webui' not in value:
                value.append(u'webui')

        return obj

    def _retrieve(self, metaobjectfull_name, name, **kwargs):
        found = False

        try:
            metaobj = self.api.Command[metaobjectfull_name]
        except KeyError:
            raise errors.NotFound(
                reason=_("%(metaobject)s: %(oname)s not found") % {
                    'metaobject': metaobjectfull_name, 'oname': self.name,
                }
            )

        if 'command' in self.api.Object:
            plugin = self.api.Object['command']
            found = True
        elif 'class' in self.api.Object:
            plugin = self.api.Object['class']
            found = True

        if found:
            for param in plugin._iter_params(metaobj):
                if param.name == name:
                    return metaobj, param

        raise errors.NotFound(
            reason=_("%(pkey)s: %(oname)s not found") % {
                'pkey': name, 'oname': self.name,
            }
        )

    def _search(self, metaobjectfull_name, **kwargs):
        try:
            metaobj = self.api.Command[metaobjectfull_name]
            plugin = self.api.Object['command']
        except KeyError:
            try:
                metaobj = self.api.Object[metaobjectfull_name]
                plugin = self.api.Object['class']
            except KeyError:
                return tuple()

        return ((metaobj, param) for param in plugin._iter_params(metaobj))


@register()
class param_show(BaseParamRetrieve):
    __doc__ = _("Display information about a command parameter.")


@register()
class param_find(BaseParamSearch):
    __doc__ = _("Search command parameters.")


@register()
class output(BaseParam):
    @property
    def parent(self):
        return self.api.Object.command

    def _get_obj(self, cmd_output, **kwargs):
        cmd, output = cmd_output
        required = True
        multivalue = False

        if isinstance(output, (Entry, ListOfEntries)):
            type_type = dict
            multivalue = isinstance(output, ListOfEntries)
        elif isinstance(output, (PrimaryKey, ListOfPrimaryKeys)):
            if getattr(cmd, 'obj', None) and cmd.obj.primary_key:
                type_type = cmd.obj.primary_key.type
            else:
                type_type = type(None)
            multivalue = isinstance(output, ListOfPrimaryKeys)
        elif isinstance(output.type, tuple):
            if tuple in output.type or list in output.type:
                type_type = None
                multivalue = True
            else:
                type_type = output.type[0]
            required = type(None) not in output.type
        else:
            type_type = output.type

        obj = dict()
        obj['name'] = unicode(output.name)

        if type_type is unicode:
            obj['type'] = u'str'
        elif type_type is bytes:
            obj['type'] = u'bytes'
        elif type_type is not None:
            obj['type'] = unicode(type_type.__name__)

        if not required:
            obj['required'] = False

        if multivalue:
            obj['multivalue'] = True

        if 'doc' in output.__dict__:
            obj['doc'] = unicode(output.doc)

        return obj

    def _retrieve(self, commandfull_name, name, **kwargs):
        if not commandfull_name in self.api.Command:
            raise errors.NotFound(
                reason=_("%(command_name)s: %(oname)s not found") % {
                    'command_name': commandfull_name, 'oname': self.name,
                }
            )

        cmd = self.api.Command[commandfull_name]
        try:
            return (cmd, cmd.output[name])
        except KeyError:
            raise errors.NotFound(
                reason=_("%(pkey)s: %(oname)s not found") % {
                    'pkey': name, 'oname': self.name,
                }
            )

    def _search(self, commandfull_name, **kwargs):
        if not commandfull_name in self.api.Command:
            return None

        cmd = self.api.Command[commandfull_name]
        return ((cmd, output) for output in cmd.output())


@register()
class output_show(BaseParamRetrieve):
    __doc__ = _("Display information about a command output.")


@register()
class output_find(BaseParamSearch):
    __doc__ = _("Search for command outputs.")


@register()
class schema(Command):
    __doc__ = _('Store and provide schema for commands and topics')
    NO_CLI = True

    takes_options = (
        Str(
            'known_fingerprints*',
            label=_("Fingerprint of schema cached by client")
        ),
    )

    @staticmethod
    def _calculate_fingerprint(data):
        """
        Returns fingerprint for schema

        Behavior of this function can be changed at any time
        given that it always generates identical fingerprint for
        identical data (change in order of items in dict is
        irelevant) and the risk of generating identical fingerprint
        for different inputs is low.
        """
        to_process = [data]
        fingerprint = hashlib.sha1()

        for entry in to_process:
            if isinstance(entry, (list, tuple)):
                for item in entry:
                    to_process.append(item)
            elif isinstance(entry, dict):
                for key in sorted(entry.keys()):
                    to_process.append(key)
                    to_process.append(entry[key])
            else:
                fingerprint.update(unicode(entry).encode('utf-8'))

        return unicode(fingerprint.hexdigest()[:8])

    def _generate_schema(self, **kwargs):
        commands = list(self.api.Object.command.search(**kwargs))
        for command in commands:
            name = command['name']
            command['params'] = list(
                self.api.Object.param.search(name, **kwargs))
            command['output'] = list(
                self.api.Object.output.search(name, **kwargs))

        classes = list(self.api.Object['class'].search(**kwargs))
        for cls in classes:
            cls['params'] = list(
                self.api.Object.param.search(cls['name'], **kwargs))

        topics = list(self.api.Object.topic.search(**kwargs))

        schema = dict()
        schema['version'] = API_VERSION
        schema['commands'] = commands
        schema['classes'] = classes
        schema['topics'] = topics
        schema['fingerprint'] = self._calculate_fingerprint(schema)

        return schema

    def execute(self, *args, **kwargs):
        langs = "".join(getattr(context, "languages", []))

        if getattr(self.api, "_schema", None) is None:
            setattr(self.api, "_schema", {})

        schema = self.api._schema.get(langs)
        if schema is None:
            schema = self._generate_schema(**kwargs)
            self.api._schema[langs] = schema

        schema['ttl'] = SCHEMA_TTL

        if schema['fingerprint'] in kwargs.get('known_fingerprints', []):
            raise errors.SchemaUpToDate(
                fingerprint=schema['fingerprint'],
                ttl=schema['ttl'],
            )

        return dict(result=schema)
