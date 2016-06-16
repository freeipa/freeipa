#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import importlib
import itertools
import sys

import six

from .baseldap import LDAPObject
from ipalib import errors
from ipalib.crud import PKQuery, Retrieve, Search
from ipalib.frontend import Command, Local, Method, Object
from ipalib.output import Entry, ListOfEntries, ListOfPrimaryKeys, PrimaryKey
from ipalib.parameters import Bool, Dict, Flag, Int, Str
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython.version import API_VERSION

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
            primary_key=True,
            normalizer=lambda name: name.replace(u'-', u'_'),
            flags={'no_search'},
        ),
        Str(
            'doc?',
            label=_("Documentation"),
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
        result = (self._get_obj(r, **kwargs) for r in result)

        if criteria:
            criteria = criteria.lower()
            result = (r for r in result
                      if (criteria in r['name'].lower() or
                          criteria in r.get('doc', u'').lower()))

        if not kwargs.get('all', False) and kwargs.get('pkey_only', False):
            result = ({'name': r['name']} for r in result)

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

    def execute(self, criteria=None, **options):
        result = list(self.obj.search(criteria, **options))
        return dict(result=result, count=len(result), truncated=False)


class MetaObject(BaseMetaObject):
    takes_params = BaseMetaObject.takes_params + (
        Str(
            'topic_topic?',
            label=_("Help topic"),
            flags={'no_search'},
        ),
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
        Str(
            'args_param*',
            label=_("Arguments"),
            flags={'no_search'},
        ),
        Str(
            'options_param*',
            label=_("Options"),
            flags={'no_search'},
        ),
        Bool(
            'no_cli?',
            label=_("Exclude from CLI"),
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
                obj['topic_topic'] = topic['name']

        if isinstance(cmd, Method):
            obj['obj_class'] = unicode(cmd.obj_name)
            obj['attr_name'] = unicode(cmd.attr_name)

        if cmd.NO_CLI:
            obj['no_cli'] = True

        if len(cmd.args):
            obj['args_param'] = tuple(unicode(n) for n in cmd.args)

        if len(cmd.options):
            obj['options_param'] = tuple(
                unicode(n) for n in cmd.options if n != 'version')

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
    NO_CLI = True

    takes_options = (
        Str('params*'),
        Dict('kw?'),
    )

    def execute(self, name, **options):
        command = self.api.Command[name]

        params = options.get('params', [])
        kw = options.get('kw', {})

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

    def __get_topics(self):
        if self.__topics is None:
            topics = {}
            object.__setattr__(self, '_topic___topics', topics)

            for command in self.api.Command():
                topic_value = command.topic
                if topic_value is None:
                    continue
                topic_name = unicode(topic_value)

                while topic_name not in topics:
                    topic = topics[topic_name] = {'name': topic_name}

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
                            topic['topic_topic'] = topic_name
                        else:
                            topic.pop('topic_topic', None)

        return self.__topics

    def _get_obj(self, topic, **kwargs):
        return topic

    def _retrieve(self, name, **kwargs):
        try:
            return self.__get_topics()[name]
        except KeyError:
            raise errors.NotFound(
                reason=_("%(pkey)s: %(oname)s not found") % {
                    'pkey': name, 'oname': self.name,
                }
            )

    def _search(self, **kwargs):
        return self.__get_topics().values()


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
        Bool(
            'autofill?',
            label=_("Autofill"),
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
            'deprecated_cli_aliases*',
            label=_("Deprecated CLI aliases"),
            flags={'no_search'},
        ),
        Str(
            'exclude*',
            label=_("Exclude from"),
            flags={'no_search'},
        ),
        Str(
            'hint?',
            label=_("Hint"),
            flags={'no_search'},
        ),
        Str(
            'include*',
            label=_("Include in"),
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
        Int(
            'sortorder?',
            label=_("Sort order"),
            flags={'no_search'},
        ),
        Bool(
            'dnsrecord_extra?',
            label=_("Extra field (DNS record)"),
            flags={'no_search'},
        ),
        Bool(
            'dnsrecord_part?',
            label=_("Part (DNS record)"),
            flags={'no_search'},
        ),
        Bool(
            'no_option?',
            label=_("No option"),
            flags={'no_search'},
        ),
        Bool(
            'no_output?',
            label=_("No output"),
            flags={'no_search'},
        ),
        Bool(
            'suppress_empty?',
            label=_("Suppress empty"),
            flags={'no_search'},
        ),
        Bool(
            'sensitive?',
            label=_("Sensitive"),
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

        for key, value in param._Param__clonekw.items():
            if key in ('doc',
                       'label'):
                obj[key] = unicode(value)
            elif key in ('exclude',
                         'include'):
                obj[key] = list(unicode(v) for v in value)
            if isinstance(metaobj, Command):
                if key in ('alwaysask',
                           'autofill',
                           'confirm',
                           'sortorder'):
                    obj[key] = value
                elif key in ('cli_metavar',
                             'cli_name',
                             'hint',
                             'option_group'):
                    obj[key] = unicode(value)
                elif key == 'default':
                    if param.multivalue:
                        obj[key] = [unicode(v) for v in value]
                    else:
                        obj[key] = [unicode(value)]
                elif key == 'default_from':
                    obj['default_from_param'] = list(unicode(k)
                                                     for k in value.keys)
                elif key == 'deprecated_cli_aliases':
                    obj[key] = list(unicode(v) for v in value)
                elif key in ('exponential',
                             'normalizer',
                             'only_absolute',
                             'precision'):
                    obj['no_convert'] = True

        for flag in (param.flags or []):
            if flag in ('no_output',
                        'suppress_empty'):
                obj[flag] = True
            if isinstance(metaobj, Command):
                if flag in ('dnsrecord_extra',
                            'dnsrecord_part',
                            'no_option'):
                    obj[flag] = True

        return obj

    def _retrieve(self, metaobjectname, name, **kwargs):
        try:
            metaobj = self.api.Command[metaobjectname]
            plugin = self.api.Object['command']
        except KeyError:
            metaobj = self.api.Object[metaobjectname]
            plugin = self.api.Object['class']

        for param in plugin._iter_params(metaobj):
            if param.name == name:
                return metaobj, param

        raise errors.NotFound(
            reason=_("%(pkey)s: %(oname)s not found") % {
                'pkey': name, 'oname': self.name,
            }
        )

    def _search(self, metaobjectname, **kwargs):
        try:
            metaobj = self.api.Command[metaobjectname]
            plugin = self.api.Object['command']
        except KeyError:
            metaobj = self.api.Object[metaobjectname]
            plugin = self.api.Object['class']

        return ((metaobj, param) for param in plugin._iter_params(metaobj))


@register()
class param_show(BaseParamRetrieve):
    __doc__ = _("Display information about a command parameter.")


@register()
class param_find(BaseParamSearch):
    __doc__ = _("Search command parameters.")


@register()
class output(BaseParam):
    takes_params = BaseParam.takes_params + (
        Bool(
            'no_display?',
            label=_("Do not display"),
            flags={'no_search'},
        ),
    )

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

        if 'flags' in output.__dict__:
            if 'no_display' in output.flags:
                obj['no_display'] = True

        return obj

    def _retrieve(self, commandname, name, **kwargs):
        cmd = self.api.Command[commandname]
        try:
            return (cmd, cmd.output[name])
        except KeyError:
            raise errors.NotFound(
                reason=_("%(pkey)s: %(oname)s not found") % {
                    'pkey': name, 'oname': self.name,
                }
            )

    def _search(self, commandname, **kwargs):
        cmd = self.api.Command[commandname]
        return ((cmd, output) for output in cmd.output())


@register()
class output_show(BaseParamRetrieve):
    __doc__ = _("Display information about a command output.")


@register()
class output_find(BaseParamSearch):
    __doc__ = _("Search for command outputs.")


@register()
class schema(Command):
    NO_CLI = True

    def execute(self, *args, **kwargs):
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

        return dict(result=schema)
