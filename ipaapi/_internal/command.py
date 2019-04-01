#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#
"""FreeIPA API package -- internal API wrapper
"""
from __future__ import absolute_import

import collections
import inspect
import sys

import cryptography.x509
import dns.name
import six

import ipalib.x509
from ipalib import parameters
import ipapython.dnsutil

from .common import APIMapping, APIWrapper

try:
    import typing
except ImportError:
    typing = None

HAS_SIGNATURE = sys.version_info >= (3, 5)

if HAS_SIGNATURE:  # pylint: disable=no-member
    POSITIONAL_OR_KEYWORD = inspect.Parameter.POSITIONAL_OR_KEYWORD
    KEYWORD_ONLY = inspect.Parameter.KEYWORD_ONLY
    EMPTY = inspect.Parameter.empty
else:
    POSITIONAL_OR_KEYWORD = object()
    KEYWORD_ONLY = object()
    EMPTY = object()


class CommandNamespace(APIMapping):
    """IPA dynamic API wrapper"""

    __slots__ = ("_commands",)

    # blacklist for commands and topics
    _blacklist = frozenset()

    @classmethod
    def _create(cls, api):
        """Dynamically create Command namespace subclass and instance

        :param api: ipalib.api
        :return: instance of a CommandNamespace subclass
        """
        commands = {}
        topics = collections.defaultdict(set)
        for cmd in api.Command.values():
            if getattr(cmd, "NO_CLI", False):
                # skip internal plugins
                continue
            if cmd.name in cls._blacklist or cmd.topic in cls._blacklist:
                continue
            commands[cmd.name] = APICommand._create(api, cmd)
            topics[cmd.topic].add((cmd.name, cmd.summary))
        # build dynamic docstring
        lines = cls.__doc__.split("\n")
        for topic, cmds in sorted(topics.items()):
            lines.append("")
            lines.append("    {}:".format(topic))
            for name, summary in sorted(cmds):
                lines.append("      - {}: {}".format(name, summary))
        doc = "\n".join(lines)

        newcls = type(cls.__name__, (cls,), {"__doc__": doc})
        return newcls(api, commands)

    def __init__(self, api, commands):
        super(CommandNamespace, self).__init__(api)
        self._commands = commands

    def __dir__(self):
        items = set(super(CommandNamespace, self).__dir__())
        items.update(self._commands)
        return sorted(items)

    def __getattr__(self, item):
        try:
            return self[item]
        except KeyError:
            raise AttributeError(item)

    def __getitem__(self, item):
        return self._commands[item]

    def __len__(self):
        return len(self._commands)

    def __iter__(self):
        return iter(self._commands)


_map_types = {
    # map internal certificate subclass to generic cryptography class
    ipalib.x509.IPACertificate: cryptography.x509.Certificate,
    # map internal DNS name class to generic dnspython class
    ipapython.dnsutil.DNSName: dns.name.Name,
    # DN, Principal have their names mangled in ipaapi.__init__
}

ParameterSignature = collections.namedtuple(
    "ParameterSignature", "name kind default annotation doc"
)


def param_to_signature(param, is_arg=False):
    """Convert a ipalib parameter instance

    :param param: ipalib.parameters.Param instance
    :param is_arg: is the parameter a positional or keyword arg
    :return: ParameterSignature instance
    """
    kind = POSITIONAL_OR_KEYWORD if is_arg else KEYWORD_ONLY
    default = EMPTY if param.required else param.default

    allowed_types = tuple(_map_types.get(t, t) for t in param.allowed_types)

    # ipalib.parameters.DNSNameParam also handles text
    if isinstance(param, parameters.DNSNameParam):
        allowed_types += (six.text_type,)

    if typing is not None:
        ann = typing.Union[allowed_types]
        if param.multivalue:
            ann = typing.List[ann]
    else:
        # platforms without typing, fake Union as set and List as tuple
        if len(allowed_types) > 1:
            ann = frozenset(allowed_types)
        else:
            ann = allowed_types[0]
        if param.multivalue:
            ann = (ann,)

    if param.label:
        doc = six.text_type(param.label)
    elif param.doc:
        doc = six.text_type(param.doc)
    else:
        doc = None

    return ParameterSignature(param.name, kind, default, ann, doc)


class APICommand(APIWrapper):
    __slot__ = ("_command",)

    _blacklist_params = frozenset(["version"])

    @classmethod
    def _create(cls, api, cmd):
        """Dynamically create a APICommand subclass and instance

        :param api: ipalib.api
        :param cmd: ipa plugin instance (server or client)
        :return: instance of a APICommand subclass
        """
        # hook in here to override a specific command
        parentcls = cls

        # build dynamic signature and filter out duplicates
        # For example user_del has preserve flag and preserve bool
        params = []
        seen = set(cls._blacklist_params)
        args_options = [(cmd.get_args(), True), (cmd.get_options(), False)]
        for entries, flag in args_options:
            for entry in entries:
                if not isinstance(entry, parameters.Param):
                    # ipalib.plugins.misc.env has wrong type
                    return None
                param = param_to_signature(entry, flag)
                if param.name in seen:
                    continue
                params.append(param)
                seen.add(param.name)

        if HAS_SIGNATURE:  # pylint: disable=no-member
            params = [
                inspect.Parameter(
                    p.name, p.kind, default=p.default, annotation=p.annotation
                )
                for p in params
            ]
            # cannot describe return parameter with typing yet. TypedDict
            # is only available with mypy_extension.
            signature = inspect.Signature(
                params, return_annotation=typing.Dict[typing.Text, typing.Any]
            )
        else:
            signature = None

        if parentcls.__doc__ is not APICommand.__doc__:
            doc = parentcls.__doc__
        else:
            doc = cmd.summary

        newcls = type(
            cmd.name,
            (parentcls,),
            {"__doc__": doc, "__signature__": signature},
        )
        return newcls(api, cmd)

    def __init__(self, api, command):
        super(APICommand, self).__init__(api)
        self._command = command

    def __repr__(self):
        return "<Command {}>".format(self._command.name)

    def __call__(self, *args, **kwargs):
        return self._command(*args, **kwargs)

    @property
    def name(self):
        return self._command.name

    @property
    def topic(self):
        return self._command.topic

    @property
    def output(self):
        out = {o.name: o.type for o in self._command.output()}
        result_type = out.get("result")
        if result_type is not None:
            if issubclass(dict, result_type):
                pass
