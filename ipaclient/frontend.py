#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from ipalib import api
from ipalib.frontend import Command, Method
from ipalib.parameters import Str
from ipalib.text import _
from ipalib.util import classproperty


class ClientCommand(Command):
    def get_options(self):
        skip = set()
        for option in super(ClientCommand, self).get_options():
            if option.name in skip:
                continue
            if option.name in ('all', 'raw'):
                skip.add(option.name)
            yield option


class ClientMethod(ClientCommand, Method):
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
        # group, hostgroup
        Str(
            'membermanager',
            label=_("Failed member manager"),
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
        for param in self.params():
            if param.name not in self.obj.params:
                seen.add(param.name)
                yield param
        for output_param in super(ClientMethod, self).get_output_params():
            seen.add(output_param.name)
            yield output_param
        for output_param in self._failed_member_output_params:
            if output_param.name not in seen:
                yield output_param


class CommandOverride(Command):
    def __init__(self, api):
        super(CommandOverride, self).__init__(api)

        next_class = self.__get_next()
        self.next = next_class(api)

    @classmethod
    def __get_next(cls):
        return api.get_plugin_next(cls)

    @classmethod
    def __doc_getter(cls):
        return cls.__get_next().doc

    doc = classproperty(__doc_getter)

    @classmethod
    def __summary_getter(cls):
        return cls.__get_next().summary

    summary = classproperty(__summary_getter)

    @classmethod
    def __NO_CLI_getter(cls):
        return cls.__get_next().NO_CLI

    NO_CLI = classproperty(__NO_CLI_getter)

    @classmethod
    def __topic_getter(cls):
        return cls.__get_next().topic

    topic = classproperty(__topic_getter)

    @property
    def forwarded_name(self):
        return self.next.forwarded_name

    @property
    def api_version(self):
        return self.next.api_version

    def _on_finalize(self):
        self.next.finalize()

        super(CommandOverride, self)._on_finalize()

    def get_args(self):
        for arg in self.next.args():
            yield arg
        for arg in super(CommandOverride, self).get_args():
            yield arg

    def get_options(self):
        for option in self.next.options():
            yield option
        for option in super(CommandOverride, self).get_options():
            if option.name not in ('all', 'raw', 'version'):
                yield option

    def get_output_params(self):
        for output_param in self.next.output_params():
            yield output_param
        for output_param in super(CommandOverride, self).get_output_params():
            yield output_param

    def _iter_output(self):
        return self.next.output()


class MethodOverride(CommandOverride, Method):
    @property
    def obj_name(self):
        try:
            return self.next.obj_name
        except AttributeError:
            return None

    @property
    def attr_name(self):
        try:
            return self.next.attr_name
        except AttributeError:
            return None

    @property
    def obj(self):
        return self.next.obj

    def get_output_params(self):
        seen = set()
        for output_param in super(MethodOverride, self).get_output_params():
            if output_param.name in seen:
                continue
            seen.add(output_param.name)
            yield output_param
