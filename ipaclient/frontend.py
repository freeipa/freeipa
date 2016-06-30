#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from ipalib.frontend import Command, Method


class CommandOverride(Command):
    def __init__(self, api):
        super(CommandOverride, self).__init__(api)

        next_class = api.get_plugin_next(type(self))
        self.next = next_class(api)

    @property
    def doc(self):
        return self.next.doc

    @property
    def NO_CLI(self):
        return self.next.NO_CLI

    @property
    def topic(self):
        return self.next.topic

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
