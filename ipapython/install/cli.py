#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
Command line support.
"""

import collections
import optparse
import signal

from ipapython import admintool
from ipapython.ipautil import CheckedIPAddress, private_ccache

from . import core, common

__all__ = ['install_tool', 'uninstall_tool']


def install_tool(configurable_class, command_name, log_file_name,
                 debug_option=False, uninstall_log_file_name=None):
    if uninstall_log_file_name is not None:
        uninstall_kwargs = dict(
            configurable_class=configurable_class,
            command_name=command_name,
            log_file_name=uninstall_log_file_name,
            debug_option=debug_option,
        )
    else:
        uninstall_kwargs = None

    return type(
        'install_tool({0})'.format(configurable_class.__name__),
        (InstallTool,),
        dict(
            configurable_class=configurable_class,
            command_name=command_name,
            log_file_name=log_file_name,
            debug_option=debug_option,
            uninstall_kwargs=uninstall_kwargs,
        )
    )


def uninstall_tool(configurable_class, command_name, log_file_name,
                   debug_option=False):
    return type(
        'uninstall_tool({0})'.format(configurable_class.__name__),
        (UninstallTool,),
        dict(
            configurable_class=configurable_class,
            command_name=command_name,
            log_file_name=log_file_name,
            debug_option=debug_option,
        )
    )


class ConfigureTool(admintool.AdminTool):
    configurable_class = None
    debug_option = False

    @staticmethod
    def _transform(configurable_class):
        raise NotImplementedError

    @classmethod
    def add_options(cls, parser):
        basic_group = optparse.OptionGroup(parser, "basic options")

        groups = collections.OrderedDict()
        groups[None] = basic_group

        transformed_cls = cls._transform(cls.configurable_class)
        for owner_cls, name in transformed_cls.knobs():
            knob_cls = getattr(owner_cls, name)
            if not knob_cls.initializable:
                continue

            group_cls = owner_cls.group()
            try:
                opt_group = groups[group_cls]
            except KeyError:
                opt_group = groups[group_cls] = optparse.OptionGroup(
                    parser, "{0} options".format(group_cls.description))

            kwargs = dict()
            if knob_cls.type is bool:
                kwargs['type'] = None
            elif knob_cls.type is int:
                kwargs['type'] = 'int'
            elif knob_cls.type is long:
                kwargs['type'] = 'long'
            elif knob_cls.type is float:
                kwargs['type'] = 'float'
            elif knob_cls.type is complex:
                kwargs['type'] = 'complex'
            elif isinstance(knob_cls.type, set):
                kwargs['type'] = 'choice'
                kwargs['choices'] = list(knob_cls.type)
            else:
                kwargs['type'] = 'string'
            kwargs['dest'] = name
            kwargs['action'] = 'callback'
            kwargs['callback'] = cls._option_callback
            kwargs['callback_args'] = (knob_cls,)
            if knob_cls.sensitive:
                kwargs['sensitive'] = True
            if knob_cls.cli_metavar:
                kwargs['metavar'] = knob_cls.cli_metavar

            if knob_cls.cli_short_name:
                short_opt_str = '-{0}'.format(knob_cls.cli_short_name)
            else:
                short_opt_str = ''
            cli_name = knob_cls.cli_name or name
            opt_str = '--{0}'.format(cli_name.replace('_', '-'))
            if not knob_cls.deprecated:
                help = knob_cls.description
            else:
                help = optparse.SUPPRESS_HELP
            opt_group.add_option(
                short_opt_str, opt_str,
                help=help,
                **kwargs
            )

            if knob_cls.cli_aliases:
                opt_group.add_option(
                    *knob_cls.cli_aliases,
                    help=optparse.SUPPRESS_HELP,
                    **kwargs
                )

        if issubclass(transformed_cls, common.Interactive):
            basic_group.add_option(
                '-U', '--unattended',
                dest='unattended',
                default=False,
                action='store_true',
                help="unattended (un)installation never prompts the user",
            )

        for group, opt_group in groups.iteritems():
            parser.add_option_group(opt_group)

        super(ConfigureTool, cls).add_options(parser,
                                              debug_option=cls.debug_option)

    @classmethod
    def _option_callback(cls, option, opt_str, value, parser, knob):
        if knob.type is bool:
            value_type = bool
            is_list = False
            value = True
        else:
            if isinstance(knob.type, tuple):
                assert knob.type[0] is list
                value_type = knob.type[1]
                is_list = True
            else:
                value_type = knob.type
                is_list = False

            if value_type == 'ip':
                value_type = CheckedIPAddress
            elif value_type == 'ip-local':
                value_type = lambda v: CheckedIPAddress(v, match_local=True)

        try:
            value = value_type(value)
        except ValueError as e:
            raise optparse.OptionValueError(
                "option {0}: {1}".format(opt_str, e))

        if is_list:
            old_value = getattr(parser.values, option.dest) or []
            old_value.append(value)
            value = old_value

        setattr(parser.values, option.dest, value)

    def validate_options(self, needs_root=True):
        super(ConfigureTool, self).validate_options(needs_root=needs_root)

    def run(self):
        kwargs = {}

        transformed_cls = self._transform(self.configurable_class)
        for owner_cls, name in transformed_cls.knobs():
            value = getattr(self.options, name, None)
            if value is not None:
                kwargs[name] = value

        if (issubclass(self.configurable_class, common.Interactive) and
                not self.options.unattended):
            kwargs['interactive'] = True

        try:
            cfgr = transformed_cls(**kwargs)
        except core.KnobValueError as e:
            knob_cls = getattr(transformed_cls, e.name)
            cli_name = knob_cls.cli_name or e.name
            opt_str = '--{0}'.format(cli_name.replace('_', '-'))
            self.option_parser.error("option {0}: {1}".format(opt_str, e))
        except RuntimeError as e:
            self.option_parser.error(str(e))

        signal.signal(signal.SIGTERM, self.__signal_handler)

        # Use private ccache
        with private_ccache():
            super(ConfigureTool, self).run()

            cfgr.run()

    @staticmethod
    def __signal_handler(signum, frame):
        raise KeyboardInterrupt


class InstallTool(ConfigureTool):
    uninstall_kwargs = None

    _transform = staticmethod(common.installer)

    @classmethod
    def add_options(cls, parser):
        super(InstallTool, cls).add_options(parser)

        if cls.uninstall_kwargs is not None:
            uninstall_group = optparse.OptionGroup(parser, "uninstall options")
            uninstall_group.add_option(
                '--uninstall',
                dest='uninstall',
                default=False,
                action='store_true',
                help=("uninstall an existing installation. The uninstall can "
                      "be run with --unattended option"),
            )
            parser.add_option_group(uninstall_group)

    @classmethod
    def get_command_class(cls, options, args):
        if cls.uninstall_kwargs is not None and options.uninstall:
            uninstall_cls = uninstall_tool(**cls.uninstall_kwargs)
            uninstall_cls.option_parser = cls.option_parser
            return uninstall_cls
        else:
            return super(InstallTool, cls).get_command_class(options, args)


class UninstallTool(ConfigureTool):
    _transform = staticmethod(common.uninstaller)
