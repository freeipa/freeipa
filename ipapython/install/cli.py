#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
Command line support.
"""

import collections
import optparse
import signal

from ipapython import admintool, ipa_log_manager
from ipapython.ipautil import CheckedIPAddress, private_ccache

from . import core, common

__all__ = ['install_tool', 'uninstall_tool']


def install_tool(configurable_class, command_name, log_file_name,
                 positional_arguments=None, usage=None, debug_option=False,
                 uninstall_log_file_name=None,
                 uninstall_positional_arguments=None, uninstall_usage=None):
    if (uninstall_log_file_name is not None or
            uninstall_positional_arguments is not None or
            uninstall_usage is not None):
        uninstall_kwargs = dict(
            configurable_class=configurable_class,
            command_name=command_name,
            log_file_name=uninstall_log_file_name,
            positional_arguments=uninstall_positional_arguments,
            usage=uninstall_usage,
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
            positional_arguments=positional_arguments,
            usage=usage,
            debug_option=debug_option,
            uninstall_kwargs=uninstall_kwargs,
        )
    )


def uninstall_tool(configurable_class, command_name, log_file_name,
                   positional_arguments=None, usage=None, debug_option=False):
    return type(
        'uninstall_tool({0})'.format(configurable_class.__name__),
        (UninstallTool,),
        dict(
            configurable_class=configurable_class,
            command_name=command_name,
            log_file_name=log_file_name,
            positional_arguments=positional_arguments,
            usage=usage,
            debug_option=debug_option,
        )
    )


class ConfigureTool(admintool.AdminTool):
    configurable_class = None
    debug_option = False
    positional_arguments = None

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
            if cls.positional_arguments and name in cls.positional_arguments:
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
            cli_name = knob_cls.cli_name or name.replace('_', '-')
            opt_str = '--{0}'.format(cli_name)
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
                opt_strs = ['--{0}'.format(a) for a in knob_cls.cli_aliases]
                opt_group.add_option(
                    *opt_strs,
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
    def _option_callback(cls, option, opt_str, value, parser, knob_cls):
        old_value = getattr(parser.values, option.dest, None)
        try:
            value = cls._parse_knob(knob_cls, old_value, value)
        except ValueError as e:
            raise optparse.OptionValueError(
                "option {0}: {1}".format(opt_str, e))

        setattr(parser.values, option.dest, value)

    @classmethod
    def _parse_knob(cls, knob_cls, old_value, value):
        if knob_cls.type is bool:
            parse = bool
            is_list = False
            value = True
        else:
            if isinstance(knob_cls.type, tuple):
                assert knob_cls.type[0] is list
                value_type = knob_cls.type[1]
                is_list = True
            else:
                value_type = knob_cls.type
                is_list = False

            if value_type is int:
                def parse(value):
                    try:
                        return int(value, 0)
                    except ValueError:
                        raise ValueError(
                            "invalid integer value: {0}".format(repr(value)))
            elif value_type is long:
                def parse(value):
                    try:
                        return long(value, 0)
                    except ValueError:
                        raise ValueError(
                            "invalid long integer value: {0}".format(
                                repr(value)))
            elif value_type == 'ip':
                def parse(value):
                    try:
                        return CheckedIPAddress(value)
                    except Exception as e:
                        raise ValueError("invalid IP address {0}: {1}".format(
                            value, e))
            elif value_type == 'ip-local':
                def parse(value):
                    try:
                        return CheckedIPAddress(value, match_local=True)
                    except Exception as e:
                        raise ValueError("invalid IP address {0}: {1}".format(
                            value, e))
            elif isinstance(value_type, set):
                def parse(value):
                    if value not in value_type:
                        raise ValueError(
                            "invalid choice {0} (choose from {1})".format(
                                repr(value), ', '.join(repr(value_type))))
                    return value
            else:
                parse = value_type

        value = parse(value)

        if is_list:
            old_value = old_value or []
            old_value.append(value)
            value = old_value

        return value

    def validate_options(self, needs_root=True):
        super(ConfigureTool, self).validate_options(needs_root=needs_root)

        if self.positional_arguments:
            if len(self.args) > len(self.positional_arguments):
                self.option_parser.error("Too many arguments provided")

            index = 0

            transformed_cls = self._transform(self.configurable_class)
            for owner_cls, name in transformed_cls.knobs():
                knob_cls = getattr(owner_cls, name)
                if name not in self.positional_arguments:
                    continue

                try:
                    value = self.args[index]
                except IndexError:
                    break

                old_value = getattr(self.options, name, None)
                try:
                    value = self._parse_knob(knob_cls, old_value, value)
                except ValueError as e:
                    self.option_parser.error(
                        "argument {0}: {1}".format(index + 1, e))

                setattr(self.options, name, value)

                index += 1

    def _setup_logging(self, log_file_mode='w', no_file=False):
        if no_file:
            log_file_name = None
        elif self.options.log_file:
            log_file_name = self.options.log_file
        else:
            log_file_name = self.log_file_name
        ipa_log_manager.standard_logging_setup(log_file_name,
                                               debug=self.options.verbose)
        self.log = ipa_log_manager.log_mgr.get_logger(self)
        if log_file_name:
            self.log.debug('Logging to %s' % log_file_name)
        elif not no_file:
            self.log.debug('Not logging to a file')

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
            try:
                index = self.positional_arguments.index(e.name)
            except IndexError:
                cli_name = knob_cls.cli_name or e.name.replace('_', '-')
                desc = "option --{0}".format(cli_name)
            else:
                desc = "argument {0}".format(index + 1)
            self.option_parser.error("{0}: {1}".format(desc, e))
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
