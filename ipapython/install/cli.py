#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
Command line support.
"""

import collections
import enum
import logging
import optparse  # pylint: disable=deprecated-module
import signal

import six

from ipapython import admintool
from ipapython.ipa_log_manager import standard_logging_setup
from ipapython.ipautil import (CheckedIPAddress, CheckedIPAddressLoopback,
                               private_ccache)

from . import core, common

__all__ = ['install_tool', 'uninstall_tool']

if six.PY3:
    long = int

NoneType = type(None)

logger = logging.getLogger(__name__)


def _get_usage(configurable_class):
    usage = '%prog [options]'

    for owner_cls, name in configurable_class.knobs():
        knob_cls = getattr(owner_cls, name)
        if knob_cls.is_cli_positional():
            if knob_cls.cli_metavar is not None:
                metavar = knob_cls.cli_metavar
            elif knob_cls.cli_names:
                metavar = knob_cls.cli_names[0].upper()
            else:
                metavar = name.replace('_', '-').upper()

            try:
                knob_cls.default
            except AttributeError:
                fmt = ' {}'
            else:
                fmt = ' [{}]'

            usage += fmt.format(metavar)

    return usage


def install_tool(configurable_class, command_name, log_file_name,
                 debug_option=False, verbose=False, console_format=None,
                 use_private_ccache=True, uninstall_log_file_name=None,
                 ignore_return_codes=()):
    """
    Some commands represent multiple related tools, e.g.
    ``ipa-server-install`` and ``ipa-server-install --uninstall`` would be
    represented by separate classes. Only their options are the same.

    :param configurable_class: the command class for options
    :param command_name: the command name shown in logs/output
    :param log_file_name: if None, logging is to stderr only
    :param debug_option: log level is DEBUG
    :param verbose: log level is INFO
    :param console_format: logging format for stderr
    :param use_private_ccache: a temporary ccache is created and used
    :param uninstall_log_file_name: if not None the log for uninstall
    :param ignore_return_codes: tuple of error codes to not log errors
                                for. Let the caller do it if it wants.
    """
    if uninstall_log_file_name is not None:
        uninstall_kwargs = dict(
            configurable_class=configurable_class,
            command_name=command_name,
            log_file_name=uninstall_log_file_name,
            debug_option=debug_option,
            verbose=verbose,
            console_format=console_format,
            ignore_return_codes=ignore_return_codes,
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
            usage=_get_usage(configurable_class),
            debug_option=debug_option,
            verbose=verbose,
            console_format=console_format,
            uninstall_kwargs=uninstall_kwargs,
            use_private_ccache=use_private_ccache,
            ignore_return_codes=ignore_return_codes,
        )
    )


def uninstall_tool(configurable_class, command_name, log_file_name,
                   debug_option=False, verbose=False, console_format=None,
                   ignore_return_codes=()):
    return type(
        'uninstall_tool({0})'.format(configurable_class.__name__),
        (UninstallTool,),
        dict(
            configurable_class=configurable_class,
            command_name=command_name,
            log_file_name=log_file_name,
            usage=_get_usage(configurable_class),
            debug_option=debug_option,
            verbose=verbose,
            console_format=console_format,
            ignore_return_codes=ignore_return_codes,
        )
    )


class ConfigureTool(admintool.AdminTool):
    configurable_class = None
    debug_option = False
    verbose = False
    console_format = None
    use_private_ccache = True

    @staticmethod
    def _transform(configurable_class):
        raise NotImplementedError

    @classmethod
    def add_options(cls, parser, positional=False):
        transformed_cls = cls._transform(cls.configurable_class)

        if issubclass(transformed_cls, common.Interactive):
            parser.add_option(
                '-U', '--unattended',
                dest='unattended',
                default=False,
                action='store_true',
                help="unattended (un)installation never prompts the user",
            )

        groups = collections.OrderedDict()
        # if no group is defined, add the option to the parser top level
        groups[None] = parser

        for owner_cls, name in transformed_cls.knobs():
            knob_cls = getattr(owner_cls, name)
            if knob_cls.is_cli_positional() is not positional:
                continue

            group_cls = knob_cls.group()
            try:
                opt_group = groups[group_cls]
            except KeyError:
                opt_group = groups[group_cls] = optparse.OptionGroup(
                        parser, "{0} options".format(group_cls.description))
                parser.add_option_group(opt_group)

            knob_type = knob_cls.type
            if issubclass(knob_type, list):
                try:
                    # typing.List[X].__parameters__ == (X,)
                    knob_scalar_type = knob_type.__parameters__[0]
                except AttributeError:
                    knob_scalar_type = str
            else:
                knob_scalar_type = knob_type

            kwargs = dict()
            if knob_scalar_type is NoneType:
                kwargs['type'] = None
                kwargs['const'] = True
                kwargs['default'] = False
            elif knob_scalar_type is str:
                kwargs['type'] = 'string'
            elif knob_scalar_type is int:
                kwargs['type'] = 'int'
            elif knob_scalar_type is long:
                kwargs['type'] = 'long'
            elif knob_scalar_type is CheckedIPAddressLoopback:
                kwargs['type'] = 'ip_with_loopback'
            elif knob_scalar_type is CheckedIPAddress:
                kwargs['type'] = 'ip'
            elif issubclass(knob_scalar_type, enum.Enum):
                kwargs['type'] = 'choice'
                kwargs['choices'] = [i.value for i in knob_scalar_type]
                kwargs['metavar'] = "{{{0}}}".format(
                                                ",".join(kwargs['choices']))
            else:
                kwargs['type'] = 'constructor'
                kwargs['constructor'] = knob_scalar_type
            kwargs['dest'] = name
            if issubclass(knob_type, list):
                if kwargs['type'] is None:
                    kwargs['action'] = 'append_const'
                else:
                    kwargs['action'] = 'append'
            else:
                if kwargs['type'] is None:
                    kwargs['action'] = 'store_const'
                else:
                    kwargs['action'] = 'store'
            if knob_cls.sensitive:
                kwargs['sensitive'] = True
            if knob_cls.cli_metavar:
                kwargs['metavar'] = knob_cls.cli_metavar

            if not positional:
                cli_info = (
                    (knob_cls.deprecated, knob_cls.cli_names),
                    (True, knob_cls.cli_deprecated_names),
                )
            else:
                cli_info = (
                    (knob_cls.deprecated, (None,)),
                )
            for hidden, cli_names in cli_info:
                opt_strs = []
                for cli_name in cli_names:
                    if cli_name is None:
                        cli_name = '--{}'.format(name.replace('_', '-'))
                    opt_strs.append(cli_name)
                if not opt_strs:
                    continue

                if not hidden:
                    help = knob_cls.description
                else:
                    help = optparse.SUPPRESS_HELP

                opt_group.add_option(
                    *opt_strs,
                    help=help,
                    **kwargs
                )

        super(ConfigureTool, cls).add_options(parser,
                                              debug_option=cls.debug_option)

    def __init__(self, options, args):
        super(ConfigureTool, self).__init__(options, args)

        self.transformed_cls = self._transform(self.configurable_class)
        self.positional_arguments = []

        for owner_cls, name in self.transformed_cls.knobs():
            knob_cls = getattr(owner_cls, name)
            if knob_cls.is_cli_positional():
                self.positional_arguments.append(name)

        # fake option parser to parse positional arguments
        # (because optparse does not support positional argument parsing)
        fake_option_parser = optparse.OptionParser()
        self.add_options(fake_option_parser, True)

        fake_option_map = {option.dest: option
                           for group in fake_option_parser.option_groups
                           for option in group.option_list}

        for index, name in enumerate(self.positional_arguments):
            try:
                value = self.args.pop(0)
            except IndexError:
                break

            fake_option = fake_option_map[name]
            fake_option.process('argument {}'.format(index + 1),
                                value,
                                self.options,
                                self.option_parser)

    def validate_options(self, needs_root=True):
        super(ConfigureTool, self).validate_options(needs_root=needs_root)

        if self.args:
            self.option_parser.error("Too many arguments provided")

    def _setup_logging(self, log_file_mode='w', no_file=False):
        if no_file:
            log_file_name = None
        elif self.options.log_file:
            log_file_name = self.options.log_file
        else:
            log_file_name = self.log_file_name
        standard_logging_setup(
           log_file_name,
           verbose=self.verbose,
           debug=self.options.verbose,
           console_format=self.console_format)
        if log_file_name:
            logger.debug('Logging to %s', log_file_name)
        elif not no_file:
            logger.debug('Not logging to a file')

    def init_configurator(self):
        """Executes transformation, getting a flattened Installer object

        :returns: common.installer.Installer object
        """
        kwargs = {}

        transformed_cls = self._transform(self.configurable_class)
        knob_classes = {n: getattr(c, n) for c, n in transformed_cls.knobs()}
        for name in knob_classes:
            value = getattr(self.options, name, None)
            if value is not None:
                kwargs[name] = value

        if (issubclass(self.configurable_class, common.Interactive) and
                not self.options.unattended):
            kwargs['interactive'] = True

        try:
            return transformed_cls(**kwargs)
        except core.KnobValueError as e:
            knob_cls = knob_classes[e.name]
            try:
                index = self.positional_arguments.index(e.name)
            except ValueError:
                cli_name = knob_cls.cli_names[0] or e.name.replace('_', '-')
                desc = "option {0}".format(cli_name)
            else:
                desc = "argument {0}".format(index + 1)
            self.option_parser.error("{0}: {1}".format(desc, e))
        except RuntimeError as e:
            self.option_parser.error(str(e))

    def run(self):
        cfgr = self.init_configurator()

        signal.signal(signal.SIGTERM, self.__signal_handler)

        if self.use_private_ccache:
            with private_ccache():
                super(ConfigureTool, self).run()
                return cfgr.run()
        else:
            super(ConfigureTool, self).run()
            return cfgr.run()

    @staticmethod
    def __signal_handler(signum, frame):
        raise KeyboardInterrupt


class InstallTool(ConfigureTool):
    uninstall_kwargs = None

    _transform = staticmethod(common.installer)

    @classmethod
    def add_options(cls, parser, positional=False):
        super(InstallTool, cls).add_options(parser, positional)

        if cls.uninstall_kwargs is not None:
            parser.add_option(
                '--uninstall',
                dest='uninstall',
                default=False,
                action='store_true',
                help=("uninstall an existing installation. The uninstall can "
                      "be run with --unattended option"),
            )

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
