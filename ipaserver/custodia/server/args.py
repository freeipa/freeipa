# Copyright (C) 2015-2017  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import

import argparse
import os


class AbsFileType(argparse.FileType):
    """argparse file type with absolute path
    """
    def __call__(self, string):
        if string != '-':
            string = os.path.abspath(string)
        return super(AbsFileType, self).__call__(string)


class ConfigfileAction(argparse.Action):
    """Default action handler for configfile
    """
    default_path = '/etc/custodia/custodia.conf'
    default_instance = '/etc/custodia/{instance}.conf'

    def __call__(self, parser, namespace, values, option_string=None):
        if values is None:
            if namespace.instance is not None:
                values = self.default_instance.format(
                    instance=namespace.instance
                )
            else:
                values = self.default_path
            values = self.type(values)
        setattr(namespace, self.dest, values)


def instance_name(string):
    """Check for valid instance name
    """
    invalid = ':/@'
    if set(string).intersection(invalid):
        msg = 'Invalid instance name {}'.format(string)
        raise argparse.ArgumentTypeError(msg)
    return string


default_argparser = argparse.ArgumentParser(
    prog='custodia',
    description='Custodia server'
)
default_argparser.add_argument(
    '--debug',
    action='store_true',
    help='Debug mode'
)
default_argparser.add_argument(
    '--instance',
    type=instance_name,
    help='Instance name',
    default=None
)
default_argparser.add_argument(
    'configfile',
    nargs='?',
    action=ConfigfileAction,
    type=AbsFileType('r'),
    help=('Path to custodia server config (default: '
          '/etc/custodia/{instance}/custodia.conf)'),
)


def parse_args(args=None, argparser=None):
    if argparser is None:
        argparser = default_argparser

    # namespace with default values
    namespace = argparse.Namespace(
        debug=False,
        instance=None,
    )

    return argparser.parse_args(args, namespace)
