# Copyright (C) 2015-2017  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import

import glob
import os
import socket

import six

from custodia.compat import configparser
from custodia.compat import url_escape


class CustodiaConfig(object):
    CONFIG_SPECIALS = ['authenticators', 'authorizers', 'consumers', 'stores']

    DEFAULT_PATHS = [
        ('libdir', '/var/lib/custodia/{instance}'),
        ('logdir', '/var/log/custodia/{instance}'),
        ('rundir', '/var/run/custodia/{instance}'),
        ('socketdir', '/var/run/custodia'),
    ]

    def __init__(self, args):
        self.args = args
        self.config = {}
        self.defaults = None
        self.parser = None

    def get_defaults(self):
        configpath = self.args.configfile.name
        instance = self.args.instance
        defaults = {
            # Do not use getfqdn(). Internaly it calls gethostbyaddr which
            # might perform a DNS query.
            'hostname': socket.gethostname(),
            'configdir': os.path.dirname(configpath),
            'confdpattern': os.path.join(configpath + '.d', '*.conf'),
            'instance': instance if instance else '',
        }
        for name, path in self.DEFAULT_PATHS:
            defaults[name] = os.path.abspath(path.format(**defaults))
        return defaults

    def create_parser(self):
        parser = configparser.ConfigParser(
            interpolation=configparser.ExtendedInterpolation(),
            defaults=self.defaults
        )
        parser.optionxform = str

        # add env
        parser.add_section(u'ENV')
        for k, v in os.environ.items():
            if set(v).intersection('\r\n\x00'):
                continue
            if six.PY2:
                k = k.decode('utf-8', 'replace')
                v = v.decode('utf-8', 'replace')
            parser.set(u'ENV', k, v.replace(u'$', u'$$'))

        # default globals
        parser.add_section(u'global')
        parser.set(u'global', u'auditlog', u'${logdir}/audit.log')
        parser.set(u'global', u'debug', u'false')
        parser.set(u'global', u'umask', u'027')
        parser.set(u'global', u'makedirs', u'false')

        return parser

    def read_configs(self):
        with self.args.configfile as f:
            self.parser.read_file(f)

        configfiles = [self.args.configfile.name]

        pattern = self.parser.get(u'DEFAULT', u'confdpattern')
        if pattern:
            confdfiles = glob.glob(pattern)
            confdfiles.sort()
            for confdfile in confdfiles:
                with open(confdfile) as f:
                    self.parser.read_file(f)
                configfiles.append(confdfile)

        return configfiles

    def makedirs(self):
        for name, _ in self.DEFAULT_PATHS:
            path = self.parser.get(u'DEFAULT', name)
            parent = os.path.dirname(path)
            # create parents according to umask
            if not os.path.isdir(parent):
                os.makedirs(parent)
            # create final directory with restricted permissions
            if not os.path.isdir(path):
                os.mkdir(path, 0o700)

    def populate_config(self):
        config = self.config

        for s in self.CONFIG_SPECIALS:
            config[s] = {}

        for opt, val in self.parser.items(u'global'):
            if opt in self.CONFIG_SPECIALS:
                raise ValueError('"%s" is an invalid '
                                 '[global] option' % opt)
            config[opt] = val

        config['tls_verify_client'] = self.parser.getboolean(
            'global', 'tls_verify_client', fallback=False)
        config['debug'] = self.parser.getboolean(
            'global', 'debug', fallback=False)
        config['makedirs'] = self.parser.getboolean(
            'global', 'makedirs', fallback=False)
        if self.args.debug:
            config['debug'] = self.args.debug

        config['auditlog'] = os.path.abspath(config.get('auditlog'))
        config['umask'] = int(config.get('umask', '027'), 8)

        url = config.get('server_url')
        sock = config.get('server_socket')

        if url and sock:
            raise ValueError(
                "'server_url' and 'server_socket' are mutually exclusive.")

        if not url and not sock:
            # no option but, use default socket path
            socketdir = self.parser.get(u'DEFAULT', u'socketdir')
            name = self.args.instance if self.args.instance else 'custodia'
            sock = os.path.join(socketdir, name + '.sock')

        if sock:
            server_socket = os.path.abspath(sock)
            config['server_url'] = 'http+unix://{}/'.format(
                url_escape(server_socket, ''))

    def __call__(self):
        self.defaults = self.get_defaults()
        self.parser = self.create_parser()
        self.config['configfiles'] = self.read_configs()
        self.populate_config()
        if self.config[u'makedirs']:
            self.makedirs()
        return self.parser, self.config


def parse_config(args):
    ccfg = CustodiaConfig(args)
    return ccfg()


def test(arglist):
    from pprint import pprint
    from .args import parse_args
    args = parse_args(arglist)
    parser, config = parse_config(args)
    pprint(parser.items("DEFAULT"))
    pprint(config)


if __name__ == '__main__':
    test(['--instance=demo', './tests/empty.conf'])
