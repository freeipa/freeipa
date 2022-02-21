# Copyright (C) 2017  Custodia Project Contributors - see LICENSE file
import os
import socket

import pytest

from ipaserver.custodia.server.args import parse_args
from ipaserver.custodia.server.config import parse_config

HERE = os.path.dirname(os.path.abspath(__file__))
EMPTY_CONF = os.path.join(HERE, 'empty.conf')


@pytest.fixture()
def args():
    return parse_args([EMPTY_CONF])


@pytest.fixture()
def args_instance():
    return parse_args(['--instance=testing', '--debug', EMPTY_CONF])


def test_args(args):
    assert not args.debug
    assert args.instance is None
    assert args.configfile.name == EMPTY_CONF


def test_args_instance(args_instance):
    assert args_instance.debug
    assert args_instance.instance == 'testing'
    assert args_instance.configfile.name == EMPTY_CONF


def test_parse_config(args):
    parser, config = parse_config(args)

    assert parser.has_section(u'/')
    assert parser.get(u'/', u'handler') == u'Root'

    assert config == {
        'auditlog': u'/var/log/custodia/audit.log',
        'authenticators': {},
        'authorizers': {},
        'confdpattern': EMPTY_CONF + u'.d/*.conf',
        'configdir': HERE,
        'configfiles': [
            EMPTY_CONF,
            EMPTY_CONF + u'.d/root.conf'
        ],
        'consumers': {},
        'debug': False,
        'hostname': socket.gethostname(),
        'instance': u'',
        'libdir': u'/var/lib/custodia',
        'logdir': u'/var/log/custodia',
        'makedirs': False,
        'rundir': u'/var/run/custodia',
        'server_url': 'http+unix://%2Fvar%2Frun%2Fcustodia%2Fcustodia.sock/',
        'socketdir': u'/var/run/custodia',
        'stores': {},
        'tls_verify_client': False,
        'umask': 23
    }


def test_parse_config_instance(args_instance):
    parser, config = parse_config(args_instance)

    assert parser.has_section(u'/')
    assert parser.get(u'/', u'handler') == u'Root'

    assert config == {
        'auditlog': u'/var/log/custodia/testing/audit.log',
        'authenticators': {},
        'authorizers': {},
        'confdpattern': EMPTY_CONF + u'.d/*.conf',
        'configdir': HERE,
        'configfiles': [
            EMPTY_CONF,
            EMPTY_CONF + u'.d/root.conf'
        ],
        'consumers': {},
        'debug': True,
        'hostname': socket.gethostname(),
        'instance': u'testing',
        'libdir': u'/var/lib/custodia/testing',
        'logdir': u'/var/log/custodia/testing',
        'makedirs': False,
        'rundir': u'/var/run/custodia/testing',
        'server_url': 'http+unix://%2Fvar%2Frun%2Fcustodia%2Ftesting.sock/',
        'socketdir': u'/var/run/custodia',
        'stores': {},
        'tls_verify_client': False,
        'umask': 23
    }
