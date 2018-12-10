# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2011  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Pytest plugin for IPA Integration tests"""

from __future__ import print_function, absolute_import

import logging
import os
import tempfile
import shutil
import re

import pytest
from pytest_multihost import make_multihost_fixture

from ipapython import ipautil
from ipaplatform.paths import paths
from ipatests.test_util import yield_fixture
from .config import Config
from .env_config import get_global_config
from . import tasks

logger = logging.getLogger(__name__)


def pytest_addoption(parser):
    group = parser.getgroup("IPA integration tests")

    group.addoption(
        '--logfile-dir', dest="logfile_dir", default=None,
        help="Directory to store integration test logs in.")


def _get_logname_from_node(node):
    name = node.nodeid
    name = re.sub('\(\)/', '', name)      # remove ()/
    name = re.sub('[()]', '', name)       # and standalone brackets
    name = re.sub('(/|::)', '-', name)
    return name


def collect_test_logs(node, logs_dict, test_config):
    """Collect logs from a test

    Calls collect_logs

    :param node: The pytest collection node (request.node)
    :param logs_dict: Mapping of host to list of log filnames to collect
    :param test_config: Pytest configuration
    """
    collect_logs(
        name=_get_logname_from_node(node),
        logs_dict=logs_dict,
        logfile_dir=test_config.getoption('logfile_dir'),
        beakerlib_plugin=test_config.pluginmanager.getplugin('BeakerLibPlugin'),
    )


def collect_systemd_journal(node, hosts, test_config):
    """Collect systemd journal from remote hosts

    :param node: The pytest collection node (request.node)
    :param hosts: List of hosts from which to collect journal
    :param test_config: Pytest configuration
    """
    name = _get_logname_from_node(node)
    logfile_dir = test_config.getoption('logfile_dir')

    if logfile_dir is None:
        return

    for host in hosts:
        logger.info("Collecting journal from: %s", host.hostname)

        topdirname = os.path.join(logfile_dir, name, host.hostname)
        if not os.path.exists(topdirname):
            os.makedirs(topdirname)

        # Get journal content
        cmd = host.run_command(
            ['journalctl', '--since', host.config.log_journal_since],
            log_stdout=False, raiseonerr=False)
        if cmd.returncode:
            logger.error('An error occurred while collecting journal')
            continue

        # Write journal to file
        with open(os.path.join(topdirname, "journal"), 'w') as f:
            f.write(cmd.stdout_text)


def collect_logs(name, logs_dict, logfile_dir=None, beakerlib_plugin=None):
    """Collect logs from remote hosts

    Calls collect_logs

    :param name: Name under which logs arecollected, e.g. name of the test
    :param logs_dict: Mapping of host to list of log filnames to collect
    :param logfile_dir: Directory to log to
    :param beakerlib_plugin:
        BeakerLibProcess or BeakerLibPlugin used to collect tests for BeakerLib

    If neither logfile_dir nor beakerlib_plugin is given, no tests are
    collected.
    """
    if logs_dict and (logfile_dir or beakerlib_plugin):

        if logfile_dir:
            remove_dir = False
        else:
            logfile_dir = tempfile.mkdtemp()
            remove_dir = True

        topdirname = os.path.join(logfile_dir, name)

        for host, logs in logs_dict.items():
            logger.info('Collecting logs from: %s', host.hostname)
            dirname = os.path.join(topdirname, host.hostname)
            if not os.path.isdir(dirname):
                os.makedirs(dirname)
            tarname = os.path.join(dirname, 'logs.tar.xz')
            # get temporary file name
            cmd = host.run_command(['mktemp'])
            tmpname = cmd.stdout_text.strip()
            # Tar up the logs on the remote server
            cmd = host.run_command(
                ['tar', 'cJvf', tmpname, '--ignore-failed-read'] + logs,
                log_stdout=False, raiseonerr=False)
            if cmd.returncode:
                logger.warning('Could not collect all requested logs')
            # fetch tar file
            with open(tarname, 'wb') as f:
                f.write(host.get_file_contents(tmpname))
            # delete from remote
            host.run_command(['rm', '-f', tmpname])
            # Unpack on the local side
            ipautil.run([paths.TAR, 'xJvf', 'logs.tar.xz'], cwd=dirname,
                        raiseonerr=False)
            os.unlink(tarname)

        if beakerlib_plugin:
            # Use BeakerLib's rlFileSubmit on the indifidual files
            # The resulting submitted filename will be
            # $HOSTNAME-$FILENAME (with '/' replaced by '-')
            beakerlib_plugin.run_beakerlib_command(['pushd', topdirname])
            try:
                for dirpath, _dirnames, filenames in os.walk(topdirname):
                    for filename in filenames:
                        fullname = os.path.relpath(
                            os.path.join(dirpath, filename), topdirname)
                        logger.debug('Submitting file: %s', fullname)
                        beakerlib_plugin.run_beakerlib_command(
                            ['rlFileSubmit', fullname])
            finally:
                beakerlib_plugin.run_beakerlib_command(['popd'])

        if remove_dir:
            if beakerlib_plugin:
                # The BeakerLib process runs asynchronously, let it clean up
                # after it's done with the directory
                beakerlib_plugin.run_beakerlib_command(
                    ['rm', '-rvf', topdirname])
            else:
                shutil.rmtree(topdirname)


@pytest.fixture(scope='class')
def class_integration_logs():
    """Internal fixture providing class-level logs_dict"""
    return {}


@yield_fixture
def integration_logs(class_integration_logs, request):
    """Provides access to test integration logs, and collects after each test
    """
    yield class_integration_logs
    hosts = class_integration_logs.keys()
    collect_test_logs(request.node, class_integration_logs, request.config)
    collect_systemd_journal(request.node, hosts, request.config)


@yield_fixture(scope='class')
def mh(request, class_integration_logs):
    """IPA's multihost fixture object
    """
    cls = request.cls

    domain_description = {
        'type': 'IPA',
        'hosts': {
            'master': 1,
            'replica': cls.num_replicas,
            'client': cls.num_clients,
        },
    }
    domain_description['hosts'].update(
        {role: 1 for role in cls.required_extra_roles})

    domain_descriptions = [domain_description]
    for _i in range(cls.num_ad_domains):
        domain_descriptions.append({
            'type': 'AD',
            'hosts': {
                'ad': 1,
                'ad_subdomain': cls.num_ad_domains,
                'ad_treedomain': cls.num_ad_domains,
            }
        })

    mh = make_multihost_fixture(
        request,
        domain_descriptions,
        config_class=Config,
        _config=get_global_config(),
    )

    mh.domain = mh.config.domains[0]
    [mh.master] = mh.domain.hosts_by_role('master')
    mh.replicas = mh.domain.hosts_by_role('replica')
    mh.clients = mh.domain.hosts_by_role('client')

    cls.logs_to_collect = class_integration_logs

    def collect_log(host, filename):
        logger.info('Adding %s:%s to list of logs to collect',
                    host.external_hostname, filename)
        class_integration_logs.setdefault(host, []).append(filename)

    print(mh.config)
    for host in mh.config.get_all_hosts():
        host.add_log_collector(collect_log)
        logger.info('Preparing host %s', host.hostname)
        tasks.prepare_host(host)

    setup_class(cls, mh)
    mh._pytestmh_request.addfinalizer(lambda: teardown_class(cls))

    try:
        yield mh.install()
    finally:
        hosts = list(cls.get_all_hosts())
        for host in hosts:
            host.remove_log_collector(collect_log)
        collect_test_logs(
            request.node, class_integration_logs, request.config
        )
        collect_systemd_journal(request.node, hosts, request.config)


def setup_class(cls, mh):
    """Add convenience attributes to the test class

    This is deprecated in favor of the mh fixture.
    To be removed when no more tests using this.
    """
    cls.domain = mh.domain
    cls.master = mh.master
    cls.replicas = mh.replicas
    cls.clients = mh.clients
    cls.ad_domains = mh.config.ad_domains


def teardown_class(cls):
    """Remove convenience attributes from the test class

    This is deprecated in favor of the mh fixture.
    To be removed when no more tests using this.
    """
    del cls.master
    del cls.replicas
    del cls.clients
    del cls.ad_domains
    del cls.domain
