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

from pprint import pformat

import logging
import os
import tempfile
import shutil
import re
import functools

import pytest
from pytest_multihost import make_multihost_fixture

from ipapython import ipautil
from ipaplatform.paths import paths
from ipaplatform.constants import constants
from . import fips
from .config import Config
from .env_config import get_global_config
from . import tasks

logger = logging.getLogger(__name__)

CLASS_LOGFILES = [
    # BIND logs
    os.path.join(paths.NAMED_VAR_DIR, constants.NAMED_DATA_DIR),
    # dirsrv logs
    paths.VAR_LOG_DIRSRV,
    # IPA install logs
    paths.IPASERVER_INSTALL_LOG,
    paths.IPASERVER_ADTRUST_INSTALL_LOG,
    paths.IPASERVER_DNS_INSTALL_LOG,
    paths.IPASERVER_KRA_INSTALL_LOG,
    paths.IPACLIENT_INSTALL_LOG,
    paths.IPAREPLICA_INSTALL_LOG,
    paths.IPAREPLICA_CONNCHECK_LOG,
    paths.IPAREPLICA_CA_INSTALL_LOG,
    paths.IPA_CUSTODIA_AUDIT_LOG,
    paths.IPACLIENTSAMBA_INSTALL_LOG,
    paths.IPACLIENTSAMBA_UNINSTALL_LOG,
    paths.IPATRUSTENABLEAGENT_LOG,
    # IPA uninstall logs
    paths.IPASERVER_UNINSTALL_LOG,
    paths.IPACLIENT_UNINSTALL_LOG,
    # IPA upgrade logs
    paths.IPAUPGRADE_LOG,
    # IPA backup and restore logs
    paths.IPARESTORE_LOG,
    paths.IPABACKUP_LOG,
    # EPN log
    paths.IPAEPN_LOG,
    # kerberos related logs
    paths.KADMIND_LOG,
    paths.KRB5KDC_LOG,
    # httpd logs
    paths.VAR_LOG_HTTPD_DIR,
    # dogtag logs
    paths.VAR_LOG_PKI_DIR,
    # dogtag conf
    paths.PKI_TOMCAT_SERVER_XML,
    paths.PKI_TOMCAT + "/ca/CS.cfg",
    paths.PKI_TOMCAT + "/kra/CS.cfg",
    paths.PKI_TOMCAT_ALIAS_DIR,
    paths.PKI_TOMCAT_ALIAS_PWDFILE_TXT,
    # selinux logs
    paths.VAR_LOG_AUDIT,
    # sssd
    paths.VAR_LOG_SSSD_DIR,
    # system
    paths.RESOLV_CONF,
    paths.HOSTS,
    # IPA renewal lock
    paths.IPA_RENEWAL_LOCK,
    paths.LETS_ENCRYPT_LOG,
    # resolvers management
    paths.NETWORK_MANAGER_CONFIG,
    paths.NETWORK_MANAGER_CONFIG_DIR,
    paths.SYSTEMD_RESOLVED_CONF,
    paths.SYSTEMD_RESOLVED_CONF_DIR,
    '/var/log/samba',
]


def make_class_logs(host):
    logs = list(CLASS_LOGFILES)
    env_filename = os.path.join(host.config.test_dir, 'env.sh')
    logs.append(env_filename)
    return logs


def pytest_addoption(parser):
    group = parser.getgroup("IPA integration tests")

    group.addoption(
        '--logfile-dir', dest="logfile_dir", default=None,
        help="Directory to store integration test logs in.")


def _get_logname_from_node(node):
    name = node.nodeid
    name = re.sub(r'\(\)/', '', name)      # remove ()/
    name = re.sub(r'[()]', '', name)       # and standalone brackets
    name = re.sub(r'(/|::)', '-', name)
    return name


def collect_test_logs(node, logs_dict, test_config, suffix=''):
    """Collect logs from a test

    Calls collect_logs and collect_systemd_journal

    :param node: The pytest collection node (request.node)
    :param logs_dict: Mapping of host to list of log filnames to collect
    :param test_config: Pytest configuration
    :param suffix: The custom suffix of the name of logfiles' directory
    """
    name = '{node}{suffix}'.format(
        node=_get_logname_from_node(node),
        suffix=suffix,
    )
    logfile_dir = test_config.getoption('logfile_dir')
    collect_logs(
        name=name,
        logs_dict=logs_dict,
        logfile_dir=logfile_dir,
        beakerlib_plugin=test_config.pluginmanager.getplugin('BeakerLibPlugin'),
    )

    hosts = logs_dict.keys()  # pylint: disable=dict-keys-not-iterating
    collect_systemd_journal(name, hosts, logfile_dir)


def collect_systemd_journal(name, hosts, logfile_dir=None):
    """Collect systemd journal from remote hosts

    :param name: Name under which logs are collected, e.g. name of the test
    :param hosts: List of hosts from which to collect journal
    :param logfile_dir: Directory to log to
    """
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
            # make list of unique log filenames
            logs = list(set(logs))
            dirname = os.path.join(topdirname, host.hostname)
            if not os.path.isdir(dirname):
                os.makedirs(dirname)
            tarname = os.path.join(dirname, 'logs.tar.xz')
            # get temporary file name
            cmd = host.run_command(['mktemp'])
            tmpname = cmd.stdout_text.strip()
            # Tar up the logs on the remote server
            cmd = host.run_command(
                [
                    "tar",
                    "cJvf",
                    tmpname,
                    "--ignore-failed-read",
                    "--warning=no-failed-read",
                    "--dereference",
                ] + logs,
                log_stdout=False,
                raiseonerr=False,
            )
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


class IntegrationLogs:
    """Represent logfile collections
    Collection is a mapping of IPA hosts and a list of logfiles to be
    collected. There are two types of collections: class and method.
    The former contains a list of logfiles which will be collected on
    each test (within class) completion, while the latter contains
    a list of logfiles which will be collected on only certain test
    completion (once).
    """
    def __init__(self):
        self._class_logs = {}
        self._method_logs = {}

    def set_logs(self, host, logs):
        self._class_logs[host] = list(logs)

    @property
    def method_logs(self):
        return self._method_logs

    @property
    def class_logs(self):
        return self._class_logs

    def init_method_logs(self):
        """Initilize method logs with the class ones"""
        self._method_logs = {}
        for host, logs in self._class_logs.items():
            self._method_logs[host] = list(logs)

    def collect_class_log(self, host, filename):
        """Add class scope log
        The file with the given filename will be collected from the
        host on an each test completion(within a test class).
        """
        logger.info('Adding %s:%s to list of class logs to collect',
                    host.external_hostname, filename)
        self._class_logs.setdefault(host, []).append(filename)
        self._method_logs.setdefault(host, []).append(filename)

    def collect_method_log(self, host, filename):
        """Add method scope log
        The file with the given filename will be collected from the
        host on a test completion.
        """
        logger.info('Adding %s:%s to list of method logs to collect',
                    host.external_hostname, filename)
        self._method_logs.setdefault(host, []).append(filename)


@pytest.fixture(scope='class')
def class_integration_logs(request):
    """Internal fixture providing class-level logs_dict
    For adjusting collection of logs, please, use 'integration_logs'
    fixture.
    """
    integration_logs = IntegrationLogs()
    yield integration_logs
    # since the main fixture of integration tests('mh') depends on
    # this one the class logs collecting happens *after* the teardown
    # of that fixture. The 'uninstall' is among the finalizers of 'mh'.
    # This means that the logs collected here are the IPA *uninstall*
    # logs.
    class_logs = integration_logs.class_logs
    collect_test_logs(request.node, class_logs, request.config,
                      suffix='-uninstall')


@pytest.fixture
def integration_logs(class_integration_logs, request):
    """Provides access to test integration logs, and collects after each test
    To collect a logfile on a test completion one should add the dependency on
    this fixture and call its 'collect_method_log' method.
    For example, run TestFoo.
    ```
    class TestFoo(IntegrationTest):
        def test_foo(self):
            pass

        def test_bar(self, integration_logs):
            integration_logs.collect_method_log(self.master, '/logfile')
    ```
    '/logfile' will be collected only for 'test_bar' test.

    To collect a logfile on a test class completion one should add the
    dependency on this fixture and call its 'collect_class_log' method.
    For example, run TestFoo.
    ```
    class TestFoo(IntegrationTest):
        def test_foo(self, integration_logs):
            integration_logs.collect_class_log(self.master, '/logfile')

        def test_bar(self):
            pass
    ```
    '/logfile' will be collected 3 times:
    1) on 'test_foo' completion
    2) on 'test_bar' completion
    3) on 'TestFoo' completion

    Note, the registration of a collection works at the runtime. This means
    that if the '/logfile' will be registered in 'test_bar' then
    it will not be collected on 'test_foo' completion:
    1) on 'test_bar' completion
    2) on 'TestFoo' completion
    """
    class_integration_logs.init_method_logs()
    yield class_integration_logs
    method_logs = class_integration_logs.method_logs
    collect_test_logs(request.node, method_logs, request.config)


@pytest.fixture(scope='class')
def mh(request, class_integration_logs):
    """IPA's multihost fixture object
    """
    cls = request.cls

    if cls.num_trusted_domains == 1:
        mh = make_multihost_fixture(request, descriptions=[
            {
                'type': 'IPA',
                'hosts':
                {
                    'master': 1,
                    'replica': cls.num_replicas,
                    'client': cls.num_clients,
                }
            },
            {
                'type': 'TRUSTED_IPA',
                'hosts':
                {
                    'master': 1,
                    'replica': cls.num_trusted_replicas,
                    'client': cls.num_trusted_clients,

                },
            },
        ], config_class=Config, _config=get_global_config(),)
    else:
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
                'hosts': {'ad': 1}
            })
        for _i in range(cls.num_ad_subdomains):
            domain_descriptions.append({
                'type': 'AD_SUBDOMAIN',
                'hosts': {'ad_subdomain': 1}
            })
        for _i in range(cls.num_ad_treedomains):
            domain_descriptions.append({
                'type': 'AD_TREEDOMAIN',
                'hosts': {'ad_treedomain': 1}
            })
        mh = make_multihost_fixture(
            request,
            domain_descriptions,
            config_class=Config,
            _config=get_global_config(),
        )
    if cls.num_trusted_domains == 1:
        mh.domain1 = mh.config.domains[0]
        mh.domain2 = mh.config.domains[1]

        [mh.master] = mh.domain1.hosts_by_role('master')
        mh.replicas = mh.domain1.hosts_by_role('replica')
        mh.clients = mh.domain1.hosts_by_role('client')
        [mh.trusted_master] = mh.domain2.hosts_by_role('master')
        mh.trusted_replicas = mh.domain2.hosts_by_role('replica')
        mh.trusted_clients = mh.domain2.hosts_by_role('client')
    else:
        mh.domain = mh.config.domains[0]
        [mh.master] = mh.domain.hosts_by_role('master')
        mh.replicas = mh.domain.hosts_by_role('replica')
        mh.clients = mh.domain.hosts_by_role('client')

    ad_domains = mh.config.ad_domains
    if ad_domains:
        mh.ads = []
        for domain in ad_domains:
            mh.ads.extend(domain.hosts_by_role('ad'))
        mh.ad_subdomains = []
        for domain in ad_domains:
            mh.ad_subdomains.extend(domain.hosts_by_role('ad_subdomain'))
        mh.ad_treedomains = []
        for domain in ad_domains:
            mh.ad_treedomains.extend(domain.hosts_by_role('ad_treedomain'))

    cls.logs_to_collect = class_integration_logs.class_logs

    if logger.isEnabledFor(logging.INFO):
        logger.info(pformat(mh.config.to_dict()))

    for ipa_host in mh.config.get_all_ipa_hosts():
        class_integration_logs.set_logs(ipa_host, make_class_logs(ipa_host))

    for host in mh.config.get_all_hosts():
        logger.info('Preparing host %s', host.hostname)
        tasks.prepare_host(host)

    add_compat_attrs(cls, mh)

    def fin():
        del_compat_attrs(cls)
    mh._pytestmh_request.addfinalizer(fin)

    try:
        yield mh.install()
    finally:
        # the 'mh' fixture depends on 'class_integration_logs' one,
        # thus, the class logs collecting happens *after* the teardown
        # of 'mh' fixture. The 'uninstall' is among the finalizers of 'mh'.
        # This means that the logs collected here are the IPA *uninstall*
        # logs and the 'install' ones can be removed during the IPA
        # uninstall phase. To address this problem(e.g. installation error)
        # the install logs will be collected into '{nodeid}-install' directory
        # while the uninstall ones into '{nodeid}-uninstall'.
        class_logs = class_integration_logs.class_logs
        collect_test_logs(request.node, class_logs, request.config,
                          suffix='-install')


def add_compat_attrs(cls, mh):
    """Add convenience attributes to the test class

    This is deprecated in favor of the mh fixture.
    To be removed when no more tests using this.
    """
    if cls.num_trusted_domains == 1:
        cls.domain1 = mh.domain1
        cls.domain2 = mh.domain2
        cls.master = mh.master
        cls.replicas = mh.replicas
        cls.clients = mh.clients
        cls.trusted_master = mh.trusted_master
        cls.trusted_replicas = mh.trusted_replicas
        cls.trusted_clients = mh.trusted_clients
        cls.ad_domains = mh.config.ad_domains
    else:
        cls.domain = mh.domain
        cls.master = mh.master
        cls.replicas = mh.replicas
        cls.clients = mh.clients
        cls.ad_domains = mh.config.ad_domains
        if cls.ad_domains:
            cls.ads = mh.ads
            cls.ad_subdomains = mh.ad_subdomains
            cls.ad_treedomains = mh.ad_treedomains


def del_compat_attrs(cls):
    """Remove convenience attributes from the test class

    This is deprecated in favor of the mh fixture.
    To be removed when no more tests using this.
    """
    if cls.num_trusted_domains == 1:
        del cls.master
        del cls.replicas
        del cls.clients
        del cls.trusted_master
        del cls.trusted_replicas
        del cls.trusted_clients
        del cls.domain1
        del cls.domain2
    else:
        del cls.master
        del cls.replicas
        del cls.clients
        del cls.domain
        if cls.ad_domains:
            del cls.ads
            del cls.ad_subdomains
            del cls.ad_treedomains
        del cls.ad_domains


def skip_if_fips(reason='Not supported in FIPS mode', host='master'):
    if callable(reason):
        raise TypeError('Invalid decorator usage, add "()"')

    def decorator(test_method):
        @functools.wraps(test_method)
        def wrapper(instance, *args, **kwargs):
            if fips.is_fips_enabled(getattr(instance, host)):
                pytest.skip(reason)
            else:
                test_method(instance, *args, **kwargs)
        return wrapper
    return decorator
