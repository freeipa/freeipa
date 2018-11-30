#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#
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

from __future__ import absolute_import

import os
import re
import time
import tempfile

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipaplatform.paths import paths

from itertools import chain, repeat
from ipatests.create_external_ca import ExternalCA, ISSUER_CN

IPA_CA = 'ipa_ca.crt'
ROOT_CA = 'root_ca.crt'

# string to identify PKI restart in the journal
PKI_START_STR = 'Started pki_tomcatd'


def check_CA_flag(host, nssdb=paths.PKI_TOMCAT_ALIAS_DIR,
                  cn=ISSUER_CN):
    """
    Check if external CA (by default 'example.test' in our test env) has
    CA flag in nssdb.
    """
    result = host.run_command(['certutil', '-L', '-d', nssdb])
    text = result.stdout_text

    # match CN in cert nickname and C flag in SSL section of NSS flags table
    match_CA_flag = re.compile('.*{}.*\s+C'.format(cn))
    match = re.search(match_CA_flag, text)

    return match


def match_in_journal(host, string, since='today', services=('certmonger',)):
    """
    Returns match object for the particular string.
    """
    # prepend '-u' before every service name
    service_args = list(chain.from_iterable(list(zip(repeat('-u'), services))))
    command_args = ['journalctl', '--since={}'.format(since)] + service_args
    result = host.run_command(command_args)

    output = result.stdout_text

    traceback = re.compile(string)
    match = re.search(traceback, output)

    return match


def install_server_external_ca_step1(host):
    """Step 1 to install the ipa server with external ca"""
    return tasks.install_master(host, external_ca=True)


def install_server_external_ca_step2(host, ipa_ca_cert, root_ca_cert):
    """Step 2 to install the ipa server with external ca"""
    args = ['ipa-server-install',
            '-a', host.config.admin_password,
            '-p', host.config.dirman_password,
            '--external-cert-file', ipa_ca_cert,
            '--external-cert-file', root_ca_cert]

    cmd = host.run_command(args)
    return cmd


def service_control_dirsrv(host, function):
    """Function to control the dirsrv service i.e start, stop, restart etc"""

    dashed_domain = host.domain.realm.replace(".", '-')
    dirsrv_service = "dirsrv@%s.service" % dashed_domain
    cmd = host.run_command(['systemctl', function, dirsrv_service])
    assert cmd.returncode == 0


class TestExternalCA(IntegrationTest):
    """
    Test of FreeIPA server installation with external CA
    """
    num_replicas = 1
    num_clients = 1

    def test_external_ca(self):
        # Step 1 of ipa-server-install.
        result = install_server_external_ca_step1(self.master)
        assert result.returncode == 0

        # Sign CA, transport it to the host and get ipa a root ca paths.
        root_ca_fname, ipa_ca_fname = tasks.sign_ca_and_transport(
            self.master, paths.ROOT_IPA_CSR, ROOT_CA, IPA_CA)

        # Step 2 of ipa-server-install.
        result = install_server_external_ca_step2(
            self.master, ipa_ca_fname, root_ca_fname)
        assert result.returncode == 0

        # Make sure IPA server is working properly
        tasks.kinit_admin(self.master)
        result = self.master.run_command(['ipa', 'user-show', 'admin'])
        assert 'User login: admin' in result.stdout_text

        # check that we can also install replica
        tasks.install_replica(self.master, self.replicas[0])

        # check that nsds5ReplicaReleaseTimeout option was set
        result = self.master.run_command([
            'ldapsearch',
            '-x',
            '-ZZ',
            '-h', self.master.hostname,
            '-D', 'cn=directory manager',
            '-w', self.master.config.dirman_password,
            '-b', 'cn=mapping tree,cn=config',
            '(cn=replica)',
            '-LLL',
            '-o',
            'ldif-wrap=no'])
        # case insensitive match
        text = result.stdout_text.lower()
        # see ipaserver.install.replication.REPLICA_FINAL_SETTINGS
        assert 'nsds5ReplicaReleaseTimeout: 60'.lower() in text
        assert 'nsDS5ReplicaBindDnGroupCheckInterval: 60'.lower() in text

    def test_client_installation_with_otp(self):
        # Test for issue 7526: client installation fails with one-time
        # password when the master is installed with an externally signed
        # CA because the whole cert chain is not published in
        # /usr/share/ipa/html/ca.crt

        # Create a random password for the client
        client = self.clients[0]
        client_pwd = 'Secret123'
        args = ['ipa',
                'host-add', client.hostname,
                '--ip-address', client.ip,
                '--no-reverse',
                '--password', client_pwd]
        self.master.run_command(args)

        # Enroll the client with the client_pwd
        client.run_command(
            ['ipa-client-install',
             '--domain', self.master.domain.name,
             '--server', self.master.hostname,
             '-w', client_pwd,
             '-U'])


class TestSelfExternalSelf(IntegrationTest):
    """
    Test self-signed > external CA > self-signed test case.
    """
    def test_install_master(self):
        result = tasks.install_master(self.master)
        assert result.returncode == 0

    def test_switch_to_external_ca(self):

        result = self.master.run_command([paths.IPA_CACERT_MANAGE, 'renew',
                                         '--external-ca'])
        assert result.returncode == 0

        # Sign CA, transport it to the host and get ipa a root ca paths.
        root_ca_fname, ipa_ca_fname = tasks.sign_ca_and_transport(
            self.master, paths.IPA_CA_CSR, ROOT_CA, IPA_CA)

        # renew CA with externally signed one
        result = self.master.run_command([paths.IPA_CACERT_MANAGE, 'renew',
                                          '--external-cert-file={}'.
                                          format(ipa_ca_fname),
                                          '--external-cert-file={}'.
                                          format(root_ca_fname)])
        assert result.returncode == 0

        # update IPA certificate databases
        result = self.master.run_command([paths.IPA_CERTUPDATE])
        assert result.returncode == 0

        # Check if external CA have "C" flag after the switch
        result = check_CA_flag(self.master)
        assert bool(result), ('External CA does not have "C" flag')

    def test_issuerDN_after_renew_to_external(self):
        """ Check if issuer DN is updated after self-signed > external-ca

        This test checks if issuer DN is updated properly after CA is
        renewed from self-signed to external-ca
        """
        result = self.master.run_command(['ipa', 'ca-show', 'ipa'])
        assert "Issuer DN: CN={}".format(ISSUER_CN) in result.stdout_text

    def test_switch_back_to_self_signed(self):

        # for journalctl --since
        switch_time = time.strftime('%H:%M:%S')
        # switch back to self-signed CA
        result = self.master.run_command([paths.IPA_CACERT_MANAGE, 'renew',
                                          '--self-signed'])
        assert result.returncode == 0

        # Confirm there is no traceback in the journal
        result = match_in_journal(self.master, since=switch_time,
                                  string='Traceback')
        assert not bool(result), ('"Traceback" keyword found in the journal.'
                                  'Please check further')

        # Check if pki-tomcatd was started after switching back.
        result = match_in_journal(self.master, since=switch_time,
                                  string=PKI_START_STR)
        assert bool(result), ('pki_tomcatd not started after switching back to'
                              'self-signed CA')

        result = self.master.run_command([paths.IPA_CERTUPDATE])
        assert result.returncode == 0


class TestExternalCAdirsrvStop(IntegrationTest):
    """When the dirsrv service, which gets started during the first
    ipa-server-install --external-ca phase, is not running when the
    second phase is run with --external-cert-file options, the
    ipa-server-install command fail.

    This test checks if second phase installs successfully when dirsrv
    is stoped.

    related ticket: https://pagure.io/freeipa/issue/6611"""
    def test_external_ca_dirsrv_stop(self):

        # Step 1 of ipa-server-install
        result = install_server_external_ca_step1(self.master)
        assert result.returncode == 0

        # stop dirsrv server.
        service_control_dirsrv(self.master, 'stop')

        # Sign CA, transport it to the host and get ipa and root ca paths.
        root_ca_fname, ipa_ca_fname = tasks.sign_ca_and_transport(
            self.master, paths.ROOT_IPA_CSR, ROOT_CA, IPA_CA)

        # Step 2 of ipa-server-install.
        result = install_server_external_ca_step2(
            self.master, ipa_ca_fname, root_ca_fname)
        assert result.returncode == 0

        # Make sure IPA server is working properly
        tasks.kinit_admin(self.master)
        result = self.master.run_command(['ipa', 'user-show', 'admin'])
        assert 'User login: admin' in result.stdout_text


class TestExternalCAInvalidCert(IntegrationTest):
    """Manual renew external CA cert with invalid file"""

    def test_external_ca(self):
        # Step 1 of ipa-server-install.
        install_server_external_ca_step1(self.master)

        # Sign CA, transport it to the host and get ipa a root ca paths.
        root_ca_fname, ipa_ca_fname = tasks.sign_ca_and_transport(
            self.master, paths.ROOT_IPA_CSR, ROOT_CA, IPA_CA)

        # Step 2 of ipa-server-install.
        install_server_external_ca_step2(self.master, ipa_ca_fname,
                                         root_ca_fname)

        self.master.run_command([paths.IPA_CACERT_MANAGE, 'renew',
                                 '--external-ca'])
        result = self.master.run_command(['grep', '-v', 'CERTIFICATE',
                                          ipa_ca_fname])
        contents = result.stdout_text

        BAD_CERT = 'bad_ca.crt'
        invalid_cert = os.path.join(self.master.config.test_dir, BAD_CERT)
        self.master.put_file_contents(invalid_cert, contents)
        # Sign CA, transport it to the host and get ipa a root ca paths.
        root_ca_fname, ipa_ca_fname = tasks.sign_ca_and_transport(
            self.master, paths.IPA_CA_CSR, ROOT_CA, IPA_CA)
        # renew CA with invalid cert
        cmd = [paths.IPA_CACERT_MANAGE, 'renew', '--external-cert-file',
               invalid_cert, '--external-cert-file', root_ca_fname]
        result = self.master.run_command(cmd, raiseonerr=False)
        assert result.returncode == 1


class TestExternalCAInstall(IntegrationTest):
    """install CA cert manually """

    def test_install_master(self):
        # step 1 install ipa-server

        tasks.install_master(self.master)

    def test_install_external_ca(self):
        # Create root CA
        external_ca = ExternalCA()
        # Create root CA
        root_ca = external_ca.create_ca()
        root_ca_fname = os.path.join(self.master.config.test_dir, ROOT_CA)

        # Transport certificates (string > file) to master
        self.master.put_file_contents(root_ca_fname, root_ca)

        # Install new cert
        self.master.run_command([paths.IPA_CACERT_MANAGE, 'install',
                                 root_ca_fname])


class TestMultipleExternalCA(IntegrationTest):
    """Setup externally signed ca1

    install ipa-server with externally signed ca1
    Setup externally signed ca2 and renew ipa-server with
    externally signed ca2 and check the difference in certificate
    """

    def test_master_install_ca1(self):
        install_server_external_ca_step1(self.master)
        # Sign CA, transport it to the host and get ipa a root ca paths.
        root_ca_fname1 = tempfile.mkdtemp(suffix='root_ca.crt', dir=paths.TMP)
        ipa_ca_fname1 = tempfile.mkdtemp(suffix='ipa_ca.crt', dir=paths.TMP)

        ipa_csr = self.master.get_file_contents(paths.ROOT_IPA_CSR)

        external_ca = ExternalCA()
        root_ca = external_ca.create_ca(cn='RootCA1')
        ipa_ca = external_ca.sign_csr(ipa_csr)
        self.master.put_file_contents(root_ca_fname1, root_ca)
        self.master.put_file_contents(ipa_ca_fname1, ipa_ca)
        # Step 2 of ipa-server-install.
        install_server_external_ca_step2(self.master, ipa_ca_fname1,
                                         root_ca_fname1)

        cert_nick = "caSigningCert cert-pki-ca"
        result = self.master.run_command([
            'certutil', '-L', '-d', paths.PKI_TOMCAT_ALIAS_DIR,
            '-n', cert_nick])
        assert "CN=RootCA1" in result.stdout_text

    def test_master_install_ca2(self):
        root_ca_fname2 = tempfile.mkdtemp(suffix='root_ca.crt', dir=paths.TMP)
        ipa_ca_fname2 = tempfile.mkdtemp(suffix='ipa_ca.crt', dir=paths.TMP)

        self.master.run_command([
            paths.IPA_CACERT_MANAGE, 'renew', '--external-ca'])

        ipa_csr = self.master.get_file_contents(paths.IPA_CA_CSR)

        external_ca = ExternalCA()
        root_ca = external_ca.create_ca(cn='RootCA2')
        ipa_ca = external_ca.sign_csr(ipa_csr)
        self.master.put_file_contents(root_ca_fname2, root_ca)
        self.master.put_file_contents(ipa_ca_fname2, ipa_ca)
        # Step 2 of ipa-server-install.
        self.master.run_command([paths.IPA_CACERT_MANAGE, 'renew',
                                 '--external-cert-file', ipa_ca_fname2,
                                 '--external-cert-file', root_ca_fname2])

        cert_nick = "caSigningCert cert-pki-ca"
        result = self.master.run_command([
            'certutil', '-L', '-d', paths.PKI_TOMCAT_ALIAS_DIR,
            '-n', cert_nick])
        assert "CN=RootCA2" in result.stdout_text
