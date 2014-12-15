# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2013  Red Hat
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

import os
import tempfile
import shutil
import base64
import glob
import contextlib
import nose
import pytest

from ipalib import x509
from ipapython import ipautil
from ipaplatform.paths import paths
from ipapython.dn import DN
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration import tasks

_DEFAULT = object()


def get_install_stdin(cert_passwords=()):
    lines = [
        'yes',  # Existing BIND configuration detected, overwrite? [no]
        '',  # Server host name (has default)
        '',  # Confirm domain name (has default)
    ]
    lines.extend(cert_passwords)  # Enter foo.p12 unlock password
    lines += [
        '',  # Do you want to configure the reverse zone? [yes]
        '',  # Please specify the reverse zone name [47.34.10.in-addr.arpa.]
        'yes',  # Continue with these values?
    ]
    return '\n'.join(lines + [''])


def get_replica_prepare_stdin(cert_passwords=()):
    lines = list(cert_passwords)  # Enter foo.p12 unlock password
    return '\n'.join(lines + [''])


def assert_error(result, stderr_text, returncode=None):
    "Assert that `result` command failed and its stderr contains `stderr_text`"
    assert stderr_text in result.stderr_text, result.stderr_text
    if returncode:
        assert result.returncode == returncode
    else:
        assert result.returncode > 0


class CALessBase(IntegrationTest):
    @classmethod
    def install(cls, mh):
        super(CALessBase, cls).install(mh)
        cls.cert_dir = tempfile.mkdtemp(prefix="ipatest-")
        cls.pem_filename = os.path.join(cls.cert_dir, 'root.pem')
        scriptfile = os.path.join(os.path.dirname(__file__),
                                  'scripts',
                                  'caless-create-pki')
        cls.cert_password = cls.master.config.admin_password

        cls.crl_path = os.path.join(cls.master.config.test_dir, 'crl')

        if cls.replicas:
            replica_hostname = cls.replicas[0].hostname
        else:
            replica_hostname = 'unused-replica.test'
        if cls.clients:
            client_hostname = cls.clients[0].hostname
        else:
            client_hostname = 'unused-client.test'
        env = {
            'domain': cls.master.domain.name,
            'server1': cls.master.hostname,
            'server2': replica_hostname,
            'client': client_hostname,
            'dbdir': 'nssdb',
            'dbpassword': cls.cert_password,
            'crl_path': cls.crl_path,
        }
        ipautil.run(['bash', '-ex', scriptfile], cwd=cls.cert_dir, env=env)

        for host in cls.get_all_hosts():
            tasks.apply_common_fixes(host)

            # Copy CRLs over
            base = os.path.join(cls.cert_dir, 'nssdb')
            host.transport.mkdir_recursive(cls.crl_path)
            for source in glob.glob(os.path.join(base, '*.crl')):
                dest = os.path.join(cls.crl_path, os.path.basename(source))
                host.transport.put_file(source, dest)

    @classmethod
    def uninstall(cls, mh):
        # Remove the NSS database
        shutil.rmtree(cls.cert_dir)

        # Remove CA cert in /etc/pki/nssdb, in case of failed (un)install
        for host in cls.get_all_hosts():
            cls.master.run_command(['certutil', '-d', paths.NSS_DB_DIR, '-D',
                                    '-n', 'External CA cert'],
                                   raiseonerr=False)

        super(CALessBase, cls).uninstall()

    @classmethod
    def install_server(cls, host=None,
                       http_pkcs12='server.p12', dirsrv_pkcs12='server.p12',
                       http_pkcs12_exists=True, dirsrv_pkcs12_exists=True,
                       http_pin=_DEFAULT, dirsrv_pin=_DEFAULT,
                       root_ca_file='root.pem', unattended=True,
                       stdin_text=None):
        """Install a CA-less server

        Return value is the remote ipa-server-install command
        """
        if host is None:
            host = cls.master
        if http_pin is _DEFAULT:
            http_pin = cls.cert_password
        if dirsrv_pin is _DEFAULT:
            dirsrv_pin = cls.cert_password

        files_to_copy = ['root.pem']
        if http_pkcs12_exists:
            files_to_copy.append(http_pkcs12)
        if dirsrv_pkcs12_exists:
            files_to_copy.append(dirsrv_pkcs12)
        for filename in set(files_to_copy):
            cls.copy_cert(host, filename)

        host.collect_log(paths.IPASERVER_INSTALL_LOG)
        host.collect_log(paths.IPACLIENT_INSTALL_LOG)
        inst = host.domain.realm.replace('.', '-')
        host.collect_log(paths.SLAPD_INSTANCE_ERROR_LOG_TEMPLATE % inst)
        host.collect_log(paths.SLAPD_INSTANCE_ACCESS_LOG_TEMPLATE % inst)

        args = [
            'ipa-server-install',
            '--http-cert-file', http_pkcs12,
            '--dirsrv-cert-file', dirsrv_pkcs12,
            '--ca-cert-file', root_ca_file,
            '--ip-address', host.ip,
            '-r', host.domain.name,
            '-p', host.config.dirman_password,
            '-a', host.config.admin_password,
            '--setup-dns',
            '--forwarder', host.config.dns_forwarder,
        ]

        if http_pin is not None:
            args.extend(['--http-pin', http_pin])
        if dirsrv_pin is not None:
            args.extend(['--dirsrv-pin', dirsrv_pin])
        if unattended:
            args.extend(['-U'])

        return host.run_command(args, raiseonerr=False, stdin_text=stdin_text)

    @classmethod
    def copy_cert(cls, host, filename):
        host.transport.put_file(os.path.join(cls.cert_dir, filename),
                                os.path.join(host.config.test_dir, filename))

    @classmethod
    def uninstall_server(self, host=None):
        if host is None:
            host = self.master
        host.run_command(['ipa-server-install', '--uninstall', '-U'])

    def prepare_replica(self, _replica_number=0, replica=None, master=None,
                        http_pkcs12='replica.p12', dirsrv_pkcs12='replica.p12',
                        http_pkcs12_exists=True, dirsrv_pkcs12_exists=True,
                        http_pin=_DEFAULT, dirsrv_pin=_DEFAULT,
                        root_ca_file='root.pem', unattended=True,
                        stdin_text=None):
        """Prepare a CA-less replica

        Puts the bundle file into test_dir on the replica if successful,
        otherwise ensures it is missing.

        Return value is the remote ipa-replica-prepare command
        """
        if replica is None:
            replica = self.replicas[_replica_number]
        if master is None:
            master = self.master
        if http_pin is _DEFAULT:
            http_pin = self.cert_password
        if dirsrv_pin is _DEFAULT:
            dirsrv_pin = self.cert_password

        files_to_copy = ['root.pem']
        if http_pkcs12_exists:
            files_to_copy.append(http_pkcs12)
        if dirsrv_pkcs12_exists:
            files_to_copy.append(dirsrv_pkcs12)
        for filename in set(files_to_copy):
            master.transport.put_file(
                os.path.join(self.cert_dir, filename),
                os.path.join(master.config.test_dir, filename))

        replica.collect_log(paths.IPAREPLICA_INSTALL_LOG)
        replica.collect_log(paths.IPACLIENT_INSTALL_LOG)
        inst = replica.domain.realm.replace('.', '-')
        replica.collect_log(paths.SLAPD_INSTANCE_ERROR_LOG_TEMPLATE % inst)
        replica.collect_log(paths.SLAPD_INSTANCE_ACCESS_LOG_TEMPLATE % inst)

        args = [
            'ipa-replica-prepare',
            '--ip-address', replica.ip,
            '-p', replica.config.dirman_password,
        ]

        if http_pkcs12:
            args.extend(['--http-cert-file', http_pkcs12])
        if dirsrv_pkcs12:
            args.extend(['--dirsrv-cert-file', dirsrv_pkcs12])
        if http_pin is not None:
            args.extend(['--http-pin', http_pin])
        if dirsrv_pin is not None:
            args.extend(['--dirsrv-pin', dirsrv_pin])

        args.extend([replica.hostname])

        result = master.run_command(args, raiseonerr=False,
                                    stdin_text=stdin_text)

        if result.returncode == 0:
            replica_bundle = master.get_file_contents(
                paths.REPLICA_INFO_GPG_TEMPLATE % replica.hostname)
            replica.put_file_contents(self.get_replica_filename(replica),
                                      replica_bundle)
        else:
            replica.run_command(['rm', self.get_replica_filename(replica)],
                                raiseonerr=False)

        return result

    def get_replica_filename(self, replica):
        return os.path.join(replica.config.test_dir,
                            'replica-info.gpg')

    def install_replica(self, _replica_number=0, replica=None,
                        unattended=True):
        """Install a CA-less replica

        The bundle file is expected to be in the test_dir

        Return value is the remote ipa-replica-install command
        """
        if replica is None:
            replica = self.replicas[_replica_number]

        args = ['ipa-replica-install', '-U',
                '-p', replica.config.dirman_password,
                '-w', replica.config.admin_password,
                '--ip-address', replica.ip,
                self.get_replica_filename(replica)]
        if unattended:
            args.append('-U')
        return replica.run_command(args)

    @classmethod
    def export_pkcs12(cls, nickname, filename='server.p12', password=None):
        """Export a cert as PKCS#12 to the given file"""
        if password is None:
            password = cls.cert_password
        ipautil.run(['pk12util',
                     '-o', filename,
                     '-n', nickname,
                     '-d', 'nssdb',
                     '-K', cls.cert_password,
                     '-W', password], cwd=cls.cert_dir)

    @classmethod
    def get_pem(cls, nickname):
        pem_cert, _stderr, _returncode = ipautil.run(
            ['certutil', '-L', '-d', 'nssdb', '-n', nickname, '-a'],
            cwd=cls.cert_dir)
        return pem_cert

    def verify_installation(self):
        """Verify CA cert PEM file and LDAP entry created by install

        Called from every positive server install test
        """
        with open(self.pem_filename) as f:
            expected_cacrt = f.read()
        self.log.debug('Expected /etc/ipa/ca.crt contents:\n%s',
                       expected_cacrt)
        expected_binary_cacrt = base64.b64decode(x509.strip_header(
            expected_cacrt))
        self.log.debug('Expected binary CA cert:\n%r',
                       expected_binary_cacrt)
        for host in [self.master] + self.replicas:
            # Check the LDAP entry
            ldap = host.ldap_connect()
            entry = ldap.get_entry(DN(('cn', 'CACert'), ('cn', 'ipa'),
                                      ('cn', 'etc'), host.domain.basedn))
            cert_from_ldap = entry.single_value['cACertificate']
            self.log.debug('CA cert from LDAP on %s:\n%r',
                           host, cert_from_ldap)
            assert cert_from_ldap == expected_binary_cacrt

            # Verify certmonger was not started
            result = host.run_command(['getcert', 'list'], raiseonerr=False)
            assert result > 0
            assert ('Please verify that the certmonger service has been '
                    'started.' in result.stdout_text), result.stdout_text

        for host in self.get_all_hosts():
            # Check the cert PEM file
            remote_cacrt = host.get_file_contents(paths.IPA_CA_CRT)
            self.log.debug('%s:/etc/ipa/ca.crt contents:\n%s',
                           host, remote_cacrt)
            binary_cacrt = base64.b64decode(x509.strip_header(remote_cacrt))
            self.log.debug('%s: Decoded /etc/ipa/ca.crt:\n%r',
                           host, binary_cacrt)
            assert expected_binary_cacrt == binary_cacrt


class TestServerInstall(CALessBase):
    num_replicas = 0

    def tearDown(self):
        self.uninstall_server()

        # Remove CA cert in /etc/pki/nssdb, in case of failed (un)install
        for host in self.get_all_hosts():
            self.master.run_command(['certutil', '-d', paths.NSS_DB_DIR, '-D',
                                     '-n', 'External CA cert'],
                                    raiseonerr=False)

    def test_nonexistent_ca_pem_file(self):
        "IPA server install with non-existent CA PEM file "

        self.export_pkcs12('ca1/server')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca2'))

        result = self.install_server(root_ca_file='does_not_exist')
        assert_error(result,
                     'Failed to open does_not_exist: No such file '
                     'or directory')

    def test_unknown_ca(self):
        "IPA server install with CA PEM file with unknown CA certificate"

        self.export_pkcs12('ca1/server')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca2'))

        result = self.install_server()
        assert_error(result,
                     'server.p12 is not signed by root.pem, or the full '
                     'certificate chain is not present in the PKCS#12 '
                     'file')

    def test_ca_server_cert(self):
        "IPA server install with CA PEM file with server certificate"

        self.export_pkcs12('ca1/server')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1/server'))

        result = self.install_server()
        assert_error(result,
                     'trust chain of the server certificate in server.p12 '
                     'contains 1 certificates, expected 2')

    def test_ca_2_certs(self):
        "IPA server install with CA PEM file with 2 certificates"

        self.export_pkcs12('ca1/server')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))
            f.write(self.get_pem('ca2'))

        result = self.install_server()
        assert_error(result, 'root.pem contains more than one certificate')

    def test_nonexistent_http_pkcs12_file(self):
        "IPA server install with non-existent HTTP PKCS#12 file"

        self.export_pkcs12('ca1/server')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pkcs12='does_not_exist',
                                     http_pkcs12_exists=False)
        assert_error(result, 'Failed to open does_not_exist')

    def test_nonexistent_ds_pkcs12_file(self):
        "IPA server install with non-existent DS PKCS#12 file"

        self.export_pkcs12('ca1/server')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(dirsrv_pkcs12='does_not_exist',
                                     dirsrv_pkcs12_exists=False)
        assert_error(result, 'Failed to open does_not_exist')

    def test_missing_http_password(self):
        "IPA server install with missing HTTP PKCS#12 password (unattended)"

        self.export_pkcs12('ca1/server')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pin=None)
        assert_error(result,
                     'ipa-server-install: error: You must specify --http-pin '
                     'with --http-cert-file')

    def test_missing_ds_password(self):
        "IPA server install with missing DS PKCS#12 password (unattended)"

        self.export_pkcs12('ca1/server')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(dirsrv_pin=None)
        assert_error(result,
                     'ipa-server-install: error: You must specify '
                     '--dirsrv-pin with --dirsrv-cert-file')

    def test_incorect_http_pin(self):
        "IPA server install with incorrect HTTP PKCS#12 password"

        self.export_pkcs12('ca1/server')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pin='bad<pin>')
        assert_error(result, 'incorrect password for pkcs#12 file server.p12')

    def test_incorect_ds_pin(self):
        "IPA server install with incorrect DS PKCS#12 password"

        self.export_pkcs12('ca1/server')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(dirsrv_pin='bad<pin>')
        assert_error(result, 'incorrect password for pkcs#12 file server.p12')

    def test_invalid_http_cn(self):
        "IPA server install with HTTP certificate with invalid CN"

        self.export_pkcs12('ca1/server-badname', filename='http.p12')
        self.export_pkcs12('ca1/server', filename='dirsrv.p12')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pkcs12='http.p12',
                                     dirsrv_pkcs12='dirsrv.p12')
        assert_error(result,
                     'The server certificate in http.p12 is not valid: '
                     'invalid for server %s' % self.master.hostname)

    def test_invalid_ds_cn(self):
        "IPA server install with DS certificate with invalid CN"

        self.export_pkcs12('ca1/server', filename='http.p12')
        self.export_pkcs12('ca1/server-badname', filename='dirsrv.p12')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pkcs12='http.p12',
                                     dirsrv_pkcs12='dirsrv.p12')
        assert_error(result,
                     'The server certificate in dirsrv.p12 is not valid: '
                     'invalid for server %s' % self.master.hostname)

    def test_expired_http(self):
        "IPA server install with expired HTTP certificate"

        self.export_pkcs12('ca1/server-expired', filename='http.p12')
        self.export_pkcs12('ca1/server', filename='dirsrv.p12')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pkcs12='http.p12',
                                     dirsrv_pkcs12='dirsrv.p12')
        assert_error(result,
                     'The server certificate in http.p12 is not valid: '
                     "(SEC_ERROR_EXPIRED_CERTIFICATE) Peer's Certificate has "
                     'expired.')

    def test_expired_ds(self):
        "IPA server install with expired DS certificate"

        self.export_pkcs12('ca1/server', filename='http.p12')
        self.export_pkcs12('ca1/server-expired', filename='dirsrv.p12')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pkcs12='http.p12',
                                     dirsrv_pkcs12='dirsrv.p12')
        assert_error(result,
                     'The server certificate in dirsrv.p12 is not valid: '
                     "(SEC_ERROR_EXPIRED_CERTIFICATE) Peer's Certificate has "
                     'expired.')

    def test_http_bad_usage(self):
        "IPA server install with HTTP certificate with invalid key usage"

        self.export_pkcs12('ca1/server-badusage', filename='http.p12')
        self.export_pkcs12('ca1/server', filename='dirsrv.p12')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pkcs12='http.p12',
                                     dirsrv_pkcs12='dirsrv.p12')
        assert_error(result,
                     'The server certificate in http.p12 is not valid: '
                     'invalid for a SSL server')

    def test_ds_bad_usage(self):
        "IPA server install with DS certificate with invalid key usage"

        self.export_pkcs12('ca1/server', filename='http.p12')
        self.export_pkcs12('ca1/server-badusage', filename='dirsrv.p12')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pkcs12='http.p12',
                                     dirsrv_pkcs12='dirsrv.p12')
        assert_error(result,
                     'The server certificate in dirsrv.p12 is not valid: '
                     'invalid for a SSL server')

    def test_revoked_http(self):
        "IPA server install with revoked HTTP certificate"

        self.export_pkcs12('ca1/server-revoked', filename='http.p12')
        self.export_pkcs12('ca1/server', filename='dirsrv.p12')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pkcs12='http.p12',
                                     dirsrv_pkcs12='dirsrv.p12')

        if result.returncode == 0:
            raise nose.SkipTest(
                "Known CA-less installation defect, see "
                + "https://fedorahosted.org/freeipa/ticket/4270")

        assert result.returncode > 0

    def test_revoked_ds(self):
        "IPA server install with revoked DS certificate"

        self.export_pkcs12('ca1/server', filename='http.p12')
        self.export_pkcs12('ca1/server-revoked', filename='dirsrv.p12')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pkcs12='http.p12',
                                     dirsrv_pkcs12='dirsrv.p12')

        if result.returncode == 0:
            raise nose.SkipTest(
                "Known CA-less installation defect, see "
                + "https://fedorahosted.org/freeipa/ticket/4270")

        assert result.returncode > 0

    def test_http_intermediate_ca(self):
        "IPA server install with HTTP certificate issued by intermediate CA"

        self.export_pkcs12('ca1/subca/server', filename='http.p12')
        self.export_pkcs12('ca1/server', filename='dirsrv.p12')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pkcs12='http.p12',
                                     dirsrv_pkcs12='dirsrv.p12')
        assert_error(result,
                     'http.p12 is not signed by root.pem, or the full '
                     'certificate chain is not present in the PKCS#12 file')

    def test_ds_intermediate_ca(self):
        "IPA server install with DS certificate issued by intermediate CA"

        self.export_pkcs12('ca1/server', filename='http.p12')
        self.export_pkcs12('ca1/subca/server', filename='dirsrv.p12')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pkcs12='http.p12',
                                     dirsrv_pkcs12='dirsrv.p12')
        assert_error(result,
                     'dirsrv.p12 is not signed by root.pem, or the full '
                     'certificate chain is not present in the PKCS#12 file')

    def test_ca_self_signed(self):
        "IPA server install with self-signed certificate"

        self.export_pkcs12('server-selfsign')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('server-selfsign'))

        result = self.install_server()
        assert result.returncode > 0

    def test_valid_certs(self):
        "IPA server install with valid certificates"

        self.export_pkcs12('ca1/server')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server()
        assert result.returncode == 0
        self.verify_installation()

    def test_wildcard_http(self):
        "IPA server install with wildcard HTTP certificate"

        self.export_pkcs12('ca1/wildcard', filename='http.p12')
        self.export_pkcs12('ca1/server', filename='dirsrv.p12')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pkcs12='http.p12',
                                     dirsrv_pkcs12='dirsrv.p12')
        assert result.returncode == 0
        self.verify_installation()

    def test_wildcard_ds(self):
        "IPA server install with wildcard DS certificate"

        self.export_pkcs12('ca1/server', filename='http.p12')
        self.export_pkcs12('ca1/wildcard', filename='dirsrv.p12')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pkcs12='http.p12',
                                     dirsrv_pkcs12='dirsrv.p12')
        assert result.returncode == 0
        self.verify_installation()

    def test_http_san(self):
        "IPA server install with HTTP certificate with SAN"

        self.export_pkcs12('ca1/server-altname', filename='http.p12')
        self.export_pkcs12('ca1/server', filename='dirsrv.p12')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pkcs12='http.p12',
                                     dirsrv_pkcs12='dirsrv.p12')
        assert result.returncode == 0
        self.verify_installation()

    def test_ds_san(self):
        "IPA server install with DS certificate with SAN"

        self.export_pkcs12('ca1/server', filename='http.p12')
        self.export_pkcs12('ca1/server-altname', filename='dirsrv.p12')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pkcs12='http.p12',
                                     dirsrv_pkcs12='dirsrv.p12')
        assert result.returncode == 0
        self.verify_installation()

    def test_interactive_missing_http_pkcs_password(self):
        "IPA server install with prompt for HTTP PKCS#12 password"

        self.export_pkcs12('ca1/server')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        stdin_text = get_install_stdin(cert_passwords=[self.cert_password])

        result = self.install_server(http_pin=None, unattended=False,
                                     stdin_text=stdin_text)
        assert result.returncode == 0
        self.verify_installation()
        assert ('Enter server.p12 unlock password:'
                in result.stdout_text), result.stdout_text

    def test_interactive_missing_ds_pkcs_password(self):
        "IPA server install with prompt for DS PKCS#12 password"

        self.export_pkcs12('ca1/server')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        stdin_text = get_install_stdin(cert_passwords=[self.cert_password])

        result = self.install_server(dirsrv_pin=None, unattended=False,
                                     stdin_text=stdin_text)
        assert result.returncode == 0
        self.verify_installation()
        assert ('Enter server.p12 unlock password:'
                in result.stdout_text), result.stdout_text

    def test_no_http_password(self):
        "IPA server install with empty HTTP password"

        self.export_pkcs12('ca1/server', filename='http.p12', password='')
        self.export_pkcs12('ca1/server', filename='dirsrv.p12')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pkcs12='http.p12',
                                     dirsrv_pkcs12='dirsrv.p12',
                                     http_pin='')
        assert result.returncode == 0
        self.verify_installation()

    def test_no_ds_password(self):
        "IPA server install with empty DS password"

        self.export_pkcs12('ca1/server', filename='http.p12')
        self.export_pkcs12('ca1/server', filename='dirsrv.p12', password='')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server(http_pkcs12='http.p12',
                                     dirsrv_pkcs12='dirsrv.p12',
                                     dirsrv_pin='')
        assert result.returncode == 0
        self.verify_installation()


class TestReplicaInstall(CALessBase):
    num_replicas = 1

    def setUp(self):
        # Install the master for every test
        self.export_pkcs12('ca1/server')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server()
        assert result.returncode == 0

    def tearDown(self):
        # Uninstall both master and replica
        replica = self.replicas[0]
        tasks.kinit_admin(self.master)
        self.uninstall_server(replica)
        self.master.run_command(['ipa-replica-manage', 'del', replica.hostname,
                                 '--force'], raiseonerr=False)
        self.master.run_command(['ipa', 'host-del', replica.hostname],
                                raiseonerr=False)

        replica.run_command(['certutil', '-d', paths.NSS_DB_DIR, '-D',
                             '-n', 'External CA cert'], raiseonerr=False)

        self.uninstall_server()
        self.master.run_command(['certutil', '-d', paths.NSS_DB_DIR, '-D',
                                 '-n', 'External CA cert'], raiseonerr=False)

    def test_no_certs(self):
        "IPA replica install without certificates"

        result = self.master.run_command(['ipa-replica-prepare',
                                          self.replicas[0].hostname],
                                         raiseonerr=False)
        assert result.returncode > 0
        assert ('Cannot issue certificates: a CA is not installed. Use the '
                '--http-cert-file, --dirsrv-cert-file options to provide '
                'custom certificates.' in result.stderr_text), \
               result.stderr_text

    def test_nonexistent_http_pkcs12_file(self):
        "IPA replica install with non-existent HTTP PKCS#12 file"

        self.export_pkcs12('ca1/replica', filename='dirsrv.p12')

        result = self.prepare_replica(http_pkcs12='does_not_exist',
                                      dirsrv_pkcs12='dirsrv.p12',
                                      http_pkcs12_exists=False)
        assert_error(result, 'Failed to open does_not_exist')

    def test_nonexistent_ds_pkcs12_file(self):
        "IPA replica install with non-existent DS PKCS#12 file"

        self.export_pkcs12('ca1/replica', filename='http.p12')

        result = self.prepare_replica(dirsrv_pkcs12='does_not_exist',
                                      http_pkcs12='http.p12',
                                      dirsrv_pkcs12_exists=False)
        assert_error(result, 'Failed to open does_not_exist')

    def test_incorect_http_pin(self):
        "IPA replica install with incorrect HTTP PKCS#12 password"

        self.export_pkcs12('ca1/replica', filename='replica.p12')

        result = self.prepare_replica(http_pin='bad<pin>')
        assert result.returncode > 0
        assert_error(result, 'incorrect password for pkcs#12 file replica.p12')

    def test_incorect_ds_pin(self):
        "IPA replica install with incorrect DS PKCS#12 password"

        self.export_pkcs12('ca1/replica', filename='replica.p12')

        result = self.prepare_replica(dirsrv_pin='bad<pin>')
        assert_error(result, 'incorrect password for pkcs#12 file replica.p12')

    def test_http_unknown_ca(self):
        "IPA replica install with HTTP certificate issued by unknown CA"

        self.export_pkcs12('ca2/replica', filename='http.p12')
        self.export_pkcs12('ca1/replica', filename='dirsrv.p12')

        result = self.prepare_replica(http_pkcs12='http.p12',
                                      dirsrv_pkcs12='dirsrv.p12')
        assert_error(result,
                     'http.p12 is not signed by /etc/ipa/ca.crt, or the full '
                     'certificate chain is not present in the PKCS#12 file')

    def test_ds_unknown_ca(self):
        "IPA replica install with DS certificate issued by unknown CA"

        self.export_pkcs12('ca1/replica', filename='http.p12')
        self.export_pkcs12('ca2/replica', filename='dirsrv.p12')

        result = self.prepare_replica(http_pkcs12='http.p12',
                                      dirsrv_pkcs12='dirsrv.p12')
        assert_error(result,
                     'dirsrv.p12 is not signed by /etc/ipa/ca.crt, or the '
                     'full certificate chain is not present in the PKCS#12 '
                     'file')

    def test_invalid_http_cn(self):
        "IPA replica install with HTTP certificate with invalid CN"

        self.export_pkcs12('ca1/replica-badname', filename='http.p12')
        self.export_pkcs12('ca1/replica', filename='dirsrv.p12')

        result = self.prepare_replica(http_pkcs12='http.p12',
                                      dirsrv_pkcs12='dirsrv.p12')
        assert_error(result,
                     'The server certificate in http.p12 is not valid: '
                     'invalid for server %s' % self.replicas[0].hostname)

    def test_invalid_ds_cn(self):
        "IPA replica install with DS certificate with invalid CN"

        self.export_pkcs12('ca1/replica', filename='http.p12')
        self.export_pkcs12('ca1/replica-badname', filename='dirsrv.p12')

        result = self.prepare_replica(http_pkcs12='http.p12',
                                      dirsrv_pkcs12='dirsrv.p12')
        assert_error(result,
                     'The server certificate in dirsrv.p12 is not valid: '
                     'invalid for server %s' % self.replicas[0].hostname)

    def test_expired_http(self):
        "IPA replica install with expired HTTP certificate"

        self.export_pkcs12('ca1/replica-expired', filename='http.p12')
        self.export_pkcs12('ca1/replica', filename='dirsrv.p12')

        result = self.prepare_replica(http_pkcs12='http.p12',
                                      dirsrv_pkcs12='dirsrv.p12')
        assert_error(result,
                     'The server certificate in http.p12 is not valid: '
                     "(SEC_ERROR_EXPIRED_CERTIFICATE) Peer's Certificate has "
                     'expired.')

    def test_expired_ds(self):
        "IPA replica install with expired DS certificate"

        self.export_pkcs12('ca1/replica-expired', filename='http.p12')
        self.export_pkcs12('ca1/replica', filename='dirsrv.p12')

        result = self.prepare_replica(http_pkcs12='http.p12',
                                      dirsrv_pkcs12='dirsrv.p12')
        assert_error(result,
                     'The server certificate in http.p12 is not valid: '
                     "(SEC_ERROR_EXPIRED_CERTIFICATE) Peer's Certificate has "
                     'expired.')

    def test_http_bad_usage(self):
        "IPA replica install with HTTP certificate with invalid key usage"

        self.export_pkcs12('ca1/replica-badusage', filename='http.p12')
        self.export_pkcs12('ca1/replica', filename='dirsrv.p12')

        result = self.prepare_replica(http_pkcs12='http.p12',
                                      dirsrv_pkcs12='dirsrv.p12')
        assert_error(result,
                     'The server certificate in http.p12 is not valid: '
                     'invalid for a SSL server')

    def test_ds_bad_usage(self):
        "IPA replica install with DS certificate with invalid key usage"

        self.export_pkcs12('ca1/replica', filename='http.p12')
        self.export_pkcs12('ca1/replica-badusage', filename='dirsrv.p12')

        result = self.prepare_replica(http_pkcs12='http.p12',
                                      dirsrv_pkcs12='dirsrv.p12')
        assert_error(result,
                     'The server certificate in dirsrv.p12 is not valid: '
                     'invalid for a SSL server')

    def test_revoked_http(self):
        "IPA replica install with revoked HTTP certificate"

        self.export_pkcs12('ca1/replica-revoked', filename='http.p12')
        self.export_pkcs12('ca1/replica', filename='dirsrv.p12')

        result = self.prepare_replica(http_pkcs12='http.p12',
                                      dirsrv_pkcs12='dirsrv.p12')

        if result.returncode == 0:
            raise nose.SkipTest(
                "Known CA-less installation defect, see "
                + "https://fedorahosted.org/freeipa/ticket/4270")

        assert result.returncode > 0

    def test_revoked_ds(self):
        "IPA replica install with revoked DS certificate"

        self.export_pkcs12('ca1/replica', filename='http.p12')
        self.export_pkcs12('ca1/replica-revoked', filename='dirsrv.p12')

        result = self.prepare_replica(http_pkcs12='http.p12',
                                      dirsrv_pkcs12='dirsrv.p12')

        if result.returncode == 0:
            raise nose.SkipTest(
                "Known CA-less installation defect, see "
                + "https://fedorahosted.org/freeipa/ticket/4270")

        assert result.returncode > 0

    def test_http_intermediate_ca(self):
        "IPA replica install with HTTP certificate issued by intermediate CA"

        self.export_pkcs12('ca1/subca/replica', filename='http.p12')
        self.export_pkcs12('ca1/replica', filename='dirsrv.p12')

        result = self.prepare_replica(http_pkcs12='http.p12',
                                      dirsrv_pkcs12='dirsrv.p12')
        assert_error(result,
                     'http.p12 is not signed by /etc/ipa/ca.crt, or the full '
                     'certificate chain is not present in the PKCS#12 file')

    def test_ds_intermediate_ca(self):
        "IPA replica install with DS certificate issued by intermediate CA"

        self.export_pkcs12('ca1/replica', filename='http.p12')
        self.export_pkcs12('ca1/subca/replica', filename='dirsrv.p12')

        result = self.prepare_replica(http_pkcs12='http.p12',
                                      dirsrv_pkcs12='dirsrv.p12')
        assert_error(result,
                     'dirsrv.p12 is not signed by /etc/ipa/ca.crt, or the '
                     'full certificate chain is not present in the PKCS#12 '
                     'file')

    def test_valid_certs(self):
        "IPA replica install with valid certificates"

        self.export_pkcs12('ca1/replica', filename='server.p12')

        result = self.prepare_replica(http_pkcs12='server.p12',
                                      dirsrv_pkcs12='server.p12')
        assert result.returncode == 0

        result = self.install_replica()
        assert result.returncode == 0

        self.verify_installation()

    def test_wildcard_http(self):
        "IPA replica install with wildcard HTTP certificate"

        self.export_pkcs12('ca1/wildcard', filename='http.p12')
        self.export_pkcs12('ca1/replica', filename='dirsrv.p12')

        result = self.prepare_replica(http_pkcs12='http.p12',
                                      dirsrv_pkcs12='dirsrv.p12')
        assert result.returncode == 0

        result = self.install_replica()
        assert result.returncode == 0

        self.verify_installation()

    def test_wildcard_ds(self):
        "IPA replica install with wildcard DS certificate"

        self.export_pkcs12('ca1/wildcard', filename='http.p12')
        self.export_pkcs12('ca1/replica', filename='dirsrv.p12')

        result = self.prepare_replica(http_pkcs12='http.p12',
                                      dirsrv_pkcs12='dirsrv.p12')
        assert result.returncode == 0

        result = self.install_replica()
        assert result.returncode == 0

        self.verify_installation()

    def test_http_san(self):
        "IPA replica install with HTTP certificate with SAN"

        self.export_pkcs12('ca1/replica-altname', filename='http.p12')
        self.export_pkcs12('ca1/replica', filename='dirsrv.p12')

        result = self.prepare_replica(http_pkcs12='http.p12',
                                      dirsrv_pkcs12='dirsrv.p12')
        assert result.returncode == 0

        result = self.install_replica()
        assert result.returncode == 0

        self.verify_installation()

    def test_ds_san(self):
        "IPA replica install with DS certificate with SAN"

        self.export_pkcs12('ca1/replica', filename='http.p12')
        self.export_pkcs12('ca1/replica-altname', filename='dirsrv.p12')

        result = self.prepare_replica(http_pkcs12='http.p12',
                                      dirsrv_pkcs12='dirsrv.p12')
        assert result.returncode == 0

        result = self.install_replica()
        assert result.returncode == 0

        self.verify_installation()

    def test_interactive_missing_http_pkcs_password(self):
        "IPA replica install with missing HTTP PKCS#12 password"

        self.export_pkcs12('ca1/replica', filename='replica.p12')

        stdin_text = get_replica_prepare_stdin(
            cert_passwords=[self.cert_password])

        result = self.prepare_replica(http_pin=None, unattended=False,
                                      stdin_text=stdin_text)
        assert result.returncode == 0

        result = self.install_replica()
        assert result.returncode == 0

        self.verify_installation()

    def test_interactive_missing_ds_pkcs_password(self):
        "IPA replica install with missing DS PKCS#12 password"

        self.export_pkcs12('ca1/replica', filename='replica.p12')

        stdin_text = get_replica_prepare_stdin(
            cert_passwords=[self.cert_password])

        result = self.prepare_replica(dirsrv_pin=None, unattended=False,
                                      stdin_text=stdin_text)
        assert result.returncode == 0

        result = self.install_replica()
        assert result.returncode == 0

        self.verify_installation()

    def test_no_http_password(self):
        "IPA replica install with empty HTTP password"

        self.export_pkcs12('ca1/replica', filename='http.p12', password='')
        self.export_pkcs12('ca1/replica', filename='dirsrv.p12')

        result = self.prepare_replica(http_pkcs12='http.p12',
                                      dirsrv_pkcs12='dirsrv.p12',
                                      http_pin='')
        assert result.returncode == 0

        result = self.install_replica()
        assert result.returncode == 0

        self.verify_installation()

    def test_no_ds_password(self):
        "IPA replica install with empty DS password"

        self.export_pkcs12('ca1/replica', filename='http.p12')
        self.export_pkcs12('ca1/replica', filename='dirsrv.p12', password='')

        result = self.prepare_replica(http_pkcs12='http.p12',
                                      dirsrv_pkcs12='dirsrv.p12',
                                      dirsrv_pin='')
        assert result.returncode == 0

        result = self.install_replica()
        assert result.returncode == 0


class TestClientInstall(CALessBase):
    num_clients = 1

    def test_client_install(self):
        "IPA client install"

        self.export_pkcs12('ca1/server')
        with open(self.pem_filename, 'w') as f:
            f.write(self.get_pem('ca1'))

        result = self.install_server()
        assert result.returncode == 0

        self.clients[0].run_command(['ipa-client-install',
                                     '--domain', self.master.domain.name,
                                     '--server', self.master.hostname,
                                     '-p', self.master.config.admin_name,
                                     '-w', self.master.config.admin_password,
                                     '-U'])

        self.verify_installation()


class TestIPACommands(CALessBase):
    @classmethod
    def install(cls, mh):
        super(TestIPACommands, cls).install(mh)

        cls.export_pkcs12('ca1/server')
        with open(cls.pem_filename, 'w') as f:
            f.write(cls.get_pem('ca1'))

        result = cls.install_server()
        assert result.returncode == 0

        tasks.kinit_admin(cls.master)

        cls.client_pem = ''.join(cls.get_pem('ca1/client').splitlines()[1:-1])
        cls.log.debug('Client PEM:\n%r' % cls.client_pem)
        cls.test_hostname = 'testhost.%s' % cls.master.domain.name
        cls.test_service = 'test/%s' % cls.test_hostname

    def check_ipa_command_not_available(self, command):
        "Verify that the given IPA subcommand is not available"

        result = self.master.run_command(['ipa', command], raiseonerr=False)
        assert_error(result, "ipa: ERROR: unknown command '%s'" % command)

    @pytest.mark.parametrize('command', (
        'cert-status',
        'cert-show',
        'cert-find',
        'cert-revoke',
        'cert-remove-hold',
        'cert-status'))
    def test_cert_commands_unavailable(self, command):
        result = self.master.run_command(['ipa', command], raiseonerr=False)
        assert_error(result, "ipa: ERROR: unknown command '%s'" % command)

    def test_cert_help_unavailable(self):
        "Verify that cert plugin help is not available"
        result = self.master.run_command(['ipa', 'help', 'cert'],
                                         raiseonerr=False)
        assert_error(result,
                     "ipa: ERROR: no command nor help topic 'cert'",
                     returncode=1)

    @contextlib.contextmanager
    def host(self):
        "Context manager that adds and removes a host entry with a certificate"
        self.master.run_command(['ipa', 'host-add', self.test_hostname,
                                 '--force',
                                 '--certificate', self.client_pem])
        try:
            yield
        finally:
            self.master.run_command(['ipa', 'host-del', self.test_hostname],
                                    raiseonerr=False)

    @contextlib.contextmanager
    def service(self):
        "Context manager that adds and removes host & service entries"
        with self.host():
            self.master.run_command(['ipa', 'service-add', self.test_service,
                                     '--force',
                                     '--certificate', self.client_pem])
            yield

    def test_service_mod_doesnt_revoke(self):
        "Verify that service-mod does not attempt to revoke certificate"
        with self.service():
            self.master.run_command(['ipa', 'service-mod', self.test_service,
                                     '--certificate='])

    def test_service_disable_doesnt_revoke(self):
        "Verify that service-disable does not attempt to revoke certificate"
        with self.service():
            self.master.run_command(['ipa', 'service-disable',
                                     self.test_service])

    def test_service_del_doesnt_revoke(self):
        "Verify that service-del does not attempt to revoke certificate"
        with self.service():
            self.master.run_command(['ipa', 'service-del', self.test_service])

    def test_host_mod_doesnt_revoke(self):
        "Verify that host-mod does not attempt to revoke host's certificate"
        with self.host():
            self.master.run_command(['ipa', 'host-mod', self.test_hostname,
                                     '--certificate='])

    def test_host_disable_doesnt_revoke(self):
        "Verify that host-disable does not attempt to revoke host certificate"
        with self.host():
            self.master.run_command(['ipa', 'host-disable',
                                     self.test_hostname])

    def test_host_del_doesnt_revoke(self):
        "Verify that host-del does not attempt to revoke host's certificate"
        with self.host():
            self.master.run_command(['ipa', 'host-del', self.test_hostname])


class TestCertinstall(CALessBase):
    @classmethod
    def install(cls, mh):
        super(TestCertinstall, cls).install()

        cls.export_pkcs12('ca1/server')
        with open(cls.pem_filename, 'w') as f:
            f.write(cls.get_pem('ca1'))

        result = cls.install_server()
        assert result.returncode == 0

        tasks.kinit_admin(cls.master)

    def certinstall(self, mode, cert_nick=None, cert_exists=True,
                    filename='server.p12', pin=_DEFAULT, stdin_text=None,
                    p12_pin=None, args=None):
        if cert_nick:
            self.export_pkcs12(cert_nick, password=p12_pin)
        if pin is _DEFAULT:
            pin = self.cert_password
        if cert_exists:
            self.copy_cert(self.master, filename)
        if not args:
            args = ['ipa-server-certinstall',
                    '-%s' % mode, filename]
            if pin is not None:
                args += ['--pin', pin]
            if mode == 'd':
                args += ['--dirman-password',
                         self.master.config.dirman_password]
        return self.master.run_command(args,
                                       raiseonerr=False,
                                       stdin_text=stdin_text)

    def test_nonexistent_http_pkcs12_file(self):
        "Install new HTTP certificate from non-existent PKCS#12 file"

        result = self.certinstall('w', filename='does_not_exist', pin='none',
                                  cert_exists=False)
        assert_error(result, 'Failed to open does_not_exist')

    def test_nonexistent_ds_pkcs12_file(self):
        "Install new DS certificate from non-existent PKCS#12 file"

        result = self.certinstall('d', filename='does_not_exist', pin='none',
                                  cert_exists=False)
        assert_error(result, 'Failed to open does_not_exist')

    def test_incorect_http_pin(self):
        "Install new HTTP certificate with incorrect PKCS#12 password"

        result = self.certinstall('w', 'ca1/server', pin='bad<pin>')
        assert_error(result,
                     'incorrect password for pkcs#12 file server.p12')

    def test_incorect_dirsrv_pin(self):
        "Install new DS certificate with incorrect PKCS#12 password"

        result = self.certinstall('d', 'ca1/server', pin='bad<pin>')
        assert_error(result,
                     'incorrect password for pkcs#12 file server.p12')

    def test_invalid_http_cn(self):
        "Install new HTTP certificate with invalid CN "

        result = self.certinstall('w', 'ca1/server-badname')
        assert_error(result,
                     'The server certificate in server.p12 is not valid: '
                     'invalid for server %s' % self.master.hostname)

    def test_invalid_ds_cn(self):
        "Install new DS certificate with invalid CN "

        result = self.certinstall('d', 'ca1/server-badname')
        assert_error(result,
                     'The server certificate in server.p12 is not valid: '
                     'invalid for server %s' % self.master.hostname)

    def test_expired_http(self):
        "Install new expired HTTP certificate"

        result = self.certinstall('w', 'ca1/server-expired')
        assert_error(result,
                     'The server certificate in server.p12 is not valid: '
                     "(SEC_ERROR_EXPIRED_CERTIFICATE) Peer's Certificate has "
                     'expired.')

    def test_expired_ds(self):
        "Install new expired DS certificate"

        result = self.certinstall('d', 'ca1/server-expired')
        assert_error(result,
                     'The server certificate in server.p12 is not valid: '
                     "(SEC_ERROR_EXPIRED_CERTIFICATE) Peer's Certificate has "
                     'expired.')

    def test_http_bad_usage(self):
        "Install new HTTP certificate with invalid key usage"

        result = self.certinstall('w', 'ca1/server-badusage')
        assert_error(result,
                     'The server certificate in server.p12 is not valid: '
                     'invalid for a SSL server')

    def test_ds_bad_usage(self):
        "Install new DS certificate with invalid key usage"

        result = self.certinstall('d', 'ca1/server-badusage')
        assert_error(result,
                     'The server certificate in server.p12 is not valid: '
                     'invalid for a SSL server')

    def test_revoked_http(self):
        "Install new revoked HTTP certificate"

        result = self.certinstall('w', 'ca1/server-revoked')

        if result.returncode == 0:
            raise nose.SkipTest(
                "Known CA-less installation defect, see "
                + "https://fedorahosted.org/freeipa/ticket/4270")

        assert result.returncode > 0

    def test_revoked_ds(self):
        "Install new revoked DS certificate"

        result = self.certinstall('d', 'ca1/server-revoked')

        if result.returncode == 0:
            raise nose.SkipTest(
                "Known CA-less installation defect, see "
                + "https://fedorahosted.org/freeipa/ticket/4270")

        assert result.returncode > 0

    def test_http_intermediate_ca(self):
        "Install new HTTP certificate issued by intermediate CA"

        result = self.certinstall('w', 'ca1/subca/server')
        assert_error(result,
                     'server.p12 is not signed by /etc/ipa/ca.crt, or the '
                     'full certificate chain is not present in the PKCS#12 '
                     'file')

    def test_ds_intermediate_ca(self):
        "Install new DS certificate issued by intermediate CA"

        result = self.certinstall('d', 'ca1/subca/server')
        assert_error(result,
                     'server.p12 is not signed by /etc/ipa/ca.crt, or the '
                     'full certificate chain is not present in the PKCS#12 '
                     'file')

    def test_self_signed(self):
        "Install new self-signed certificate"

        result = self.certinstall('w', 'server-selfsign')
        assert_error(result,
                     'server.p12 is not signed by /etc/ipa/ca.crt, or the '
                     'full certificate chain is not present in the PKCS#12 '
                     'file')

    def test_valid_http(self):
        "Install new valid HTTP certificate"

        result = self.certinstall('w', 'ca1/server')
        assert result.returncode == 0

    def test_valid_ds(self):
        "Install new valid DS certificate"

        result = self.certinstall('d', 'ca1/server')
        assert result.returncode == 0

    def test_wildcard_http(self):
        "Install new wildcard HTTP certificate"

        result = self.certinstall('w', 'ca1/wildcard')
        assert result.returncode == 0

    def test_wildcard_ds(self):
        "Install new wildcard DS certificate"

        result = self.certinstall('d', 'ca1/wildcard')
        assert result.returncode == 0

    def test_http_san(self):
        "Install new HTTP certificate with SAN"

        result = self.certinstall('w', 'ca1/server-altname')
        assert result.returncode == 0

    def test_ds_san(self):
        "Install new DS certificate with SAN"

        result = self.certinstall('d', 'ca1/server-altname')
        assert result.returncode == 0

    def test_interactive_missing_http_pkcs_password(self):
        "Install new HTTP certificate with missing PKCS#12 password"

        result = self.certinstall('w', 'ca1/server',
                                  pin=None,
                                  stdin_text=self.cert_password + '\n')
        assert result.returncode == 0

    def test_interactive_missing_ds_pkcs_password(self):
        "Install new DS certificate with missing PKCS#12 password"

        result = self.certinstall('d', 'ca1/server',
                                  pin=None,
                                  stdin_text=self.cert_password + '\n')
        assert result.returncode == 0

    def test_no_http_password(self):
        "Install new HTTP certificate with no PKCS#12 password"

        result = self.certinstall('w', 'ca1/server', pin='', p12_pin='')
        assert result.returncode == 0

    def test_no_ds_password(self):
        "Install new DS certificate with no PKCS#12 password"

        result = self.certinstall('d', 'ca1/server', pin='', p12_pin='')
        assert result.returncode == 0

    def test_http_old_options(self):
        "Install new valid DS certificate using pre-v3.3 CLI options"
        # http://www.freeipa.org/page/V3/ipa-server-certinstall_CLI_cleanup

        args = ['ipa-server-certinstall',
                '-w', 'server.p12',
                '--http-pin', self.cert_password]

        result = self.certinstall('w', 'ca1/server', args=args)
        assert result.returncode == 0

    def test_ds_old_options(self):
        "Install new valid DS certificate using pre-v3.3 CLI options"
        # http://www.freeipa.org/page/V3/ipa-server-certinstall_CLI_cleanup

        args = ['ipa-server-certinstall',
                '-d', 'server.p12',
                '--dirsrv-pin', self.cert_password]
        stdin_text = self.master.config.dirman_password + '\n'

        result = self.certinstall('d', 'ca1/server',
                                  args=args, stdin_text=stdin_text)
        assert result.returncode == 0
