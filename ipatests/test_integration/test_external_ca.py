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

import synta
import synta.ext
import synta.oids

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipalib import x509 as ipa_x509
from ipaplatform.paths import paths
from ipapython.dn import DN

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
    match_CA_flag = re.compile(r'.*{}.*\s+C'.format(cn))
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


def install_server_external_ca_step1(host, extra_args=(), raiseonerr=True):
    """Step 1 to install the ipa server with external ca"""
    return tasks.install_master(
        host, external_ca=True, extra_args=extra_args, raiseonerr=raiseonerr,
    )


def install_server_external_ca_step2(host, ipa_ca_cert, root_ca_cert,
                                     extra_args=(),
                                     raiseonerr=True):
    """Step 2 to install the ipa server with external ca"""
    args = ['ipa-server-install', '-U', '-r', host.domain.realm,
            '-a', host.config.admin_password,
            '-p', host.config.dirman_password,
            '--external-cert-file', ipa_ca_cert,
            '--external-cert-file', root_ca_cert]
    args.extend(extra_args)
    cmd = host.run_command(args, raiseonerr=raiseonerr)
    return cmd


def check_ipaca_issuerDN(host, expected_dn):
    result = host.run_command(['ipa', 'ca-show', 'ipa'])
    assert "Issuer DN: {}".format(expected_dn) in result.stdout_text


def create_external_ca_with_subject(subject_attrs):
    """
    Create an external CA with custom subject attributes including non-standard
    OIDs.

    :param subject_attrs: List of (oid, value_str) tuples where oid is a
    synta.ObjectIdentifier (e.g. from synta.oids.attr) or a dotted-string OID
    :return: Tuple of (ExternalCA object, root CA certificate as PEM bytes)

    Example:
        subj_attrs = [
            (synta.oids.attr.COMMON_NAME, 'My CA'),
            (synta.oids.attr.COUNTRY, 'US'),
            (synta.oids.attr.ORG_IDENTIFIER, 'VATEU-123456789'),
        ]
        external_ca, root_ca_pem = create_external_ca_with_subject(subj_attrs)
        signed_cert = external_ca.sign_csr(csr_data)
    """
    external_ca = ExternalCA()
    external_ca.create_ca_key()

    nb = synta.NameBuilder()
    for oid, value_str in subject_attrs:
        nb = nb.add_attr(str(oid), value_str)
    name_der = nb.build()
    external_ca.issuer = name_der

    spki_der = external_ca.ca_public_key.to_der()
    ku_bits = synta.ext.KU_KEY_CERT_SIGN | synta.ext.KU_CRL_SIGN
    cert = (
        synta.CertificateBuilder()
        .subject_name(name_der)
        .issuer_name(name_der)
        .public_key(external_ca.ca_public_key)
        .serial_number(int.from_bytes(os.urandom(20), 'big'))
        .not_valid_before_utc(external_ca.now)
        .not_valid_after_utc(external_ca.now + external_ca.delta)
        .add_extension(synta.oids.KEY_USAGE, True,
                       synta.ext.key_usage(ku_bits))
        .add_extension(synta.oids.BASIC_CONSTRAINTS, True,
                       synta.ext.basic_constraints(ca=True))
        .add_extension(synta.oids.SUBJECT_KEY_IDENTIFIER, False,
                       synta.ext.subject_key_identifier(spki_der))
        .add_extension(synta.oids.AUTHORITY_KEY_IDENTIFIER, False,
                       synta.ext.authority_key_identifier(spki_der))
        .sign(external_ca.ca_key, "sha256")
    )
    return external_ca, cert.to_pem()


def find_cert_in_chain(cert_chain, subject_attrs=None, issuer_attrs=None):
    """
    Retrieves a certificate from a provided chain that matches specified
    criteria. The search can be filtered using dictionaries of subject
    attributes, issuer attributes, or a combination of both.

    :param cert_chain: List of IPACertificate objects to search through
    :param subject_attrs: Dict of {oid -> expected_value} for subject attrs,
        where oid is a synta.ObjectIdentifier or dotted-decimal OID string
    :param issuer_attrs: Dict of {oid -> expected_value} for issuer attrs
    :return: The matching certificate or None if not found

    Example:
        cert = find_cert_in_chain(
            ca_chain,
            subject_attrs={
                synta.oids.attr.COMMON_NAME: "Certificate Authority",
                synta.oids.attr.ORGANIZATION: "EXAMPLE.TEST"
            },
            issuer_attrs={
                synta.oids.attr.ORG_IDENTIFIER: "VATEU-123456789"
            }
        )
    """
    def _match(name_der, attrs):
        pairs = synta.parse_name_attrs(name_der)
        return all(
            any(o == str(oid) and v == val for o, v in pairs)
            for oid, val in attrs.items()
        )

    for cert in cert_chain:
        if subject_attrs and not _match(cert.subject, subject_attrs):
            continue
        if issuer_attrs and not _match(cert.issuer, issuer_attrs):
            continue
        return cert

    return None


def check_mscs_extension(ipa_csr, template):
    # Parse the CSR and locate the MSCS extension by walking the DER.
    # CSR structure: CertificationRequest { CertificationRequestInfo { ...
    #   attributes [0] IMPLICIT SET OF Attribute {
    #     Attribute { attrType OID, attrValues SET { Extensions } }
    #   }
    # }, signatureAlgorithm, signature }
    csr = synta.CertificationRequest.from_pem(ipa_csr)
    cr_dec = synta.Decoder(csr.to_der(), synta.Encoding.DER)
    cri_dec = cr_dec.decode_sequence()   # CertificationRequest
    cri_dec = cri_dec.decode_sequence()  # CertificationRequestInfo
    cri_dec.decode_integer()             # version
    cri_dec.decode_sequence()            # subject Name
    cri_dec.decode_sequence()            # subjectPublicKeyInfo

    ext_value_der = None
    if not cri_dec.is_empty():
        attrs_dec = cri_dec.decode_implicit_tag(0, "Context")
        while not attrs_dec.is_empty():
            attr_dec = attrs_dec.decode_sequence()
            attr_type = attr_dec.decode_oid()
            if str(attr_type) != str(synta.oids.PKCS9_EXTENSION_REQUEST):
                continue
            # attrValues SET { Extensions SEQUENCE OF Extension }
            vals_dec = attr_dec.decode_set()
            exts_dec = vals_dec.decode_sequence()
            while not exts_dec.is_empty():
                ext_seq = exts_dec.decode_sequence()
                ext_oid = ext_seq.decode_oid()
                if str(ext_oid) == template.ext_oid:
                    # optional critical BOOLEAN, then extnValue OCTET STRING
                    if not ext_seq.is_empty():
                        tag, _, _ = ext_seq.peek_tag()
                        if tag == 1:  # BOOLEAN
                            ext_seq.decode_boolean()
                    ext_value_der = ext_seq.decode_octet_string().to_bytes()
                    break
            if ext_value_der is not None:
                break

    assert ext_value_der is not None, \
        f"Extension {template.ext_oid} not found in CSR"
    assert ext_value_der == template.get_ext_data()


class TestExternalCA(IntegrationTest):
    """
    Test of FreeIPA server installation with external CA
    """
    num_replicas = 1
    num_clients = 1

    def test_external_ca(self):
        # Step 1 of ipa-server-install.
        result = install_server_external_ca_step1(
            self.master, extra_args=['--external-ca-type=ms-cs']
        )
        assert result.returncode == 0

        # check CSR for extension
        ipa_csr = self.master.get_file_contents(paths.ROOT_IPA_CSR)
        check_mscs_extension(ipa_csr, ipa_x509.MSCSTemplateV1(u'SubCA'))

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
        result = tasks.ldapsearch_dm(
            self.master,
            'cn=mapping tree,cn=config',
            ['(cn=replica)'],
        )
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


class TestExternalCAConstraints(IntegrationTest):
    """Test of FreeIPA server installation with external CA and constraints
    """
    num_replicas = 0
    num_clients = 1

    def test_external_ca_constrained(self):
        install_server_external_ca_step1(self.master)

        # name constraints for IPA DNS domain (dot prefix)
        nc_der = (
            synta.ext.NC()
            .permit_dns("." + self.master.domain.name)
            .build()
        )

        root_ca_fname, ipa_ca_fname = tasks.sign_ca_and_transport(
            self.master, paths.ROOT_IPA_CSR, ROOT_CA, IPA_CA,
            root_ca_extensions=[
                (synta.oids.NAME_CONSTRAINTS, True, nc_der),
            ],
        )

        install_server_external_ca_step2(
            self.master, ipa_ca_fname, root_ca_fname
        )

        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa', 'ping'])


class TestExternalCAInstallWithOrgId(IntegrationTest):
    """Test 2-step installation with external CA containing
    organizationIdentifier.

    This test verifies that FreeIPA can successfully install with a 2-step
    external CA process when the external CA certificate contains the
    organizationIdentifier attribute (OID 2.5.4.97) in its issuer DN.

    This tests the fix for DN parsing in ensure_ipa_authority_entry in
    cainstance.py where the issuer DN must be properly parsed against
    ATTR_NAME_BY_OID to recognize all OIDs including organizationIdentifier.
    """
    num_replicas = 0
    num_clients = 0

    def test_external_ca_install_with_organization_identifier(self):
        """Test 2-step installation with organizationIdentifier (OID 2.5.4.97)

        Verify that FreeIPA can successfully complete a 2-step installation
        with an external CA that contains organizationIdentifier (OID 2.5.4.97)
        in the issuer DN. The issuer DN should be properly parsed and stored
        in LDAP during the ensure_ipa_authority_entry process.
        """

        # Test parameters
        org_id_value = "VATEU-123456789"
        external_ca_cn = "External CA with OrgID"

        # Step 1 of ipa-server-install
        result = install_server_external_ca_step1(self.master)
        assert result.returncode == 0

        # Get the CSR generated by step 1
        ipa_csr = self.master.get_file_contents(paths.ROOT_IPA_CSR)

        # Create an external CA with organizationIdentifier in the subject
        subject_attrs = [
            (synta.oids.attr.COMMON_NAME, external_ca_cn),
            (synta.oids.attr.COUNTRY, 'US'),
            (synta.oids.attr.ORGANIZATION, 'Test Organization'),
            (synta.oids.attr.ORG_IDENTIFIER, org_id_value),
        ]
        external_ca, root_ca = create_external_ca_with_subject(subject_attrs)

        # Sign the IPA CSR with the external CA that has organizationIdentifier
        ipa_ca = external_ca.sign_csr(ipa_csr)

        # Write certificates to files
        root_ca_fname = os.path.join(
            self.master.config.test_dir,
            'root_ca_with_orgid.crt'
        )
        ipa_ca_fname = os.path.join(
            self.master.config.test_dir,
            'ipa_ca_signed_with_orgid.crt'
        )

        # Transport certificates to master
        self.master.put_file_contents(root_ca_fname, root_ca)
        self.master.put_file_contents(ipa_ca_fname, ipa_ca)

        # Step 2 of ipa-server-install
        # This should succeed despite organizationIdentifier in issuer DN
        result = install_server_external_ca_step2(
            self.master, ipa_ca_fname, root_ca_fname
        )
        assert result.returncode == 0

        # Make sure IPA server is working properly
        tasks.kinit_admin(self.master)
        result = self.master.run_command(['ipa', 'user-show', 'admin'])
        assert 'User login: admin' in result.stdout_text

        # Verify IPA is functional
        result = self.master.run_command(['ipa', 'ping'])
        assert result.returncode == 0

        # Verify the certificate chain contains the expected certificates
        # Load all certificates from /etc/ipa/ca.crt (the CA chain)
        ca_chain_content = self.master.get_file_contents(paths.IPA_CA_CRT)
        ca_chain = ipa_x509.load_certificate_list(ca_chain_content)

        # 1. Find and verify the IPA CA certificate
        # It should have subject O=REALM, CN=Certificate Authority
        # and issuer with organizationIdentifier
        ipa_ca_cert = find_cert_in_chain(
            ca_chain,
            subject_attrs={
                synta.oids.attr.COMMON_NAME: "Certificate Authority",
                synta.oids.attr.ORGANIZATION: self.master.domain.realm
            },
            issuer_attrs={
                synta.oids.attr.ORG_IDENTIFIER: org_id_value,
                synta.oids.attr.COMMON_NAME: external_ca_cn
            }
        )
        assert ipa_ca_cert is not None, \
            f"Did not find IPA CA certificate with subject " \
            f"O={self.master.domain.realm}, CN=Certificate Authority " \
            f"and issuer with organizationIdentifier={org_id_value}"

        # 2. Find and verify the external root CA certificate
        # It should be self-signed with organizationIdentifier in subject
        external_ca_cert = find_cert_in_chain(
            ca_chain,
            subject_attrs={
                synta.oids.attr.COMMON_NAME: external_ca_cn,
                synta.oids.attr.ORG_IDENTIFIER: org_id_value
            },
            issuer_attrs={
                synta.oids.attr.COMMON_NAME: external_ca_cn,
                synta.oids.attr.ORG_IDENTIFIER: org_id_value
            }
        )
        assert external_ca_cert is not None, \
            f"Did not find external root CA certificate (CN={external_ca_cn})" \
            f" with organizationIdentifier={org_id_value} in subject"

        # 3. Verify the issuer DN is correctly stored in LDAP
        # The issuer DN should contain organizationIdentifier
        # Note: The order in the DN string representation matters
        result = self.master.run_command(['ipa', 'ca-show', 'ipa'])
        assert f"organizationIdentifier={org_id_value}" in result.stdout_text, \
            "organizationIdentifier not found in IPA CA issuer DN"


def verify_caentry(host, cert):
    """
    Verify the content of cn=DOMAIN IPA CA,cn=certificates,cn=ipa,cn=etc,basedn
    and make sure that ipaConfigString contains the expected values.
    Verify the content of cn=cacert,cn=certificates,cn=ipa,cn=etc,basedn
    and make sure that it contains the expected certificate.
    """
    # Check the LDAP entry
    ldap = host.ldap_connect()
    # cn=DOMAIN IPA CA must contain ipaConfigString: ipaCa, compatCA
    ca_nick = '{} IPA CA'.format(host.domain.realm)
    entry = ldap.get_entry(DN(('cn', ca_nick), ('cn', 'certificates'),
                              ('cn', 'ipa'), ('cn', 'etc'),
                              host.domain.basedn))
    ipaconfigstring = [x.lower() for x in entry.get('ipaconfigstring')]
    expected = ['compatca', 'ipaca']
    assert expected == sorted(ipaconfigstring)

    # cn=cacert,cn=certificates,cn=etc,basedn must contain the latest
    # IPA CA
    entry2 = ldap.get_entry(DN(('cn', 'CACert'), ('cn', 'ipa'),
                               ('cn', 'etc'), host.domain.basedn))
    cert_from_ldap = entry2.single_value['cACertificate']
    assert cert == cert_from_ldap


class TestSelfExternalSelf(IntegrationTest):
    """
    Test self-signed > external CA > self-signed test case.
    """
    def test_install_master(self):
        result = tasks.install_master(self.master)
        assert result.returncode == 0

        # Check the content of the ldap entries for the CA
        remote_cacrt = self.master.get_file_contents(paths.IPA_CA_CRT)
        cacrt = ipa_x509.load_pem_x509_certificate(remote_cacrt)
        verify_caentry(self.master, cacrt)

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

        # Check that ldap entries for the CA have been updated
        remote_cacrt = self.master.get_file_contents(ipa_ca_fname)
        cacrt = ipa_x509.load_pem_x509_certificate(remote_cacrt)
        verify_caentry(self.master, cacrt)

    def test_issuerDN_after_renew_to_external(self):
        """ Check if issuer DN is updated after self-signed > external-ca

        This test checks if issuer DN is updated properly after CA is
        renewed from self-signed to external-ca
        """
        check_ipaca_issuerDN(self.master, "CN={}".format(ISSUER_CN))

    def test_switch_back_to_self_signed(self):

        # for journalctl --since
        switch_time = time.strftime('%Y-%m-%d %H:%M:%S')
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

    def test_issuerDN_after_renew_to_self_signed(self):
        """ Check if issuer DN is updated after external-ca > self-signed

        This test checks if issuer DN is updated properly after CA is
        renewed back from external-ca to self-signed
        """
        issuer_dn = 'CN=Certificate Authority,O={}'.format(
            self.master.domain.realm)
        check_ipaca_issuerDN(self.master, issuer_dn)


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
        tasks.service_control_dirsrv(self.master, 'stop')

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

    def test_external_ca_with_too_small_key(self):
        # reuse the existing deployment and renewal CSR
        root_ca_fname, ipa_ca_fname = tasks.sign_ca_and_transport(
            self.master, paths.IPA_CA_CSR, ROOT_CA, IPA_CA, key_size=1024)

        cmd = [
            paths.IPA_CACERT_MANAGE, 'renew',
            '--external-cert-file', ipa_ca_fname,
            '--external-cert-file', root_ca_fname,
        ]
        result = self.master.run_command(cmd, raiseonerr=False)
        assert result.returncode == 1


class TestExternalCAInvalidIntermediate(IntegrationTest):
    """Test case for https://pagure.io/freeipa/issue/7877"""

    def test_invalid_intermediate(self):
        install_server_external_ca_step1(self.master)
        root_ca_fname, ipa_ca_fname = tasks.sign_ca_and_transport(
            self.master, paths.ROOT_IPA_CSR, ROOT_CA, IPA_CA,
            root_ca_path_length=0
        )
        result = install_server_external_ca_step2(
            self.master, ipa_ca_fname, root_ca_fname, raiseonerr=False
        )
        assert result.returncode > 0
        assert "basic contraint pathlen" in result.stderr_text


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

    def test_renew_external_ca_with_organization_identifier(self):
        """Test CA renewal with organizationIdentifier (OID 2.5.4.97)

        Verify that FreeIPA can successfully renew CA with an external CA
        that contains organizationIdentifier (OID 2.5.4.97) in the issuer DN.
        The IPA CA will be signed by this external CA, and the issuer DN
        will contain the organizationIdentifier attribute.
        """

        # Test parameters
        org_id_value = "VATEU-123456789"
        external_ca_cn = "External CA with OrgID"

        # Initiate CA renewal with external CA
        result = self.master.run_command([paths.IPA_CACERT_MANAGE, 'renew',
                                         '--external-ca'])
        assert result.returncode == 0

        # Get the CSR generated by the renewal process
        ipa_csr = self.master.get_file_contents(paths.IPA_CA_CSR)

        # Create an external CA with organizationIdentifier in the subject
        subject_attrs = [
            (synta.oids.attr.COMMON_NAME, external_ca_cn),
            (synta.oids.attr.COUNTRY, 'US'),
            (synta.oids.attr.ORGANIZATION, 'Test Organization'),
            (synta.oids.attr.ORG_IDENTIFIER, org_id_value),
        ]
        external_ca, root_ca = create_external_ca_with_subject(subject_attrs)

        # Sign the IPA CSR with the external CA that has organizationIdentifier
        ipa_ca = external_ca.sign_csr(ipa_csr)

        # Write certificates to files
        root_ca_fname = os.path.join(
            self.master.config.test_dir,
            'root_ca_with_orgid.crt'
        )
        ipa_ca_fname = os.path.join(
            self.master.config.test_dir,
            'ipa_ca_signed_with_orgid.crt'
        )

        # Transport certificates to master
        self.master.put_file_contents(root_ca_fname, root_ca)
        self.master.put_file_contents(ipa_ca_fname, ipa_ca)

        # Complete the renewal with the signed certificates
        # This should succeed despite organizationIdentifier in issuer DN
        result = self.master.run_command([
            paths.IPA_CACERT_MANAGE, 'renew',
            '--external-cert-file', ipa_ca_fname,
            '--external-cert-file', root_ca_fname
        ])
        assert result.returncode == 0

        # Verify the CA was properly installed
        result = self.master.run_command([paths.IPA_CERTUPDATE])
        assert result.returncode == 0

        # Verify IPA is still functional
        tasks.kinit_admin(self.master)
        result = self.master.run_command(['ipa', 'ping'])
        assert result.returncode == 0

        # Verify the certificate chain contains the expected certificates
        # Load all certificates from /etc/ipa/ca.crt (the CA chain)
        ca_chain_content = self.master.get_file_contents(paths.IPA_CA_CRT)
        ca_chain = ipa_x509.load_certificate_list(ca_chain_content)

        # 1. Find and verify the IPA CA certificate
        # It should have subject O=REALM, CN=Certificate Authority
        # and issuer with organizationIdentifier
        ipa_ca_cert = find_cert_in_chain(
            ca_chain,
            subject_attrs={
                synta.oids.attr.COMMON_NAME: "Certificate Authority",
                synta.oids.attr.ORGANIZATION: self.master.domain.realm
            },
            issuer_attrs={
                synta.oids.attr.ORG_IDENTIFIER: org_id_value,
                synta.oids.attr.COMMON_NAME: external_ca_cn
            }
        )
        assert ipa_ca_cert is not None, \
            f"Did not find IPA CA certificate with subject " \
            f"O={self.master.domain.realm}, CN=Certificate Authority " \
            f"and issuer with organizationIdentifier={org_id_value}"

        # 2. Find and verify the external root CA certificate
        # It should be self-signed with organizationIdentifier in subject
        external_ca_cert = find_cert_in_chain(
            ca_chain,
            subject_attrs={
                synta.oids.attr.COMMON_NAME: external_ca_cn,
                synta.oids.attr.ORG_IDENTIFIER: org_id_value
            },
            issuer_attrs={
                synta.oids.attr.COMMON_NAME: external_ca_cn,
                synta.oids.attr.ORG_IDENTIFIER: org_id_value
            }
        )
        assert external_ca_cert is not None, \
            f"Did not find external root CA certificate (CN={external_ca_cn})"\
            f" with organizationIdentifier={org_id_value} in subject"


class TestMultipleExternalCA(IntegrationTest):
    """Setup externally signed ca1

    install ipa-server with externally signed ca1
    Setup externally signed ca2 and renew ipa-server with
    externally signed ca2 and check the difference in certificate
    """

    def test_master_install_ca1(self):
        install_server_external_ca_step1(self.master)
        # Sign CA, transport it to the host and get ipa a root ca paths.
        root_ca_fname1 = tasks.create_temp_file(
            self.master, directory=paths.TMP, suffix="root_ca.crt"
        )
        ipa_ca_fname1 = tasks.create_temp_file(
            self.master, directory=paths.TMP, suffix="ipa_ca.crt"
        )

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
        root_ca_fname2 = tasks.create_temp_file(
            self.master, directory=paths.TMP, suffix="root_ca.crt"
        )
        ipa_ca_fname2 = tasks.create_temp_file(
            self.master, directory=paths.TMP, suffix="ipa_ca.crt"
        )

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


def _step1_profile(master, s):
    return install_server_external_ca_step1(
        master,
        extra_args=['--external-ca-type=ms-cs', f'--external-ca-profile={s}'],
        raiseonerr=False,
    )


def _test_invalid_profile(master, profile):
    result = _step1_profile(master, profile)
    assert result.returncode != 0
    assert '--external-ca-profile' in result.stderr_text


def _test_valid_profile(master, profile_cls, profile):
    result = _step1_profile(master, profile)
    assert result.returncode == 0
    ipa_csr = master.get_file_contents(paths.ROOT_IPA_CSR)
    check_mscs_extension(ipa_csr, profile_cls(profile))


class TestExternalCAProfileScenarios(IntegrationTest):
    """
    Test the various --external-ca-profile scenarios.
    This test is broken into sections, with each section first
    testing invalid arguments, then a valid argument, and finally
    uninstalling the half-installed IPA.

    """

    '''
    Tranche 1: version 1 templates.

    Test that --external-ca-profile=Foo gets propagated to the CSR.

    The default template extension when --external-ca-type=ms-cs,
    a V1 extension with value "SubCA", already gets tested by the
    ``TestExternalCA`` class.

    We only need to do Step 1 of installation, then check the CSR.

    '''
    def test_invalid_v1_template(self):
        _test_invalid_profile(self.master, 'NotAnOid:1')

    def test_valid_v1_template(self):
        _test_valid_profile(
            self.master, ipa_x509.MSCSTemplateV1, 'TemplateOfAwesome')

    def test_uninstall_1(self):
        tasks.uninstall_master(self.master)

    '''
    Tranche 2: V2 templates without minor version.

    Test that V2 template specifiers without minor version get
    propagated to CSR.  This class also tests all error modes in
    specifying a V2 template, those being:

    - no major version specified
    - too many parts specified (i.e. major, minor, and then some more)
    - major version is not an int
    - major version is negative
    - minor version is not an int
    - minor version is negative

    We only need to do Step 1 of installation, then check the CSR.

    '''
    def test_v2_template_too_few_parts(self):
        _test_invalid_profile(self.master, '1.2.3.4')

    def test_v2_template_too_many_parts(self):
        _test_invalid_profile(self.master, '1.2.3.4:100:200:300')

    def test_v2_template_major_version_not_int(self):
        _test_invalid_profile(self.master, '1.2.3.4:wat:200')

    def test_v2_template_major_version_negative(self):
        _test_invalid_profile(self.master, '1.2.3.4:-1:200')

    def test_v2_template_minor_version_not_int(self):
        _test_invalid_profile(self.master, '1.2.3.4:100:wat')

    def test_v2_template_minor_version_negative(self):
        _test_invalid_profile(self.master, '1.2.3.4:100:-2')

    def test_v2_template_valid_major_only(self):
        _test_valid_profile(
            self.master, ipa_x509.MSCSTemplateV2, '1.2.3.4:100')

    def test_uninstall_2(self):
        tasks.uninstall_master(self.master)

    '''
    Tranche 3: V2 templates with minor version.

    Test that V2 template specifiers _with_ minor version get
    propagated to CSR.  All error modes of V2 template specifiers
    were tested in ``TestExternalCAProfileV2Major``.

    We only need to do Step 1 of installation, then check the CSR.

    '''
    def test_v2_template_valid_major_minor(self):
        _test_valid_profile(
            self.master, ipa_x509.MSCSTemplateV2, '1.2.3.4:100:200')

    # this is the end; no need to uninstall.
