#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#
"""
Module provides tests for the ipa-winsync-migrate command.
"""
import os
import base64
import re

import pytest

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


def get_windows_certificate(ad_host):
    certs_path = '/cygdrive/c/Windows/System32/CertSrv/CertEnroll/'
    cert_filename = '%s_%s-%s-CA.crt' % (
        ad_host.hostname, ad_host.domain.name.split('.')[0],
        ad_host.shortname.upper())
    return ad_host.get_file_contents(os.path.join(certs_path, cert_filename))


def convert_crt_to_cer(data):
    header = b'-----BEGIN CERTIFICATE-----\n'
    trailer = b'-----END CERTIFICATE-----\n'
    return header + base64.encodebytes(data) + trailer


def establish_winsync_agreement(master, ad):
    win_cert = get_windows_certificate(ad)
    cert_path = master.run_command(['mktemp']).stdout_text.strip()
    master.put_file_contents(cert_path, convert_crt_to_cer(win_cert))
    master.run_command(['kdestroy', '-A'])
    master.run_command([
        'ipa-replica-manage', 'connect', '--winsync',
        '--binddn', 'cn=%s,cn=users,%s' % (ad.config.ad_admin_name,
                                           ad.domain.basedn),
        '--bindpw', ad.config.ad_admin_password,
        '--password', master.config.dirman_password,
        '--cacert', cert_path,
        '--passsync', 'dummy',
        ad.hostname, '-v'
    ])
    master.run_command(['rm', cert_path])


def ipa_output_fields(s):
    return [line.strip() for line in s.splitlines()]


class TestWinsyncMigrate(IntegrationTest):
    topology = 'star'
    num_ad_domains = 1

    ipa_group = 'ipa_group'
    ad_user = 'testuser'
    test_role = 'test_role'
    test_hbac_rule = 'test_hbac_rule'
    test_selinux_map = 'test_selinux_map'
    test_role_with_nonposix_chars = '$the test,role!'
    test_role_with_nonposix_chars_normalized = 'the_testrole'
    collision_role1 = 'collision role'
    collision_role2 = 'collision, role'
    collision_role3 = 'collision_role'
    collision_role_normalized = 'collision_role'

    @classmethod
    def install(cls, mh):
        super(TestWinsyncMigrate, cls).install(mh)

        cls.ad = cls.ads[0]  # pylint: disable=no-member
        cls.trust_test_user = '%s@%s' % (cls.ad_user, cls.ad.domain.name)
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.install_adtrust(cls.master)
        cls.create_test_objects()
        establish_winsync_agreement(cls.master, cls.ad)
        tasks.kinit_admin(cls.master)
        cls.setup_user_memberships(cls.ad_user)
        # store user uid and gid
        result = cls.master.run_command(['getent', 'passwd', cls.ad_user])
        testuser_regex = (
            r"^{0}:\*:(\d+):(\d+):{0}:/home/{0}:/bin/sh$".format(
                cls.ad_user))
        m = re.match(testuser_regex, result.stdout_text)
        cls.test_user_uid, cls.test_user_gid = m.groups()

    @classmethod
    def create_test_objects(cls):
        tasks.group_add(cls.master, cls.ipa_group)

        for role in [cls.test_role, cls.collision_role1, cls.collision_role2,
                     cls.collision_role3, cls.test_role_with_nonposix_chars]:
            cls.master.run_command(['ipa', 'role-add', role])

        cls.master.run_command(['ipa', 'hbacrule-add', cls.test_hbac_rule])
        cls.master.run_command([
            'ipa', 'selinuxusermap-add', cls.test_selinux_map,
            '--selinuxuser', 'guest_u:s0'])

    @classmethod
    def setup_user_memberships(cls, user):
        cls.master.run_command(['ipa', 'group-add-member', cls.ipa_group,
                                '--users', user])
        for role in [cls.test_role, cls.collision_role1, cls.collision_role2,
                     cls.collision_role3, cls.test_role_with_nonposix_chars]:
            cls.master.run_command(['ipa', 'role-add-member', role,
                                    '--users', user])
        cls.master.run_command(['ipa', 'hbacrule-add-user',
                                cls.test_hbac_rule, '--users', user])
        cls.master.run_command(['ipa', 'selinuxusermap-add-user',
                                cls.test_selinux_map, '--users', user])

    def check_replication_agreement_exists(self, server_name, should_exist):
        result = self.master.run_command(
            ['ipa-replica-manage', 'list', server_name])
        if should_exist:
            expected_message = '%s: winsync' % self.ad.hostname
        else:
            expected_message = ('Cannot find %s in public server list' %
                                server_name)
        assert result.stdout_text.strip() == expected_message

    def test_preconditions(self):
        self.check_replication_agreement_exists(self.ad.hostname, True)
        # check user exists at ipa server
        result = self.master.run_command(['ipa', 'user-show', self.ad_user],
                                         raiseonerr=False)
        assert result.returncode == 0

    def test_migration(self):
        tasks.establish_trust_with_ad(self.master, self.ad.domain.name)
        result = self.master.run_command([
            'ipa-winsync-migrate', '-U', '--realm', self.ad.domain.name,
            '--server', self.ad.hostname])
        assert ('The ipa-winsync-migrate command was successful'
                in result.stderr_text)
        tasks.clear_sssd_cache(self.master)

    def test_replication_agreement_deleted(self):
        self.check_replication_agreement_exists(self.ad.hostname, False)

    def test_user_deleted_from_ipa_server(self):
        result = self.master.run_command(['ipa', 'user-show', self.ad_user],
                                         raiseonerr=False)
        assert result.returncode == 2

    def test_user_attributes_preserved(self):
        result = self.master.run_command(['getent', 'passwd',
                                          self.trust_test_user])
        passwd_template = (
            '{trust_user}:*:{uid}:{gid}:{user}:/home/{domain}/{user}:/bin/sh')
        expected_result = passwd_template.format(
            user=self.ad_user, uid=self.test_user_uid, gid=self.test_user_gid,
            domain=self.ad.domain.name, trust_user=self.trust_test_user)
        assert result.stdout_text.strip() == expected_result

    def test_idoverride(self):
        result = self.master.run_command([
            'ipa', 'idoverrideuser-show', '--raw',
            'Default Trust View', self.trust_test_user])
        idoverride_fields = [line
                             for line in ipa_output_fields(result.stdout_text)
                             if 'ipaanchoruuid:' not in line]
        expected_fields = [
            'uid: %s' % self.ad_user,
            'uidnumber: %s' % self.test_user_uid,
            'gidnumber: %s' % self.test_user_gid,
            'gecos: %s' % self.ad_user,
            'loginshell: /bin/sh'

        ]
        assert sorted(idoverride_fields) == sorted(expected_fields)

    def test_groups_membership_preserved(self):
        result = self.master.run_command([
            'ipa', 'group-show', 'group_%s_winsync_external' % self.ipa_group])
        output_fields = ipa_output_fields(result.stdout_text)
        assert 'External member: %s' % self.trust_test_user in output_fields
        assert 'Member of groups: %s' % self.ipa_group in output_fields

    def test_role_membership_preserved(self):
        result = self.master.run_command([
            'ipa', 'group-show', 'role_%s_winsync_external' % self.test_role])
        output_fields = ipa_output_fields(result.stdout_text)
        assert 'External member: %s' % self.trust_test_user in output_fields
        assert 'Roles: %s' % self.test_role

    def test_selinuxusermap_membership_preserved(self):
        wrapper_group = 'selinux_%s_winsync_external' % self.test_selinux_map

        result = self.master.run_command(['ipa', 'selinuxusermap-show',
                                          self.test_selinux_map])
        assert ('User Groups: %s' % wrapper_group
                in ipa_output_fields(result.stdout_text))

        result = self.master.run_command(['ipa', 'group-show', wrapper_group])
        assert ('External member: %s' % self.trust_test_user
                in ipa_output_fields(result.stdout_text))

    def test_hbacrule_membership_preserved(self):
        result = self.master.run_command([
            'ipa', 'group-show',
            'hbacrule_%s_winsync_external' % self.test_hbac_rule])
        output_fields = ipa_output_fields(result.stdout_text)
        assert 'External member: %s' % self.trust_test_user in output_fields
        assert 'Member of HBAC rule: %s' % self.test_hbac_rule in output_fields

    def test_non_posix_chars_in_group_names_replaced(self):
        result = self.master.run_command([
            'ipa', 'role-show', self.test_role_with_nonposix_chars])
        expected_group_name = ('role_%s_winsync_external' %
                               self.test_role_with_nonposix_chars_normalized)
        assert ('Member groups: %s' % expected_group_name
                in ipa_output_fields(result.stdout_text))

    @pytest.mark.xfail(reason='BZ1698118', strict=True)
    def test_collisions_resolved(self):
        group = 'role_%s_winsync_external' % self.collision_role_normalized
        result = self.master.run_command(['ipa', 'group-show', group])
        output_fields = ipa_output_fields(result.stdout_text)
        assert 'Roles: %s' % self.collision_role1 in output_fields
        assert 'External member: %s' % self.trust_test_user in output_fields

        group = 'role_%s_winsync_external1' % self.collision_role_normalized
        result = self.master.run_command(['ipa', 'group-show', group])
        output_fields = ipa_output_fields(result.stdout_text)
        assert 'Roles: %s' % self.collision_role2 in output_fields
        assert 'External member: %s' % self.trust_test_user in output_fields

        group = 'role_%s_winsync_external2' % self.collision_role_normalized
        result = self.master.run_command(['ipa', 'group-show', group])
        output_fields = ipa_output_fields(result.stdout_text)
        assert 'Roles: %s' % self.collision_role3 in output_fields
        assert 'External member: %s' % self.trust_test_user in output_fields
