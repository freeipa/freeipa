#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""Unit tests of the AD host classes of the integration test harness.

Active Directory operations of the tests are methods of the AD host, so that
the same test runs against Windows (PowerShell, dnscmd) or Samba AD
(samba-tool, ldb tools); `host_type: samba` in the test configuration
selects Samba. These tests do not need any host.
"""
import os
import shutil
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from ipatests.pytest_ipa.integration import config
import ipatests.pytest_ipa.integration.host as host_module
from ipatests.pytest_ipa.integration.host import SambaADHost, WinHost


@pytest.fixture(autouse=True)
def no_resolver_setup():
    # creating an IPA host would ssh to it to learn about its resolver
    with patch.object(host_module, 'resolver', MagicMock()):
        yield


def make_config(ad_host_type=None):
    ad_host = dict(name='dc', ip='192.0.2.10', role='ad')
    if ad_host_type:
        ad_host['host_type'] = ad_host_type
    return config.Config.from_dict(dict(
        ssh_username='root',
        domains=[
            dict(name='ipa.test', type='IPA',
                 hosts=[dict(name='master', ip='192.0.2.1')]),
            dict(name='ad.test', type='AD', hosts=[ad_host]),
        ]))


class Recorder:
    """Stand-in for run_command: remember the commands, answer from a map"""

    def __init__(self, answers=None):
        self.calls = []
        self.answers = answers or {}

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        out = next((v for k, v in self.answers.items() if k in argv), '')
        return type('Result', (), {'stdout_text': out, 'returncode': 0})()

    @property
    def argvs(self):
        return [argv for argv, _kwargs in self.calls]


def ad_host(host_type=None):
    return make_config(host_type).domains[1].hosts[0]


def test_ad_host_is_windows_unless_the_configuration_says_samba():
    assert type(ad_host()) is WinHost
    assert type(ad_host('samba')) is SambaADHost
    assert ad_host().ad_flavor == 'windows'
    assert ad_host('samba').ad_flavor == 'samba'


def test_the_ipa_host_is_not_affected_by_host_type():
    master = make_config('samba').domains[0].hosts[0]
    assert not hasattr(master, 'ad_flavor')


def test_windows_forwarder_is_a_dnscmd_zone():
    host = ad_host()
    rec = Recorder()
    with patch.object(WinHost, 'run_command', rec):
        host.dns_forwarder_add('ipa.test', '192.0.2.1')
        host.dns_forwarder_del('ipa.test')
    assert rec.argvs == [
        ['dnscmd', '/zoneadd', 'ipa.test', '/Forwarder', '192.0.2.1'],
        ['dnscmd', '/zonedelete', 'ipa.test', '/f'],
    ]


def test_windows_group_membership_asks_powershell():
    host = ad_host()
    rec = Recorder({'powershell': 'SamAccountName : testuser\n'})
    with patch.object(WinHost, 'run_command', rec):
        assert host.group_has_member('grp', 'testuser')
    argv = rec.argvs[0]
    assert argv[:2] == ['powershell', '-c']
    assert 'Get-ADGroupMember -Identity "grp"' in argv[2]
    assert rec.calls[0][1]['set_env'] is False

    # a listing of other members is not a membership
    rec = Recorder({'powershell': 'SamAccountName : someoneelse\n'
                                  'SamAccountName : testuser2\n'})
    with patch.object(WinHost, 'run_command', rec):
        assert host.group_has_member('grp', 'testuser') is False
    rec = Recorder({'powershell': '  \n'})
    with patch.object(WinHost, 'run_command', rec):
        assert host.group_has_member('grp', 'testuser') is False


def test_windows_password_policy_keeps_run_command_options():
    host = ad_host()
    rec = Recorder()
    with patch.object(WinHost, 'run_command', rec):
        host.password_min_age_set(1, raiseonerr=False)
    argv, kwargs = rec.calls[0]
    assert '-MinPasswordAge 1.00:00:00' in argv[2]
    assert kwargs['raiseonerr'] is False


def test_samba_group_membership_is_case_insensitive():
    host = ad_host('samba')
    rec = Recorder({'listmembers': 'Administrator\nTestUser\n'})
    with patch.object(SambaADHost, 'run_command', rec):
        assert host.group_has_member('grp', 'testuser')
        assert not host.group_has_member('grp', 'other')
    assert rec.argvs[0] == ['samba-tool', 'group', 'listmembers', 'grp']


def test_samba_upn_suffix_is_an_ldb_modification():
    host = ad_host('samba')
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs.get('stdin_text')))
        return type('R', (), {'stdout_text': '', 'returncode': 0})()

    with patch.object(SambaADHost, 'run_command', side_effect=run):
        host.upn_suffix_add('sub.ad.test')
        host.upn_suffix_del('sub.ad.test')
    argv, ldif = calls[0]
    ldif_del = calls[1][1]
    assert argv[:3] == ['ldbmodify', '-H', host.sam_ldb]
    assert ('dn: CN=Partitions,CN=Configuration,DC=ad,DC=test\n'
            in ldif)
    # the value is base64 (an LDIF value cannot start a second record)
    value = host_module._ldif_line('uPNSuffixes', 'sub.ad.test')
    assert 'add: uPNSuffixes\n' + value in ldif
    assert 'delete: uPNSuffixes\n' + value in ldif_del


def test_samba_user_upn_finds_the_user_dn_first():
    host = ad_host('samba')
    answers = {'ldbsearch': 'dn: CN=Test User,CN=Users,DC=ad,DC=test\n'}
    rec = Recorder(answers)
    with patch.object(SambaADHost, 'run_command', rec):
        host.user_set_upn('testuser', 'testuser@sub.ad.test')
    search, modify = rec.calls[0], rec.calls[1]
    assert '(sAMAccountName=testuser)' in search[0]
    ldif = modify[1]['stdin_text']
    assert host_module._ldif_line(
        'dn', 'CN=Test User,CN=Users,DC=ad,DC=test') in ldif
    assert host_module._ldif_line(
        'userPrincipalName', 'testuser@sub.ad.test') in ldif


def test_samba_user_upn_of_an_unknown_user_is_an_error():
    host = ad_host('samba')
    with patch.object(SambaADHost, 'run_command', Recorder()):
        with pytest.raises(ValueError, match='no user nobody'):
            host.user_set_upn('nobody', 'nobody@ad.test')


def test_samba_shared_secret_trust_reads_the_remote_from_the_config():
    host = ad_host('samba')
    rec = Recorder({'list': 'Type[Forest] Direction[INCOMING] Name[ipa.test]'})
    with patch.object(SambaADHost, 'run_command', rec):
        host.trust_local_side_create('ipa.test', 's3cret')
    create, kwargs = rec.calls[0]
    assert 'samba-tool' in create and create[create.index('create') - 1] \
        == 'trust'
    assert 'ipa.test' in create
    assert '--ipaddress=192.0.2.1' in create
    assert 'IPA\\admin' in create
    assert '--create-location=local' in create
    # no password is an argument of a process: they go in on stdin, the
    # administrator's first (read into PASSWD), then the trust secret twice
    assert kwargs['stdin_text'] == 'Secret123\ns3cret\ns3cret\n'
    assert not any(p in a for a in create for p in ('s3cret', 'Secret123'))
    # samba-tool exits non-zero while the other side is missing
    assert kwargs['raiseonerr'] is False


def test_samba_trust_that_was_not_created_is_an_error():
    host = ad_host('samba')
    with patch.object(SambaADHost, 'run_command', Recorder({'list': ''})):
        with pytest.raises(AssertionError, match='did not create the trust'):
            host.trust_local_side_create('ipa.test', 's3cret')


def test_samba_trust_of_another_domain_is_not_the_trust_that_was_asked():
    host = ad_host('samba')
    listing = 'Type[Forest] Direction[INCOMING] Name[sub.ipa.test.example]'
    with patch.object(SambaADHost, 'run_command', Recorder({'list': listing})):
        with pytest.raises(AssertionError, match='did not create the trust'):
            host.trust_local_side_create('ipa.test', 's3cret')


def test_samba_password_reset_is_not_in_the_arguments():
    host = ad_host('samba')
    rec = Recorder()
    with patch.object(SambaADHost, 'run_command', rec):
        host.user_reset_password('testuser', 'Pa55w0rd!', raiseonerr=False)
    argv, kwargs = rec.calls[0]
    assert argv == ['samba-tool', 'user', 'setpassword', 'testuser']
    assert kwargs['stdin_text'] == 'Pa55w0rd!\nPa55w0rd!\n'
    assert kwargs['raiseonerr'] is False


def test_samba_forwarder_is_an_argument_not_part_of_the_script():
    host = ad_host('samba')
    rec = Recorder()
    with patch.object(SambaADHost, 'run_command', rec):
        host.dns_forwarder_add('ipa.test', '192.0.2.1')
    argv = rec.argvs[0]
    assert argv[:2] == ['sh', '-c'] and argv[-1] == '192.0.2.1'
    assert '192.0.2.1' not in argv[2]


@pytest.mark.parametrize('bad', ['1.2.3.4; reboot', '$(id)', 'a b', '',
                                 '192.0.2.1\nsh'])
def test_samba_forwarder_that_is_not_an_address_is_refused(bad):
    host = ad_host('samba')
    rec = Recorder()
    with patch.object(SambaADHost, 'run_command', rec):
        with pytest.raises(ValueError):
            host.dns_forwarder_add('ipa.test', bad)
    assert not rec.calls


@pytest.mark.skipif(not (shutil.which('sh') and shutil.which('awk')),
                    reason='sh and awk needed')
@pytest.mark.parametrize('before', [
    '[global]\n\tdns forwarder = 10.0.2.3\n\trealm = X\n',
    '[global]\n\trealm = X\n',               # no forwarder yet
])
def test_samba_forwarder_scripts_set_it_and_put_back_what_was_there(
        tmp_path, before):
    conf = tmp_path / 'smb.conf'
    conf.write_text(before)
    systemctl = tmp_path / 'systemctl'
    systemctl.write_text('#!/bin/sh\nexit 0\n')
    systemctl.chmod(0o755)
    env = dict(os.environ, PATH='{}:{}'.format(tmp_path, os.environ['PATH']))

    def sh(script, *args):
        subprocess.run(
            ['sh', '-c', script.replace(host_module._SMB_CONF, str(conf)),
             'sh', *args], env=env, check=True)

    sh(host_module._FORWARDER_ADD, '192.0.2.7')
    assert '\tdns forwarder = 192.0.2.7\n' in conf.read_text()
    # a second add must not take the first one's value for the original
    sh(host_module._FORWARDER_ADD, '192.0.2.8')
    text = conf.read_text()
    assert text.count('dns forwarder') == 1 and '192.0.2.8' in text
    sh(host_module._FORWARDER_DEL)
    assert conf.read_text() == before
    sh(host_module._FORWARDER_DEL)          # nothing to put back: no change
    assert conf.read_text() == before


def test_a_line_break_in_an_ldif_value_is_refused_not_a_second_record():
    host = ad_host('samba')
    rec = Recorder()
    with patch.object(SambaADHost, 'run_command', rec):
        with pytest.raises(ValueError, match='line breaks'):
            host.upn_suffix_add('x.test\n\ndn: CN=other\nchangetype: delete')
        with pytest.raises(ValueError, match='line breaks'):
            host.user_set_upn('testuser', 'a@x\r\nreplace: member')
    assert not rec.calls


def test_ldif_values_are_base64_and_come_back_the_same():
    value = 'sub.\u00e4d.test'
    line = host_module._ldif_line('uPNSuffixes', value)
    assert line.startswith('uPNSuffixes:: ')
    assert host_module._ldif_values(line, 'uPNSuffixes') == [value]
    # a plain value of ldbsearch output is read as it is
    assert host_module._ldif_values('uPNSuffixes: a.test\n',
                                    'uPNSuffixes') == ['a.test']


def test_host_type_goes_through_the_environment_variables():
    from ipatests.pytest_ipa.integration import env_config
    cfg = make_config('samba')
    env = env_config.config_to_env(cfg)
    assert env['BEAKERAD1_TYPE_env2'] == 'samba'
    assert 'BEAKERMASTER1_TYPE_env1' not in env      # a default host: none
    back = env_config.config_from_env(env)
    assert type(back.domains[1].hosts[0]) is SambaADHost
    assert type(back.domains[0].hosts[0]) is not SambaADHost


@pytest.mark.parametrize('external, kind', [(False, 'forest'),
                                            (True, 'external')])
def test_samba_trust_has_the_type_of_the_ipa_side(external, kind):
    host = ad_host('samba')
    rec = Recorder({'list': 'Type[Forest] Direction[INCOMING] Name[ipa.test]'})
    with patch.object(SambaADHost, 'run_command', rec):
        host.trust_local_side_create('ipa.test', 's3cret', external=external)
    assert '--type=' + kind in rec.calls[0][0]
