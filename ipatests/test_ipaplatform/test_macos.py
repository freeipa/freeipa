# Copyright (C) 2026 FreeIPA Contributors see COPYING for license
"""Administration-only Darwin platform behavior."""

import os
import subprocess
import sys

import pytest


def test_darwin_platform_selection():
    # A subprocess exercises initial discovery and the real import hook without
    # changing the provider selected by the surrounding Linux test suite.
    env = os.environ.copy()
    env.pop('IPAPLATFORM_OVERRIDE', None)
    subprocess.run(
        [sys.executable, '-c', '''
import ctypes.util
import sys
# Preserve native library discovery on Linux before simulating Darwin.
sys.platform = 'darwin'
# Distribution builds may contain a generated provider override. Exercise
# automatic Darwin discovery independently of that packaging policy.
sys.modules['ipaplatform.override'] = None
from ipaplatform.osinfo import osinfo
from ipaplatform.constants import constants
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks
assert osinfo.id == 'macos'
assert osinfo.platform == 'macos'
assert not tasks.is_fips_enabled()
assert paths.IPA_CA_CRT == '/etc/ipa/ca.crt'
assert constants.IPAAPI_USER is not None
'''], env=env, check=True,
    )


def test_macos_rejects_service_management():
    from ipaplatform.macos.services import service

    with pytest.raises(NotImplementedError, match='macOS'):
        service('sssd')


@pytest.mark.parametrize('method,args', [
    ('set_hostname', ('client.ipa.test',)),
    ('add_user_to_group', ('test-user', 'test-group')),
    ('migrate_auth_configuration', (None,)),
    ('configure_httpd', (None, None, None, None)),
    ('restore_httpd', (None, None, None, None)),
    ('configure_dns_resolver', (None, None)),
    ('unconfigure_dns_resolver', (None,)),
    ('configure_nsswitch_database', (None, 'passwd', [])),
    ('disable_ldap_automount', (None,)),
])
def test_macos_rejects_host_configuration(method, args, monkeypatch):
    from ipaplatform.macos.tasks import tasks

    def reject_command(*args, **kwargs):
        pytest.fail("Unsupported host task attempted a local command")

    monkeypatch.setattr("ipapython.ipautil.run", reject_command)
    with pytest.raises(NotImplementedError):
        getattr(tasks, method)(*args)


@pytest.mark.skipif(sys.platform != 'darwin', reason='native macOS smoke test')
def test_macos_client_bootstrap(tmp_path):
    env = os.environ.copy()
    env.pop('IPA_CONFDIR', None)
    subprocess.run([sys.executable, '-c', '''
import sys
from ipalib import api
api.bootstrap(context='client', confdir=sys.argv[1],
              domain='ipa.test', realm='IPA.TEST', server='ipa.ipa.test',
              host='controller.ipa.test', in_server=False, in_tree=False,
              log=None)
assert api.env.context == 'client'
assert api.env.realm == 'IPA.TEST'
assert not api.env.in_server
''', str(tmp_path)], env=env, check=True)
