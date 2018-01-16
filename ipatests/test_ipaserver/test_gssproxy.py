import os
import time
import pytest
import shutil
import contextlib

from ipapython.ipautil import run

GSSPROXY_MAIN_CONF = '/etc/gssproxy/gssproxy.conf'
GSSPROXY_MAIN_CONF_BKP = GSSPROXY_MAIN_CONF + '.bkp'

GSSPROXY_NFS_CLIENT_TEST_SECTION = '''
[service/nfs-client]
  mechs = krb5
  cred_store = keytab:/etc/krb5.keytab
  cred_store = ccache:FILE:/var/lib/gssproxy/clients/krb5cc_%U
  cred_store = client_keytab:/var/lib/gssproxy/clients/%U.keytab
  cred_usage = initiate
  allow_any_uid = no
  trusted = yes
  euid = 0
'''

DUPLICATE_WARNING = 'Duplicate section detected in snippet:'

# to check journal logs only "since" we started our testcase
test_start = time.strftime('%H:%M:%S')


@contextlib.contextmanager
def restore_gss_proxy_conf():
    shutil.copy(GSSPROXY_MAIN_CONF, GSSPROXY_MAIN_CONF_BKP)
    try:
        yield
    finally:
            # restore original gssproxy conf
            os.rename(GSSPROXY_MAIN_CONF_BKP, GSSPROXY_MAIN_CONF)

            # make sure gssproxy is running fine for the other tests
            run(['systemctl', 'restart', 'gssproxy'])


@pytest.mark.skipif(
    os.getuid() != 0, reason=('we can restart gssproxy and change its config '
                              'only as root'))
def test_duplicate_sections():
    """ Related to the issue where ipa-server-install failed because gssproxy
    was not able to start due to a duplicated section"""

    with restore_gss_proxy_conf():
        with open(GSSPROXY_MAIN_CONF, 'a') as fd:
            fd.write(GSSPROXY_NFS_CLIENT_TEST_SECTION)

        # test if gssproxy is not failing due to a duplicated section
        result = run(['systemctl', 'restart', 'gssproxy'], raiseonerr=False)
        assert result.returncode == 0

        # check if there is the expected warning in the journal
        result = run(['journalctl', '-u', 'gssproxy', '--since', test_start],
                     raiseonerr=False)
        assert DUPLICATE_WARNING in result.output_log
