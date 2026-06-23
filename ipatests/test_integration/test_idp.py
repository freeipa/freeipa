from __future__ import absolute_import

import time
import pytest
import re

import textwrap
from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks, create_keycloak

# OAuth device flow: Keycloak prints "Authenticate at {url} ..."; Microsoft
# Entra prints "Authenticate with PIN {user_code} at {url} ..." and the user
# must submit {user_code} on the device login page before signing in.
DEVICE_AUTH_PROMPT_RE = re.compile(
    r'Authenticate(?:\s+with\s+PIN\s+(\S+))?'
    r'\s+at\s+(.+?)\s+and\s+press\s+ENTER\.:',
    re.DOTALL,
)


def selenium_remote_finally(shot_path):
    """Return try/finally tail for remote Selenium scripts."""
    return textwrap.dedent(
        """
        finally:
            now = datetime.now().strftime("%M-%S")
            driver.get_screenshot_as_file({path} % now)
            driver.quit()
        """
    ).strip().format(path=repr(shot_path))


SELENIUM_REMOTE_HEAD = textwrap.dedent(
    """
    from selenium import webdriver
    from datetime import datetime
    from packaging.version import parse as parse_version
    from selenium.webdriver.firefox.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    import time
    options = Options()
    if parse_version(webdriver.__version__) < parse_version('4.10.0'):
        options.headless = True
        driver = webdriver.Firefox(
            executable_path="/opt/geckodriver", options=options)
    else:
        options.add_argument('-headless')
        service = webdriver.FirefoxService(
            executable_path="/opt/geckodriver")
        driver = webdriver.Firefox(options=options, service=service)

    """
).strip() + "\n\n"


KEYCLOCK_USER_CODE_BODY = textwrap.dedent(
    """
    verification_uri = "{uri}"
    driver.get(verification_uri)
    try:
        element = WebDriverWait(driver, 90).until(
            EC.presence_of_element_located((By.ID, "username")))
        driver.find_element(By.ID, "username").send_keys("testuser1")
        driver.find_element(By.ID, "password").send_keys("{passwd}")
        driver.find_element(By.ID, "kc-login").click()
        element = WebDriverWait(driver, 90).until(
            EC.presence_of_element_located((By.ID, "kc-login")))
        driver.find_element(By.ID, "kc-login").click()
        assert "Device Login Successful" in driver.page_source
    """
).strip()

keyclock_user_code_script = (
    SELENIUM_REMOTE_HEAD
    + KEYCLOCK_USER_CODE_BODY
    + "\n"
    + selenium_remote_finally("/var/log/httpd/screenshot-keyclock-%s.png")
)


AZUREUSER_CODE_BODY = textwrap.dedent(
    """
    DEVICE_USER_CODE = {device_user_code!r}
    verification_uri = "{uri}"
    driver.get(verification_uri)
    try:
        # Click through the device code confirmation page if present
        try:
            btn = WebDriverWait(driver, 15).until(
                EC.element_to_be_clickable((By.ID, "idSIButton9")))
            btn.click()
        except Exception:
            pass
        # Entra: submit user code on "Enter code to allow access" first
        if DEVICE_USER_CODE:
            def _find_code_input(d):
                selectors = [
                    (By.NAME, "otc"),
                    (By.ID, "otc"),
                    (By.CSS_SELECTOR, "input[name='otc']"),
                    (By.CSS_SELECTOR, "input[formcontrolname='otc']"),
                    (By.CSS_SELECTOR, "input[aria-label*='Code']"),
                    (By.CSS_SELECTOR, "input[aria-label*='code']"),
                    (By.CSS_SELECTOR, "input[placeholder*='Code']"),
                    (By.CSS_SELECTOR, "input[placeholder*='code']"),
                ]
                last_exc = None
                for by, sel in selectors:
                    try:
                        return WebDriverWait(d, 10).until(
                            EC.element_to_be_clickable((by, sel)))
                    except Exception as exc:
                        last_exc = exc
                        continue
                raise last_exc

            code_el = _find_code_input(driver)
            code_el.clear()
            code_el.send_keys(DEVICE_USER_CODE)
            time.sleep(0.5)
            next_btn = WebDriverWait(driver, 15).until(
                EC.element_to_be_clickable((By.ID, "idSIButton9")))
            next_btn.click()
            time.sleep(2)
        # Enter email/username on Microsoft login page
        element = WebDriverWait(driver, 90).until(
            EC.presence_of_element_located((By.NAME, "loginfmt")))
        driver.find_element(By.NAME, "loginfmt").send_keys("{username}")
        driver.find_element(By.ID, "idSIButton9").click()
        # Enter password
        element = WebDriverWait(driver, 90).until(
            EC.element_to_be_clickable((By.NAME, "passwd")))
        driver.find_element(By.NAME, "passwd").send_keys("{password}")
        driver.find_element(By.ID, "idSIButton9").click()
        # Handle remaining prompts (consent / stay signed in)
        for _ in range(3):
            try:
                btn = WebDriverWait(driver, 15).until(
                    EC.element_to_be_clickable((By.ID, "idSIButton9")))
                btn.click()
                time.sleep(2)
            except Exception:
                break
        time.sleep(5)
    """
).strip()

azure_user_code_script = (
    SELENIUM_REMOTE_HEAD
    + AZUREUSER_CODE_BODY
    + "\n"
    + selenium_remote_finally("/var/log/httpd/screenshot-azure-%s.png")
)


class TestIDP(IntegrationTest):
    """Common IdP integration test setup and helpers."""

    num_replicas = 2
    topology = 'line'

    @classmethod
    def install(cls, mh):
        cls.client = cls.replicas[0]
        cls.replica = cls.replicas[1]
        tasks.install_master(cls.master, extra_args=['--no-dnssec-validation'])
        tasks.install_client(cls.master, cls.replicas[0],
                             extra_args=["--mkhomedir"])
        tasks.install_replica(cls.master, cls.replicas[1])
        for host in [cls.master, cls.replicas[0], cls.replicas[1]]:
            content = host.get_file_contents(paths.IPA_DEFAULT_CONF,
                                             encoding='utf-8')
            new_content = content + "\noidc_child_debug_level = 10"
            host.put_file_contents(paths.IPA_DEFAULT_CONF, new_content)
        with tasks.remote_sssd_config(cls.master) as sssd_config:
            sssd_config.edit_domain(
                cls.master.domain, 'krb5_auth_timeout', 1100)
        tasks.clear_sssd_cache(cls.master)
        tasks.clear_sssd_cache(cls.replicas[0])
        tasks.kinit_admin(cls.master)
        cls.master.run_command(["ipa", "config-mod", "--user-auth-type=idp",
                                "--user-auth-type=password"])
        xvfb = ("nohup /usr/bin/Xvfb :99 -ac -noreset -screen 0 1400x1200x8 "
                "</dev/null &>/dev/null &")
        cls.replicas[0].run_command(xvfb)

    @staticmethod
    def parse_device_auth_prompt(prompt):
        match = DEVICE_AUTH_PROMPT_RE.search(prompt)
        assert match is not None, prompt
        user_code = match.group(1)
        uri = match.group(2).strip()
        if user_code is not None:
            user_code = user_code.strip()
        return uri, user_code

    @staticmethod
    def run_remote_selenium(host, script, remote_basename, timeout=30):
        path = "/tmp/%s" % remote_basename
        try:
            host.put_file_contents(path, script)
            tasks.run_repeatedly(host, ["python3", path], timeout=timeout)
        finally:
            host.run_command(["rm", "-f", path])

    @staticmethod
    def kinit_idp_device_flow(host, user, complete_device_auth):
        """
        kinit for users with --user-auth-type=idp: complete OAuth2 device
        code flow in a browser via ``complete_device_auth(uri, user_code)``.
        """
        armor = "/tmp/armor"
        tasks.kdestroy_all(host)
        host.run_command(["kinit", "-n", "-c", armor])
        cmd = ["kinit", "-T", armor, user]

        with host.spawn_expect(cmd, default_timeout=100) as e:
            e.expect(DEVICE_AUTH_PROMPT_RE)
            prompt = e.get_last_output()
            uri, device_user_code = TestIDP.parse_device_auth_prompt(prompt)
            time.sleep(15)
            if uri:
                complete_device_auth(uri, device_user_code)
            e.sendline('\n')
            e.expect_exit()

        test_idp = host.run_command(["klist", "-C"])
        assert "152" in test_idp.stdout_text


class TestIDPKeycloak(TestIDP):
    """Keycloak IdP integration tests."""

    KEYCLOAK_IDP_NAME = "keycloakidp"
    KEYCLOAK_USER = "keycloakuser"
    KEYCLOAK_IDP_USER_ID = "testuser1@ipa.test"
    BACKUP_RESTORE_USER = "backupmultiuser"
    # (cn, provider, extra ipa CLI args, substring expected in idp-show)
    BUILTIN_IDP_PROVIDER_SPECS = (
        ("idp-google", "google", [], "googleapis.com"),
        ("idp-github", "github", [], "github.com"),
        (
            "idp-microsoft", "microsoft",
            ["--organization", "00000000-0000-0000-0000-000000000001"],
            "microsoftonline.com",
        ),
        (
            "idp-okta", "okta",
            ["--org", "testorg", "--base-url", "dev-12345.okta.com"],
            "okta.com",
        ),
    )

    @staticmethod
    def add_keycloak_user_code(host, verification_uri):
        contents = keyclock_user_code_script.format(
            uri=verification_uri,
            passwd=host.config.admin_password,
        )
        TestIDP.run_remote_selenium(
            host, contents, "add_keycloak_user_code.py")

    @staticmethod
    def kinit_idp_keycloak(host, user, keycloak_server):
        """kinit via Keycloak device authorization flow."""
        def complete(uri, _device_user_code):
            TestIDPKeycloak.add_keycloak_user_code(keycloak_server, uri)

        TestIDP.kinit_idp_device_flow(host, user, complete)

    def secret_stdin(self):
        secret = self.client.config.admin_password
        return "%s\n%s\n" % (secret, secret)

    def _add_builtin_provider_idp(self, cn, provider, extra_cli_args=None):
        cmd = [
            "ipa", "idp-add", cn,
            "--provider", provider,
            "--client-id", "idp-backup-restore-client",
        ]
        if extra_cli_args:
            cmd.extend(extra_cli_args)
        self.master.run_command(cmd, stdin_text=self.secret_stdin())

    def test_auth_keycloak_idp(self):
        """
        Test case to check that OAuth 2.0 Device
        Authorization Grant is working as
        expected for user configured with external idp.
        """
        create_keycloak.setup_keycloakserver(self.client)
        time.sleep(60)
        create_keycloak.setup_keycloak_client(self.client)
        tasks.kinit_admin(self.master)
        cmd = ["ipa", "idp-add", self.KEYCLOAK_IDP_NAME,
               "--provider=keycloak",
               "--client-id=ipa_oidc_client", "--org=master",
               "--base-url={0}:8443".format(self.client.hostname)]
        self.master.run_command(cmd, stdin_text="{0}\n{0}".format(
            self.client.config.admin_password))
        tasks.user_add(
            self.master, self.KEYCLOAK_USER,
            extra_args=["--user-auth-type=idp",
                        "--idp-user-id=" + self.KEYCLOAK_IDP_USER_ID,
                        "--idp=" + self.KEYCLOAK_IDP_NAME]
        )
        list_user = self.master.run_command(
            ["ipa", "user-find",
             "--idp-user-id=" + self.KEYCLOAK_IDP_USER_ID]
        )
        assert self.KEYCLOAK_USER in list_user.stdout_text
        list_by_idp = self.master.run_command(
            ["ipa", "user-find", "--idp=" + self.KEYCLOAK_IDP_NAME])
        assert self.KEYCLOAK_USER in list_by_idp.stdout_text
        list_by_user = self.master.run_command(
            ["ipa", "user-find",
             "--idp-user-id=" + self.KEYCLOAK_IDP_USER_ID, "--all"]
        )
        assert self.KEYCLOAK_IDP_NAME in list_by_user.stdout_text
        tasks.clear_sssd_cache(self.master)
        self.kinit_idp_keycloak(self.master, self.KEYCLOAK_USER,
                                keycloak_server=self.client)

    def test_idp_login_with_expired_password(self):
        """
        Password expiration must not block passwordless authentication.

        The KDC checks pw_expiration before pre-authentication runs, so
        when a passwordless method is available the IPA KDB plugin clears
        pw_expiration to let the request through.  The kdcpolicy plugin
        then enforces expiration only when a password-based method was
        actually used.

        This test verifies four scenarios:
        1. IdP-only user with expired password   -> IdP kinit succeeds
        2. IdP+password user with expired password -> IdP kinit succeeds
        3. IdP+password user with expired password -> password kinit fails
        4. Password-only user with expired password -> password kinit fails

        Related: https://pagure.io/freeipa/issue/XXXX
        """
        PAST_EXPIRATION = "20200101000000Z"
        pwuser = "pwexpireuser"
        pwuser_password = "Secret123"

        tasks.kinit_admin(self.master)
        try:
            # Give the IdP user a password so we can test password kinit
            # later when both auth types are enabled.
            self.master.run_command(
                ["ipa", "passwd", self.KEYCLOAK_USER],
                stdin_text="{0}\n{0}\n".format(pwuser_password),
            )

            # Expire the IdP user's password
            self.master.run_command([
                "ipa", "user-mod", self.KEYCLOAK_USER,
                "--password-expiration", PAST_EXPIRATION,
            ])

            # --- Scenario 1: IdP-only, expired password, IdP kinit ---
            tasks.clear_sssd_cache(self.master)
            self.kinit_idp_keycloak(
                self.master, self.KEYCLOAK_USER,
                keycloak_server=self.client,
            )

            # --- Scenario 2 & 3: IdP+password, expired password ---
            tasks.kinit_admin(self.master)
            self.master.run_command([
                "ipa", "user-mod", self.KEYCLOAK_USER,
                "--user-auth-type=idp", "--user-auth-type=password",
            ])
            tasks.clear_sssd_cache(self.master)

            # Scenario 2: IdP kinit must still succeed
            self.kinit_idp_keycloak(
                self.master, self.KEYCLOAK_USER,
                keycloak_server=self.client,
            )

            # Scenario 3: password kinit must fail
            tasks.kdestroy_all(self.master)
            result = tasks.kinit_as_user(
                self.master, self.KEYCLOAK_USER, pwuser_password,
                raiseonerr=False,
            )
            assert result.returncode != 0, (
                "kinit should fail for idp+password user authenticating "
                "with expired password"
            )

            # --- Scenario 4: password-only user, expired password ---
            tasks.kinit_admin(self.master)
            tasks.user_add(
                self.master, pwuser, password=pwuser_password,
                extra_args=["--user-auth-type=password"],
            )
            self.master.run_command([
                "ipa", "user-mod", pwuser,
                "--password-expiration", PAST_EXPIRATION,
            ])
            tasks.kdestroy_all(self.master)
            tasks.clear_sssd_cache(self.master)

            result = tasks.kinit_as_user(
                self.master, pwuser, pwuser_password,
                raiseonerr=False,
            )
            assert result.returncode != 0, (
                "kinit should fail for password-only user with expired "
                "password"
            )
        finally:
            tasks.kdestroy_all(self.master)
            tasks.kinit_admin(self.master)
            # Restore KEYCLOAK_USER to idp-only with no expiration
            self.master.run_command([
                "ipa", "user-mod", self.KEYCLOAK_USER,
                "--user-auth-type=idp",
            ], raiseonerr=False)
            self.master.run_command([
                "ipa", "user-mod", self.KEYCLOAK_USER,
                "--password-expiration", "29991231235959Z",
            ], raiseonerr=False)
            tasks.user_del(self.master, pwuser, raiseonerr=False)
            tasks.clear_sssd_cache(self.master)

    @pytest.fixture
    def hbac_setup_teardown(self):
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"])
        self.master.run_command(["ipa", "hbacrule-add", "rule1"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule1",
                                 "--users=" + self.KEYCLOAK_USER])
        self.master.run_command(["ipa", "hbacrule-add-host", "rule1",
                                 "--hosts", self.replica.hostname])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule1",
                                 "--hbacsvcs=sshd"])
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.replica)
        yield

        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-enable", "allow_all"])
        self.master.run_command(["ipa", "hbacrule-del", "rule1"])

    def test_auth_hbac(self, hbac_setup_teardown):
        """
        Test case to check that hbacrule is working as
        expected for user configured with external idp.
        """
        self.kinit_idp_keycloak(self.master, self.KEYCLOAK_USER,
                                keycloak_server=self.client)
        ssh_cmd = "ssh -q -K -l {0} {{0}} whoami".format(self.KEYCLOAK_USER)
        valid_ssh = self.master.run_command(
            ssh_cmd.format(self.replica.hostname))
        assert self.KEYCLOAK_USER in valid_ssh.stdout_text
        negative_ssh = self.master.run_command(
            ssh_cmd.format(self.master.hostname), raiseonerr=False
        )
        assert negative_ssh.returncode == 255

    def test_auth_sudo_idp(self):
        """
        Test case to check that sudorule is working as
        expected for user configured with external idp.
        """
        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)
        cmdlist = [
            ["ipa", "sudocmd-add", "/usr/bin/yum"],
            ["ipa", "sudorule-add", "sudorule"],
            ['ipa', 'sudorule-add-user',
             '--users=' + self.KEYCLOAK_USER, 'sudorule'],
            ['ipa', 'sudorule-add-host', '--hosts',
             self.client.hostname, 'sudorule'],
            ['ipa', 'sudorule-add-runasuser',
             '--users=root', 'sudorule'],
            ['ipa', 'sudorule-add-allow-command',
             '--sudocmds=/usr/bin/yum', 'sudorule'],
            ['ipa', 'sudorule-show', 'sudorule', '--all'],
            ['ipa', 'sudorule-add-option',
             'sudorule', '--sudooption', "!authenticate"]
        ]
        for cmd in cmdlist:
            self.master.run_command(cmd)
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.client)
        try:
            cmd = 'sudo -ll -U ' + self.KEYCLOAK_USER
            test = self.client.run_command(cmd).stdout_text
            msg = ("User %s may run the following commands"
                   % self.KEYCLOAK_USER)
            assert msg in test
            assert "/usr/bin/yum" in test
            self.kinit_idp_keycloak(self.client, self.KEYCLOAK_USER,
                                    keycloak_server=self.client)
            test_sudo = ('su -c "sudo yum list sssd-client" %s'
                         % self.KEYCLOAK_USER)
            self.client.run_command(test_sudo)
            list_fail = self.master.run_command(cmd).stdout_text
            msg = "User %s is not allowed to run sudo" % self.KEYCLOAK_USER
            assert msg in list_fail
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'sudorule-del', 'sudorule'])
            self.master.run_command(["ipa", "sudocmd-del", "/usr/bin/yum"])

    def test_auth_replica(self):
        """
        Test case to check that OAuth 2.0 Device
        Authorization is working as expected on replica.
        """
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.replica)
        tasks.kinit_admin(self.replica)
        list_user = self.master.run_command(
            ["ipa", "user-find",
             "--idp-user-id=" + self.KEYCLOAK_IDP_USER_ID]
        )
        assert self.KEYCLOAK_USER in list_user.stdout_text
        list_by_idp = self.replica.run_command(
            ["ipa", "user-find", "--idp=" + self.KEYCLOAK_IDP_NAME])
        assert self.KEYCLOAK_USER in list_by_idp.stdout_text
        list_by_user = self.replica.run_command(
            ["ipa", "user-find",
             "--idp-user-id=" + self.KEYCLOAK_IDP_USER_ID, "--all"]
        )
        assert self.KEYCLOAK_IDP_NAME in list_by_user.stdout_text
        self.kinit_idp_keycloak(self.replica, self.KEYCLOAK_USER,
                                keycloak_server=self.client)

    def test_idp_with_services(self):
        """
        Test case to check that services can be configured
        auth indicator as idp.
        """
        tasks.clear_sssd_cache(self.master)
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name.upper()
        services = [
            "DNS/{0}@{1}".format(self.master.hostname, domain),
            "HTTP/{0}@{1}".format(self.client.hostname, domain),
            "dogtag/{0}@{1}".format(self.master.hostname, domain),
            "ipa-dnskeysyncd/{0}@{1}".format(self.master.hostname, domain)
        ]
        try:
            for service in services:
                test = self.master.run_command(["ipa", "service-mod", service,
                                                "--auth-ind=idp"])
                assert "Authentication Indicators: idp" in test.stdout_text
        finally:
            for service in services:
                self.master.run_command(["ipa", "service-mod", service,
                                         "--auth-ind="])

    def test_idp_backup_restore(self):
        """
        Test case to check that after restore data is retrieved
        with related idp configuration.
        """
        tasks.kinit_admin(self.master)
        user = "backupuser"
        idp_name = "testidp"
        cmd = ["ipa", "idp-add", idp_name, "--provider=keycloak",
               "--client-id=ipa_oidc_client", "--org=master",
               "--base-url={0}:8443".format(self.client.hostname)]
        self.master.run_command(cmd, stdin_text="{0}\n{0}".format(
            self.client.config.admin_password))

        tasks.user_add(
            self.master, user,
            extra_args=["--user-auth-type=idp",
                        "--idp-user-id=" + self.KEYCLOAK_IDP_USER_ID,
                        "--idp=" + idp_name]
        )

        backup_path = tasks.get_backup_dir(self.master)
        self.master.run_command(['ipa', 'user-del', user])
        self.master.run_command(['ipa', 'idp-del', idp_name])
        dirman_password = self.master.config.dirman_password
        self.master.run_command(['ipa-restore', backup_path],
                                stdin_text=dirman_password + '\nyes')
        try:
            list_user = self.master.run_command(
                ['ipa', 'user-show', 'backupuser', '--all']
            ).stdout_text
            assert "External IdP configuration: testidp" in list_user
            assert "User authentication types: idp" in list_user
            msg = ("External IdP user identifier: %s"
                   % self.KEYCLOAK_IDP_USER_ID)
            assert msg in list_user
            list_idp = self.master.run_command(['ipa', 'idp-find', idp_name])
            assert idp_name in list_idp.stdout_text
            self.kinit_idp_keycloak(self.master, user,
                                    keycloak_server=self.client)
        finally:
            tasks.kdestroy_all(self.master)
            tasks.kinit_admin(self.master)
            self.master.run_command(["rm", "-rf", backup_path])
            self.master.run_command(["ipa", "idp-del", idp_name])

    def test_idp_providers_backup_restore(self):
        """
        Builtin provider IdPs survive ``ipa-backup`` / ``ipa-restore``.

        Adds google, github, microsoft, and okta templates, takes a backup,
        removes the IdP entries and a linked user, restores, and verifies each
        provider reference and user linkage are present again.
        """
        tasks.kinit_admin(self.master)
        idp_names = []
        backup_path = None
        try:
            for cn, provider, extra_args, _marker in (
                    self.BUILTIN_IDP_PROVIDER_SPECS):
                self._add_builtin_provider_idp(cn, provider, extra_args)
                idp_names.append(cn)

            tasks.user_add(
                self.master, self.BACKUP_RESTORE_USER,
                extra_args=["--user-auth-type=idp",
                            "--idp-user-id=" + self.KEYCLOAK_IDP_USER_ID,
                            "--idp=idp-google"],
            )

            backup_path = tasks.get_backup_dir(self.master)
            for cn in idp_names:
                self.master.run_command(["ipa", "idp-del", cn])
            self.master.run_command(
                ["ipa", "user-del", self.BACKUP_RESTORE_USER])

            dirman_password = self.master.config.dirman_password
            self.master.run_command(
                ["ipa-restore", backup_path],
                stdin_text=dirman_password + "\nyes",
            )

            for cn, provider, _extra_args, marker in (
                    self.BUILTIN_IDP_PROVIDER_SPECS):
                show = self.master.run_command(["ipa", "idp-show", cn])
                assert cn in show.stdout_text
                assert marker in show.stdout_text
                find = self.master.run_command(["ipa", "idp-find", cn])
                assert cn in find.stdout_text

            user_show = self.master.run_command(
                ["ipa", "user-show", self.BACKUP_RESTORE_USER, "--all"],
            ).stdout_text
            assert "External IdP configuration: idp-google" in user_show
            assert "User authentication types: idp" in user_show
            assert ("External IdP user identifier: %s"
                    % self.KEYCLOAK_IDP_USER_ID) in user_show
        finally:
            tasks.kinit_admin(self.master)
            for cn, _provider, _extra_args, _marker in (
                    self.BUILTIN_IDP_PROVIDER_SPECS):
                self.master.run_command(["ipa", "idp-del", cn])
            self.master.run_command(
                ["ipa", "user-del", self.BACKUP_RESTORE_USER])
            if backup_path:
                self.master.run_command(
                    ["rm", "-rf", backup_path])

    def test_idp_with_service_user(self):
        """
        HTTP service with ``idp`` auth indicator requires an IdP TGT.

        A user configured for external IdP authentication can obtain a
        service ticket only after completing the device authorization flow.
        """
        domain = self.master.domain.name.upper()
        service = "HTTP/{0}@{1}".format(self.client.hostname, domain)
        keytab = "/tmp/idp-http-service.keytab"
        tasks.kinit_admin(self.master)
        try:
            if self.master.run_command(["ipa", "service-show", service],
                                       raiseonerr=False
                                       ).returncode != 0:
                self.master.run_command(
                    ["ipa", "service-add", service, "--auth-ind=idp"])
            else:
                self.master.run_command(
                    ["ipa", "service-mod", service, "--auth-ind=idp"])
            show = self.master.run_command(["ipa", "service-show", service])
            assert "Authentication Indicators: idp" in show.stdout_text

            self.master.run_command(
                ["ipa-getkeytab", "-p", service, "-k", keytab])

            tasks.kdestroy_all(self.master)
            tasks.kinit_admin(self.master)
            denied = self.master.run_command(
                ["kvno", service], raiseonerr=False)
            assert denied.returncode != 0
            assert "rejects" in (
                denied.stderr_text + denied.stdout_text).lower()

            self.kinit_idp_keycloak(
                self.master, self.KEYCLOAK_USER,
                keycloak_server=self.client)
            self.master.run_command(["kvno", service])
            klist = self.master.run_command(["klist"])
            assert service in klist.stdout_text
        finally:
            tasks.kdestroy_all(self.master)
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "service-mod", service, "--auth-ind="])
            self.master.run_command(["rm", "-f", keytab])


class TestIDPAzure(TestIDP):
    """
    Microsoft Entra (Azure) IdP integration tests.

    Requires Microsoft Entra ID configured for Device Flow with client
    credentials and a preconfigured user account.  Multihost YAML keys:

    ``azure_tenant_id``
        Tenant ID.
    ``azure_admin_client_id``
        Application (client) ID.
    ``azure_admin_client_secret``
        Client secret.
    ``azure_username``
        Entra user principal name.
    ``azure_user_password``
        Entra user password.
    """

    AZURE_IDP_NAME = "azureidp"
    AZURE_IPA_USERNAME = "testazure"

    @classmethod
    def install(cls, mh):
        """Install IPA topology and provision Azure IdP test objects."""
        cls.require_azure_multihost_config()
        super(TestIDPAzure, cls).install(mh)
        cls.ensure_azure_idp_and_user()

    @staticmethod
    def add_azure_user_code(host, verification_uri, username, password,
                            device_user_code=None):
        contents = azure_user_code_script.format(
            uri=verification_uri,
            username=username,
            password=password,
            device_user_code=device_user_code or "",
        )
        TestIDP.run_remote_selenium(
            host, contents, "add_azure_user_code.py", timeout=180)

    @staticmethod
    def kinit_idp_azure(host, user, azure_email, azure_password):
        """kinit via Microsoft Entra device authorization flow."""
        def complete(uri, device_user_code):
            TestIDPAzure.add_azure_user_code(
                host, uri, azure_email, azure_password,
                device_user_code=device_user_code,
            )

        TestIDP.kinit_idp_device_flow(host, user, complete)

    @classmethod
    def require_azure_multihost_config(cls):
        """
        Skip the class when Azure multihost configuration is incomplete.

        All of ``azure_username``, ``azure_user_password``,
        ``azure_tenant_id``, ``azure_admin_client_id``, and
        ``azure_admin_client_secret`` must be set in the test config.
        """
        cls.cfg = cls.master.config
        if not all((
                cls.cfg.azure_username,
                cls.cfg.azure_user_password,
                cls.cfg.azure_tenant_id,
                cls.cfg.azure_admin_client_id,
                cls.cfg.azure_admin_client_secret,
        )):
            pytest.skip(
                "Azure IdP tests require Azure multihost configuration")

    @classmethod
    def ensure_azure_idp_and_user(cls):
        """Create Microsoft IdP and linked IPA user if absent."""
        host = cls.master
        tasks.kinit_admin(host)
        idp_show = host.run_command(
            ["ipa", "idp-show", cls.AZURE_IDP_NAME], raiseonerr=False)
        if idp_show.returncode != 0:
            host.run_command(
                [
                    "ipa", "idp-add", cls.AZURE_IDP_NAME,
                    "--provider", "microsoft",
                    "--organization", cls.cfg.azure_tenant_id,
                    "--client-id", cls.cfg.azure_admin_client_id,
                    "--secret",
                ],
                stdin_text=cls.cfg.azure_admin_client_secret + "\n",
            )

        user_show = host.run_command(
            ["ipa", "user-show", cls.AZURE_IPA_USERNAME], raiseonerr=False)
        if user_show.returncode != 0:
            tasks.user_add(
                host,
                cls.AZURE_IPA_USERNAME,
                first="azure",
                last="User",
                extra_args=[
                    "--user-auth-type=idp",
                    "--idp-user-id=" + cls.cfg.azure_username,
                    "--idp=" + cls.AZURE_IDP_NAME,
                ],
            )

    def test_azure_idp_add_and_user(self):
        """
        Add Azure IDP with Microsoft provider and associate user with mail id.

        Uses ipa idp-add with --provider microsoft, --organization (tenant ID),
        --client-id, and --secret from stdin. Then adds IPA user linked to
        the IdP with idp-user-id set to the user's email.
        """
        result = self.master.run_command(
            ["ipa", "idp-show", self.AZURE_IDP_NAME])
        assert self.AZURE_IDP_NAME in result.stdout_text
        assert "login.microsoftonline.com" in result.stdout_text

        list_user = self.master.run_command(
            ["ipa", "user-find",
             "--idp-user-id=" + self.cfg.azure_username]
        )
        assert self.AZURE_IPA_USERNAME in list_user.stdout_text

        list_by_idp = self.master.run_command(
            ["ipa", "user-find", "--idp=" + self.AZURE_IDP_NAME]
        )
        assert self.AZURE_IPA_USERNAME in list_by_idp.stdout_text

        user_show = self.master.run_command(
            ["ipa", "user-show", self.AZURE_IPA_USERNAME, "--all"]
        )
        assert self.AZURE_IDP_NAME in user_show.stdout_text
        assert self.cfg.azure_username in user_show.stdout_text

    def test_azure_idp_kinit(self):
        """
        Full OAuth 2.0 Device Authorization Grant kinit with Azure IdP.

        Performs kinit with FAST armor for the IdP-configured user and
        automates the Microsoft login page via headless Selenium to
        complete the device code flow end-to-end.  Verifies the
        resulting ticket carries the IdP authentication indicator (152).
        """
        tasks.clear_sssd_cache(self.client)
        self.kinit_idp_azure(
            self.client,
            self.AZURE_IPA_USERNAME,
            self.cfg.azure_username,
            self.cfg.azure_user_password,
        )
