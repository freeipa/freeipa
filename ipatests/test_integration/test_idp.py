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


def parse_device_auth_prompt(prompt):
    match = DEVICE_AUTH_PROMPT_RE.search(prompt)
    assert match is not None, prompt
    user_code = match.group(1)
    uri = match.group(2).strip()
    return uri, (user_code.strip() if user_code else None)


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


def run_remote_selenium(host, script, remote_basename, timeout=30):
    path = "/tmp/%s" % remote_basename
    try:
        host.put_file_contents(path, script)
        tasks.run_repeatedly(host, ["python3", path], timeout=timeout)
    finally:
        host.run_command(["rm", "-f", path])


def add_keyclock_user_code(host, verification_uri):
    contents = keyclock_user_code_script.format(
        uri=verification_uri,
        passwd=host.config.admin_password,
    )
    run_remote_selenium(host, contents, "add_keyclock_user_code.py")


def kinit_idp(
    host,
    user,
    keycloak_server=None,
    *,
    azure_email=None,
    azure_password=None,
):
    """
    kinit for users with --user-auth-type=idp: complete OAuth2 device code flow
    in a browser. Use either keycloak_server= for Keycloak, or
    azure_email= and azure_password= for Microsoft Entra.
    """
    if keycloak_server is not None:
        if azure_email is not None or azure_password is not None:
            raise TypeError(
                "kinit_idp: do not combine keycloak_server= with "
                "azure_email=/azure_password="
            )
    elif azure_email is not None and azure_password is not None:
        pass
    elif azure_email is not None or azure_password is not None:
        raise TypeError(
            "kinit_idp: for Microsoft IdP, pass both azure_email= and "
            "azure_password="
        )
    else:
        raise TypeError(
            "kinit_idp: pass keycloak_server=... (Keycloak) or both "
            "azure_email= and azure_password= (Microsoft)"
        )

    ARMOR = "/tmp/armor"
    tasks.kdestroy_all(host)
    # create armor for FAST
    host.run_command(["kinit", "-n", "-c", ARMOR])
    cmd = ["kinit", "-T", ARMOR, user]

    with host.spawn_expect(cmd, default_timeout=100) as e:
        e.expect(DEVICE_AUTH_PROMPT_RE)
        prompt = e.get_last_output()
        uri, device_user_code = parse_device_auth_prompt(prompt)
        time.sleep(15)
        if uri:
            if keycloak_server is not None:
                add_keyclock_user_code(keycloak_server, uri)
            else:
                add_azure_user_code(
                    host, uri, azure_email, azure_password,
                    device_user_code=device_user_code,
                )
        e.sendline('\n')
        e.expect_exit()

    test_idp = host.run_command(["klist", "-C"])
    assert "152" in test_idp.stdout_text


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


def add_azure_user_code(host, verification_uri, username, password,
                        device_user_code=None):
    contents = azure_user_code_script.format(
        uri=verification_uri,
        username=username,
        password=password,
        device_user_code=device_user_code or "",
    )
    run_remote_selenium(host, contents, "add_azure_user_code.py",
                        timeout=180)


def _azure_multihost_config_missing_attrs(config):
    """Names of multihost config attributes that are None (Azure IdP suite)."""
    pairs = (
        ("azure_username", config.azure_username),
        ("azure_user_password", config.azure_user_password),
        ("azure_tenant_id", config.azure_tenant_id),
        ("azure_admin_client_id", config.azure_admin_client_id),
        ("azure_admin_client_secret", config.azure_admin_client_secret),
        ("azure_domain", config.azure_domain),
    )
    return [name for name, val in pairs if val is None]


class TestIDP(IntegrationTest):

    num_replicas = 2
    topology = 'line'
    AZURE_IDP_NAME = "azureidp"
    AZURE_IPA_USERNAME = "testazure"

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
        cmd = ["ipa", "idp-add", "keycloakidp", "--provider=keycloak",
               "--client-id=ipa_oidc_client", "--org=master",
               "--base-url={0}:8443".format(self.client.hostname)]
        self.master.run_command(cmd, stdin_text="{0}\n{0}".format(
            self.client.config.admin_password))
        tasks.user_add(self.master, 'keycloakuser',
                       extra_args=["--user-auth-type=idp",
                                   "--idp-user-id=testuser1@ipa.test",
                                   "--idp=keycloakidp"]
                       )
        list_user = self.master.run_command(
            ["ipa", "user-find", "--idp-user-id=testuser1@ipa.test"]
        )
        assert "keycloakuser" in list_user.stdout_text
        list_by_idp = self.master.run_command(["ipa", "user-find",
                                               "--idp=keycloakidp"]
                                              )
        assert "keycloakuser" in list_by_idp.stdout_text
        list_by_user = self.master.run_command(
            ["ipa", "user-find", "--idp-user-id=testuser1@ipa.test", "--all"]
        )
        assert "keycloakidp" in list_by_user.stdout_text
        tasks.clear_sssd_cache(self.master)
        kinit_idp(self.master, 'keycloakuser', keycloak_server=self.client)

    @pytest.fixture
    def hbac_setup_teardown(self):
        # allow sshd only on given host
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"])
        self.master.run_command(["ipa", "hbacrule-add", "rule1"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule1",
                                 "--users=keycloakuser"]
                                )
        self.master.run_command(["ipa", "hbacrule-add-host", "rule1",
                                 "--hosts", self.replica.hostname])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule1",
                                 "--hbacsvcs=sshd"]
                                )
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.replica)
        yield

        # cleanup
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-enable", "allow_all"])
        self.master.run_command(["ipa", "hbacrule-del", "rule1"])

    def test_auth_hbac(self, hbac_setup_teardown):
        """
        Test case to check that hbacrule is working as
        expected for user configured with external idp.
        """
        kinit_idp(self.master, 'keycloakuser', keycloak_server=self.client)
        ssh_cmd = "ssh -q -K -l keycloakuser {0} whoami"
        valid_ssh = self.master.run_command(
            ssh_cmd.format(self.replica.hostname))
        assert "keycloakuser" in valid_ssh.stdout_text
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
        #  rule: keycloakuser are allowed to execute yum on
        #  the client machine as root.
        cmdlist = [
            ["ipa", "sudocmd-add", "/usr/bin/yum"],
            ["ipa", "sudorule-add", "sudorule"],
            ['ipa', 'sudorule-add-user', '--users=keycloakuser',
             'sudorule'],
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
            cmd = 'sudo -ll -U keycloakuser'
            test = self.client.run_command(cmd).stdout_text
            assert "User keycloakuser may run the following commands" in test
            assert "/usr/bin/yum" in test
            kinit_idp(self.client, 'keycloakuser', self.client)
            test_sudo = 'su -c "sudo yum list sssd-client" keycloakuser'
            self.client.run_command(test_sudo)
            list_fail = self.master.run_command(cmd).stdout_text
            assert "User keycloakuser is not allowed to run sudo" in list_fail
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
            ["ipa", "user-find", "--idp-user-id=testuser1@ipa.test"]
        )
        assert "keycloakuser" in list_user.stdout_text
        list_by_idp = self.replica.run_command(["ipa", "user-find",
                                                "--idp=keycloakidp"]
                                               )
        assert "keycloakuser" in list_by_idp.stdout_text
        list_by_user = self.replica.run_command(
            ["ipa", "user-find", "--idp-user-id=testuser1@ipa.test", "--all"]
        )
        assert "keycloakidp" in list_by_user.stdout_text
        kinit_idp(self.replica, 'keycloakuser', keycloak_server=self.client)

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
                                                "--auth-ind=idp"]
                                               )
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
        cmd = ["ipa", "idp-add", "testidp", "--provider=keycloak",
               "--client-id=ipa_oidc_client", "--org=master",
               "--base-url={0}:8443".format(self.client.hostname)]
        self.master.run_command(cmd, stdin_text="{0}\n{0}".format(
            self.client.config.admin_password))

        tasks.user_add(self.master, user,
                       extra_args=["--user-auth-type=idp",
                                   "--idp-user-id=testuser1@ipa.test",
                                   "--idp=testidp"]
                       )

        backup_path = tasks.get_backup_dir(self.master)
        # change data after backup
        self.master.run_command(['ipa', 'user-del', user])
        self.master.run_command(['ipa', 'idp-del', 'testidp'])
        dirman_password = self.master.config.dirman_password
        self.master.run_command(['ipa-restore', backup_path],
                                stdin_text=dirman_password + '\nyes')
        try:
            list_user = self.master.run_command(
                ['ipa', 'user-show', 'backupuser', '--all']
            ).stdout_text
            assert "External IdP configuration: testidp" in list_user
            assert "User authentication types: idp" in list_user
            assert ("External IdP user identifier: "
                    "testuser1@ipa.test") in list_user
            list_idp = self.master.run_command(['ipa', 'idp-find', 'testidp'])
            assert "testidp" in list_idp.stdout_text
            kinit_idp(self.master, user, self.client)
        finally:
            tasks.kdestroy_all(self.master)
            tasks.kinit_admin(self.master)
            self.master.run_command(["rm", "-rf", backup_path])
            self.master.run_command(["ipa", "idp-del", "testidp"])

    def require_azure_multihost_config(self):
        """Skip if Azure multihost config is incomplete."""
        cfg = self.master.config
        missing = _azure_multihost_config_missing_attrs(cfg)
        if missing:
            pytest.skip(
                "Azure IdP tests require these multihost configuration "
                "attributes (non-null): " + ", ".join(missing)
            )
        self.azure_username = cfg.azure_username
        self.azure_user_password = cfg.azure_user_password
        self.azure_tenant_id = cfg.azure_tenant_id
        self.azure_admin_client_id = cfg.azure_admin_client_id
        self.azure_admin_client_secret = cfg.azure_admin_client_secret
        self.azure_domain = cfg.azure_domain

    def ensure_azure_idp_and_user(self):
        """Create Microsoft IdP and linked IPA user if absent."""
        host = self.master
        idp_name = self.AZURE_IDP_NAME
        ipa_user = self.AZURE_IPA_USERNAME
        tasks.kinit_admin(host)
        idp_show = host.run_command(
            ["ipa", "idp-show", idp_name], raiseonerr=False)
        if idp_show.returncode != 0:
            host.run_command(
                [
                    "ipa", "idp-add", idp_name,
                    "--provider", "microsoft",
                    "--organization", self.azure_tenant_id,
                    "--client-id", self.azure_admin_client_id,
                    "--secret",
                ],
                stdin_text=self.azure_admin_client_secret + "\n",
            )

        user_show = host.run_command(
            ["ipa", "user-show", ipa_user], raiseonerr=False)
        if user_show.returncode != 0:
            tasks.user_add(
                host,
                ipa_user,
                first="azure",
                last="User",
                extra_args=[
                    "--user-auth-type=idp",
                    "--idp-user-id=" + self.azure_username,
                    "--idp=" + idp_name,
                ],
            )

    def test_azure_idp_add_and_user(self):
        """
        Add Azure IDP with Microsoft provider and associate user with mail id.

        Uses ipa idp-add with --provider microsoft, --organization (tenant ID),
        --client-id, and --secret from stdin. Then adds IPA user linked to
        the IdP with idp-user-id set to the user's email.
        """
        self.require_azure_multihost_config()
        self.ensure_azure_idp_and_user()

        result = self.master.run_command(
            ["ipa", "idp-show", self.AZURE_IDP_NAME])
        assert self.AZURE_IDP_NAME in result.stdout_text
        assert "login.microsoftonline.com" in result.stdout_text

        list_user = self.master.run_command(
            ["ipa", "user-find", "--idp-user-id=" + self.azure_username]
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
        assert self.azure_username in user_show.stdout_text

    def test_azure_idp_kinit(self):
        """
        Full OAuth 2.0 Device Authorization Grant kinit with Azure IdP.

        Performs kinit with FAST armor for the IdP-configured user and
        automates the Microsoft login page via headless Selenium to
        complete the device code flow end-to-end.  Verifies the
        resulting ticket carries the IdP authentication indicator (152).
        """
        self.require_azure_multihost_config()
        self.ensure_azure_idp_and_user()
        tasks.clear_sssd_cache(self.client)
        kinit_idp(
            self.client,
            self.AZURE_IPA_USERNAME,
            azure_email=self.azure_username,
            azure_password=self.azure_user_password,
        )
