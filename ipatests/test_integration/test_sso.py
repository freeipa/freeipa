from __future__ import absolute_import


import pytest
import textwrap
from ipaplatform.osinfo import osinfo
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks, create_keycloak
from ipatests.pytest_ipa.integration import create_bridge

user_code_script = textwrap.dedent("""
from selenium import webdriver
from datetime import datetime
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
options = Options()
options.headless = True
driver = webdriver.Firefox(executable_path="/opt/geckodriver", options=options)
verification_uri = "https://{hostname}:8443/realms/master/account/#/"
driver.get(verification_uri)

try:
    element = WebDriverWait(driver, 90).until(
        EC.element_to_be_clickable((By.ID, "landingSignInButton")))
    driver.find_element(By.ID, "landingSignInButton").click()
    element = WebDriverWait(driver, 90).until(
        EC.presence_of_element_located((By.ID, "kc-login")))
    driver.find_element(By.ID, "username").send_keys("{username}")
    driver.find_element(By.ID, "password").send_keys("{password}")
    driver.find_element(By.ID, "kc-login").click()
    element = WebDriverWait(driver, 900).until(
        EC.text_to_be_present_in_element((By.ID, "landingLoggedInUser"),
                                         "{username_fl}"))
    assert driver.find_element(By.ID, "landingLoggedInUser").text \
        == "{username_fl}"
finally:
    now = datetime.now().strftime("%M-%S")
    driver.get_screenshot_as_file("/var/log/httpd/screenshot-%s.png" % now)
    driver.quit()
""")


def keycloak_login(host, username, password, username_fl=None):
    if username_fl is None:
        username_fl = username
    contents = user_code_script.format(hostname=host.hostname,
                                       username=username,
                                       password=password,
                                       username_fl=username_fl)
    try:
        host.put_file_contents("/tmp/keycloak_login.py", contents)
        tasks.run_repeatedly(host, ['python3', '/tmp/keycloak_login.py'])
    finally:
        host.run_command(["rm", "-f", "/tmp/keycloak_login.py"])


def keycloak_add_user(host, kcadm_pass, username, password=None):
    domain = host.domain.name
    kcadmin_sh = "/opt/keycloak/bin/kcadm.sh"
    kcadmin = [kcadmin_sh, "config", "credentials", "--server",
               f"https://{host.hostname}:8443",
               "--realm", "master", "--user", "admin",
               "--password", kcadm_pass]

    host.run_command(kcadmin)
    host.run_command([kcadmin_sh, "create", "users", "-r", "master",
                      "-s", f"username={username}",
                      "-s", f"email={username}@{domain}",
                      "-s", "enabled=true"])

    if password is not None:
        host.run_command([kcadmin_sh, "set-password", "-r", "master",
                          "--username", "testuser1", "--new-password",
                          password])


class TestSsoBridge(IntegrationTest):

    # Replicas used instead of clients due to memory requirements
    # for running Keycloak and Bridge servers
    num_replicas = 2

    @classmethod
    def install(cls, mh):
        cls.keycloak = cls.replicas[0]
        cls.bridge = cls.replicas[1]
        tasks.install_master(cls.master, extra_args=['--no-dnssec-validation'])
        tasks.install_client(cls.master, cls.replicas[0],
                             extra_args=["--mkhomedir"])
        tasks.install_client(cls.master, cls.replicas[1],
                             extra_args=["--mkhomedir"])
        tasks.clear_sssd_cache(cls.master)
        tasks.clear_sssd_cache(cls.keycloak)
        tasks.clear_sssd_cache(cls.bridge)
        tasks.kinit_admin(cls.master)
        username = 'ipauser1'
        password = cls.keycloak.config.admin_password
        tasks.create_active_user(cls.master, username, password)
        create_keycloak.setup_keycloakserver(cls.keycloak)
        create_keycloak.setup_keycloak_client(cls.keycloak)
        create_bridge.setup_scim_server(cls.bridge)
        create_bridge.setup_keycloak_scim_plugin(cls.keycloak,
                                                 cls.bridge.hostname)

    @classmethod
    def uninstall(cls, mh):
        tasks.uninstall_client(cls.keycloak)
        tasks.uninstall_client(cls.bridge)
        tasks.uninstall_master(cls.master)
        create_keycloak.uninstall_keycloak(cls.keycloak)
        create_bridge.uninstall_scim_server(cls.bridge)
        create_bridge.uninstall_scim_plugin(cls.keycloak)

    def test_sso_login_with_ipa_user(self):
        """
        Test case to check authenticating to Keycloak as an IPA user
        """
        username = 'ipauser1'
        username_fl = 'test user'
        password = self.keycloak.config.admin_password
        keycloak_login(self.keycloak, username, password, username_fl)

    @pytest.mark.xfail(
        osinfo.id == 'fedora',
        reason='freeipa ticket 9264', strict=True)
    def test_ipa_login_with_sso_user(self):
        """
        Test case to authenticate via ssh to IPA client as Keycloak
        user with password set in IPA without using external IdP

        related: https://pagure.io/freeipa/issue/9250
        """
        username = "kcuser1"
        password = self.keycloak.config.admin_password

        keycloak_add_user(self.keycloak, password, username)
        tasks.set_user_password(self.master, username, password)

        tasks.run_ssh_cmd(to_host=self.master.external_hostname,
                          username=username, auth_method="password",
                          password=password)
