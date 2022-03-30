from __future__ import absolute_import

import time

import textwrap
from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks, create_quarkus

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
verification_uri = "{uri}"
driver.get(verification_uri)
try:
    element = WebDriverWait(driver, 90).until(
        EC.presence_of_element_located((By.ID, "username")))
    driver.find_element_by_id("username").send_keys("testuser1")
    driver.find_element_by_id("password").send_keys("{passwd}")
    driver.find_element_by_id("kc-login").click()
    element = WebDriverWait(driver, 90).until(
        EC.presence_of_element_located((By.ID, "kc-login")))
    driver.find_element_by_id("kc-login").click()
    assert "Device Login Successful" in driver.page_source
finally:
    now = datetime.now().strftime("%M-%S")
    driver.get_screenshot_as_file("/var/log/httpd/screenshot-%s.png" % now)
    driver.quit()
""")


def add_user_code(host, verification_uri):
    contents = user_code_script.format(uri=verification_uri,
                                       passwd=host.config.admin_password)
    host.put_file_contents("/tmp/add_user_code.py", contents)
    tasks.run_repeatedly(
        host, ['python3', '/tmp/add_user_code.py'])


def get_verification_uri(host, since, keycloak_server_name):
    command = textwrap.dedent("""
    journalctl -u ipa-otpd\\* --since="%s" | grep "user_code:" | awk '{ print substr($7,2,9) }'""" % since)  # noqa: E501
    user_code = host.run_command(command).stdout_text.rstrip("\r\n")
    uri = ("https://{0}:8443/auth/realms/master/device?user_code={1}".format(
        keycloak_server_name, user_code))
    return uri


def kinit_idp(host, user, keycloak_server):
    ARMOR = "/tmp/armor"
    tasks.kdestroy_all(host)
    # create armor for FAST
    host.run_command(["kinit", "-n", "-c", ARMOR])
    since = time.strftime('%Y-%m-%d %H:%M:%S')
    cmd = ["kinit", "-T", ARMOR, user]
    with host.spawn_expect(cmd, default_timeout=100) as e:
        e.expect('Authenticate at .+: ')
        uri = get_verification_uri(host, since, keycloak_server.hostname)
        if uri:
            add_user_code(keycloak_server, uri)
        e.sendline('\n')
        e.expect_exit()

    test_idp = host.run_command(["klist", "-C"])
    assert "152" in test_idp.stdout_text


class TestIDPKeycloak(IntegrationTest):

    num_replicas = 1
    topology = 'line'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_client(cls.master, cls.replicas[0])
        content = cls.master.get_file_contents(paths.IPA_DEFAULT_CONF,
                                               encoding='utf-8')
        new_content = content + "\noidc_child_debug_level = 10"
        cls.master.put_file_contents(paths.IPA_DEFAULT_CONF, new_content)
        with tasks.remote_sssd_config(cls.master) as sssd_config:
            sssd_config.edit_domain(
                cls.master.domain, 'krb5_auth_timeout', 1100)
        tasks.clear_sssd_cache(cls.master)
        tasks.kinit_admin(cls.master)
        cls.master.run_command(["ipa", "config-mod", "--user-auth-type=idp",
                                "--user-auth-type=password"])
        xvfb = ("nohup /usr/bin/Xvfb :99 -ac -noreset -screen 0 1400x1200x8 "
                "</dev/null &>/dev/null &")
        cls.replicas[0].run_command(xvfb)

    def test_auth_keycloak_idp(self):
        keycloak_srv = self.replicas[0]
        create_quarkus.setup_keycloakserver(keycloak_srv)
        time.sleep(60)
        create_quarkus.setup_keycloak_client(keycloak_srv)
        tasks.kinit_admin(self.master)
        cmd = ["ipa", "idp-add", "keycloak", "--provider=keycloak",
               "--client-id=ipa_oidc_client", "--org=master",
               "--base-url={0}:8443/auth".format(keycloak_srv.hostname)]
        self.master.run_command(cmd, stdin_text="{0}\n{0}".format(
            keycloak_srv.config.admin_password))
        tasks.user_add(self.master, 'keycloakuser',
                       extra_args=["--user-auth-type=idp",
                                   "--idp-user-id=testuser1@ipa.test",
                                   "--idp=keycloak"]
                       )
        tasks.clear_sssd_cache(self.master)
        kinit_idp(self.master, 'keycloakuser', keycloak_srv)
