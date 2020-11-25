#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests to verify that the upgrade script works.
"""
import base64
import configparser
import os
import io
import textwrap

from cryptography.hazmat.primitives import serialization
import pytest

from ipaplatform.paths import paths
from ipapython.dn import DN
from ipapython.ipautil import template_str
from ipaserver.install import bindinstance
from ipaserver.install.sysupgrade import STATEFILE_FILE
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

# old template without comments for testing
# and "dnssec-validation no"
OLD_NAMED_TEMPLATE = """
options {
        listen-on-v6 {any;};
        directory "$NAMED_VAR_DIR"; // the default
        dump-file               "${NAMED_DATA_DIR}cache_dump.db";
        statistics-file         "${NAMED_DATA_DIR}named_stats.txt";
        memstatistics-file      "${NAMED_DATA_DIR}named_mem_stats.txt";
        tkey-gssapi-keytab "$NAMED_KEYTAB";
        pid-file "$NAMED_PID";
        dnssec-enable yes;
        dnssec-validation no;
        bindkeys-file "$BINDKEYS_FILE";
        managed-keys-directory "$MANAGED_KEYS_DIR";
        $INCLUDE_CRYPTO_POLICY
};

logging {
        channel default_debug {
                file "${NAMED_DATA_DIR}named.run";
                severity dynamic;
                print-time yes;
        };
};

include "$RFC1912_ZONES";
include "$ROOT_KEY";

/* WARNING: This part of the config file is IPA-managed.
 * Modifications may break IPA setup or upgrades.
 */
dyndb "ipa" "$BIND_LDAP_SO" {
        uri "ldapi://%2fvar%2frun%2fslapd-$SERVER_ID.socket";
        base "cn=dns,$SUFFIX";
        server_id "$FQDN";
        auth_method "sasl";
        sasl_mech "GSSAPI";
        sasl_user "DNS/$FQDN";
};
/* End of IPA-managed part. */
"""


def named_test_template(host):
    # create bind instance to get a substitution dict
    bind = bindinstance.BindInstance()
    bind.setup_templating(
        fqdn=host.hostname,
        realm_name=host.domain.realm,
        domain_name=host.domain.name,
    )
    sub_dict = bind.sub_dict.copy()
    sub_dict.update(BINDKEYS_FILE="/etc/named.iscdlv.key")
    return template_str(OLD_NAMED_TEMPLATE, sub_dict)


def clear_sysupgrade(host, *sections):
    # get state file
    statefile = os.path.join(paths.STATEFILE_DIR, STATEFILE_FILE)
    state = host.get_file_contents(statefile, encoding="utf-8")
    # parse it
    parser = configparser.ConfigParser()
    parser.optionxform = str
    parser.read_string(state)
    # remove sections
    for section in sections:
        parser.remove_section(section)
    # dump the modified config
    out = io.StringIO()
    parser.write(out)
    # upload it
    host.put_file_contents(statefile, out.getvalue())


class TestUpgrade(IntegrationTest):
    """
    Test ipa-server-upgrade.

    Note that ipa-server-upgrade on a CA-less installation is tested
    in ``test_caless.TestIPACommands.test_invoke_upgrader``.

    """
    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)
        tasks.install_dns(cls.master)

    def test_invoke_upgrader(self):
        cmd = self.master.run_command(['ipa-server-upgrade'],
                                      raiseonerr=False)
        assert ("DN: cn=Schema Compatibility,cn=plugins,cn=config does not \
                exists or haven't been updated" not in cmd.stdout_text)
        assert cmd.returncode == 0

    def test_double_encoded_cacert(self):
        """Test for BZ 1644874

        In old IPA version, the entry cn=CAcert,cn=ipa,cn=etc,$basedn
        could contain a double-encoded cert, which leads to ipa-server-upgrade
        failure.
        Force a double-encoded value then call upgrade to check the fix.
        """
        # Read the current entry from LDAP
        ldap = self.master.ldap_connect()
        basedn = self.master.domain.basedn
        dn = DN(('cn', 'CAcert'), ('cn', 'ipa'), ('cn', 'etc'), basedn)
        entry = ldap.get_entry(dn)  # pylint: disable=no-member
        # Extract the certificate as DER then double-encode
        cacert = entry['cacertificate;binary'][0]
        cacert_der = cacert.public_bytes(serialization.Encoding.DER)
        cacert_b64 = base64.b64encode(cacert_der)
        # overwrite the value with double-encoded cert
        entry.single_value['cACertificate;binary'] = cacert_b64
        ldap.update_entry(entry)  # pylint: disable=no-member

        # try the upgrade
        self.master.run_command(['ipa-server-upgrade'])

        # reconnect to the master (upgrade stops 389-ds)
        ldap = self.master.ldap_connect()
        # read the value after upgrade, should be fixed
        entry = ldap.get_entry(dn)  # pylint: disable=no-member
        try:
            _cacert = entry['cacertificate;binary']
        except ValueError:
            raise AssertionError('%s contains a double-encoded cert'
                                 % entry.dn)

    def get_named_confs(self):
        named_conf = self.master.get_file_contents(
            paths.NAMED_CONF, encoding="utf-8"
        )
        print(named_conf)
        custom_conf = self.master.get_file_contents(
            paths.NAMED_CUSTOM_CONF, encoding="utf-8"
        )
        print(custom_conf)
        opt_conf = self.master.get_file_contents(
            paths.NAMED_CUSTOM_OPTIONS_CONF, encoding="utf-8"
        )
        print(opt_conf)
        return named_conf, custom_conf, opt_conf

    @pytest.mark.skip_if_platform(
        "debian", reason="Debian does not use crypto policy"
    )
    def test_named_conf_crypto_policy(self):
        named_conf = self.master.get_file_contents(
            paths.NAMED_CONF, encoding="utf-8"
        )
        assert paths.NAMED_CRYPTO_POLICY_FILE in named_conf

    def test_current_named_conf(self):
        named_conf, custom_conf, opt_conf = self.get_named_confs()
        # verify that both includes are present exactly one time
        inc_opt_conf = f'include "{paths.NAMED_CUSTOM_OPTIONS_CONF}";'
        assert named_conf.count(inc_opt_conf) == 1
        inc_custom_conf = f'include "{paths.NAMED_CUSTOM_CONF}";'
        assert named_conf.count(inc_custom_conf) == 1

        assert "dnssec-validation yes;" in opt_conf
        assert "dnssec-validation" not in named_conf

        assert custom_conf

    def test_update_named_conf_simple(self):
        # remove files to force a migration
        self.master.run_command(
            [
                "rm",
                "-f",
                paths.NAMED_CUSTOM_CONF,
                paths.NAMED_CUSTOM_OPTIONS_CONF,
            ]
        )
        self.master.run_command(['ipa-server-upgrade'])
        named_conf, custom_conf, opt_conf = self.get_named_confs()

        # not empty
        assert custom_conf.strip()
        # has dnssec-validation enabled in option config
        assert "dnssec-validation yes;" in opt_conf
        assert "dnssec-validation" not in named_conf

        # verify that both includes are present exactly one time
        inc_opt_conf = f'include "{paths.NAMED_CUSTOM_OPTIONS_CONF}";'
        assert named_conf.count(inc_opt_conf) == 1
        inc_custom_conf = f'include "{paths.NAMED_CUSTOM_CONF}";'
        assert named_conf.count(inc_custom_conf) == 1

    def test_update_named_conf_old(self):
        # remove files to force a migration
        self.master.run_command(
            [
                "rm",
                "-f",
                paths.NAMED_CUSTOM_CONF,
                paths.NAMED_CUSTOM_OPTIONS_CONF,
            ]
        )
        # dump an old named conf to verify migration
        old_contents = named_test_template(self.master)
        self.master.put_file_contents(paths.NAMED_CONF, old_contents)
        clear_sysupgrade(self.master, "dns", "named.conf")
        # check
        self.master.run_command(["named-checkconf", paths.NAMED_CONF])

        # upgrade
        self.master.run_command(['ipa-server-upgrade'])

        named_conf, custom_conf, opt_conf = self.get_named_confs()

        # not empty
        assert custom_conf.strip()
        # dnssec-validation is migrated as "disabled" from named.conf
        assert "dnssec-validation no;" in opt_conf
        assert "dnssec-validation" not in named_conf

        # verify that both includes are present exactly one time
        inc_opt_conf = f'include "{paths.NAMED_CUSTOM_OPTIONS_CONF}";'
        assert named_conf.count(inc_opt_conf) == 1
        inc_custom_conf = f'include "{paths.NAMED_CUSTOM_CONF}";'
        assert named_conf.count(inc_custom_conf) == 1

    def test_admin_root_alias_upgrade_CVE_2020_10747(self):
        # Test upgrade for CVE-2020-10747 fix
        # https://bugzilla.redhat.com/show_bug.cgi?id=1810160
        rootprinc = "root@{}".format(self.master.domain.realm)
        self.master.run_command(
            ["ipa", "user-remove-principal", "admin", rootprinc]
        )
        result = self.master.run_command(["ipa", "user-show", "admin"])
        assert rootprinc not in result.stdout_text

        self.master.run_command(['ipa-server-upgrade'])
        result = self.master.run_command(["ipa", "user-show", "admin"])
        assert rootprinc in result.stdout_text

    def test_pwpolicy_upgrade(self):
        """Test that ipapwdpolicy objectclass is added to all policies"""
        entry_ldif = textwrap.dedent("""
            dn: cn=global_policy,cn={realm},cn=kerberos,{base_dn}
            changetype: modify
            delete: objectclass
            objectclass: ipapwdpolicy
        """).format(
            base_dn=str(self.master.domain.basedn),
            realm=self.master.domain.realm)
        tasks.ldapmodify_dm(self.master, entry_ldif)

        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa-server-upgrade'])
        result = self.master.run_command(["ipa", "pwpolicy-find"])
        # if it is still missing the oc it won't be displayed
        assert 'global_policy' in result.stdout_text

    def test_kra_detection(self):
        """Test that ipa-server-upgrade correctly detects KRA presence

        Test for https://pagure.io/freeipa/issue/8596
        When the directory /var/lib/pki/pki-tomcat/kra/ exists, the upgrade
        wrongly assumes that KRA component is installed and crashes.
        The test creates an empty dir and calls ipa-server-upgrade
        to make sure that KRA detection is not based on the directory
        presence.
        """
        # Skip test if pki 10.10.0 is installed
        # because of https://github.com/dogtagpki/pki/issues/3397
        # pki fails to start if empty dir /var/lib/pki/pki-tomcat/kra exists
        if tasks.get_pki_version(self.master) == tasks.parse_version('10.10.0'):
            pytest.skip("Skip test with pki 10.10.0")

        kra_path = os.path.join(paths.VAR_LIB_PKI_TOMCAT_DIR, "kra")
        try:
            self.master.run_command(["mkdir", "-p", kra_path])
            result = self.master.run_command(['ipa-server-upgrade'])
            err_msg = 'Upgrade failed with no such entry'
            assert err_msg not in result.stderr_text
        finally:
            self.master.run_command(["rmdir", kra_path])
