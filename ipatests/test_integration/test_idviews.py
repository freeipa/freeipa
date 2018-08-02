#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import os
import re
import string
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration.env_config import get_global_config
from ipaplatform.paths import paths
config = get_global_config()


class TestCertsInIDOverrides(IntegrationTest):
    topology = "line"
    num_ad_domains = 1
    adview = 'Default Trust View'
    cert_re = re.compile('Certificate: (?P<cert>.*?)\\s+.*')
    adcert1 = 'MyCert1'
    adcert2 = 'MyCert2'
    adcert1_file = adcert1 + '.crt'
    adcert2_file = adcert2 + '.crt'

    @classmethod
    def uninstall(cls, mh):
        super(TestCertsInIDOverrides, cls).uninstall(mh)
        cls.master.run_command(['rm', '-rf', cls.reqdir], raiseonerr=False)

    @classmethod
    def install(cls, mh):
        super(TestCertsInIDOverrides, cls).install(mh)
        cls.ad = config.ad_domains[0].ads[0]
        cls.ad_domain = cls.ad.domain.name
        cls.aduser = "testuser@%s" % cls.ad_domain

        master = cls.master
        # A setup for test_dbus_user_lookup
        master.run_command(['dnf', 'install', '-y', 'sssd-dbus'],
                           raiseonerr=False)
        # The tasks.modify_sssd_conf way did not work because
        # sssd_domain.set_option knows nothing about 'services' parameter of
        # the sssd config file. Therefore I am using sed approach
        master.run_command(
            "sed -i '/^services/ s/$/, ifp/' %s" % paths.SSSD_CONF)
        master.run_command(
            "sed -i 's/= 7/= 0xFFF0/' %s" % paths.SSSD_CONF, raiseonerr=False)
        master.run_command(['systemctl', 'restart', 'sssd.service'])
        # End of setup for test_dbus_user_lookup

        # AD-related stuff
        tasks.install_adtrust(master)
        tasks.sync_time(master, cls.ad)
        tasks.establish_trust_with_ad(cls.master, cls.ad_domain,
                                      extra_args=['--range-type',
                                                  'ipa-ad-trust'])

        cls.reqdir = os.path.join(master.config.test_dir, "certs")
        cls.reqfile1 = os.path.join(cls.reqdir, "test1.csr")
        cls.reqfile2 = os.path.join(cls.reqdir, "test2.csr")
        cls.pwname = os.path.join(cls.reqdir, "pwd")

        # Create a NSS database folder
        master.run_command(['mkdir', cls.reqdir], raiseonerr=False)
        # Create an empty password file
        master.run_command(["touch", cls.pwname], raiseonerr=False)

        # Initialize NSS database
        tasks.run_certutil(master, ["-N", "-f", cls.pwname], cls.reqdir)
        # Now generate self-signed certs for a windows user
        stdin_text = string.digits+string.ascii_letters[2:] + '\n'
        tasks.run_certutil(master, ['-S', '-s',
                                    "cn=%s,dc=ad,dc=test" % cls.adcert1, '-n',
                                    cls.adcert1, '-x', '-t', 'CT,C,C', '-v',
                                    '120', '-m', '1234'],
                           cls.reqdir, stdin=stdin_text)
        tasks.run_certutil(master, ['-S', '-s',
                                    "cn=%s,dc=ad,dc=test" % cls.adcert2, '-n',
                                    cls.adcert2, '-x', '-t', 'CT,C,C', '-v',
                                    '120', '-m', '1234'],
                           cls.reqdir, stdin=stdin_text)

        # Export the previously generated cert
        tasks.run_certutil(master, ['-L', '-n', cls.adcert1, '-a', '>',
                                    cls.adcert1_file], cls.reqdir)
        tasks.run_certutil(master, ['-L', '-n', cls.adcert2, '-a', '>',
                                    cls.adcert2_file], cls.reqdir)
        cls.cert1_base64 = cls.master.run_command(
            "openssl x509 -outform der -in %s | base64 -w 0" % cls.adcert1_file
            ).stdout_text
        cls.cert2_base64 = cls.master.run_command(
            "openssl x509 -outform der -in %s | base64 -w 0" % cls.adcert2_file
            ).stdout_text
        cls.cert1_pem = cls.master.run_command(
            "openssl x509 -in %s -outform pem" % cls.adcert1_file
            ).stdout_text
        cls.cert2_pem = cls.master.run_command(
            "openssl x509 -in %s -outform pem" % cls.adcert2_file
            ).stdout_text

    def test_certs_in_idoverrides_ad_users(self):
        """
        http://www.freeipa.org/page/V4/Certs_in_ID_overrides/Test_Plan
        #Test_case:_Manipulate_certificate_in_ID_override_entry
        """
        master = self.master
        master.run_command(['ipa', 'idoverrideuser-add',
                            self.adview, self.aduser])
        master.run_command(['ipa', 'idoverrideuser-add-cert',
                            self.adview, self.aduser,
                            "--certificate=%s" % self.cert1_base64])
        master.run_command(['ipa', 'idoverrideuser-add-cert',
                            self.adview, self.aduser,
                            "--certificate=%s" % self.cert2_base64])
        result = master.run_command(['ipa', 'idoverrideuser-show',
                                     self.adview, self.aduser])
        assert(self.cert1_base64 in result.stdout_text and
               self.cert2_base64 in result.stdout_text), (
            "idoverrideuser-show does not show all user certificates")
        master.run_command(['ipa', 'idoverrideuser-remove-cert',
                            self.adview, self.aduser,
                            "--certificate=%s" % self.cert2_base64])

    def test_dbus_user_lookup(self):
        """
        http://www.freeipa.org/page/V4/Certs_in_ID_overrides/Test_Plan
        #Test_case:_User_lookup_by_certificate
        """

        master = self.master
        userpath_re = re.compile('.*object path "(.*?)".*')

        result0 = master.run_command([
            'dbus-send', '--system', '--print-reply',
            '--dest=org.freedesktop.sssd.infopipe',
            '/org/freedesktop/sssd/infopipe/Users',
            'org.freedesktop.sssd.infopipe.Users.FindByCertificate',
            "string:%s" % self.cert1_pem])
        assert("object path" in result0.stdout_text), (
            "command output did not contain expected"
            "string:\n\n%s" % result0.stdout_text)
        userpath = userpath_re.findall(result0.stdout_text)[0]
        result1 = master.run_command(
            "dbus-send --system --print-reply"
            " --dest=org.freedesktop.sssd.infopipe"
            " %s org.freedesktop.DBus.Properties.Get"
            " string:\"org.freedesktop.sssd.infopipe.Users.User\""
            " string:\"name\"" % userpath, raiseonerr=False)
        assert(self.aduser in result1.stdout_text)
        result2 = master.run_command(
            "dbus-send --system --print-reply"
            " --dest=org.freedesktop.sssd.infopipe"
            " %s org.freedesktop.DBus.Properties.GetAll"
            " string:\"org.freedesktop.sssd.infopipe.Users.User\"" % userpath
            )
        assert('dict entry' in result2.stdout_text)


class TestRulesWithServicePrincipals(IntegrationTest):
    """
    https://fedorahosted.org/freeipa/ticket/6146
    """

    topology = 'star'
    num_replicas = 0
    service_certprofile = 'caIPAserviceCert'
    caacl = 'test_caacl'
    keytab = "replica.keytab"
    csr = "my.csr"
    csr_conf = "replica.cnf"

    @classmethod
    def prepare_config(cls):
        template = """
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]
commonName = %s

[ v3_req ]

# Extensions to add to a certificate request

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = %s
DNS.2 = %s
EOF
        """

        contents = template % (cls.replica, cls.replica, cls.master.hostname)
        cls.master.run_command("cat <<EOF > %s\n%s" % (cls.csr_conf, contents))

    @classmethod
    def install(cls, mh):
        super(TestRulesWithServicePrincipals, cls).install(mh)
        master = cls.master
        tasks.kinit_admin(master)
        cls.replica = "replica.%s" % master.domain.name
        master.run_command(['ipa', 'host-add', cls.replica, '--force'])
        cls.service_name = "svc/%s" % master.hostname
        cls.replica_service_name = "svc/%s" % cls.replica
        master.run_command("ipa service-add %s" % cls.service_name)
        master.run_command("ipa service-add %s --force" %
                           cls.replica_service_name)
        master.run_command("ipa service-add-host %s --hosts %s" % (
            cls.service_name, cls.replica))
        master.run_command("ipa caacl-add %s --desc \"test\"" % cls.caacl)
        master.run_command("ipa caacl-add-host %s --hosts %s" % (cls.caacl,
                                                                 cls.replica))
        master.run_command("ipa caacl-add-service %s --services"
                           " svc/`hostname`" % cls.caacl)
        master.run_command("ipa-getkeytab -p host/%s@%s -k %s" % (
            cls.replica, master.domain.realm, cls.keytab))
        master.run_command("kinit -kt %s host/%s" % (cls.keytab, cls.replica))

        # Prepare a CSR

        cls.prepare_config()
        stdin_text = "qwerty\nqwerty\n%s\n" % cls.replica

        master.run_command(['openssl', 'req', '-config', cls.csr_conf, '-new',
                            '-out', cls.csr], stdin_text=stdin_text)

    def test_rules_with_service_principals(self):
        result = self.master.run_command(['ipa', 'cert-request', self.csr,
                                          '--principal', "svc/%s@%s" % (
                                              self.replica,
                                              self.master.domain.realm),
                                          '--profile-id',
                                          self.service_certprofile],
                                         raiseonerr=False)
        assert(result.returncode == 0), (
            'Failed to add a cert to custom certprofile')
