#
# Copyright (C) 2017 FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

from ipalib.plugable import Registry
from ipaplatform import services
from ipaplatform.paths import paths
from ipaserver.advise.base import Advice
from ipaserver.install.httpinstance import OCSP_ENABLED, OCSP_DIRECTIVE

register = Registry()


class common_smart_card_auth_config(Advice):
    """
    Common steps required to properly configure both server and client for
    smart card auth
    """

    systemwide_nssdb = paths.NSS_DB_DIR
    smart_card_ca_certs_variable_name = "SC_CA_CERTS"
    single_ca_cert_variable_name = 'ca_cert'

    def check_ccache_not_empty(self):
        self.log.comment('Check whether the credential cache is not empty')
        self.log.exit_on_failed_command(
            'klist',
            [
                "Credential cache is empty",
                'Use kinit as privileged user to obtain Kerberos credentials'
            ])

    def check_and_set_ca_cert_paths(self):
        ca_paths_variable = self.smart_card_ca_certs_variable_name
        single_ca_path_variable = self.single_ca_cert_variable_name

        self.log.command("{}=$@".format(ca_paths_variable))
        self.log.exit_on_predicate(
            '[ -z "${}" ]'.format(ca_paths_variable),
            ['You need to provide one or more paths to the PEM files '
             'containing CAs signing the Smart Cards']
        )
        with self.log.for_loop(single_ca_path_variable,
                               '${}'.format(ca_paths_variable)):
            self.log.exit_on_predicate(
                '[ ! -f "${}" ]'.format(single_ca_path_variable),
                ['Invalid CA certificate filename: ${}'.format(
                    single_ca_path_variable),
                 'Please check that the path exists and is a valid file']
            )

    def upload_smartcard_ca_certificates_to_systemwide_db(self):
        # Newer version of sssd use OpenSSL and read the CA certs
        # from /etc/sssd/pki/sssd_auth_ca_db.pem
        self.log.command('mkdir -p /etc/sssd/pki')
        with self.log.for_loop(
                self.single_ca_cert_variable_name,
                '${}'.format(self.smart_card_ca_certs_variable_name)):
            self.log.command(
                'certutil -d {} -A -i ${} -n "Smart Card CA $(uuidgen)" '
                '-t CT,C,C'.format(
                    self.systemwide_nssdb, self.single_ca_cert_variable_name
                )
            )
            self.log.command(
                'cat ${} >>  /etc/sssd/pki/sssd_auth_ca_db.pem'.format(
                    self.single_ca_cert_variable_name
                )
            )

    def install_smart_card_signing_ca_certs(self):
        with self.log.for_loop(
                self.single_ca_cert_variable_name,
                '${}'.format(self.smart_card_ca_certs_variable_name)):
            self.log.exit_on_failed_command(
                'ipa-cacert-manage install ${} -t CT,C,C'.format(
                    self.single_ca_cert_variable_name
                ),
                ['Failed to install external CA certificate to IPA']
            )

    def update_ipa_ca_certificate_store(self):
        self.log.exit_on_failed_command(
            'ipa-certupdate',
            ['Failed to update IPA CA certificate database']
        )


@register()
class config_server_for_smart_card_auth(common_smart_card_auth_config):
    """
    Configures smart card authentication via Kerberos (PKINIT) and for WebUI
    """

    description = ("Instructions for enabling Smart Card authentication on "
                   " a single FreeIPA server. Includes Apache configuration, "
                   "enabling PKINIT on KDC and configuring WebUI to accept "
                   "Smart Card auth requests. To enable the feature in the "
                   "whole topology you have to run the script on each master")

    ssl_conf = paths.HTTPD_SSL_CONF
    ssl_ocsp_directive = OCSP_DIRECTIVE
    kdc_service_name = services.knownservices.krb5kdc.systemd_name

    def get_info(self):
        self.log.exit_on_nonroot_euid()
        self.check_and_set_ca_cert_paths()
        self.check_ccache_not_empty()
        self.check_hostname_is_in_masters()
        self.resolve_ipaca_records()
        self.enable_ssl_ocsp()
        self.restart_httpd()
        self.record_httpd_ocsp_status()
        self.check_and_enable_pkinit()
        self.enable_ok_to_auth_as_delegate_on_http_principal()
        self.upload_smartcard_ca_certificates_to_systemwide_db()
        self.install_smart_card_signing_ca_certs()
        self.update_ipa_ca_certificate_store()
        self.restart_kdc()

    def check_hostname_is_in_masters(self):
        self.log.comment('Check whether the host is IPA master')
        self.log.exit_on_failed_command(
            'ipa server-find $(hostname -f)',
            ["This script can be run on IPA master only"])

    def resolve_ipaca_records(self):
        ipa_domain_name = self.api.env.domain

        self.log.comment('make sure bind-utils are installed so that we can '
                         'dig for ipa-ca records')
        self.log.exit_on_failed_command(
            'yum install -y bind-utils',
            ['Failed to install bind-utils'])

        self.log.comment('make sure ipa-ca records are resolvable, '
                         'otherwise error out and instruct')
        self.log.comment('the user to update the DNS infrastructure')
        self.log.command('ipaca_records=$(dig +short '
                         'ipa-ca.{})'.format(ipa_domain_name))

        self.log.exit_on_predicate(
            '[ -z "$ipaca_records" ]',
            [
                'Can not resolve ipa-ca records for ${domain_name}',
                'Please make sure to update your DNS infrastructure with ',
                'ipa-ca record pointing to IP addresses of IPA CA masters'
            ])

    def enable_ssl_ocsp(self):
        self.log.comment('look for the OCSP directive in ssl.conf')
        self.log.comment(' if it is present, switch it on')
        self.log.comment(
            'if it is absent, append it to the end of VirtualHost section')
        predicate = self._interpolate_ocsp_directive_file_into_command(
            "grep -q '{directive} ' {filename}")

        self.log.commands_on_predicate(
            predicate,
            [
                self._interpolate_ocsp_directive_file_into_command(
                    "sed -i.ipabkp -r "
                    "'s/^#*[[:space:]]*{directive}[[:space:]]+(on|off)$"
                    "/{directive} on/' {filename}")
            ],
            commands_to_run_when_false=[
                self._interpolate_ocsp_directive_file_into_command(
                    r"sed -i.ipabkp '/<\/VirtualHost>/i {directive} on' "
                    r"{filename}")
            ]
        )

    def _interpolate_ocsp_directive_file_into_command(self, fmt_line):
        return self._format_command(
            fmt_line, self.ssl_ocsp_directive, self.ssl_conf)

    def _format_command(self, fmt_line, directive, filename):
        return fmt_line.format(directive=directive, filename=filename)

    def restart_httpd(self):
        self.log.comment('finally restart apache')
        self.log.command('systemctl restart httpd')

    def record_httpd_ocsp_status(self):
        self.log.comment('store the OCSP upgrade state')
        self.log.command(
            "python3 -c 'from ipaserver.install import sysupgrade; "
            "sysupgrade.set_upgrade_state(\"httpd\", "
            "\"{}\", True)'".format(OCSP_ENABLED))

    def check_and_enable_pkinit(self):
        self.log.comment('check whether PKINIT is configured on the master')
        with self.log.if_branch(
                "ipa-pkinit-manage status | grep -q 'enabled'"):
            self.log.command('echo "PKINIT already enabled"')
        with self.log.else_branch():
            self.log.exit_on_failed_command(
                'ipa-pkinit-manage enable',
                ['Failed to issue PKINIT certificates to local KDC'])

    def enable_ok_to_auth_as_delegate_on_http_principal(self):
        self.log.comment('Enable OK-AS-DELEGATE flag on the HTTP principal')
        self.log.comment('This enables smart card login to WebUI')
        self.log.command(
            'output=$(ipa service-mod HTTP/$(hostname -f) '
            '--ok-to-auth-as-delegate=True 2>&1)')
        self.log.exit_on_predicate(
            '[ "$?" -ne "0" -a '
            '-z "$(echo $output | grep \'no modifications\')" ]',
            ["Failed to set OK_AS_AUTH_AS_DELEGATE flag on HTTP principal"]
        )

    def restart_kdc(self):
        self.log.exit_on_failed_command(
            'systemctl restart {}'.format(self.kdc_service_name),
            ['Failed to restart KDC. Please restart the service manually.']
        )


@register()
class config_client_for_smart_card_auth(common_smart_card_auth_config):
    """
    Configures smart card authentication on FreeIPA client
    """

    description = ("Instructions for enabling Smart Card authentication on "
                   " a single FreeIPA client. Configures Smart Card daemon, "
                   "set the system-wide trust store and configures SSSD to "
                   "allow smart card logins to desktop")

    opensc_module_name = "OpenSC"
    pkcs11_shared_lib = '/usr/lib64/opensc-pkcs11.so'
    smart_card_service_file = 'pcscd.service'
    smart_card_socket = 'pcscd.socket'

    def get_info(self):
        self.log.exit_on_nonroot_euid()
        self.check_and_set_ca_cert_paths()
        self.check_ccache_not_empty()
        self.check_and_remove_pam_pkcs11()
        self.install_opensc_and_dconf_packages()
        self.install_krb5_client_dependencies()
        self.start_enable_smartcard_daemon()
        self.add_pkcs11_module_to_systemwide_db()
        self.upload_smartcard_ca_certificates_to_systemwide_db()
        self.update_ipa_ca_certificate_store()
        self.run_authselect_to_configure_smart_card_auth()
        self.configure_pam_cert_auth()
        self.restart_sssd()

    def check_and_remove_pam_pkcs11(self):
        self.log.command('rpm -qi pam_pkcs11 > /dev/null')
        self.log.commands_on_predicate(
            '[ "$?" -eq "0" ]',
            [
                'yum remove -y pam_pkcs11'
            ]
        )

    def install_opensc_and_dconf_packages(self):
        self.log.comment(
            'authconfig often complains about missing dconf, '
            'install it explicitly')
        self.log.exit_on_failed_command(
            'yum install -y {} dconf'.format(self.opensc_module_name.lower()),
            ['Could not install OpenSC package']
        )

    def install_krb5_client_dependencies(self):
        self.log.exit_on_failed_command(
            'yum install -y krb5-pkinit-openssl',
            ['Failed to install Kerberos client PKINIT extensions.']
        )

    def start_enable_smartcard_daemon(self):
        self.log.command(
            'systemctl start {service} {socket} '
            '&& systemctl enable {service} {socket}'.format(
                service=self.smart_card_service_file,
                socket=self.smart_card_socket))

    def add_pkcs11_module_to_systemwide_db(self):
        module_name = self.opensc_module_name
        nssdb = self.systemwide_nssdb
        shared_lib = self.pkcs11_shared_lib

        self.log.commands_on_predicate(
            'modutil -dbdir {} -list | grep -q {}'.format(
                nssdb, module_name),
            [
                'echo "{} PKCS#11 module already configured"'.format(
                    module_name)
            ],
            commands_to_run_when_false=[
                'echo "" | modutil -dbdir {} -add "{}" -libfile {}'.format(
                    nssdb, module_name, shared_lib),
            ]
        )

    def run_authselect_to_configure_smart_card_auth(self):
        self.log.exit_on_failed_command(
            'authselect enable-feature with-smartcard',
            [
                'Failed to configure Smart Card authentication in SSSD'
            ]
        )

    def configure_pam_cert_auth(self):
        self.log.comment('Set pam_cert_auth=True in /etc/sssd/sssd.conf')
        self.log.command(
            "python3 -c 'from SSSDConfig import SSSDConfig; "
            "c = SSSDConfig(); c.import_config(); "
            "c.set(\"pam\", \"pam_cert_auth\", \"True\"); "
            "c.write()'")

    def restart_sssd(self):
        self.log.command('systemctl restart sssd.service')
