# Authors: Ana Krivokapic <akrivoka@redhat.com>
#
# Copyright (C) 2013  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
from __future__ import absolute_import

import os

from ipalib import api
from ipalib.plugable import Registry
from ipaplatform.paths import paths
from ipaserver.advise.base import Advice
from ipapython.ipautil import template_file

register = Registry()

CACERTDIR_REHASH_URL = ('https://pagure.io/authconfig/raw/master/f/'
                        'cacertdir_rehash')


class config_base_legacy_client(Advice):
    def get_uri_and_base(self):
        uri = 'ldap://%s' % api.env.host
        base = 'cn=compat,%s' % api.env.basedn
        return uri, base

    def check_compat_plugin(self):
        compat_is_enabled = api.Command['compat_is_enabled']()['result']
        if not compat_is_enabled:
            self.log.comment(
                'Schema Compatibility plugin has not been configured '
                'on this server. To configure it, run '
                '"ipa-adtrust-install --enable-compat"\n'
            )

    def configure_ca_cert(self):
        self.log.comment('Please note that this script assumes '
                         '/etc/openldap/cacerts as the default CA certificate '
                         'location. If this value is different on your system '
                         'the script needs to be modified accordingly.\n')

        self.log.comment('Download the CA certificate of the IPA server')
        self.log.command('mkdir -p -m 755 /etc/openldap/cacerts')
        self.log.command('curl http://%s/ipa/config/ca.crt -o '
                         '/etc/openldap/cacerts/ipa.crt\n' % api.env.host)

        self.log.comment('Generate hashes for the openldap library')
        self.log.command('command -v cacertdir_rehash')
        self.log.command('if [ $? -ne 0 ] ; then')
        self.log.command(' curl "%s" -o cacertdir_rehash ;' %
                         CACERTDIR_REHASH_URL)
        self.log.command(' chmod 755 ./cacertdir_rehash ;')
        self.log.command(' ./cacertdir_rehash /etc/openldap/cacerts/ ;')
        self.log.command('else')
        self.log.command(' cacertdir_rehash /etc/openldap/cacerts/ ;')
        self.log.command('fi\n')

    def configure_and_start_sssd(self):
        uri, base = self.get_uri_and_base()
        template = os.path.join(
            paths.USR_SHARE_IPA_DIR,
            'advise',
            'legacy',
            'sssd.conf.template'
        )
        sssd_conf = template_file(template, dict(URI=uri, BASE=base))

        self.log.comment('Configure SSSD')
        self.log.command('cat > /etc/sssd/sssd.conf << EOF \n'
                         '%s\nEOF' % sssd_conf)
        self.log.command('chmod 0600 /etc/sssd/sssd.conf\n')

        self.log.comment('Start SSSD')
        self.log.command('service sssd start')


@register()
class config_redhat_sssd_before_1_9(config_base_legacy_client):
    """
    Legacy client configuration for Red Hat based systems, using SSSD.
    """
    description = ('Instructions for configuring a system with an old version '
                   'of SSSD (1.5-1.8) as a FreeIPA client. This set of '
                   'instructions is targeted for platforms that include '
                   'the authconfig utility, which are all Red Hat based '
                   'platforms.')

    def get_info(self):
        self.check_compat_plugin()

        self.log.comment('Install required packages via yum')
        self.log.command('yum install -y sssd authconfig curl openssl\n')

        self.configure_ca_cert()

        self.log.comment('Use the authconfig to configure nsswitch.conf '
                         'and the PAM stack')
        self.log.command('authconfig --updateall --enablesssd '
                         '--enablesssdauth\n')

        self.configure_and_start_sssd()

    def configure_ca_cert(self):
        self.log.comment('NOTE: IPA certificate uses the SHA-256 hash '
                         'function. SHA-256 was introduced in RHEL5.2. '
                         'Therefore, clients older than RHEL5.2 will not be '
                         'able to interoperate with IPA server 3.x.')
        super(config_redhat_sssd_before_1_9, self).configure_ca_cert()


@register()
class config_generic_linux_sssd_before_1_9(config_base_legacy_client):
    """
    Legacy client configuration for non Red Hat based linux systems,
    using SSSD.
    """
    description = ('Instructions for configuring a system with an old version '
                   'of SSSD (1.5-1.8) as a FreeIPA client. This set of '
                   'instructions is targeted for linux systems that do not '
                   'include the authconfig utility.')

    def get_info(self):
        self.check_compat_plugin()

        with open(os.path.join(
                paths.USR_SHARE_IPA_DIR,
                'advise',
                'legacy',
                'pam.conf.sssd.template')) as fd:
            pam_conf = fd.read()

        self.log.comment('Install required packages using your system\'s '
                         'package manager. E.g:')
        self.log.command('apt-get -y install sssd curl openssl\n')

        self.configure_ca_cert()

        self.log.comment('Configure nsswitch.conf. Append sss to the lines '
                         'beginning with passwd and group. ')
        self.log.command('grep "^passwd.*sss" /etc/nsswitch.conf')
        self.log.command('if [ $? -ne 0 ] ; then sed -i '
                         '\'/^passwd/s|$| sss|\' /etc/nsswitch.conf ; fi')
        self.log.command('grep "^group.*sss" /etc/nsswitch.conf')
        self.log.command('if [ $? -ne 0 ] ; then sed -i '
                         '\'/^group/s|$| sss|\' /etc/nsswitch.conf ; fi\n')

        self.log.comment('Configure PAM. Configuring the PAM stack differs on '
                         'particular distributions. The resulting PAM stack '
                         'should look like this:')
        self.log.command('cat > /etc/pam.conf << EOF \n'
                         '%s\nEOF\n' % pam_conf)

        self.configure_and_start_sssd()

    def configure_ca_cert(self):
        super(config_generic_linux_sssd_before_1_9, self).configure_ca_cert()

        self.log.comment('Configure ldap.conf. Set the value of '
                         'TLS_CACERTDIR to /etc/openldap/cacerts. Make sure '
                         'that the location of ldap.conf file matches your '
                         'system\'s configuration.')
        self.log.command('echo "TLS_CACERTDIR /etc/openldap/cacerts" >> '
                         '/etc/ldap/ldap.conf\n')


@register()
class config_redhat_nss_pam_ldapd(config_base_legacy_client):
    """
    Legacy client configuration for Red Hat based systems,
    using nss-pam-ldapd.
    """
    description = ('Instructions for configuring a system with nss-pam-ldapd '
                   'as a FreeIPA client. This set of instructions is targeted '
                   'for platforms that include the authconfig utility, which '
                   'are all Red Hat based platforms.')

    def get_info(self):
        uri, base = self.get_uri_and_base()
        self.check_compat_plugin()

        self.log.comment('Install required packages via yum')
        self.log.command('yum install -y curl openssl nss-pam-ldapd pam_ldap '
                         'authconfig\n')

        self.configure_ca_cert()

        self.log.comment('Use the authconfig to configure nsswitch.conf '
                         'and the PAM stack')
        self.log.command('authconfig --updateall --enableldap --enableldaptls '
                         '--enableldapauth --ldapserver=%s --ldapbasedn=%s\n'
                         % (uri, base))

    def configure_ca_cert(self):
        self.log.comment('NOTE: IPA certificate uses the SHA-256 hash '
                         'function. SHA-256 was introduced in RHEL5.2. '
                         'Therefore, clients older than RHEL5.2 will not be '
                         'able to interoperate with IPA server 3.x.')
        super(config_redhat_nss_pam_ldapd, self).configure_ca_cert()


@register()
class config_generic_linux_nss_pam_ldapd(config_base_legacy_client):
    """
    Legacy client configuration for non Red Hat based linux systems,
    using nss-pam-ldapd.
    """
    description = ('Instructions for configuring a system with nss-pam-ldapd. '
                   'This set of instructions is targeted for linux systems '
                   'that do not include the authconfig utility.')

    def get_info(self):
        uri, base = self.get_uri_and_base()
        self.check_compat_plugin()

        with open(os.path.join(
                paths.USR_SHARE_IPA_DIR,
                'advise',
                'legacy',
                'pam.conf.nss_pam_ldapd.template')) as fd:
            pam_conf = fd.read()

        nslcd_conf = 'uri %s\nbase %s' % (uri, base)

        self.log.comment('Install required packages using your system\'s '
                         'package manager. E.g:')
        self.log.command('apt-get -y install curl openssl libnss-ldapd '
                         'libpam-ldapd nslcd\n')

        self.configure_ca_cert()

        self.log.comment('Configure nsswitch.conf. Append ldap to the lines '
                         'beginning with passwd and group. ')
        self.log.command('grep "^passwd.*ldap" /etc/nsswitch.conf')
        self.log.command('if [ $? -ne 0 ] ; then sed -i '
                         '\'/^passwd/s|$| ldap|\' /etc/nsswitch.conf ; fi')
        self.log.command('grep "^group.*ldap" /etc/nsswitch.conf')
        self.log.command('if [ $? -ne 0 ] ; then sed -i '
                         '\'/^group/s|$| ldap|\' /etc/nsswitch.conf ; fi\n')

        self.log.comment('Configure PAM. Configuring the PAM stack differs on '
                         'particular distributions. The resulting PAM stack '
                         'should look like this:')
        self.log.command('cat > /etc/pam.conf << EOF \n'
                         '%s\nEOF\n' % pam_conf)

        self.log.comment('Configure nslcd.conf:')
        self.log.command('cat > /etc/nslcd.conf << EOF \n'
                         '%s\nEOF\n' % nslcd_conf)

        self.log.comment('Configure pam_ldap.conf:')
        self.log.command('cat > /etc/pam_ldap.conf << EOF \n'
                         '%s\nEOF\n' % nslcd_conf)

        self.log.comment('Stop nscd and restart nslcd')
        self.log.command('service nscd stop && service nslcd restart')

    def configure_ca_cert(self):
        super(config_generic_linux_nss_pam_ldapd, self).configure_ca_cert()

        self.log.comment('Configure ldap.conf. Set the value of '
                         'TLS_CACERTDIR to /etc/openldap/cacerts. Make sure '
                         'that the location of ldap.conf file matches your '
                         'system\'s configuration.')
        self.log.command('echo "TLS_CACERTDIR /etc/openldap/cacerts" >> '
                         '/etc/ldap/ldap.conf\n')


@register()
class config_freebsd_nss_pam_ldapd(config_base_legacy_client):
    """
    Legacy client configuration for FreeBSD, using nss-pam-ldapd.
    """
    description = ('Instructions for configuring a FreeBSD system with '
                   'nss-pam-ldapd. ')

    def get_info(self):
        uri, base = self.get_uri_and_base()
        cacrt = '/usr/local/etc/ipa.crt'

        self.check_compat_plugin()

        with open(os.path.join(
                paths.USR_SHARE_IPA_DIR,
                'advise',
                'legacy',
                'pam_conf_sshd.template')) as fd:
            pam_conf = fd.read()

        self.log.comment('Install required packages')
        self.log.command('pkg_add -r nss-pam-ldapd curl\n')

        self.configure_ca_cert(cacrt)

        self.log.comment('Configure nsswitch.conf')
        self.log.command('sed -i \'\' -e \'s/^passwd:/passwd: files ldap/\' '
                         '/etc/nsswitch.conf')
        self.log.command('sed -i \'\' -e \'s/^group:/group: files ldap/\' '
                         '/etc/nsswitch.conf\n')

        self.log.comment('Configure PAM stack for the sshd service')
        self.log.command('cat > /etc/pam.d/sshd << EOF \n'
                         '%s\nEOF\n' % pam_conf)

        self.log.comment('Add automated start of nslcd to /etc/rc.conf')
        self.log.command('echo \'nslcd_enable="YES"\nnslcd_debug="NO"\' >> '
                         '/etc/rc.conf')

        self.log.comment('Configure nslcd.conf:')
        self.log.command('echo "uid nslcd\n'
                         'gid nslcd\n'
                         'uri %s\n'
                         'base %s\n'
                         'scope sub\n'
                         'base group cn=groups,%s\n'
                         'base passwd cn=users,%s\n'
                         'base shadow cn=users,%s\n'
                         'ssl start_tls\n'
                         'tls_cacertfile %s\n" >  /usr/local/etc/nslcd.conf'
                         % ((uri,) + (base,)*4 + (cacrt,)))

        self.log.comment('Configure ldap.conf:')
        self.log.command('echo "uri %s\nbase %s\nssl start_tls\ntls_cacert %s"'
                         '> /usr/local/etc/ldap.conf' % (uri, base, cacrt))

        self.log.comment('Restart nslcd')
        self.log.command('/usr/local/etc/rc.d/nslcd restart')

    def configure_ca_cert(self, cacrt):
        self.log.comment('Download the CA certificate of the IPA server')
        self.log.command('curl -k https://%s/ipa/config/ca.crt > '
                         '%s' % (api.env.host, cacrt))


@register()
class config_redhat_nss_ldap(config_base_legacy_client):
    """
    Legacy client configuration for Red Hat based systems,
    using nss-ldap.
    """
    description = ('Instructions for configuring a system with nss-ldap '
                   'as a FreeIPA client. This set of instructions is targeted '
                   'for platforms that include the authconfig utility, which '
                   'are all Red Hat based platforms.')

    def get_info(self):
        uri, base = self.get_uri_and_base()
        self.check_compat_plugin()

        self.log.comment('Install required packages via yum')
        self.log.command('yum install -y curl openssl nss_ldap '
                         'authconfig\n')

        self.configure_ca_cert()

        self.log.comment('Use the authconfig to configure nsswitch.conf '
                         'and the PAM stack')
        self.log.command('authconfig --updateall --enableldap --enableldaptls '
                         '--enableldapauth --ldapserver=%s --ldapbasedn=%s\n'
                         % (uri, base))

    def configure_ca_cert(self):
        self.log.comment('NOTE: IPA certificate uses the SHA-256 hash '
                         'function. SHA-256 was introduced in RHEL5.2. '
                         'Therefore, clients older than RHEL5.2 will not be '
                         'able to interoperate with IPA server 3.x.')
        super(config_redhat_nss_ldap, self).configure_ca_cert()
