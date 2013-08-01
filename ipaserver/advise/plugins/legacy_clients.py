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
import os

from ipalib import api
from ipalib.frontend import Advice
from ipapython.ipautil import template_file, SHARE_DIR


class config_base_sssd_before_1_9(Advice):
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

        cacertdir_rehash = ('https://fedorahosted.org/authconfig/browser/'
                            'cacertdir_rehash?format=txt')
        self.log.comment('Download the CA certificate of the IPA server')
        self.log.command('mkdir -p -m 755 /etc/openldap/cacerts')
        self.log.command('wget http://%s/ipa/config/ca.crt -O '
                         '/etc/openldap/cacerts/ipa.crt\n' % api.env.host)

        self.log.comment('Generate hashes for the openldap library')
        self.log.command('which cacertdir_rehash')
        self.log.command('if [ $? -ne 0 ] ; then')
        self.log.command(' wget "%s" -O cacertdir_rehash ;' % cacertdir_rehash)
        self.log.command(' chmod 755 ./cacertdir_rehash ;')
        self.log.command(' ./cacertdir_rehash /etc/openldap/cacerts/ ;')
        self.log.command('else')
        self.log.command(' cacertdir_rehash /etc/openldap/cacerts/ ;')
        self.log.command('fi\n')

    def configure_and_start_sssd(self):
        sub_dict = dict(
            IPA_SERVER_HOSTNAME=api.env.host,
            BASE_DN=','. join(['dc=%s' % c for c in api.env.domain.split('.')])
        )
        template = os.path.join(
            SHARE_DIR,
            'advise',
            'legacy',
            'sssd.conf.template'
        )
        sssd_conf = template_file(template, sub_dict)

        self.log.comment('Configure SSSD')
        self.log.command('cat > /etc/sssd/sssd.conf << EOF \n'
                         '%s\nEOF' % sssd_conf)
        self.log.command('chmod 0600 /etc/sssd/sssd.conf\n')

        self.log.comment('Start SSSD')
        self.log.command('service sssd start')


class config_redhat_sssd_before_1_9(config_base_sssd_before_1_9):
    """
    Legacy client configuration for Red Hat based platforms.
    """
    description = ('Instructions for configuring a system with an old version '
                   'of SSSD (1.5-1.8) as a FreeIPA client. This set of '
                   'instructions is targeted for platforms that include '
                   'the authconfig utility, which are all Red Hat based '
                   'platforms.')

    def get_info(self):
        self.check_compat_plugin()

        self.log.comment('Install required packages via yum')
        self.log.command('yum install -y sssd authconfig wget openssl\n')

        self.configure_ca_cert()

        self.log.comment('Use the authconfig to configure nsswitch.conf '
                         'and the PAM stack')
        self.log.command('authconfig --updateall --enablesssd '
                         '--enablesssdauth\n')

        self.configure_and_start_sssd()


api.register(config_redhat_sssd_before_1_9)


class config_generic_sssd_before_1_9(config_base_sssd_before_1_9):
    """
    Legacy client configuration for non Red Hat based platforms.
    """
    description = ('Instructions for configuring a system with an old version '
                   'of SSSD (1.5-1.8) as a FreeIPA client. This set of '
                   'instructions is targeted for platforms that do not '
                   'include the authconfig utility.')

    def get_info(self):
        self.check_compat_plugin()

        with open(os.path.join(
                SHARE_DIR,
                'advise',
                'legacy',
                'pam.conf.template')) as fd:
            pam_conf = fd.read()

        self.log.comment('Install required packages using your system\'s '
                         'package manager. E.g:')
        self.log.command('apt-get -y install sssd wget openssl\n')

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
        super(config_generic_sssd_before_1_9, self).configure_ca_cert()

        self.log.comment('Configure ldap.conf. Set the value of '
                         'TLS_CACERTDIR to /etc/openldap/cacerts. Make sure '
                         'that the location of ldap.conf file matches your '
                         'system\'s configuration.')
        self.log.command('echo "TLS_CACERTDIR /etc/openldap/cacerts" >> '
                         '/etc/ldap/ldap.conf\n')


api.register(config_generic_sssd_before_1_9)
