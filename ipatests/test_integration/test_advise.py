# Authors:
#   Gabe Alford <redhatrises@gmail.com>
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

# FIXME: Pylint errors
# pylint: disable=no-member

import re
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


def run_advice(master, advice_id, advice_regex, raiseerr):
    # Obtain the advice from the server
    tasks.kinit_admin(master)
    result = master.run_command(['ipa-advise', advice_id],
                                     raiseonerr=raiseerr)

    if not result.stdout_text:
        advice = result.stderr_text
    else:
        advice = result.stdout_text

    assert re.search(advice_regex, advice, re.S)


class TestAdvice(IntegrationTest):
    """
    Tests ipa-advise output.
    """
    advice_id = None
    raiseerr = None
    advice_regex = ''
    topology = 'line'

    def test_invalid_advice(self):
        advice_id = 'invalid-advise-param'
        advice_regex = "invalid[\s]+\'advice\'.*"
        raiseerr = False

        run_advice(self.master, advice_id, advice_regex, raiseerr)


    def test_advice_FreeBSDNSSPAM(self):
        advice_id = 'config-freebsd-nss-pam-ldapd'
        advice_regex = "\#\!\/bin\/sh.*" \
                       "pkg_add[\s]+\-r[\s]+nss\-pam\-ldapd[\s]+curl.*" \
                       "\/usr\/local\/etc\/rc\.d\/nslcd[\s]+restart"
        raiseerr = True

        run_advice(self.master, advice_id, advice_regex, raiseerr)


    def test_advice_GenericNSSPAM(self):
        advice_id = 'config-generic-linux-nss-pam-ldapd'
        advice_regex = "\#\!\/bin\/sh.*" \
                       "apt\-get[\s]+\-y[\s]+install[\s]+curl[\s]+openssl[\s]+" \
                       "libnss\-ldapd[\s]+libpam\-ldapd[\s]+nslcd.*" \
                       "service[\s]+nscd[\s]+stop[\s]+\&\&[\s]+service[\s]+" \
                       "nslcd[\s]+restart"
        raiseerr = True

        run_advice(self.master, advice_id, advice_regex, raiseerr)


    def test_advice_GenericSSSDBefore19(self):
        advice_id = 'config-generic-linux-sssd-before-1-9'
        advice_regex = "\#\!\/bin\/sh.*" \
                       "apt\-get[\s]+\-y[\s]+install sssd curl openssl.*" \
                       "service[\s]+sssd[\s]+start"
        raiseerr = True

        run_advice(self.master, advice_id, advice_regex, raiseerr)


    def test_advice_RedHatNSS(self):
        advice_id = 'config-redhat-nss-ldap'
        advice_regex = "\#\!\/bin\/sh.*" \
                       "yum[\s]+install[\s]+\-y[\s]+curl[\s]+openssl[\s]+nss_ldap" \
                       "[\s]+authconfig.*authconfig[\s]+\-\-updateall" \
                       "[\s]+\-\-enableldap[\s]+\-\-enableldaptls"\
                       "[\s]+\-\-enableldapauth[\s]+" \
                       "\-\-ldapserver=.*[\s]+\-\-ldapbasedn=.*"
        raiseerr = True

        run_advice(self.master, advice_id, advice_regex, raiseerr)


    def test_advice_RedHatNSSPAM(self):
        advice_id = 'config-redhat-nss-pam-ldapd'
        advice_regex = "\#\!\/bin\/sh.*" \
                       "yum[\s]+install[\s]+\-y[\s]+curl[\s]+openssl[\s]+" \
                       "nss\-pam\-ldapd[\s]+pam_ldap[\s]+authconfig.*" \
                       "authconfig[\s]+\-\-updateall[\s]+\-\-enableldap"\
                       "[\s]+\-\-enableldaptls[\s]+\-\-enableldapauth[\s]+" \
                       "\-\-ldapserver=.*[\s]+\-\-ldapbasedn=.*"
        raiseerr = True

        run_advice(self.master, advice_id, advice_regex, raiseerr)


    def test_advice_RedHatSSSDBefore19(self):
        advice_id = 'config-redhat-sssd-before-1-9'
        advice_regex = "\#\!\/bin\/sh.*" \
                       "yum[\s]+install[\s]+\-y[\s]+sssd[\s]+authconfig[\s]+" \
                       "curl[\s]+openssl.*service[\s]+sssd[\s]+start"
        raiseerr = True

        run_advice(self.master, advice_id, advice_regex, raiseerr)
