#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
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

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestSettings(IntegrationTest):
    """
    Test installation settings
    """
    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)
        tasks.install_replica(cls.master, cls.replicas[0], setup_ca=False)

    def test_nsslapd_db_deadlock_policy(self):
        """
        Check that nsslapd-db-deadlock-policy was set to DB_LOCK_MINWRITE (6)
        rather than DB_LOCK_YOUNGEST (9).
        """
        config_dn = 'cn=bdb,cn=config,cn=ldbm database,cn=plugins,cn=config'
        config_attr = 'nsslapd-db-deadlock-policy'
        expected_txt = 'nsslapd-db-deadlock-policy: 6'
        for host in (self.master, self.replicas[0]):
            result = tasks.ldapsearch_dm(
                host,
                config_dn,
                [config_attr],
            )
            text = result.stdout_text.lower()
            assert expected_txt in text
