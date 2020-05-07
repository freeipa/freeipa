#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
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

from __future__ import print_function, absolute_import

import datetime
import json
import logging
import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

logger = logging.getLogger(__name__)


def datetime_to_generalized_time(dt):
    """Convert datetime to LDAP_GENERALIZED_TIME_FORMAT
       Note: Move into ipalib.
    """
    dt = dt.timetuple()
    generalized_time_str = str(dt.tm_year) + "".join(
        "0" * (2 - len(str(item))) + str(item)
        for item in (dt.tm_mon, dt.tm_mday, dt.tm_hour, dt.tm_min, dt.tm_sec,)
    )
    return generalized_time_str + "Z"


def configure_postfix(host):
    """Configure postfix to be the destination of the IPA domain.
    """
    host.run_command(["systemctl", "start", "postfix"])
    result = host.run_command(["postconf", "mydestination"])
    mydestination = result.stdout_text.strip() + ", " + host.domain.name
    cmd = ["postconf", "-e", mydestination]
    print(cmd)
    host.run_command(cmd)


class TestEPN(IntegrationTest):
    """Test Suite for EPN: https://pagure.io/freeipa/issue/3687
    """

    num_clients = 1

    def _check_epn_output(
        self,
        host,
        dry_run=False,
        from_nbdays=None,
        to_nbdays=None,
        raiseonerr=True,
    ):
        result = tasks.ipa_epn(host, raiseonerr=raiseonerr, dry_run=dry_run,
                               from_nbdays=from_nbdays,
                               to_nbdays=to_nbdays)
        json.dumps(json.loads(result.stdout_text), ensure_ascii=False)
        return (result.stdout_text, result.stderr_text)

    @classmethod
    def install(cls, mh):
        tasks.install_packages(cls.master, ["postfix"])
        tasks.install_packages(cls.clients[0], ["postfix"])
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_client(cls.master, cls.clients[0])
        configure_postfix(cls.master)
        configure_postfix(cls.clients[0])

    @classmethod
    def uninstall(cls, mh):
        super(TestEPN, cls).uninstall(mh)
        tasks.uninstall_packages(cls.master, ["postfix"])
        tasks.uninstall_packages(cls.clients[0], ["postfix"])

    def test_EPN_smoketest_1(self):
        """No users except admin. Check --dry-run output.
           With the default configuration, the result should be an empty list.
           Also check behavior on master and client alike.
        """
        # check EPN on client (LDAP+GSSAPI)
        (stdout_text, unused) = self._check_epn_output(
            self.clients[0], dry_run=True
        )
        assert len(json.loads(stdout_text)) == 0
        # check EPN on master (LDAPI)
        (stdout_text, unused) = self._check_epn_output(
            self.master, dry_run=True
        )
        assert len(json.loads(stdout_text)) == 0

    @pytest.fixture
    def cleanupusers(self):
        """Fixture to remove any users added as part of the tests.

           It isn't necessary to remove all users created.

           Ignore all errors.
        """
        yield
        for user in ["testuser0", "testuser1"]:
            try:
                self.master.run_command(['ipa', 'user-del', user])
            except Exception:
                pass

    def test_EPN_smoketest_2(self, cleanupusers):
        """Add a user without password.
           Add a user whose password expires within the default time range.
           Check --dry-run output.
        """
        tasks.user_add(self.master, "testuser0")
        tasks.user_add(
            self.master,
            "testuser1",
            password="Secret123",
            extra_args=[
                "--password-expiration",
                datetime_to_generalized_time(
                    datetime.datetime.utcnow() + datetime.timedelta(days=7)
                ),
            ],
        )
        (stdout_text_client, unused) = self._check_epn_output(
            self.clients[0], dry_run=True
        )
        print(json.dumps(json.loads(stdout_text_client), ensure_ascii=False))
        (stdout_text_master, unused) = self._check_epn_output(
            self.master, dry_run=True
        )
        print(json.dumps(json.loads(stdout_text_master), ensure_ascii=False))
        assert stdout_text_master == stdout_text_client
        assert "testuser0" not in stdout_text_client
        assert "testuser1" in stdout_text_client

    def test_EPN_smoketest_3(self):
        """Add a bunch of users with incrementally expiring passwords
           (one per day). Check --dry-run output.
        """

        users = {}
        userbase_str = "user"

        for i in range(30):
            uid = userbase_str + str(i)
            users[i] = dict(
                uid=uid,
                days=i,
                krbpasswordexpiration=datetime_to_generalized_time(
                    datetime.datetime.utcnow() + datetime.timedelta(days=i)
                ),
            )

        for key in users:
            tasks.user_add(
                self.master,
                users[key]["uid"],
                extra_args=[
                    "--password-expiration",
                    users[key]["krbpasswordexpiration"],
                ],
                password=None,
            )

        (stdout_text_client, unused) = self._check_epn_output(
            self.clients[0], dry_run=True
        )
        print(json.dumps(json.loads(stdout_text_client), ensure_ascii=False))
        (stdout_text_master, unused) = self._check_epn_output(
            self.master, dry_run=True
        )
        print(json.dumps(json.loads(stdout_text_master), ensure_ascii=False))
        assert stdout_text_master == stdout_text_client
        user_lst = []
        for user in json.loads(stdout_text_master):
            user_lst.append(user["uid"])
        expected_users = ["user1", "user3", "user7", "user14", "user28"]
        assert sorted(user_lst) == sorted(expected_users)

    def test_EPN_nbdays(self):
        """Test the to/from nbdays options (implies --dry-run)

           We have a set of users installed with varying expiration
           dates. Confirm that to/from nbdays finds them.
        """

        # Compare the notify_ttls values
        for i in (28, 14, 7, 3, 1):
            user_list = []
            (stdout_text_client, unused) = self._check_epn_output(
                self.clients[0], from_nbdays=i, to_nbdays=i + 1, dry_run=True)
            for user in json.loads(stdout_text_client):
                user_list.append(user["uid"])
            assert len(user_list) == 1
            assert user_list[0] == "user%d" % i
