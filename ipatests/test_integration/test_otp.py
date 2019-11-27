#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#
"""OTP token tests
"""
import base64
import re
import time
from urllib.parse import urlparse, parse_qs

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.twofactor.hotp import HOTP
from cryptography.hazmat.primitives.twofactor.totp import TOTP

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


PASSWORD = "DummyPassword123"
USER = "opttestuser"
ARMOR = "/tmp/armor"


def add_otptoken(host, owner, *, otptype="hotp", digits=6, algo="sha1"):
    args = [
        "ipa",
        "otptoken-add",
        "--owner",
        owner,
        "--type",
        otptype,
        "--digits",
        str(digits),
        "--algo",
        algo,
        "--no-qrcode",
    ]
    result = host.run_command(args)
    otpuid = re.search(
        r"Unique ID:\s*([a-z0-9-]*)\s+", result.stdout_text
    ).group(1)
    otpuristr = re.search(r"URI:\s*(.*)\s+", result.stdout_text).group(1)
    otpuri = urlparse(otpuristr)
    assert otpuri.netloc == otptype

    query = parse_qs(otpuri.query)
    assert query["algorithm"][0] == algo.upper()
    assert query["digits"][0] == str(digits)
    key = base64.b32decode(query["secret"][0])
    assert len(key) == 35

    hashcls = getattr(hashes, algo.upper())
    if otptype == "hotp":
        return otpuid, HOTP(key, digits, hashcls(), default_backend())
    else:
        period = int(query["period"][0])
        return otpuid, TOTP(key, digits, hashcls(), period, default_backend())


def del_otptoken(host, otpuid):
    tasks.kinit_admin(host)
    host.run_command(["ipa", "otptoken-del", otpuid])


def kinit_otp(host, user, *, password, otp, success=True):
    tasks.kdestroy_all(host)
    # create armor for FAST
    host.run_command(["kinit", "-n", "-c", ARMOR])
    host.run_command(
        ["kinit", "-T", ARMOR, user],
        stdin_text=f"{password}{otp}\n",
        ok_returncode=0 if success else 1,
    )


class TestOTPToken(IntegrationTest):
    """Tests for member manager feature for groups and hostgroups
    """

    topology = "line"

    @classmethod
    def install(cls, mh):
        super(TestOTPToken, cls).install(mh)
        master = cls.master

        tasks.kinit_admin(master)
        # create service with OTP auth indicator
        cls.service_name = f"otponly/{master.hostname}"
        master.run_command(
            ["ipa", "service-add", cls.service_name, "--auth-ind=otp"]
        )
        # service needs a keytab before user can acquire a ticket for it
        keytab = "/tmp/otponly.keytab"
        master.run_command(
            ["ipa-getkeytab", "-p", cls.service_name, "-k", keytab]
        )
        master.run_command(["rm", "-f", keytab])

        tasks.create_active_user(master, USER, PASSWORD)
        tasks.kinit_admin(master)
        master.run_command(["ipa", "user-mod", USER, "--user-auth-type=otp"])

    @classmethod
    def uninstall(cls, mh):
        cls.master.run_command(["rm", "-f", ARMOR])
        super(TestOTPToken, cls).uninstall(mh)

    def test_otp_auth_ind(self):
        tasks.kinit_admin(self.master)
        result = self.master.run_command(
            ["kvno", self.service_name], ok_returncode=1
        )
        assert "KDC policy rejects request" in result.stderr_text

    def test_hopt(self):
        master = self.master

        tasks.kinit_admin(self.master)
        otpuid, hotp = add_otptoken(master, USER, otptype="hotp")
        master.run_command(["ipa", "otptoken-show", otpuid])
        # normal password login fails
        master.run_command(
            ["kinit", USER], stdin_text=f"{PASSWORD}\n", ok_returncode=1
        )
        # OTP login works
        otpvalue = hotp.generate(0).decode("ascii")
        kinit_otp(master, USER, password=PASSWORD, otp=otpvalue)
        # repeating OTP fails
        kinit_otp(
            master, USER, password=PASSWORD, otp=otpvalue, success=False
        )
        # skipping an OTP is ok
        otpvalue = hotp.generate(2).decode("ascii")
        kinit_otp(master, USER, password=PASSWORD, otp=otpvalue)
        # TGT with OTP auth indicator can get a ticket for OTP-only service
        master.run_command(["kvno", self.service_name])
        result = master.run_command(["klist"])
        assert self.service_name in result.stdout_text

        del_otptoken(master, otpuid)

    def test_totp(self):
        master = self.master

        tasks.kinit_admin(self.master)
        otpuid, totp = add_otptoken(master, USER, otptype="totp")

        otpvalue = totp.generate(int(time.time())).decode("ascii")
        kinit_otp(master, USER, password=PASSWORD, otp=otpvalue)
        # TGT with OTP auth indicator can get a ticket for OTP-only service
        master.run_command(["kvno", self.service_name])
        result = master.run_command(["klist"])
        assert self.service_name in result.stdout_text

        del_otptoken(master, otpuid)

    def test_otptoken_sync(self):
        master = self.master

        tasks.kinit_admin(self.master)
        otpuid, hotp = add_otptoken(master, USER, otptype="hotp")

        otp1 = hotp.generate(10).decode("ascii")
        otp2 = hotp.generate(11).decode("ascii")

        master.run_command(
            ["ipa", "otptoken-sync", "--user", USER],
            stdin_text=f"{PASSWORD}\n{otp1}\n{otp2}\n",
        )
        otpvalue = hotp.generate(12).decode("ascii")
        kinit_otp(master, USER, password=PASSWORD, otp=otpvalue)

        otp1 = hotp.generate(20).decode("ascii")
        otp2 = hotp.generate(21).decode("ascii")

        master.run_command(
            ["ipa", "otptoken-sync", otpuid, "--user", USER],
            stdin_text=f"{PASSWORD}\n{otp1}\n{otp2}\n",
        )
        otpvalue = hotp.generate(22).decode("ascii")
        kinit_otp(master, USER, password=PASSWORD, otp=otpvalue)

        del_otptoken(master, otpuid)
