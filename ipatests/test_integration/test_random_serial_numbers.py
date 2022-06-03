#
# Copyright (C) 2022  FreeIPA Contributors see COPYING for license
#

import pytest

from ipatests.test_integration.test_installation import (
    TestInstallWithCA_DNS1,
    TestInstallWithCA_KRA1,
)
from ipatests.test_integration.test_caless import TestServerCALessToExternalCA

from ipatests.test_integration.test_commands import TestIPACommand


def pki_supports_RSNv3(host):
    """
    Return whether the host supports RNSv3 based on the pki version
    """
    script = ("from ipaserver.install.ca import "
              "random_serial_numbers_version; "
              "print(random_serial_numbers_version(True))")
    result = host.run_command(['python3', '-c', script])
    if 'true' in result.stdout_text.strip().lower():
        return True
    return False


class TestInstallWithCA_DNS1_RSN(TestInstallWithCA_DNS1):
    random_serial = True

    @classmethod
    def install(cls, mh):
        if not pki_supports_RSNv3(mh.master):
            raise pytest.skip("RNSv3 not supported")
        super(TestInstallWithCA_DNS1_RSN, cls).install(mh)


class TestInstallWithCA_KRA1_RSN(TestInstallWithCA_KRA1):
    random_serial = True

    @classmethod
    def install(cls, mh):
        if not pki_supports_RSNv3(mh.master):
            raise pytest.skip("RNSv3 not supported")
        super(TestInstallWithCA_KRA1_RSN, cls).install(mh)


class TestIPACommand_RSN(TestIPACommand):
    random_serial = True

    @classmethod
    def install(cls, mh):
        if not pki_supports_RSNv3(mh.master):
            raise pytest.skip("RNSv3 not supported")
        super(TestIPACommand_RSN, cls).install(mh)


class TestServerCALessToExternalCA_RSN(TestServerCALessToExternalCA):
    random_serial = True

    @classmethod
    def install(cls, mh):
        if not pki_supports_RSNv3(mh.master):
            raise pytest.skip("RNSv3 not supported")
        super(TestServerCALessToExternalCA_RSN, cls).install(mh)
