#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#

from pathlib import Path
import textwrap

import pytest

from ipatests.pytest_ipa.integration.tasks import FileBackup
from ipatests.test_integration.base import IntegrationTest


OS_RELEASE_TEST_DATA = textwrap.dedent(
    """\
        NAME="Test Platform"
        VERSION="1"
        ID=testplatform
        ID_LIKE="foo bar"
        VERSION_ID="1.2"
    """
)

PATHS_CODE = textwrap.dedent(
    """\
        from ipaplatform.base.paths import BasePathNamespace


        class TestplatformPathsNamespace(BasePathNamespace):
            TEST_STR_PATH = "/foo/bar"
            TEST_INT_PATH = 1
            TEST_BOOL_PATH = True
            TEST_NONE_PATH = None
            TEST_LIST_PATH = ["foo", "bar"]
            TEST_TUPLE_PATH = ("foo", "bar")
            TEST_DICT_PATH = {"foo": "bar"}

            TEST_OBJ_PATH = object()
            def foo(self):
                pass

        paths = TestplatformPathsNamespace()
    """
)

CONSTANTS_CODE = textwrap.dedent(
    """\
        from ipaplatform.base.constants import (
            BaseConstantsNamespace,
            User,
            Group,
        )


        class TestplatformConstantsNamespace(BaseConstantsNamespace):
            TEST_STR_CONST = "/foo/bar"
            TEST_INT_CONST = 1
            TEST_BOOL_CONST = True
            TEST_NONE_CONST = None
            TEST_LIST_CONST = ["foo", "bar"]
            TEST_TUPLE_CONST = ("foo", "bar")
            TEST_DICT_CONST = {"foo": "bar"}

            TEST_USER_CONST = User("_someuser")
            TEST_GROUP_CONST = Group("_somegroup")

            TEST_OBJ_CONST = object()
            def foo(self):
                pass

        constants = TestplatformConstantsNamespace()
    """
)

TASKS_CODE = textwrap.dedent(
    """\
        from ipaplatform.redhat.tasks import RedHatTaskNamespace


        class TestplatformTaskNamespace(RedHatTaskNamespace):
            pass

        tasks = TestplatformTaskNamespace()
    """
)

SERVICES_CODE = textwrap.dedent(
    """\
        from ipaplatform.redhat import services as rh_services


        testplatform_system_units = rh_services.redhat_system_units.copy()
        testplatform_system_units = {"ipa": "foo-bar.service"}

        def testplatform_service_class_factory(name, api=None):
            if name in ["ipa"]:
                return TestplatformService(name, api)
            return rh_services.redhat_service_class_factory(name, api)


        class TestplatformService(rh_services.RedHatService):
            system_units = testplatform_system_units


        class TestplatformServices(rh_services.RedHatServices):
            def service_class_factory(self, name, api=None):
                return testplatform_service_class_factory(name, api)

        knownservices = TestplatformServices()
    """
)


@pytest.fixture(scope="class")
def remote_ipaplatform(request):
    """Prepare custom ipaplatform on remote host"""
    client = request.cls.replicas[0]
    test_platform = "testplatform"
    os_release = "/etc/os-release"

    result = client.run_command(
        [
            "python3",
            "-c",
            textwrap.dedent(
                """\
                    from pathlib import Path

                    import ipaplatform


                    print(Path(ipaplatform.__file__).parent)
                """
            ),
        ]
    )
    ipaplatform_path = Path(result.stdout_text.rstrip())
    platform_path = ipaplatform_path / test_platform
    override_path = ipaplatform_path / "override.py"
    paths_path = platform_path / "paths.py"
    constants_path = platform_path / "constants.py"
    tasks_path = platform_path / "tasks.py"
    services_path = platform_path / "services.py"

    with FileBackup(client, os_release):
        client.put_file_contents(os_release, OS_RELEASE_TEST_DATA)
        client.run_command(["mkdir", platform_path])

        with FileBackup(client, override_path):
            client.put_file_contents(
                override_path, f"OVERRIDE = '{test_platform}'"
            )
            client.put_file_contents(paths_path, PATHS_CODE)
            client.put_file_contents(constants_path, CONSTANTS_CODE)
            client.put_file_contents(tasks_path, TASKS_CODE)
            client.put_file_contents(services_path, SERVICES_CODE)
            yield
            client.run_command(["rm", "-rf", platform_path])


@pytest.mark.usefixtures("remote_ipaplatform")
class TestHostPlatform(IntegrationTest):
    """Tests for remote IPA platform

    0) Install nothing
    1) Create remote test os-release
    2) Create remote test ipaplatform
    3) Override remote ipaplatform
    4) Verify remote paths
    5) Verify remote constants
    6) Verify remote osinfo
    7) Verify remote knownservices
    """

    num_replicas = 1

    @classmethod
    def install(cls, mh):
        # make_class_logs caches actual platform not the test one,
        # invalidate cache
        cls.replicas[0]._paths = None
        cls.replicas[0]._constants = None
        cls.replicas[0]._osinfo = None
        cls.replicas[0]._knownservices = None

    @classmethod
    def uninstall(cls, mh):
        pass

    def test_paths_attrs(self):
        host_paths = self.replicas[0].paths

        # pylint: disable=no-member
        assert host_paths.TEST_STR_PATH == "/foo/bar", host_paths
        assert host_paths.TEST_INT_PATH == 1, host_paths
        assert host_paths.TEST_BOOL_PATH is True, host_paths
        assert host_paths.TEST_NONE_PATH is None, host_paths
        assert host_paths.TEST_LIST_PATH == ["foo", "bar"], host_paths
        assert host_paths.TEST_TUPLE_PATH == ["foo", "bar"], host_paths
        assert host_paths.TEST_DICT_PATH == {"foo": "bar"}, host_paths

        with pytest.raises(AttributeError):
            assert host_paths.TEST_OBJ_PATH == "something"

        with pytest.raises(AttributeError):
            assert host_paths.foo == "something"
        # pylint: enable=no-member

    def test_constants_attrs(self):
        host_constants = self.replicas[0].constants
        # pylint: disable=no-member
        assert host_constants.TEST_STR_CONST == "/foo/bar", host_constants
        assert host_constants.TEST_INT_CONST == 1, host_constants
        assert host_constants.TEST_BOOL_CONST is True, host_constants
        assert host_constants.TEST_NONE_CONST is None, host_constants
        assert host_constants.TEST_LIST_CONST == ["foo", "bar"], host_constants
        assert (
            host_constants.TEST_TUPLE_CONST == ["foo", "bar"]
        ), host_constants
        assert host_constants.TEST_DICT_CONST == {"foo": "bar"}, host_constants

        assert host_constants.TEST_USER_CONST == "_someuser", host_constants
        assert host_constants.TEST_GROUP_CONST == "_somegroup", host_constants

        with pytest.raises(AttributeError):
            assert host_constants.TEST_OBJ_CONST == "something"

        with pytest.raises(AttributeError):
            assert host_constants.foo == "something"
        # pylint: enable=no-member

    def test_osinfo_attrs(self):
        host_osinfo = self.replicas[0].osinfo
        assert host_osinfo.name == "Test Platform", host_osinfo
        assert host_osinfo.id == "testplatform", host_osinfo
        assert host_osinfo.id_like == ["foo", "bar"], host_osinfo
        assert host_osinfo.version == "1", host_osinfo
        assert host_osinfo.version_number == [1, 2], host_osinfo
        assert host_osinfo.platform == "testplatform", host_osinfo

    def test_knownservices_attrs(self):
        host_knownservices = self.replicas[0].knownservices
        test_service = host_knownservices["ipa"]
        assert test_service.service_name == "ipa", host_knownservices
        assert (
            test_service.systemd_name == "foo-bar.service"
        ), host_knownservices
        assert host_knownservices.ipa is host_knownservices["ipa"]
