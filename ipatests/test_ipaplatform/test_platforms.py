#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""Test import and basic properties of platforms
"""
from importlib import import_module

import pytest

from ipaplatform.base.constants import BaseConstantsNamespace, User, Group
from ipaplatform.base.paths import BasePathNamespace
from ipaplatform.base.services import KnownServices
from ipaplatform.base.tasks import BaseTaskNamespace

PLATFORMS = [
    "debian",
    "fedora",
    "fedora_container",
    "rhel",
    "rhel_container",
    "suse",
]


@pytest.mark.parametrize("name", PLATFORMS)
def test_import_platform(name):
    constants = import_module(f"ipaplatform.{name}.constants")
    assert isinstance(constants.constants, BaseConstantsNamespace)
    assert issubclass(constants.User, User)
    assert issubclass(constants.Group, Group)

    paths = import_module(f"ipaplatform.{name}.paths")
    assert isinstance(paths.paths, BasePathNamespace)

    services = import_module(f"ipaplatform.{name}.services")
    assert isinstance(services.knownservices, KnownServices)
    assert isinstance(services.timedate_services, list)
    assert callable(services.service)

    tasks = import_module(f"ipaplatform.{name}.tasks")
    assert isinstance(tasks.tasks, BaseTaskNamespace)
