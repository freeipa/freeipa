#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import pytest


def pytest_addoption(parser):
    group = parser.getgroup("IPA tracker tests")

    group.addoption('--cli', dest='cli', action='store_true', default=False,
                    help="Run tests as CLI instead of API.")
