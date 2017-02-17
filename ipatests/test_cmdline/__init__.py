#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import pytest


if pytest.config.getoption('ipaclient_unittests', False):
    pytest.skip("Skip in ipaclient unittest mode")
