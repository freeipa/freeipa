#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

"""
Test the `ipalib.util` module.
This tests is in test_integration beucase we only can import ipaplatform here.
"""

from ipalib import util
from ipaplatform.paths import paths

import pytest
pytestmark = pytest.mark.tier0


def test_hardcoded_paths_are_right():
    """
    Test if constants created in ipalib.util are in sync with
    paths declared in ipaplatform.paths
    """
    assert util._IPA_CLIENT_SYSRESTORE == paths.IPA_CLIENT_SYSRESTORE
    assert util._IPA_DEFAULT_CONF == paths.IPA_DEFAULT_CONF
