#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
"""Tests for ipalib.util module
"""

import os

import pytest

from ipalib.util import get_pager

try:
    from unittest.mock import patch  # pylint: disable=import-error
except ImportError:
    from mock import patch  # pylint: disable=import-error


@pytest.mark.parametrize('pager,expected_result', [
    # Valid values
    ('cat', '/bin/cat'),
    ('/bin/cat', '/bin/cat'),
    # Invalid values (wrong command, package is not installed, etc)
    ('cat_', None),
    ('', None)
])
def test_get_pager(pager, expected_result):
    with patch.dict(os.environ, {'PAGER': pager}):
        pager = get_pager()
        assert(pager == expected_result or pager.endswith(expected_result))
