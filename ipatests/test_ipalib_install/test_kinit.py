#
# Copyright (C) 2024  FreeIPA Contributors see COPYING for license
#
"""Tests for ipalib.install.kinit module
"""

import pytest

from ipalib.install.kinit import validate_principal


# None means no exception is expected
@pytest.mark.parametrize('principal, exception', [
    ('testuser', None),
    ('testuser@EXAMPLE.TEST', None),
    ('test/ipa.example.test', None),
    ('test/ipa.example.test@EXAMPLE.TEST', None),
    ('test/ipa@EXAMPLE.TEST', RuntimeError),
    ('test/-ipa.example.test@EXAMPLE.TEST', RuntimeError),
    ('test/ipa.1example.test@EXAMPLE.TEST', RuntimeError),
    ('test /ipa.example,test', RuntimeError),
    ('testuser@OTHER.TEST', RuntimeError),
    ('test/ipa.example.test@OTHER.TEST', RuntimeError),
])
def test_validate_principal(principal, exception):
    try:
        validate_principal(principal)
    except Exception as e:
        assert e.__class__ == exception
