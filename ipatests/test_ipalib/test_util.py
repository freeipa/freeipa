#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
"""Tests for ipalib.util module
"""

import os
import ssl
from unittest import mock

import pytest

from ipalib.util import (
    get_pager, create_https_connection, get_proper_tls_version_span
)
from ipaplatform.constants import constants


@pytest.mark.parametrize('pager,expected_result', [
    # Valid values
    ('cat', '/bin/cat'),
    ('/bin/cat', '/bin/cat'),
    # Invalid values (wrong command, package is not installed, etc)
    ('cat_', None),
    ('', None)
])
def test_get_pager(pager, expected_result):
    with mock.patch.dict(os.environ, {'PAGER': pager}):
        pager = get_pager()
        assert(pager == expected_result or pager.endswith(expected_result))


BASE_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS)
if constants.TLS_HIGH_CIPHERS is not None:
    BASE_CTX.set_ciphers(constants.TLS_HIGH_CIPHERS)
else:
    BASE_CTX.set_ciphers("PROFILE=SYSTEM")

# options: IPA still supports Python 3.6 without min/max version setters
BASE_OPT = BASE_CTX.options
BASE_OPT |= (
    ssl.OP_ALL | ssl.OP_NO_COMPRESSION | ssl.OP_SINGLE_DH_USE |
    ssl.OP_SINGLE_ECDH_USE
)
TLS_OPT = (
    ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 |
    ssl.OP_NO_TLSv1_1
)
OP_NO_TLSv1_3 = getattr(ssl, "OP_NO_TLSv1_3", 0)  # make pylint happy


@pytest.mark.parametrize('minver,maxver,opt,expected', [
    (None, None, BASE_OPT, None),
    (None, "tls1.3", BASE_OPT | TLS_OPT, ["tls1.2", "tls1.3"]),
    ("tls1.2", "tls1.3", BASE_OPT | TLS_OPT, ["tls1.2", "tls1.3"]),
    ("tls1.2", None, BASE_OPT | TLS_OPT, ["tls1.2", "tls1.3"]),
    ("tls1.2", "tls1.2", BASE_OPT | TLS_OPT | OP_NO_TLSv1_3, ["tls1.2"]),
    (None, "tls1.2", BASE_OPT | TLS_OPT | OP_NO_TLSv1_3, ["tls1.2"]),
    ("tls1.3", "tls1.3", BASE_OPT | TLS_OPT | ssl.OP_NO_TLSv1_2, ["tls1.3"]),
    ("tls1.3", None, BASE_OPT | TLS_OPT | ssl.OP_NO_TLSv1_2, ["tls1.3"]),
])
def test_tls_version_span(minver, maxver, opt, expected):
    assert get_proper_tls_version_span(minver, maxver) == expected
    # file must exist and contain certs
    cafile = ssl.get_default_verify_paths().cafile
    conn = create_https_connection(
        "invalid.test",
        cafile=cafile,
        tls_version_min=minver,
        tls_version_max=maxver
    )
    ctx = getattr(conn, "_context")
    assert ctx.options == BASE_OPT | opt
    assert ctx.get_ciphers() == BASE_CTX.get_ciphers()
