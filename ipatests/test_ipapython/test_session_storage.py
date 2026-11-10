#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

"""
Test the `session_storage.py` module.
"""
import ctypes

import pytest

from ipapython import session_storage


def test_session_storage_file_cache(tmp_path, monkeypatch):
    """Exercise the native ABI without a KDC or an existing user's cache."""
    storage = session_storage
    monkeypatch.setenv('KRB5CCNAME', 'FILE:{}'.format(tmp_path / 'ccache'))
    principal_name = 'testuser@IPA.TEST'
    context = storage.krb5_context()
    principal = storage.krb5_principal()
    ccache = storage.krb5_ccache()
    initialize = storage.LIBKRB5.krb5_cc_initialize
    initialize.argtypes = (
        storage.krb5_context, storage.krb5_ccache, storage.krb5_principal,
    )
    initialize.restype = storage.krb5_error_code
    initialize.errcheck = storage.krb5_errcheck
    try:
        storage.krb5_init_context(ctypes.byref(context))
        storage.krb5_parse_name(
            context, principal_name.encode('ascii'), ctypes.byref(principal),
        )
        storage.krb5_cc_default(context, ctypes.byref(ccache))
        initialize(context, ccache, principal)
    finally:
        if ccache:
            storage.krb5_cc_close(context, ccache)
        if principal:
            storage.krb5_free_principal(context, principal)
        if context:
            storage.krb5_free_context(context)

    storage.store_data(principal_name, 'test-key', b'synthetic-value')
    assert storage.get_data(principal_name, 'test-key') == b'synthetic-value'
    storage.remove_data(principal_name, 'test-key')
    assert storage.get_data(principal_name, 'test-key') is None


@pytest.mark.skip_ipaclient_unittest
@pytest.mark.needs_ipaapi
class test_session_storage:
    """
    Test the session storage interface
    """

    @pytest.fixture(autouse=True)
    def session_storage_setup(self):
        # TODO: set up test user and kinit to it
        # tmpdir = tempfile.mkdtemp(prefix = "tmp-")
        # os.environ['KRB5CCNAME'] = 'FILE:%s/ccache' % tmpdir
        self.principal = 'admin'
        self.key = 'X-IPA-test-session-storage'
        self.data = b'Test Data'

    def test_01(self):
        session_storage.store_data(self.principal, self.key, self.data)

    def test_02(self):
        data = session_storage.get_data(self.principal, self.key)
        assert(data == self.data)

    def test_03(self):
        session_storage.remove_data(self.principal, self.key)
        try:
            session_storage.get_data(self.principal, self.key)
        except session_storage.KRB5Error:
            pass
