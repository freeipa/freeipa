#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

"""
Test the error reporting of ipa-migrate: get_base_dn() reports failures
to read the Root DSE or the suffix entry through handle_error(),
whatever the ipalib error is, and connect_to_local_ds() stops when the
local schema cannot be read.

No server is needed: the connections are mocks.
"""

from unittest import mock

import pytest

from ipalib import errors
from ipaserver.install.ipa_migrate import IPAMigrate


class Stop(Exception):
    """Raised by the patched handle_error(), which exits in real life."""


@pytest.mark.parametrize(
    "exc",
    [
        errors.NotFound(reason="no such entry"),
        errors.ACIError(info="denied"),
        errors.NetworkError(uri="ldap://ipa.example.test", error="lost"),
        errors.DatabaseError(desc="failed", info=""),
    ],
    ids=lambda exc: type(exc).__name__,
)
def test_get_base_dn_reports_search_failure(exc):
    migrate = IPAMigrate.__new__(IPAMigrate)
    migrate.remote_conn = mock.Mock()
    migrate.remote_conn.get_entry.side_effect = exc
    migrate.handle_error = mock.Mock(side_effect=Stop)

    with pytest.raises(Stop):
        migrate.get_base_dn(remote=True)

    msg = migrate.handle_error.call_args[0][0]
    assert msg.startswith("Failed to search Root DSE on remote server: ")


@pytest.mark.parametrize("schema, stops", [(None, True), (object(), False)])
def test_connect_to_local_ds_requires_schema(schema, stops):
    migrate = IPAMigrate.__new__(IPAMigrate)
    migrate.ldapiuri = "ldapi://%2Frun%2Fslapd-EXAMPLE-TEST.socket"
    migrate.handle_error = mock.Mock(side_effect=Stop)

    with mock.patch("ipaserver.install.ipa_migrate.LDAPClient") as client:
        client.return_value.schema = schema
        if stops:
            with pytest.raises(Stop):
                migrate.connect_to_local_ds()
            migrate.handle_error.assert_called_once_with(
                "Failed to read the local server schema"
            )
        else:
            migrate.connect_to_local_ds()
            migrate.handle_error.assert_not_called()
