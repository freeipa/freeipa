#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#
import pytest
import time

from ipaclient.remote_plugins import ServerInfo


class TestServerInfo(ServerInfo):
    """Simplified ServerInfo class with hardcoded values"""
    def __init__(self, fingerprint='deadbeef', hostname='ipa.example.test',
                 force_check=False, language='en_US',
                 version='2.0', expiration=None):
        self._force_check = force_check
        self._language = language
        self._now = time.time()
        self._dict = {
            'fingerprint': fingerprint,
            'expiration': expiration or time.time() + 3600,
            'language': language,
            'version': version,
        }

    def _read(self):
        """Running on test controller, this is a no-op"""

    def _write(self):
        """Running on test controller, this is a no-op"""


@pytest.mark.tier0
class TestIPAServerInfo:
    """Test that ServerInfo detects changes in remote configuration"""

    def test_valid(self):
        server_info = TestServerInfo()
        assert server_info.is_valid() is True

    def test_force_check(self):
        server_info = TestServerInfo(force_check=True)
        assert server_info.is_valid() is False

    def test_language_change(self):
        server_info = TestServerInfo()
        assert server_info.is_valid() is True
        server_info._language = 'fr_FR'
        assert server_info.is_valid() is False
        server_info._language = 'en_US'

    def test_expired(self):
        server_info = TestServerInfo(expiration=time.time() + 2)
        assert server_info.is_valid() is True

        # skip past the expiration time
        server_info._now = time.time() + 5
        assert server_info.is_valid() is False

        # set a new expiration time in the future
        server_info.update_validity(10)
        assert server_info.is_valid() is True

        # move to the future beyond expiration
        server_info._now = time.time() + 15
        assert server_info.is_valid() is False

    def test_update_validity(self):
        server_info = TestServerInfo(expiration=time.time() + 1)

        # Expiration and time are one second off so the cache is ok
        assert server_info.is_valid() is True

        # Simulate time passing by
        server_info._now = time.time() + 2

        # the validity should be updated because it is now expired
        server_info.update_validity(3600)

        # the cache is now valid for another hour
        assert server_info.is_valid() is True
