#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#

"""
Test the LDAPCache class.
"""
# pylint: disable=no-member

from ipalib import api, errors
from ipapython import ipaldap
from ipapython.dn import DN

import pytest


def hits_and_misses(cache, hits, misses):
    assert cache._cache_hits == hits
    assert cache._cache_misses == misses


@pytest.fixture(scope='class')
def class_cache(request):
    cache = ipaldap.LDAPCache(api.env.ldap_uri)
    hits_and_misses(cache, 0, 0)

    request.cls.cache = cache
    request.cls.userdn = DN(
        'uid=testuser', api.env.container_user, api.env.basedn
    )

    rpcclient = api.Backend.rpcclient
    was_connected = rpcclient.isconnected()

    if not was_connected:
        rpcclient.connect()

    api.Command.user_add('testuser', givenname=u'Test', sn=u'User')

    yield

    try:
        api.Command.user_del('testuser')
    except Exception:
        pass

    try:
        if not was_connected:
            rpcclient.disconnect()
    except Exception:
        pass


@pytest.mark.usefixtures('class_cache')
@pytest.mark.skip_ipaclient_unittest
@pytest.mark.needs_ipaapi
@pytest.mark.tier1
class TestLDAPCache:

    def test_one(self):
        dn = DN('uid=notfound', api.env.container_user, api.env.basedn)
        try:
            self.cache.get_entry(dn)
        except errors.EmptyResult:
            pass

        assert dn in self.cache.cache
        exc = self.cache.cache[dn].exception
        assert isinstance(exc, errors.EmptyResult)

        hits_and_misses(self.cache, 0, 1)

    def test_retrieve_exception(self):
        dn = DN('uid=notfound', api.env.container_user, api.env.basedn)
        try:
            self.cache.get_entry(dn)
        except errors.EmptyResult:
            pass
        assert dn in self.cache.cache
        exc = self.cache.cache[dn].exception
        assert isinstance(exc, errors.EmptyResult)
        hits_and_misses(self.cache, 1, 1)

    def test_get_testuser(self):
        assert self.userdn not in self.cache.cache
        self.cache.get_entry(self.userdn)
        assert self.userdn in self.cache.cache
        hits_and_misses(self.cache, 1, 2)

    def test_get_testuser_again(self):
        assert self.userdn in self.cache.cache

        # get the user again with with no attributes requested (so all)
        self.cache.get_entry(self.userdn)
        hits_and_misses(self.cache, 2, 2)

        # Now get the user with a subset of cached attributes
        entry = self.cache.get_entry(self.userdn, ('givenname', 'sn', 'cn'))
        # Make sure we only got three attributes, as requested
        assert len(entry.items()) == 3
        hits_and_misses(self.cache, 3, 2)

    def test_update_testuser(self):
        entry = self.cache.cache[self.userdn].entry
        try:
            self.cache.update_entry(entry)
        except errors.EmptyModlist:
            pass
        assert self.userdn not in self.cache.cache
        hits_and_misses(self.cache, 3, 2)

    def test_modify_testuser(self):
        self.cache.get_entry(self.userdn)
        entry = self.cache.cache[self.userdn].entry
        try:
            self.cache.modify_s(entry.dn, [])
        except errors.EmptyModlist:
            pass
        assert self.userdn not in self.cache.cache
        hits_and_misses(self.cache, 3, 3)

    def test_delete_entry(self):
        # We don't care if this is successful or not, just that the
        # cache doesn't retain the deleted entry
        try:
            self.cache.delete_entry(self.userdn)
        except Exception:
            pass
        assert self.userdn not in self.cache.cache
        hits_and_misses(self.cache, 3, 3)

    def test_add_entry(self):
        # We don't care if this is successful or not, just that the
        # cache doesn't get the added entry
        try:
            self.cache.add_entry(self.userdn)
        except Exception:
            pass
        assert self.userdn not in self.cache.cache
        hits_and_misses(self.cache, 3, 3)

    def test_clear_cache(self):
        self.cache.clear_cache()
        hits_and_misses(self.cache, 0, 0)
