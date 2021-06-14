# Copyright (C) 2016  Custodia Project Contributors - see LICENSE file
import pkg_resources
import pytest

from ipaserver.custodia.plugin import (
    CSStore, HTTPAuthenticator, HTTPAuthorizer
)


class TestCustodiaPlugins:
    project_name = 'ipaserver.custodia'

    def get_entry_points(self, group):
        eps = []
        for e in pkg_resources.iter_entry_points(group):
            if e.dist.project_name != self.project_name:
                # only interested in our own entry points
                continue
            eps.append(e)
        return eps

    def assert_ep(self, ep, basecls):
        try:
            # backwards compatibility with old setuptools
            if hasattr(ep, "resolve"):
                cls = ep.resolve()
            else:
                cls = ep.load(require=False)
        except Exception as e:  # pylint: disable=broad-except
            pytest.fail("Failed to load %r: %r" % (ep, e))
        if not issubclass(cls, basecls):
            pytest.fail("%r is not a subclass of %r" % (cls, basecls))

    def test_authenticators(self):
        for ep in self.get_entry_points('custodia.authenticators'):
            self.assert_ep(ep, HTTPAuthenticator)

    def test_authorizers(self):
        for ep in self.get_entry_points('custodia.authorizers'):
            self.assert_ep(ep, HTTPAuthorizer)

    def test_stores(self):
        for ep in self.get_entry_points('custodia.stores'):
            self.assert_ep(ep, CSStore)
