#
# Copyright (C) 2022  FreeIPA Contributors see COPYING for license
#

from ipapython.dn import DN
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.tracker.base import ConfigurationTracker
from ipatests.test_xmlrpc.xmlrpc_test import fuzzy_string
from ipatests.util import assert_deepequal


class PasskeyconfigTracker(ConfigurationTracker):
    retrieve_keys = {
        'dn',
        'iparequireuserverification',
    }

    retrieve_all_keys = retrieve_keys | {
        'cn',
        'objectclass',
        'aci',
    }

    update_keys = retrieve_keys - {'dn'}
    singlevalue_keys = {'iparequireuserverification'}

    def __init__(self, default_version=None):
        super(PasskeyconfigTracker, self).__init__(
            default_version=default_version)

        self.attrs = {
            'dn': DN(self.api.env.container_passkey, self.api.env.basedn),
            'cn': [self.api.env.container_passkey[0].value],
            'objectclass': objectclasses.passkeyconfig,
            'aci': [fuzzy_string],
            'iparequireuserverif': self.api.Command.passkeyconfig_show(
            )['result']['iparequireuserverification'],
        }

    def make_update_command(self, updates):
        return self.make_command('passkeyconfig_mod', **updates)

    def check_update(self, result, extra_keys=()):
        assert_deepequal(
            dict(
                value=None,
                summary=None,
                result=self.filter_attrs(self.update_keys | set(extra_keys)),
            ),
            result
        )

    def make_retrieve_command(self, all=False, raw=False):
        return self.make_command('passkeyconfig_show', all=all, raw=raw)

    def check_retrieve(self, result, all=False, raw=False):
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)
        assert_deepequal(
            dict(
                value=None,
                summary=None,
                result=expected,
            ),
            result
        )


class PasskeyMixin:
    def _make_add_passkey(self):
        raise NotImplementedError("_make_add_passkey method must be "
                                  "implemented in instance.")

    def _make_remove_passkey(self):
        raise NotImplementedError("_make_remove_passkey method must be "
                                  "implemented in instance.")

    def add_passkey(self, **kwargs):
        cmd = self._make_add_passkey()
        result = cmd(**kwargs)
        data = kwargs.get('ipapasskey', [])
        if not isinstance(data, list):
            data = [data]
        self.attrs.setdefault('ipapasskey', []).extend(data)

        expected = dict(
            summary=('Added passkey mappings to user '
                     '"{}"'.format(self.name)),
            value=self.name,
            result=dict(
                uid=(self.name,),
            ),
        )

        if self.attrs['ipapasskey']:
            expected['result']['ipapasskey'] = (
                self.attrs['ipapasskey'])

        assert_deepequal(expected, result)

    def remove_passkey(self, **kwargs):
        cmd = self._make_remove_passkey()

        result = cmd(**kwargs)
        data = kwargs.get('ipapasskey', [])
        if not isinstance(data, list):
            data = [data]

        for key in data:
            self.attrs['ipapasskey'].remove(key)

        expected = dict(
            summary=('Removed passkey mappings from user '
                     '"{}"'.format(self.name)),
            value=self.name,
            result=dict(
                uid=(self.name,),
            ),
        )
        if self.attrs['ipapasskey']:
            expected['result']['ipapasskey'] = (
                self.attrs['ipapasskey'])

        assert_deepequal(expected, result)
