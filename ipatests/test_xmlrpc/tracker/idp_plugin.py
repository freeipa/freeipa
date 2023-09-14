#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#

from ipalib import api
from ipapython.dn import DN
from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.test_xmlrpc import objectclasses
from ipatests.util import assert_deepequal


class IdpTracker(Tracker):
    """Class for ipd tests"""

    retrieve_keys = {
        'dn', 'cn', 'ipaidpauthendpoint', 'ipaidpdevauthendpoint',
        'ipaidpuserinfoendpoint', 'ipaidpkeysendpoint',
        'ipaidptokenendpoint', 'ipaidpissuerurl',
        'ipaidpclientid', 'ipaidpscope', 'ipaidpsub'}

    retrieve_all_keys = retrieve_keys | {
        'objectclass', 'ipaidpclientsecret'
    }

    create_keys = retrieve_all_keys

    update_keys = retrieve_keys - {'dn'}

    find_keys = retrieve_keys
    find_all_keys = retrieve_all_keys

    primary_keys = {'cn', 'dn'}

    def __init__(self, cn, **kwargs):
        super(IdpTracker, self).__init__(default_version=None)
        self.cn = cn
        self.dn = DN(('cn', cn), api.env.container_idp, api.env.basedn)
        self.kwargs = kwargs

    def make_create_command(self):
        """ Make function that creates an idp using idp-add """
        return self.make_command('idp_add', self.cn, **self.kwargs)

    def track_create(self):
        """ Update expected state for idp creation """
        self.attrs = dict(
            dn=self.dn,
            cn=[self.cn],
            objectclass=objectclasses.idp,
        )
        for key, value in self.kwargs.items():
            if key == 'ipaidpclientsecret':
                self.attrs[key] = [value.encode('utf-8')]
                continue
            if type(value) is not list:
                self.attrs[key] = [value]
            else:
                self.attrs[key] = value
        self.exists = True

    def check_create(self, result, extra_keys=()):
        """ Check idp-add command result """
        expected = self.filter_attrs(self.create_keys | set(extra_keys))
        assert_deepequal(
            dict(
                value=self.cn,
                summary='Added Identity Provider reference "%s"' % self.cn,
                result=self.filter_attrs(expected),
            ), result)

    def make_delete_command(self):
        """ Make function that deletes an idp using idp-del """
        return self.make_command('idp_del', self.cn)

    def check_delete(self, result):
        """ Check idp-del command result """
        assert_deepequal(
            dict(
                value=[self.cn],
                summary='Deleted Identity Provider reference "%s"' % self.cn,
                result=dict(failed=[]),
            ), result)

    def make_retrieve_command(self, all=False, raw=False):
        """ Make function that retrieves an idp using idp-show """
        return self.make_command('idp_show', self.cn, all=all)

    def check_retrieve(self, result, all=False, raw=False):
        """ Check idp-show command result """
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)
        assert_deepequal(dict(
            value=self.cn,
            summary=None,
            result=expected,
        ), result)

    def make_find_command(self, *args, **kwargs):
        """ Make function that finds idp using idp-find """
        return self.make_command('idp_find', *args, **kwargs)

    def check_find(self, result, all=False, raw=False, pkey_only=False):
        """ Check idp-find command result """
        if all:
            expected = self.filter_attrs(self.find_all_keys)
        elif pkey_only:
            expected = self.filter_attrs(self.primary_keys)
        else:
            expected = self.filter_attrs(self.find_keys)

        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary='1 Identity Provider reference matched',
            result=[expected],
        ), result)

    def make_update_command(self, updates):
        """ Make function that updates an idp using idp_mod """
        return self.make_command('idp_mod', self.cn, **updates)

    def update(self, updates, expected_updates=None):
        """Helper function to update this idp and check the result

        Overriding Tracker method for setting self.attrs correctly;
         * most attributes stores its value in list
         * the rest can be overridden by expected_updates
         * allow deleting parameters if update value is None
        """
        if expected_updates is None:
            expected_updates = {}

        self.ensure_exists()
        command = self.make_update_command(updates)
        result = command()

        for key, value in updates.items():
            if value is None or value == '':
                del self.attrs[key]
            elif key == 'rename':
                self.attrs['cn'] = [value]
            else:
                if type(value) is list:
                    self.attrs[key] = value
                else:
                    self.attrs[key] = [value]
        for key, value in expected_updates.items():
            if value is None or value == '':
                del self.attrs[key]
            else:
                self.attrs[key] = value

        self.check_update(
            result,
            extra_keys=set(updates.keys()) | set(expected_updates.keys())
        )

        if 'rename' in updates:
            self.cn = self.attrs['cn'][0]

    def check_update(self, result, extra_keys=()):
        """ Check idp-mod command result """
        expected = self.filter_attrs(self.update_keys | set(extra_keys))
        assert_deepequal(dict(
            value=self.cn,
            summary='Modified Identity Provider reference "%s"' % self.cn,
            result=expected
        ), result)
