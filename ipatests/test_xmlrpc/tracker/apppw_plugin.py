#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

from ipalib import api
from ipapython.dn import DN

import six

from ipatests.util import assert_deepequal
from ipatests.test_xmlrpc.tracker.base import Tracker

if six.PY3:
    unicode = str


class ApppwTracker(Tracker):
    """
    Class for app password tests
    """

    retrieve_keys = {
        u'dn', u'uid', u'description', u'ou', u'has_password'
    }

    create_keys = retrieve_keys | {
        u'userpassword', u'randompassword'
    }

    find_keys = retrieve_keys

    primary_keys = {u'uid', u'dn'}

    def __init__(self, uid=None, description=None, appname=None, **kwargs):
        """
        Check for non-empty unicode string for the required attributes in the
        init method
        """
        if not (isinstance(uid, str) and uid):
            raise ValueError("Invalid login provided: {!r}".format(uid))
        if not (isinstance(description, str) and description):
            raise ValueError(
                "Invalid display name provided: {!r}".format(description))
        if not (isinstance(appname, str) and appname):
            raise ValueError("Invalid app name provided: {!r}".format(appname))

        super(ApppwTracker, self).__init__(default_version=None)
        self.uid = unicode(uid)
        self.description = unicode(description)
        self.ou = unicode(appname)
        self.dn = DN(('uid', self.uid),
                     ('cn', 'admin'),
                     api.env.container_apppw,
                     api.env.basedn)

        self.kwargs = kwargs

    def make_create_command(self, force=None):
        """
        Make function that creates an app password using apppw-add with all set
        of attributes and with minimal values, where uid is not specified
        """
        return self.make_command(
            'apppw_add', self.uid,
            description=self.description,
            ou=self.ou, **self.kwargs
        )

    def make_delete_command(self):
        """
        Make function that deletes an app password using apppw-del
        """
        return self.make_command('apppw_del', self.uid)

    def make_retrieve_command(self, all=False, raw=False):
        """
        Make function that retrieves an app password using apppw-show
        """
        return self.make_command('apppw_show', self.uid, all=all)

    def make_find_command(self, *args, **kwargs):
        """
        Make function that finds app password(s) using apppw-find
        """
        return self.make_command('apppw_find', *args, **kwargs)

    def track_create(self):
        """
        Update expected state for app password creation
        """
        self.attrs = dict(
            dn=self.dn,
            uid=[self.uid],
            description=[self.description],
            ou=[self.ou],
            has_password=False,
        )

        for key in self.kwargs:
            if type(self.kwargs[key]) is not list:
                self.attrs[key] = [self.kwargs[key]]
            else:
                self.attrs[key] = self.kwargs[key]

        self.exists = True

    def check_create(self, result, extra_keys=()):
        """
        Check 'apppw-add' command result
        """
        expected = self.filter_attrs(self.create_keys | set(extra_keys))
        assert_deepequal(
            dict(
                value=self.uid,
                summary=u'Added app password "%s"' % self.uid,
                result=self.filter_attrs(expected),
            ),
            result
        )

    def track_delete(self, preserve=False):
        """
        Update expected state for app password deletion
        """
        self.exists = False
        self.attrs = {}

    def check_delete(self, result):
        """
        Check 'apppw-del' command result
        """
        assert_deepequal(
            dict(
                value=[self.uid],
                summary=u'Deleted app password "%s"' % self.uid,
                result=dict(failed=[]),
            ),
            result
        )

    def check_retrieve(self, result, all=False, raw=False):
        """
        Check 'apppw-show' command result
        """
        expected = self.filter_attrs(self.retrieve_keys)

        assert_deepequal(
            dict(
                value=self.uid,
                summary=None,
                result=expected,
            ),
            result
        )

    def check_find(self, result, all=False, pkey_only=False, raw=False,
                   expected_override=None):
        """
        Check 'apppw-find' command result
        """
        if pkey_only:
            expected = self.filter_attrs(self.primary_keys)
        else:
            expected = self.filter_attrs(self.find_keys)

        if expected_override:
            assert isinstance(expected_override, dict)
            expected.update(expected_override)

        assert_deepequal(
            dict(
                count=1,
                truncated=False,
                summary=u'1 app password matched',
                result=[expected],
            ),
            result
        )

    def check_find_nomatch(self, result):
        """
        Check 'apppw-find' command result when no app password should be found
        """
        assert_deepequal(
            dict(
                count=0,
                truncated=False,
                summary=u'0 app passwords matched',
                result=[],
            ),
            result
        )
