#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import fuzzy_uuid, fuzzy_sudocmddn

from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.util import assert_deepequal


class SudoCmdTracker(Tracker):
    """ Class for tracking sudo commands """
    retrieve_keys = {u'dn', u'sudocmd', u'description',
                     u'memberof_sudocmdgroup'}
    retrieve_all_keys = retrieve_keys | {u'ipauniqueid', u'objectclass'}

    create_keys = retrieve_all_keys
    update_keys = retrieve_keys - {u'dn'}

    find_keys = {u'dn', u'sudocmd', u'description'}
    find_all_keys = retrieve_all_keys

    def __init__(self, command, description="Test sudo command"):
        super(SudoCmdTracker, self).__init__(default_version=None)
        self.cmd = command
        self.dn = fuzzy_sudocmddn
        self.description = description

    @property
    def name(self):
        """ Property holding the name of the entry in LDAP """
        return self.cmd

    def make_create_command(self):
        """ Make function that creates a sudocmd using 'sudocmd-add' """
        return self.make_command('sudocmd_add', self.cmd,
                                 description=self.description)

    def make_delete_command(self):
        """ Make function that deletes a sudocmd using 'sudocmd-del' """
        return self.make_command('sudocmd_del', self.cmd)

    def make_retrieve_command(self, all=False, raw=False):
        """ Make function that retrieves a sudocmd using 'sudocmd-show' """
        return self.make_command('sudocmd_show', self.cmd, all=all)

    def make_find_command(self, *args, **kwargs):
        """ Make function that searches for a sudocmd using 'sudocmd-find' """
        return self.make_command('sudocmd_find', *args, **kwargs)

    def make_update_command(self, updates):
        """ Make function that updates a sudocmd using 'sudocmd-mod' """
        return self.make_command('sudocmd_mod', self.cmd, **updates)

    def track_create(self):
        """ Updates expected state for sudocmd creation"""
        self.attrs = dict(
            dn=self.dn,
            sudocmd=[self.cmd],
            description=[self.description],
            ipauniqueid=[fuzzy_uuid],
            objectclass=objectclasses.sudocmd,
            )
        self.exists = True

    def check_create(self, result):
        """ Checks 'sudocmd_add' command result """
        assert_deepequal(dict(
            value=self.cmd,
            summary=u'Added Sudo Command "%s"' % self.cmd,
            result=self.filter_attrs(self.create_keys)
            ), result)

    def check_delete(self, result):
        """ Checks 'sudocmd_del' command result """
        assert_deepequal(dict(
            value=[self.cmd],
            summary=u'Deleted Sudo Command "%s"' % self.cmd,
            result=dict(failed=[]),
            ), result)

    def check_retrieve(self, result, all=False, raw=False):
        """ Checks 'sudocmd_show' command result """
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        assert_deepequal(dict(
            value=self.cmd,
            summary=None,
            result=expected
            ), result)

    def check_find(self, result, all=False, raw=False):
        """ Checks 'sudocmd_find' command result """
        if all:
            expected = self.filter_attrs(self.find_all_keys)
        else:
            expected = self.filter_attrs(self.find_keys)

        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary=u'1 Sudo Command matched',
            result=[expected],
        ), result)

    def check_update(self, result, extra_keys={}):
        """ Checks 'sudocmd_mod' command result """
        assert_deepequal(dict(
            value=self.cmd,
            summary=u'Modified Sudo Command "%s"' % self.cmd,
            result=self.filter_attrs(self.update_keys | set(extra_keys))
        ), result)
