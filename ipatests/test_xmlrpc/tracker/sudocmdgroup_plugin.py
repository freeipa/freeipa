#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import fuzzy_uuid

from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.util import assert_deepequal

from ipalib import api
from ipapython.dn import DN


class SudoCmdGroupTracker(Tracker):
    """ Class for tracking sudocmdgroups """
    retrieve_keys = {u'dn', u'cn', u'member_sudocmd', u'description',
                     u'member_sudocmdgroup'}
    retrieve_all_keys = retrieve_keys | {u'ipauniqueid', u'objectclass',
                                         u'mepmanagedentry'}

    create_keys = retrieve_all_keys
    update_keys = retrieve_keys - {u'dn'}

    add_member_keys = retrieve_keys | {u'member_sudocmd'}

    find_keys = {
        u'dn', u'cn', u'description', u'member_sudocmdgroup'}
    find_all_keys = find_keys | {
        u'ipauniqueid', u'objectclass', u'mepmanagedentry'}

    def __init__(self, name, description=u'SudoCmdGroup desc'):
        super(SudoCmdGroupTracker, self).__init__(default_version=None)
        self.cn = name
        self.description = description
        self.dn = DN(('cn', self.cn), ('cn', 'sudocmdgroups'),
                     ('cn', 'sudo'), api.env.basedn)

    def make_create_command(self, *args, **kwargs):
        """ Make function that creates a sudocmdgroup
            using 'sudocmdgroup-add' """
        return self.make_command('sudocmdgroup_add', self.cn,
                                 description=self.description,
                                 *args, **kwargs)

    def make_delete_command(self):
        """ Make function that deletes a sudocmdgroup
            using 'sudocmdgroup-del' """
        return self.make_command('sudocmdgroup_del', self.cn)

    def make_retrieve_command(self, all=False, raw=False):
        """ Make function that retrieves a sudocmdgroup
            using 'sudocmdgroup-show' """
        return self.make_command('sudocmdgroup_show', self.cn, all=all)

    def make_find_command(self, *args, **kwargs):
        """ Make function that searches for a sudocmdgroup
            using 'sudocmdgroup-find' """
        return self.make_command('sudocmdgroup_find', *args, **kwargs)

    def make_update_command(self, updates):
        """ Make function that updates a sudocmdgroup using
            'sudocmdgroup-mod' """
        return self.make_command('sudocmdgroup_mod', self.cn, **updates)

    def make_add_member_command(self, options={}):
        """ Make function that adds a member to a sudocmdgroup """
        return self.make_command('sudocmdgroup_add_member', self.cn, **options)

    def make_remove_member_command(self, options={}):
        """ Make function that removes a member from a sudocmdgroup """
        return self.make_command('sudocmdgroup_remove_member',
                                 self.cn, **options)

    def track_create(self):
        """ Updates expected state for sudocmdgroup creation"""
        self.attrs = dict(
            dn=self.dn,
            cn=[self.cn],
            description=[self.description],
            ipauniqueid=[fuzzy_uuid],
            objectclass=objectclasses.sudocmdgroup,
            )
        self.exists = True

    def add_member(self, options):
        """ Add a member sudocmd to sudocmdgroup and perform check """
        try:
            self.attrs[u'member_sudocmd'] =\
                self.attrs[u'member_sudocmd'] + [options[u'sudocmd']]
        except KeyError:
            self.attrs[u'member_sudocmd'] = [options[u'sudocmd']]

        command = self.make_add_member_command(options)
        result = command()
        self.check_add_member(result)

    def remove_member(self, options):
        """ Remove a member sudocmd from sudocmdgroup and perform check """
        self.attrs[u'member_sudocmd'].remove(options[u'sudocmd'])

        try:
            if not self.attrs[u'member_sudocmd']:
                del self.attrs[u'member_sudocmd']
        except KeyError:
            pass

        command = self.make_remove_member_command(options)
        result = command()
        self.check_remove_member(result)

    def update(self, updates, expected_updates=None):
        """Helper function to update and check the result

        Overriding Tracker method for setting self.attrs correctly;
         * most attributes stores its value in list
         * the rest can be overridden by expected_updates
         * allow deleting parametrs if update value is None
        """
        if expected_updates is None:
            expected_updates = {}

        self.ensure_exists()
        command = self.make_update_command(updates)
        result = command()

        for key, value in updates.items():
            if value is None:
                del self.attrs[key]
            else:
                self.attrs[key] = [value]
        for key, value in expected_updates.items():
            if value is None:
                del self.attrs[key]
            else:
                self.attrs[key] = value

        self.check_update(
            result,
            extra_keys=set(updates.keys()) | set(expected_updates.keys())
        )

    def check_create(self, result):
        """ Checks 'sudocmdgroup_add' command result """
        assert_deepequal(dict(
            value=self.cn,
            summary=u'Added Sudo Command Group "%s"' % self.cn,
            result=self.filter_attrs(self.create_keys)
            ), result)

    def check_delete(self, result):
        """ Checks 'sudocmdgroup_del' command result """
        assert_deepequal(dict(
            value=[self.cn],
            summary=u'Deleted Sudo Command Group "%s"' % self.cn,
            result=dict(failed=[]),
            ), result)

    def check_retrieve(self, result, all=False, raw=False):
        """ Checks 'sudocmdgroup_show' command result """
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        assert_deepequal(dict(
            value=self.cn,
            summary=None,
            result=expected
            ), result)

    def check_find(self, result, all=False, raw=False):
        """ Checks 'sudocmdgroup_find' command result """
        if all:
            expected = self.filter_attrs(self.find_all_keys)
        else:
            expected = self.filter_attrs(self.find_keys)

        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary=u'1 Sudo Command Group matched',
            result=[expected],
        ), result)

    def check_update(self, result, extra_keys={}):
        """ Checks 'sudocmdgroup_mod' command result """
        assert_deepequal(dict(
            value=self.cn,
            summary=u'Modified Sudo Command Group "%s"' % self.cn,
            result=self.filter_attrs(self.update_keys | set(extra_keys))
        ), result)

    def check_add_member(self, result):
        """ Checks 'sudocmdgroup_add_member' command result """
        assert_deepequal(dict(
            completed=1,
            failed={u'member': {u'sudocmd': ()}},
            result=self.filter_attrs(self.add_member_keys)
        ), result)

    def check_add_member_negative(self, result, options):
        """ Checks 'sudocmdgroup_add_member' command result
        when expected result is failure of the operation"""
        expected = dict(
            completed=0,
            failed={u'member': {u'sudocmd': ()}},
            result=self.filter_attrs(self.add_member_keys)
        )
        expected[u'failed'][u'member'][u'sudocmd'] = [(
            options[u'sudocmd'], u'no such entry')]

        assert_deepequal(expected, result)

    def check_remove_member_negative(self, result, options):
        """ Checks 'sudocmdgroup_remove_member' command result
        when expected result is failure of the operation"""
        expected = dict(
            completed=0,
            failed={u'member': {u'sudocmd': ()}},
            result=self.filter_attrs(self.add_member_keys)
        )
        expected[u'failed'][u'member'][u'sudocmd'] = [(
            options[u'sudocmd'], u'This entry is not a member')]

        assert_deepequal(expected, result)

    def check_remove_member(self, result):
        """ Checks 'sudocmdgroup_remove_member' command result """
        self.check_add_member(result)
