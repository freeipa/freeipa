#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import fuzzy_uuid

from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.util import assert_deepequal

from ipalib import api
from ipapython.dn import DN


class HostGroupTracker(Tracker):
    """ Class for tracking hostgroups """
    retrieve_keys = {'dn', 'cn', 'member_host', 'description',
                     'member_hostgroup', 'memberindirect_host'}
    retrieve_all_keys = retrieve_keys | {'ipauniqueid', 'objectclass',
                                         'mepmanagedentry'}

    create_keys = retrieve_all_keys
    update_keys = retrieve_keys - {'dn'}

    add_member_keys = retrieve_keys | {'member_host'}

    find_keys = {
        'dn', 'cn', 'description',
    }
    find_all_keys = {
        'dn', 'cn', 'member_host', 'description', 'member_hostgroup',
        'memberindirect_host', 'ipauniqueid', 'objectclass',
        'mepmanagedentry',
    }

    def __init__(self, name, description='HostGroup desc'):
        super(HostGroupTracker, self).__init__(default_version=None)
        self.cn = name
        self.description = description
        self.dn = DN(('cn', self.cn), ('cn', 'hostgroups'),
                     ('cn', 'accounts'), api.env.basedn)

    def make_create_command(self,
                            force=True, *args, **kwargs):
        """ Make function that creates a hostgroup using 'hostgroup-add' """
        return self.make_command('hostgroup_add', self.cn,
                                 description=self.description,
                                 *args, **kwargs)

    def make_delete_command(self):
        """ Make function that deletes a hostgroup using 'hostgroup-del' """
        return self.make_command('hostgroup_del', self.cn)

    def make_retrieve_command(self, all=False, raw=False):
        """ Make function that retrieves a hostgroup using 'hostgroup-show' """
        return self.make_command('hostgroup_show', self.cn, all=all)

    def make_find_command(self, *args, **kwargs):
        """ Make function that searches for a hostgroup
            using 'hostgroup-find' """
        return self.make_command('hostgroup_find', *args, **kwargs)

    def make_update_command(self, updates):
        """ Make function that updates a hostgroup using 'hostgroup-mod' """
        return self.make_command('hostgroup_mod', self.cn, **updates)

    def make_add_member_command(self, options={}):
        """ Make function that adds a member to a hostgroup """
        return self.make_command('hostgroup_add_member', self.cn, **options)

    def make_remove_member_command(self, options={}):
        """ Make function that removes a member from a hostgroup """
        return self.make_command('hostgroup_remove_member', self.cn, **options)

    def track_create(self):
        """ Updates expected state for hostgroup creation"""
        self.attrs = dict(
            dn=self.dn,
            mepmanagedentry=[DN(('cn', self.cn), ('cn', 'ng'),
                                ('cn', 'alt'), api.env.basedn)],
            cn=[self.cn],
            description=[self.description],
            ipauniqueid=[fuzzy_uuid],
            objectclass=objectclasses.hostgroup,
            )
        self.exists = True

    def add_member(self, options):
        """ Add a member host to hostgroup and perform check """
        if 'host' in options:
            try:
                self.attrs['member_host'] =\
                    self.attrs['member_host'] + [options['host']]
            except KeyError:
                self.attrs['member_host'] = [options['host']]
            # search for hosts in the target hostgroup and
            # add them as memberindirect hosts
        elif 'hostgroup' in options:
            try:
                self.attrs['member_hostgroup'] =\
                    self.attrs['member_hostgroup'] + [options['hostgroup']]
            except KeyError:
                self.attrs['member_hostgroup'] = [options['hostgroup']]

        command = self.make_add_member_command(options)
        result = command()
        self.check_add_member(result)

    def remove_member(self, options):
        """ Remove a member host from hostgroup and perform check """
        if 'host' in options:
            self.attrs['member_host'].remove(options['host'])
        elif 'hostgroup' in options:
            self.attrs['member_hostgroup'].remove(options['hostgroup'])

        try:
            if not self.attrs['member_host']:
                del self.attrs['member_host']
        except KeyError:
            pass
        try:
            if not self.attrs['member_hostgroup']:
                del self.attrs['member_hostgroup']
        except KeyError:
            pass

        command = self.make_remove_member_command(options)
        result = command()
        self.check_remove_member(result)

    def update(self, updates, expected_updates=None):
        """Helper function to update this user and check the result

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
        """ Checks 'hostgroup_add' command result """
        assert_deepequal(dict(
            value=self.cn,
            summary='Added hostgroup "%s"' % self.cn,
            result=self.filter_attrs(self.create_keys)
            ), result)

    def check_delete(self, result):
        """ Checks 'hostgroup_del' command result """
        assert_deepequal(dict(
            value=[self.cn],
            summary='Deleted hostgroup "%s"' % self.cn,
            result=dict(failed=[]),
            ), result)

    def check_retrieve(self, result, all=False, raw=False):
        """ Checks 'hostgroup_show' command result """
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
        """ Checks 'hostgroup_find' command result """
        if all:
            expected = self.filter_attrs(self.find_all_keys)
        else:
            expected = self.filter_attrs(self.find_keys)

        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary='1 hostgroup matched',
            result=[expected],
        ), result)

    def check_update(self, result, extra_keys={}):
        """ Checks 'hostgroup_mod' command result """
        assert_deepequal(dict(
            value=self.cn,
            summary='Modified hostgroup "%s"' % self.cn,
            result=self.filter_attrs(self.update_keys | set(extra_keys))
        ), result)

    def check_add_member(self, result):
        """ Checks 'hostgroup_add_member' command result """
        assert_deepequal(dict(
            completed=1,
            failed={'member': {'host': (), 'hostgroup': ()}},
            result=self.filter_attrs(self.add_member_keys)
        ), result)

    def check_add_member_negative(self, result, options):
        """ Checks 'hostgroup_add_member' command result
        when expected result is failure of the operation"""
        expected = dict(
            completed=0,
            failed={'member': {'hostgroup': (), 'user': ()}},
            result=self.filter_attrs(self.add_member_keys)
        )
        if 'host' in options:
            expected['failed']['member']['host'] = [(
                options['host'], 'no such entry')]
        elif 'hostgroup' in options:
            expected['failed']['member']['hostgroup'] = [(
                options['hostgroup'], 'no such entry')]

        assert_deepequal(expected, result)

    def check_remove_member_negative(self, result, options):
        """ Checks 'hostgroup_remove_member' command result
        when expected result is failure of the operation"""
        expected = dict(
            completed=0,
            failed={'member': {'hostgroup': (), 'host': ()}},
            result=self.filter_attrs(self.add_member_keys)
        )
        if 'user' in options:
            expected['failed']['member']['host'] = [(
                options['user'], 'This entry is not a member')]
        elif 'hostgroup' in options:
            expected['failed']['member']['hostgroup'] = [(
                options['hostgroup'], 'This entry is not a member')]

        assert_deepequal(expected, result)

    def check_remove_member(self, result):
        """ Checks 'hostgroup_remove_member' command result """
        self.check_add_member(result)
