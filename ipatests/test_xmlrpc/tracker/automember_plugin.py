#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import (
    fuzzy_uuid, fuzzy_automember_message, fuzzy_automember_dn)

from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.util import assert_deepequal

from ipalib import api
from ipapython.dn import DN


class AutomemberTracker(Tracker):
    """ Class for tracking automembers """
    retrieve_keys = {'dn', 'cn', 'member_host', 'description',
                     'member_automember', 'memberindirect_host',
                     'automemberinclusiveregex', 'automemberexclusiveregex',
                     'automembertargetgroup'}
    retrieve_all_keys = retrieve_keys | {'objectclass',
                                         'automembertargetgroup'}

    create_keys = retrieve_all_keys
    update_keys = retrieve_keys - {'dn'}

    add_member_keys = retrieve_keys | {'member_host'}
    add_condition_keys = retrieve_keys - {'dn'} |\
        {'automemberinclusiveregex', 'automembertargetgroup'}
    add_condition_negative_keys = {'automemberinclusiveregex'}

    def __init__(self, groupname, membertype, description='Automember desc'):
        super(AutomemberTracker, self).__init__(default_version=None)
        self.cn = groupname
        self.description = description
        self.membertype = membertype
        self.dn = DN(('cn', self.cn), ('cn', self.membertype.title()),
                     ('cn', 'automember'), ('cn', 'etc'), api.env.basedn)

    def make_create_command(self, *args, **kwargs):
        """ Make function that creates an automember using 'automember-add' """
        return self.make_command('automember_add', self.cn,
                                 description=self.description,
                                 type=self.membertype,
                                 *args, **kwargs)

    def make_delete_command(self):
        """ Make function that deletes an automember using 'automember-del' """
        return self.make_command('automember_del', self.cn,
                                 **dict(type=self.membertype))

    def make_retrieve_command(self, all=False, raw=False, membertype=None):
        """ Make function that retrieves an automember
        using 'automember-show' """
        if membertype is None:
            membertype = self.membertype
        return self.make_command('automember_show', self.cn, type=membertype)

    def make_find_command(self, *args, **kwargs):
        """ Make function that searches for an automember
            using 'automember-find' """
        return self.make_command('automember_find', self.cn,
                                 type=self.membertype)

    def make_update_command(self, updates):
        """ Make function that updates an automember using 'automember-mod' """
        return self.make_command('automember_mod', self.cn,
                                 type=self.membertype, **updates)

    def make_add_member_command(self, options={}):
        """ Make function that adds a member to an automember """
        return self.make_command('automember_add_member', self.cn, **options)

    def make_remove_member_command(self, options={}):
        """ Make function that removes a member from an automember """
        return self.make_command('automember_remove_member',
                                 self.cn, **options)

    def make_rebuild_command(self, *args, **kwargs):
        """ Make function that issues automember_rebuild.
        This function can be executed with arbitrary automember tracker """
        return self.make_command('automember_rebuild', *args, **kwargs)

    def make_add_condition_command(self, *args, **kwargs):
        """ Make function that issues automember_add_condition """
        return self.make_command('automember_add_condition', self.cn,
                                 *args, **kwargs)

    def make_remove_condition_command(self, *args, **kwargs):
        """ Make function that issues automember_remove_condition """
        return self.make_command('automember_remove_condition', self.cn,
                                 *args, **kwargs)

    def track_create(self):
        """ Updates expected state for automember creation"""
        self.attrs = dict(
            dn=self.dn,
            mepmanagedentry=[DN(('cn', self.cn), ('cn', 'ng'),
                                ('cn', 'alt'), api.env.basedn)],
            cn=[self.cn],
            description=[self.description],
            ipauniqueid=[fuzzy_uuid],
            objectclass=objectclasses.automember,
            automembertargetgroup=[DN(('cn', self.cn),
                                      ('cn', self.membertype + 's'),
                                      ('cn', 'accounts'), api.env.basedn)]

            )
        self.exists = True

    def add_member(self, options):
        """ Add a member host to automember and perform check """
        if 'group' in options:
            try:
                self.attrs['group'] =\
                    self.attrs['group'] + [options['group']]
            except KeyError:
                self.attrs['group'] = [options['group']]
            # search for hosts in the target automember and
            # add them as memberindirect hosts
        elif 'hostgroup' in options:
            try:
                self.attrs['hostgroup'] =\
                    self.attrs['hostgroup'] + [options['hostgroup']]
            except KeyError:
                self.attrs['hostgroup'] = [options['hostgroup']]

        command = self.make_add_member_command(options)
        result = command()
        self.check_add_member(result)

    def remove_member(self, options):
        """ Remove a member host from automember and perform check """
        if 'host' in options:
            self.attrs['member_host'].remove(options['host'])
        elif 'automember' in options:
            self.attrs['member_automember'].remove(options['automember'])

        try:
            if not self.attrs['member_host']:
                del self.attrs['member_host']
        except KeyError:
            pass
        try:
            if not self.attrs['member_automember']:
                del self.attrs['member_automember']
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

    def add_condition(self, key, type, inclusiveregex):
        """ Add a condition with given inclusive regex and check for result.
        Only one condition can be added. For more specific uses please
        use make_add_condition_command instead. """
        command = self.make_add_condition_command(
            key=key, type=type, automemberinclusiveregex=inclusiveregex)
        self.attrs['automemberinclusiveregex'] = ['%s=%s' %
                                                  (key, inclusiveregex[0])]
        result = command()
        self.check_add_condition(result)

    def add_condition_exclusive(self, key, type, exclusiveregex):
        """ Add a condition with given exclusive regex and check for result.
        Only one condition can be added. For more specific uses please
        use make_add_condition_command instead. """
        command = self.make_add_condition_command(
            key=key, type=type, automemberexclusiveregex=exclusiveregex)
        self.attrs['automemberexclusiveregex'] = ['%s=%s' %
                                                  (key, exclusiveregex[0])]
        result = command()
        self.check_add_condition(result)

    def rebuild(self, no_wait=False):
        """ Rebuild automember conditions and check for result """
        command = self.make_rebuild_command(type=self.membertype,
                                            no_wait=no_wait)
        result = command()
        self.check_rebuild(result, no_wait=no_wait)

    def check_rebuild(self, result, no_wait=False):
        """ Check result of automember_rebuild command """
        if no_wait is False:
            assert_deepequal(dict(
                value=None, result=dict(),
                summary=fuzzy_automember_message
                ), result)
        else:
            assert_deepequal(dict(
                value=None,
                result=dict(dn=fuzzy_automember_dn),
                summary='Automember rebuild membership task started'
                ), result)

    def check_add_condition(self, result):
        """ Check result of automember_add_condition command """
        assert_deepequal(dict(
            value=self.cn,
            summary='Added condition(s) to "%s"' % self.cn,
            completed=1,
            failed=dict(
                failed=dict(automemberinclusiveregex=tuple(),
                            automemberexclusiveregex=tuple(),
                            )
            ),
            result=self.filter_attrs(self.add_condition_keys)
            ), result)

    def check_add_condition_negative(self, result):
        """ Check result of automember_add_condition command
        when the operation didn't add anything. """
        assert_deepequal(dict(
            value=self.cn,
            summary='Added condition(s) to "%s"' % self.cn,
            completed=0,
            failed=dict(
                failed=dict(automemberinclusiveregex=tuple(),
                            automemberexclusiveregex=tuple(),
                            )
            ),
            result=self.filter_attrs(self.add_condition_negative_keys)
            ), result)

    def check_create(self, result):
        """ Checks 'automember_add' command result """
        assert_deepequal(dict(
            value=self.cn,
            summary='Added automember rule "%s"' % self.cn,
            result=self.filter_attrs(self.create_keys)
            ), result)

    def check_delete(self, result):
        """ Checks 'automember_del' command result """
        assert_deepequal(dict(
            value=[self.cn],
            summary='Deleted automember rule "%s"' % self.cn,
            result=dict(failed=[]),
            ), result)

    def check_retrieve(self, result, all=False, raw=False):
        """ Checks 'automember_show' command result """
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
        """ Checks 'automember_find' command result """
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary='1 rules matched',
            result=[expected],
        ), result)

    def check_update(self, result, extra_keys={}):
        """ Checks 'automember_mod' command result """
        assert_deepequal(dict(
            value=self.cn,
            summary='Modified automember rule "%s"' % self.cn,
            result=self.filter_attrs(self.update_keys | set(extra_keys))
        ), result)

    def check_add_member(self, result):
        """ Checks 'automember_add_member' command result """
        assert_deepequal(dict(
            completed=1,
            failed={'member': {'host': (), 'automember': ()}},
            result=self.filter_attrs(self.add_member_keys)
        ), result)

    def check_add_member_negative(self, result, options):
        """ Checks 'automember_add_member' command result
        when expected result is failure of the operation"""
        expected = dict(
            completed=0,
            failed={'member': {'automember': (), 'user': ()}},
            result=self.filter_attrs(self.add_member_keys)
        )
        if 'host' in options:
            expected['failed']['member']['host'] = [(
                options['host'], 'no such entry')]
        elif 'automember' in options:
            expected['failed']['member']['automember'] = [(
                options['automember'], 'no such entry')]

        assert_deepequal(expected, result)

    def check_remove_member_negative(self, result, options):
        """ Checks 'automember_remove_member' command result
        when expected result is failure of the operation"""
        expected = dict(
            completed=0,
            failed={'member': {'automember': (), 'host': ()}},
            result=self.filter_attrs(self.add_member_keys)
        )
        if 'user' in options:
            expected['failed']['member']['host'] = [(
                options['user'], 'This entry is not a member')]
        elif 'automember' in options:
            expected['failed']['member']['automember'] = [(
                options['automember'], 'This entry is not a member')]

        assert_deepequal(expected, result)

    def check_remove_member(self, result):
        """ Checks 'automember_remove_member' command result """
        self.check_add_member(result)
