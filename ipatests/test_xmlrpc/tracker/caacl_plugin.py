#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from ipalib import errors
from ipatests.util import assert_deepequal
from ipatests.test_xmlrpc.xmlrpc_test import (fuzzy_caacldn, fuzzy_uuid,
                                              fuzzy_ipauniqueid)
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.tracker.base import Tracker


class CAACLTracker(Tracker):
    """Tracker class for CA ACL LDAP object.

    The class implements methods required by the base class
    to help with basic CRUD operations.

    Methods for adding and deleting actual member entries into an ACL
    do not have check methods as these would make the class
    unnecessarily complicated. The checks are implemented as
    a standalone test suite. However, this makes the test crucial
    in debugging more complicated test cases. Since the add/remove
    operation won't be checked right away by the tracker, a problem
    in this operation may propagate into more complicated test case.

    It is possible to pass a list of member uids to these methods.

    The test uses instances of Fuzzy class to compare results as they
    are in the UUID format. The dn and rdn properties were modified
    to reflect this as well.
    """

    member_keys = {
        u'memberuser_user', u'memberuser_group',
        u'memberhost_host', u'memberhost_hostgroup',
        u'memberservice_service',
        u'ipamembercertprofile_certprofile',
        u'ipamemberca_ca'}
    category_keys = {
        u'ipacacategory', u'ipacertprofilecategory', u'usercategory',
        u'hostcategory', u'servicecategory', u'ipacacategory'}
    retrieve_keys = {
        u'dn', u'cn', u'description', u'ipaenabledflag',
        u'ipamemberca', u'ipamembercertprofile', u'memberuser',
        u'memberhost', u'memberservice'} | member_keys | category_keys
    retrieve_all_keys = retrieve_keys | {u'objectclass', u'ipauniqueid'}
    create_keys = {u'dn', u'cn', u'description', u'ipacertprofilecategory',
                   u'usercategory', u'hostcategory', u'ipacacategory',
                   u'servicecategory', u'ipaenabledflag', u'objectclass',
                   u'ipauniqueid'}
    update_keys = create_keys - {u'dn'}

    def __init__(self, name, ipacertprofile_category=None, user_category=None,
                 service_category=None, host_category=None,
                 ipaca_category=None, description=None, default_version=None):
        super(CAACLTracker, self).__init__(default_version=default_version)

        self._name = name
        self.description = description
        self._categories = dict(
            ipacertprofilecategory=ipacertprofile_category,
            ipacacategory=ipaca_category,
            usercategory=user_category,
            servicecategory=service_category,
            hostcategory=host_category)

        self.dn = fuzzy_caacldn

    @property
    def name(self):
        return self._name

    @property
    def rdn(self):
        return fuzzy_ipauniqueid

    @property
    def categories(self):
        """To be used in track_create"""
        return {cat: v for cat, v in self._categories.items() if v}

    @property
    def create_categories(self):
        """ Return the categories set on create.
            Unused categories are left out.
        """
        return {cat: [v] for cat, v in self.categories.items() if v}

    def make_create_command(self):
        return self.make_command(u'caacl_add', self.name,
                                 description=self.description,
                                 **self.categories)

    def check_create(self, result):
        assert_deepequal(dict(
            value=self.name,
            summary=u'Added CA ACL "{}"'.format(self.name),
            result=dict(self.filter_attrs(self.create_keys))
        ), result)

    def track_create(self):
        self.attrs = dict(
            dn=self.dn,
            ipauniqueid=[fuzzy_uuid],
            cn=[self.name],
            objectclass=objectclasses.caacl,
            ipaenabledflag=[u'TRUE'])

        self.attrs.update(self.create_categories)
        if self.description:
            self.attrs.update({u'description', [self.description]})

        self.exists = True

    def make_delete_command(self):
        return self.make_command('caacl_del', self.name)

    def check_delete(self, result):
        assert_deepequal(dict(
            value=[self.name],
            summary=u'Deleted CA ACL "{}"'.format(self.name),
            result=dict(failed=[])
        ), result)

    def make_retrieve_command(self, all=False, raw=False):
        return self.make_command('caacl_show', self.name, all=all, raw=raw)

    def check_retrieve(self, result, all=False, raw=False):
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        assert_deepequal(dict(
            value=self.name,
            summary=None,
            result=expected
        ), result)

    def make_find_command(self, *args, **kwargs):
        return self.make_command('caacl_find', *args, **kwargs)

    def check_find(self, result, all=False, raw=False):
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary=u'1 CA ACL matched',
            result=[expected]
        ), result)

    def make_update_command(self, updates):
        return self.make_command('caacl_mod', self.name, **updates)

    def update(self, updates, expected_updates=None, silent=False):
        """If removing a category, delete it from tracker as well"""
        # filter out empty categories and track changes

        filtered_updates = dict()
        for key, value in updates.items():
            if key in self.category_keys:
                if not value:
                    try:
                        del self.attrs[key]
                    except IndexError:
                        if silent:
                            pass
                else:
                    # if there is a value, prepare the pair for update
                    filtered_updates.update({key: value})
            else:
                filtered_updates.update({key: value})

        if expected_updates is None:
            expected_updates = {}

        command = self.make_update_command(updates)

        try:
            result = command()
        except errors.EmptyModlist:
            if silent:
                self.attrs.update(filtered_updates)
                self.attrs.update(expected_updates)
                self.check_update(result,
                                  extra_keys=set(self.update_keys) |
                                  set(expected_updates.keys()))

    def check_update(self, result, extra_keys=()):
        assert_deepequal(dict(
            value=self.name,
            summary=u'Modified CA ACL "{}"'.format(self.name),
            result=self.filter_attrs(self.update_keys | set(extra_keys))
        ), result)

    # Helper methods for caacl subcommands. The check methods will be
    # implemented in standalone test
    #
    # The methods implemented here will be:
    # caacl_{add,remove}_{host, service, certprofile, user, ca}

    def _add_acl_component(self, command_name, keys, track):
        """ Add a resource into ACL rule and track it.

            command_name - the name in the API
            keys = {
                'tracker_attr': {
                    'api_key': 'value'
                }
            }

            e.g.

            keys = {
                'memberhost_host': {
                    'host': 'hostname'
                },
                'memberhost_hostgroup': {
                    'hostgroup': 'hostgroup_name'
                }
            }
        """

        if not self.exists:
            raise errors.NotFound(reason="The tracked entry doesn't exist.")

        command = self.make_command(command_name, self.name)
        command_options = dict()

        # track
        for tracker_attr in keys:
            api_options = keys[tracker_attr]
            if track:
                for option in api_options:
                    try:
                        if type(option) in (list, tuple):
                            self.attrs[tracker_attr].extend(api_options[option])
                        else:
                            self.attrs[tracker_attr].append(api_options[option])
                    except KeyError:
                        if type(option) in (list, tuple):
                            self.attrs[tracker_attr] = api_options[option]
                        else:
                            self.attrs[tracker_attr] = [api_options[option]]
            # prepare options for the command call
            command_options.update(api_options)

        return command(**command_options)

    def _remove_acl_component(self, command_name, keys, track):
        """ Remove a resource from ACL rule and track it.

            command_name - the name in the API
            keys = {
                'tracker_attr': {
                    'api_key': 'value'
                }
            }

            e.g.

            keys = {
                'memberhost_host': {
                    'host': 'hostname'
                },
                'memberhost_hostgroup': {
                    'hostgroup': 'hostgroup_name'
                }
            }
        """
        command = self.make_command(command_name, self.name)
        command_options = dict()

        for tracker_attr in keys:
            api_options = keys[tracker_attr]
            if track:
                for option in api_options:
                    if type(option) in (list, tuple):
                        for item in option:
                            self.attrs[tracker_attr].remove(item)
                    else:
                        self.attrs[tracker_attr].remove(api_options[option])
                    if len(self.attrs[tracker_attr]) == 0:
                        del self.attrs[tracker_attr]
            command_options.update(api_options)

        return command(**command_options)

    def add_host(self, host=None, hostgroup=None, track=True):
        """Associates an host or hostgroup entry with the ACL.

           The command takes an unicode string with the name
           of the entry (RDN).

           It is the responsibility of a test writer to provide
           the correct value, object type as the method does not
           verify whether the entry exists.

           The method can add only one entry of each type
           in one call.
        """

        options = {
            u'memberhost_host': {u'host': host},
            u'memberhost_hostgroup': {u'hostgroup': hostgroup}}

        return self._add_acl_component(u'caacl_add_host', options, track)

    def remove_host(self, host=None, hostgroup=None, track=True):
        options = {
            u'memberhost_host': {u'host': host},
            u'memberhost_hostgroup': {u'hostgroup': hostgroup}}

        return self._remove_acl_component(u'caacl_remove_host', options, track)

    def add_user(self, user=None, group=None, track=True):
        options = {
            u'memberuser_user': {u'user': user},
            u'memberuser_group': {u'group': group}}

        return self._add_acl_component(u'caacl_add_user', options, track)

    def remove_user(self, user=None, group=None, track=True):
        options = {
            u'memberuser_user': {u'user': user},
            u'memberuser_group': {u'group': group}}

        return self._remove_acl_component(u'caacl_remove_user', options, track)

    def add_service(self, service=None, track=True):
        options = {
            u'memberservice_service': {u'service': service}}

        return self._add_acl_component(u'caacl_add_service', options, track)

    def remove_service(self, service=None, track=True):
        options = {
            u'memberservice_service': {u'service': service}}

        return self._remove_acl_component(u'caacl_remove_service', options, track)

    def add_profile(self, certprofile=None, track=True):
        options = {
            u'ipamembercertprofile_certprofile':
                {u'certprofile': certprofile}}

        return self._add_acl_component(u'caacl_add_profile', options, track)

    def remove_profile(self, certprofile=None, track=True):
        options = {
            u'ipamembercertprofile_certprofile':
                {u'certprofile': certprofile}}

        return self._remove_acl_component(u'caacl_remove_profile', options, track)

    def add_ca(self, ca=None, track=True):
        options = {
            u'ipamemberca_ca':
                {u'ca': ca}}

        return self._add_acl_component(u'caacl_add_ca', options, track)

    def remove_ca(self, ca=None, track=True):
        options = {
            u'ipamemberca_ca':
                {u'ca': ca}}

        return self._remove_acl_component(u'caacl_remove_ca', options, track)

    def enable(self):
        command = self.make_command(u'caacl_enable', self.name)
        self.attrs.update({u'ipaenabledflag': [u'TRUE']})
        command()

    def disable(self):
        command = self.make_command(u'caacl_disable', self.name)
        self.attrs.update({u'ipaenabledflag': [u'FALSE']})
        command()
