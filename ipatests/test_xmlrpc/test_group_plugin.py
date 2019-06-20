# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#   Filip Skola <fskola@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Test the `ipaserver/plugins/group.py` module.
"""

import pytest

from ipalib import errors
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import (
    fuzzy_digits, fuzzy_uuid, fuzzy_set_ci, add_oc,
    XMLRPC_test, raises_exact
)
from ipatests.test_xmlrpc.tracker.group_plugin import GroupTracker
from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker
from ipatests.util import assert_deepequal, get_group_dn

notagroup = u'notagroup'
renamedgroup1 = u'renamedgroup'
invalidgroup1 = u'+tgroup1'
external_sid1 = u'S-1-1-123456-789-1'


@pytest.fixture(scope='class')
def group(request, xmlrpc_setup):
    tracker = GroupTracker(name=u'testgroup1', description=u'Test desc1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def group2(request, xmlrpc_setup):
    tracker = GroupTracker(name=u'testgroup2', description=u'Test desc2')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def managed_group(request, user):
    user.ensure_exists()
    tracker = GroupTracker(
        name=user.uid, description=u'User private group for %s' % user.uid
    )
    tracker.exists = True
    # Managed group gets created when user is created
    tracker.track_create()
    return tracker


@pytest.fixture(scope='class')
def user(request, xmlrpc_setup):
    tracker = UserTracker(name=u'user1', givenname=u'Test', sn=u'User1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user_npg2(request, group):
    """ User tracker fixture for testing users with no private group """
    tracker = UserTracker(name=u'npguser2', givenname=u'Npguser',
                          sn=u'Npguser2', noprivate=True, gidnumber=1000)
    tracker.track_create()
    del tracker.attrs['mepmanagedentry']
    tracker.attrs.update(
        gidnumber=[u'1000'], description=[], memberof_group=[group.cn],
        objectclass=add_oc(objectclasses.user_base, u'ipantuserattrs')
    )
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def admins(request, xmlrpc_setup):
    # Track the admins group
    tracker = GroupTracker(
        name=u'admins', description=u'Account administrators group'
    )
    tracker.exists = True
    tracker.track_create()
    tracker.attrs.update(member_user=[u'admin'])
    return tracker


@pytest.fixture(scope='class')
def trustadmins(request, xmlrpc_setup):
    # Track the 'trust admins' group
    tracker = GroupTracker(
        name=u'trust admins', description=u'Trusts administrators group'
    )
    tracker.exists = True
    tracker.track_create()
    tracker.attrs.update(member_user=[u'admin'])
    return tracker


@pytest.mark.tier1
class TestGroup(XMLRPC_test):
    def test_create(self, group):
        """ Create a group """
        group.create()

    def test_create_duplicate(self, group):
        """ Try to create a duplicate group """
        group.ensure_exists()
        command = group.make_create_command()

        with raises_exact(errors.DuplicateEntry(
                message=u'group with name "%s" already exists' % group.cn)):
            command()

    def test_retrieve(self, group):
        """ Retrieve a group """
        group.retrieve()

    def test_update(self, group):
        """ Update a group with new description
        and perform retrieve command to verify the update """
        group.update(dict(description=u'New desc'))
        group.retrieve()

    def test_rename(self, group):
        """ Rename a group and than rename it back """
        origname = group.cn

        command = group.make_command('group_mod', *[group.cn],
                                     **dict(setattr=u'cn=%s' % renamedgroup1))
        result = command()
        group.attrs.update(cn=[renamedgroup1])
        group.check_update(result)
        group.cn = renamedgroup1

        command = group.make_command('group_mod', *[group.cn],
                                     **dict(setattr=u'cn=%s' % origname))
        result = command()
        group.attrs.update(cn=[origname])
        group.check_update(result)
        group.cn = origname

    def test_convert_posix_to_external(self, group):
        """ Try to convert a posix group to external """
        command = group.make_update_command(dict(external=True))
        with raises_exact(errors.PosixGroupViolation(
                reason=u"""This is already a posix group and cannot
                        be converted to external one""")):
            command()

    def test_add_with_invalid_name(self, group):
        """ Try to add group with an invalid name """
        command = group.make_command(
            'group_add', *[invalidgroup1], **dict(description=u'Test')
        )
        with raises_exact(errors.ValidationError(
                name='group_name',
                error=u'may only include letters, numbers, _, -, . and $')):
            command()

    def test_create_with_name_starting_with_numeric(self):
        """Successfully create a group with name starting with numeric chars"""
        testgroup = GroupTracker(
            name=u'1234group',
            description=u'Group name starting with numeric chars',
        )
        testgroup.create()
        testgroup.delete()

    def test_create_with_numeric_only_group_name(self):
        """Try to create a group with name only contains numeric chars"""
        testgroup = GroupTracker(
            name=u'1234', description=u'Numeric only group name',
        )
        with raises_exact(errors.ValidationError(
            name='group_name',
            error=u'may only include letters, numbers, _, -, . and $',
        )):
            testgroup.create()


@pytest.mark.tier1
class TestFindGroup(XMLRPC_test):
    def test_search(self, group):
        """ Search for a group """
        group.ensure_exists()
        group.find()

    def test_search_for_all_groups_with_members(self, group, group2):
        """ Search for all groups """
        group.ensure_exists()
        group2.create()
        command = group.make_command('group_find', no_members=False)
        result = command()
        assert_deepequal(dict(
            summary=u'6 groups matched',
            count=6,
            truncated=False,
            result=[
                {
                    'dn': get_group_dn('admins'),
                    'member_user': [u'admin'],
                    'gidnumber': [fuzzy_digits],
                    'cn': [u'admins'],
                    'description': [u'Account administrators group'],
                },
                {
                    'dn': get_group_dn('editors'),
                    'gidnumber': [fuzzy_digits],
                    'cn': [u'editors'],
                    'description':
                        [u'Limited admins who can edit other users'],
                },
                {
                    'dn': get_group_dn('ipausers'),
                    'cn': [u'ipausers'],
                    'description': [u'Default group for all users'],
                },
                {
                    'dn': get_group_dn(group.cn),
                    'cn': [group.cn],
                    'description': [u'Test desc1'],
                    'gidnumber': [fuzzy_digits],
                },
                {
                    'dn': get_group_dn(group2.cn),
                    'cn': [group2.cn],
                    'description': [u'Test desc2'],
                    'gidnumber': [fuzzy_digits],
                },
                {
                    'dn': get_group_dn('trust admins'),
                    'member_user': [u'admin'],
                    'cn': [u'trust admins'],
                    'description': [u'Trusts administrators group'],
                },
            ]), result)


    def test_search_for_all_groups(self, group, group2):
        """ Search for all groups """
        group.ensure_exists()
        group2.ensure_exists()
        command = group.make_command('group_find')
        result = command()
        assert_deepequal(dict(
            summary=u'6 groups matched',
            count=6,
            truncated=False,
            result=[
                {
                    'dn': get_group_dn('admins'),
                    'gidnumber': [fuzzy_digits],
                    'cn': [u'admins'],
                    'description': [u'Account administrators group'],
                },
                {
                    'dn': get_group_dn('editors'),
                    'gidnumber': [fuzzy_digits],
                    'cn': [u'editors'],
                    'description':
                        [u'Limited admins who can edit other users'],
                },
                {
                    'dn': get_group_dn('ipausers'),
                    'cn': [u'ipausers'],
                    'description': [u'Default group for all users'],
                },
                {
                    'dn': get_group_dn(group.cn),
                    'cn': [group.cn],
                    'description': [u'Test desc1'],
                    'gidnumber': [fuzzy_digits],
                },
                {
                    'dn': get_group_dn(group2.cn),
                    'cn': [group2.cn],
                    'description': [u'Test desc2'],
                    'gidnumber': [fuzzy_digits],
                },
                {
                    'dn': get_group_dn('trust admins'),
                    'cn': [u'trust admins'],
                    'description': [u'Trusts administrators group'],
                },
            ]), result)


    def test_search_for_all_posix(self, group, group2):
        """ Search for all posix groups """
        command = group.make_command(
            'group_find', **dict(posix=True, all=True)
        )
        result = command()
        assert_deepequal(dict(
            summary=u'4 groups matched',
            count=4,
            truncated=False,
            result=[
                {
                    'dn': get_group_dn('admins'),
                    'member_user': [u'admin'],
                    'gidnumber': [fuzzy_digits],
                    'cn': [u'admins'],
                    'description': [u'Account administrators group'],
                    'objectclass': fuzzy_set_ci(add_oc(
                        objectclasses.posixgroup, u'ipantgroupattrs')),
                    'ipauniqueid': [fuzzy_uuid],
                },
                {
                    'dn': get_group_dn('editors'),
                    'gidnumber': [fuzzy_digits],
                    'cn': [u'editors'],
                    'description':
                        [u'Limited admins who can edit other users'],
                    'objectclass': fuzzy_set_ci(add_oc(
                        objectclasses.posixgroup, u'ipantgroupattrs')),
                    'ipauniqueid': [fuzzy_uuid],
                },
                {
                    'dn': get_group_dn(group.cn),
                    'cn': [group.cn],
                    'description': [u'Test desc1'],
                    'gidnumber': [fuzzy_digits],
                    'objectclass': fuzzy_set_ci(add_oc(
                        objectclasses.posixgroup, u'ipantgroupattrs')),
                    'ipauniqueid': [fuzzy_uuid],
                },
                {
                    'dn': get_group_dn(group2.cn),
                    'cn': [group2.cn],
                    'description': [u'Test desc2'],
                    'gidnumber': [fuzzy_digits],
                    'objectclass': fuzzy_set_ci(add_oc(
                        objectclasses.posixgroup, u'ipantgroupattrs')),
                    'ipauniqueid': [fuzzy_uuid],
                },
            ]), result)


@pytest.mark.tier1
class TestNonexistentGroup(XMLRPC_test):
    def test_retrieve_nonexistent(self, group):
        """ Try to retrieve a non-existent group """
        group.ensure_missing()
        command = group.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: group not found' % group.cn)):
            command()

    def test_update_nonexistent(self, group):
        """ Try to update a non-existent group """
        group.ensure_missing()
        command = group.make_update_command(
            updates=dict(description=u'hey'))
        with raises_exact(errors.NotFound(
                reason=u'%s: group not found' % group.cn)):
            command()

    def test_delete_nonexistent(self, group):
        """ Try to delete a non-existent user """
        group.ensure_missing()
        command = group.make_delete_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: group not found' % group.cn)):
            command()

    def test_rename_nonexistent(self, group):
        """ Try to rename a non-existent user """
        group.ensure_missing()
        command = group.make_update_command(
            updates=dict(setattr=u'cn=%s' % renamedgroup1))
        with raises_exact(errors.NotFound(
                reason=u'%s: group not found' % group.cn)):
            command()


@pytest.mark.tier1
class TestNonposixGroup(XMLRPC_test):
    def test_create_nonposix(self, group):
        """ Create a non-posix group """
        group.track_create()
        command = group.make_create_command(**dict(nonposix=True))
        result = command()

        del group.attrs['gidnumber']
        group.attrs.update(objectclass=objectclasses.group)
        group.check_create(result)

    def test_create_duplicate_to_nonposix(self, group):
        """ Try to create a duplicate non-posix group """
        group.ensure_exists()
        command = group.make_create_command()

        with raises_exact(errors.DuplicateEntry(
                message=u'group with name "%s" already exists' % group.cn)):
            command()

    def test_retrieve_nonposix(self, group):
        """ Retrieve a non-posix group """
        group.retrieve()

    def test_update_nonposix(self, group):
        """ Update a non-posix group with new description
        and perform retrieve command to verify the update """
        group.update(dict(description=u'New desc'))
        group.retrieve()

    def test_search_for_all_nonposix(self, group):
        """ Perform a search for all non-posix groups """
        command = group.make_command(
            'group_find', **dict(nonposix=True, all=True)
        )
        result = command()
        assert_deepequal(dict(
            summary=u'3 groups matched',
            count=3,
            truncated=False,
            result=[
                {
                    'dn': get_group_dn('ipausers'),
                    'cn': [u'ipausers'],
                    'description': [u'Default group for all users'],
                    'objectclass': fuzzy_set_ci(objectclasses.group),
                    'ipauniqueid': [fuzzy_uuid],
                },
                {
                    'dn': get_group_dn(group.cn),
                    'cn': [group.cn],
                    'description': [u'New desc'],
                    'objectclass': fuzzy_set_ci(objectclasses.group),
                    'ipauniqueid': [fuzzy_uuid],
                },
                {
                    'dn': get_group_dn('trust admins'),
                    'member_user': [u'admin'],
                    'cn': [u'trust admins'],
                    'description': [u'Trusts administrators group'],
                    'objectclass': fuzzy_set_ci(objectclasses.group),
                    'ipauniqueid': [fuzzy_uuid],
                },
            ],
        ), result)

    def test_upgrade_nonposix_to_posix(self, group):
        """ Update non-posix group to promote it to posix group """
        group.attrs.update(gidnumber=[fuzzy_digits])
        group.update(dict(posix=True), dict(posix=None))
        group.retrieve()

    def test_search_for_all_nonposix_with_criteria(self, group):
        """ Search for all non-posix groups with additional
        criteria filter """
        command = group.make_command(
            'group_find', *[u'users'], **dict(nonposix=True, all=True)
        )
        result = command()
        assert_deepequal(dict(
            summary=u'1 group matched',
            count=1,
            truncated=False,
            result=[
                {
                    'dn': get_group_dn('ipausers'),
                    'cn': [u'ipausers'],
                    'description': [u'Default group for all users'],
                    'objectclass': fuzzy_set_ci(objectclasses.group),
                    'ipauniqueid': [fuzzy_uuid],
                },
            ],
        ), result)


@pytest.mark.tier1
class TestExternalGroup(XMLRPC_test):
    def test_create_external(self, group):
        """ Create a non-posix group """
        group.track_create()
        del group.attrs['gidnumber']
        group.attrs.update(objectclass=objectclasses.externalgroup)
        command = group.make_create_command(**dict(external=True))
        result = command()
        group.check_create(result)

    def test_search_for_external(self, group):
        """ Search for all external groups """
        command = group.make_command(
            'group_find', **dict(external=True, all=True)
        )
        result = command()
        group.check_find(result, all=True)

    def test_convert_external_to_posix(self, group):
        """ Try to convert an external group to posix """
        command = group.make_update_command(dict(posix=True))
        with raises_exact(errors.ExternalGroupViolation(
                reason=u'This group cannot be posix because it is external')):
            command()

    def test_add_external_member_to_external(self, group):
        """ Try to add an invalid external member to an external
        group and check that proper exceptions are raised """
        # When adding external SID member to a group we can't test
        # it fully due to possibly missing Samba 4 python bindings
        # and/or not configured AD trusts. Thus, we'll use incorrect
        # SID value to merely test that proper exceptions are raised
        command = group.make_command('group_add_member', *[group.cn],
                                     **dict(ipaexternalmember=external_sid1))
        try:
            command()
        except Exception as ex:
            if type(ex) == errors.ValidationError:
                pass
            elif type(ex) == errors.NotFound:
                pass
            elif 'failed' in str(ex):
                pass
            else:
                raise ex

    def test_delete_external_group(self, group):
        group.delete()


@pytest.mark.tier1
class TestGroupMember(XMLRPC_test):
    def test_add_nonexistent_member(self, group):
        """ Try to add non-existent member to a group """
        group.create()
        command = group.make_add_member_command(dict(group=notagroup))
        result = command()
        group.check_add_member_negative(result, dict(group=notagroup))

    def test_remove_nonexistent_member(self, group):
        """ Try to remove non-existent member from a group """
        group.ensure_exists()
        command = group.make_remove_member_command(dict(group=notagroup))
        result = command()
        group.check_remove_member_negative(result, dict(group=notagroup))

    def test_add_member(self, group, group2):
        """ Add member group to a group """
        group.ensure_exists()
        group2.ensure_exists()
        group.add_member(dict(group=group2.cn))

    def test_remove_member(self, group, group2):
        """ Remove a group member """
        group.ensure_exists()
        group2.ensure_exists()
        group.remove_member(dict(group=group2.cn))

    def test_add_and_remove_group_from_admins(self, group, admins):
        """ Add group to protected admins group and then remove it """
        # Test scenario from ticket #4448
        # https://fedorahosted.org/freeipa/ticket/4448
        group.ensure_exists()
        admins.add_member(dict(group=group.cn))
        admins.remove_member(dict(group=group.cn))


@pytest.mark.tier1
class TestValidation(XMLRPC_test):
    # The assumption for this class of tests is that if we don't
    # get a validation error then the request was processed normally.

    def test_validation_disabled_on_delete(self, group):
        """ Test that validation is disabled on group deletes """
        command = group.make_command('group_del', invalidgroup1)
        with raises_exact(errors.NotFound(
                reason=u'%s: group not found' % invalidgroup1)):
            command()

    def test_validation_disabled_on_show(self, group):
        """ Test that validation is disabled on group retrieves """
        command = group.make_command('group_show', invalidgroup1)
        with raises_exact(errors.NotFound(
                reason=u'%s: group not found' % invalidgroup1)):
            command()

    def test_validation_disabled_on_mod(self, group):
        """ Test that validation is disabled on group mods """
        command = group.make_command('group_mod', invalidgroup1)
        with raises_exact(errors.NotFound(
                reason=u'%s: group not found' % invalidgroup1)):
            command()


@pytest.mark.tier1
class TestManagedGroups(XMLRPC_test):
    def test_verify_managed_created(self, managed_group):
        """ Verify that managed group is created with new user """
        managed_group.retrieve()

    def test_verify_managed_findable(self, managed_group):
        """ Verify that managed group can be found """
        command = managed_group.make_find_command(
            **dict(cn=managed_group.cn, private=True)
        )
        result = command()
        managed_group.check_find(result)

    def test_delete_managed(self, managed_group):
        """ Try to delete managed group """
        command = managed_group.make_delete_command()
        with raises_exact(errors.ManagedGroupError()):
            command()

    def test_detach_managed(self, managed_group):
        """ Detach managed group from a user """
        command = managed_group.make_detach_command()
        result = command()
        managed_group.check_detach(result)

    def test_delete_detached_managed(self, managed_group, user):
        """ Delete a previously managed group that is now detached
        and verify it's really gone """
        managed_group.delete()
        command = managed_group.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: group not found' % managed_group.cn)):
            command()
        user.ensure_missing()

    def test_verify_managed_missing_for_user_without_upg(self, user_npg2):
        """ Create a user without user private group and
        verify private group wasn't created """
        user_npg2.attrs.update(memberof_group=[u'ipausers'])
        command = user_npg2.make_create_command()
        result = command()
        user_npg2.check_create(result, [u'description', u'memberof_group'])
        command = user_npg2.make_command('group_show', *[user_npg2.uid])
        with raises_exact(errors.NotFound(
                reason=u'%s: group not found' % user_npg2.uid)):
            command()


@pytest.mark.tier1
class TestManagedGroupObjectclasses(XMLRPC_test):
    def test_check_objectclasses_after_detach(self, user, managed_group):
        """ Check objectclasses after user was detached from managed group """
        # https://fedorahosted.org/freeipa/ticket/4909#comment:1
        user.ensure_exists()
        user.run_command('group_detach', *[user.uid])
        managed_group.retrieve(all=True)
        managed_group.add_member(dict(user=user.uid))
        managed_group.ensure_missing()
        user.ensure_missing()


@pytest.mark.tier1
class TestAdminGroup(XMLRPC_test):
    def test_remove_admin_from_admins(self, admins):
        """ Remove the original admin from admins group """
        command = admins.make_remove_member_command(
            dict(user=u'admin')
        )
        with raises_exact(errors.LastMemberError(
                key=u'admin', label=u'group', container=admins.cn)):
            command()

    def test_add_another_admin(self, admins, user):
        """ Add second member to the admins group """
        user.ensure_exists()
        admins.add_member(dict(user=user.uid))

    def test_remove_all_admins_from_admins(self, admins, user):
        """ Try to remove both original and our admin from admins group """
        command = admins.make_remove_member_command(
            dict(user=[u'admin', user.uid])
        )
        with raises_exact(errors.LastMemberError(
                key=u'admin', label=u'group', container=admins.cn)):
            command()

    def test_delete_admins(self, admins):
        """ Try to delete the protected admins group """
        command = admins.make_delete_command()
        with raises_exact(errors.ProtectedEntryError(label=u'group',
                          key=admins.cn, reason='privileged group')):
            command()

    def test_rename_admins(self, admins):
        """ Try to rename the protected admins group """
        command = admins.make_command('group_mod', *[admins.cn],
                                      **dict(rename=renamedgroup1))
        with raises_exact(errors.ProtectedEntryError(label=u'group',
                          key=admins.cn, reason='Cannot be renamed')):
            command()

    def test_rename_admins_using_setattr(self, admins):
        """ Try to rename the protected admins group using setattr """
        command = admins.make_command('group_mod', *[admins.cn],
                                      **dict(setattr=u'cn=%s' % renamedgroup1))
        with raises_exact(errors.ProtectedEntryError(label=u'group',
                          key=admins.cn, reason='Cannot be renamed')):
            command()

    def test_update_admins_to_support_external_membership(self, admins):
        """ Try to modify the admins group to support external membership """
        command = admins.make_command('group_mod', *[admins.cn],
                                      **dict(external=True))
        with raises_exact(errors.ProtectedEntryError(label=u'group',
                          key=admins.cn,
                          reason='Cannot support external non-IPA members')):
            command()


@pytest.mark.tier1
class TestTrustAdminGroup(XMLRPC_test):
    def test_delete_trust_admins(self, trustadmins):
        """ Try to delete the protected 'trust admins' group """
        command = trustadmins.make_delete_command()
        with raises_exact(errors.ProtectedEntryError(label=u'group',
                          key=trustadmins.cn, reason='privileged group')):
            command()

    def test_rename_trust_admins(self, trustadmins):
        """ Try to rename the protected 'trust admins' group """
        command = trustadmins.make_command('group_mod', *[trustadmins.cn],
                                           **dict(rename=renamedgroup1))
        with raises_exact(errors.ProtectedEntryError(label=u'group',
                          key=trustadmins.cn, reason='Cannot be renamed')):
            command()

    def test_rename_trust_admins_using_setattr(self, trustadmins):
        """ Try to rename the protected 'trust admins' group using setattr """
        command = trustadmins.make_command(
            'group_mod', *[trustadmins.cn],
            **dict(setattr=u'cn=%s' % renamedgroup1)
        )
        with raises_exact(errors.ProtectedEntryError(label=u'group',
                          key=trustadmins.cn, reason='Cannot be renamed')):
            command()

    def test_update_trust_admins_to_support_external_membership(
            self, trustadmins
    ):
        """ Try to modify the 'trust admins' group to
            support external membership """
        command = trustadmins.make_command(
            'group_mod', *[trustadmins.cn],
            **dict(external=True)
        )
        with raises_exact(errors.ProtectedEntryError(label=u'group',
                          key=trustadmins.cn,
                          reason='Cannot support external non-IPA members')):
            command()


@pytest.mark.tier1
class TestGroupMemberManager(XMLRPC_test):
    def test_add_member_manager_user(self, user, group):
        user.ensure_exists()
        group.ensure_exists()
        group.add_member_manager({"user": user.uid})

    def test_remove_member_manager_user(self, user, group):
        user.ensure_exists()
        group.ensure_exists()
        group.remove_member_manager({"user": user.uid})

    def test_add_member_manager_group(self, group, group2):
        group.ensure_exists()
        group2.ensure_exists()
        group.add_member_manager({"group": group2.cn})

    def test_remove_member_manager_group(self, group, group2):
        group.ensure_exists()
        group2.ensure_exists()
        group.remove_member_manager({"group": group2.cn})

    def test_member_manager_delete_user(self, user, group):
        user.ensure_exists()
        group.ensure_exists()
        group.add_member_manager({"user": user.uid})
        user.delete()
        # deleting a user also deletes member manager reference
        group.attrs.pop("membermanager_user")
        group.retrieve()
