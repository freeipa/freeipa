# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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
Test the `ipaserver/plugins/selfservice.py` module.
"""

from ipalib import api, errors
from ipatests.test_xmlrpc.xmlrpc_test import (
    Declarative, XMLRPC_test, assert_attr_equal,
)
from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker
from ipatests.util import change_principal, unlock_principal_password
import pytest

selfservice1 = 'testself'
invalid_selfservice1 = 'bad+name'

@pytest.mark.tier1
class test_selfservice(Declarative):

    cleanup_commands = [
        ('selfservice_del', [selfservice1], {}),
    ]

    tests = [
        dict(
            desc='Try to retrieve non-existent %r' % selfservice1,
            command=('selfservice_show', [selfservice1], {}),
            expected=errors.NotFound(
                reason='ACI with name "%s" not found' % selfservice1
            ),
        ),
        dict(
            desc='Try to update non-existent %r' % selfservice1,
            command=(
                'selfservice_mod',
                [selfservice1],
                dict(permissions='write'),
            ),
            expected=errors.NotFound(
                reason='ACI with name "%s" not found' % selfservice1
            ),
        ),
        dict(
            desc='Try to delete non-existent %r' % selfservice1,
            command=('selfservice_del', [selfservice1], {}),
            expected=errors.NotFound(
                reason='ACI with name "%s" not found' % selfservice1
            ),
        ),
        dict(
            desc='Search for non-existent %r' % selfservice1,
            command=('selfservice_find', [selfservice1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary='0 selfservices matched',
                result=[],
            ),
        ),
        # Note that we add postalCode but expect postalcode. This tests
        # the attrs normalizer.
        dict(
            desc='Create %r' % selfservice1,
            command=(
                'selfservice_add',
                [selfservice1],
                dict(
                    attrs=['street', 'c', 'l', 'st', 'postalcode'],
                    permissions='write',
                ),
            ),
            expected=dict(
                value=selfservice1,
                summary='Added selfservice "%s"' % selfservice1,
                result=dict(
                    attrs=['street', 'c', 'l', 'st', 'postalcode'],
                    permissions=['write'],
                    selfaci=True,
                    aciname=selfservice1,
                ),
            ),
        ),
        dict(
            desc='Try to create duplicate %r' % selfservice1,
            command=(
                'selfservice_add',
                [selfservice1],
                dict(
                    attrs=['street', 'c', 'l', 'st', 'postalcode'],
                    permissions='write',
                ),
            ),
            expected=errors.DuplicateEntry(),
        ),
        dict(
            desc='Retrieve %r' % selfservice1,
            command=('selfservice_show', [selfservice1], {}),
            expected=dict(
                value=selfservice1,
                summary=None,
                result={
                    'attrs': ['street', 'c', 'l', 'st', 'postalcode'],
                    'permissions': ['write'],
                    'selfaci': True,
                    'aciname': selfservice1,
                },
            ),
        ),
        dict(
            desc='Retrieve %r with --raw' % selfservice1,
            command=('selfservice_show', [selfservice1], {'raw': True}),
            expected=dict(
                value=selfservice1,
                summary=None,
                result={
                    'aci': '(targetattr = "street || c || l || st || '
                    'postalcode")(version 3.0;acl "selfservice:testself";allow '
                    '(write) userdn = "ldap:///self";)',
                },
            ),
        ),
        dict(
            desc='Search for %r' % selfservice1,
            command=('selfservice_find', [selfservice1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 selfservice matched',
                result=[
                    {
                        'attrs': ['street', 'c', 'l', 'st', 'postalcode'],
                        'permissions': ['write'],
                        'selfaci': True,
                        'aciname': selfservice1,
                    },
                ],
            ),
        ),
        dict(
            desc='Search for %r with --pkey-only' % selfservice1,
            command=('selfservice_find', [selfservice1], {'pkey_only': True}),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 selfservice matched',
                result=[
                    {
                        'aciname': selfservice1,
                    },
                ],
            ),
        ),
        dict(
            desc='Search for %r with empty attrs and permissions'
            % selfservice1,
            command=(
                'selfservice_find',
                [selfservice1],
                {'attrs': None, 'permissions': None},
            ),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 selfservice matched',
                result=[
                    {
                        'attrs': ['street', 'c', 'l', 'st', 'postalcode'],
                        'permissions': ['write'],
                        'selfaci': True,
                        'aciname': selfservice1,
                    },
                ],
            ),
        ),
        dict(
            desc='Search for %r with --raw' % selfservice1,
            command=('selfservice_find', [selfservice1], {'raw': True}),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 selfservice matched',
                result=[
                    {
                        'aci': '(targetattr = "street || c || l || st || '
                        'postalcode")(version 3.0;acl '
                        '"selfservice:testself";allow (write) userdn = '
                        '"ldap:///self";)'
                    },
                ],
            ),
        ),
        dict(
            desc='Update %r' % selfservice1,
            command=(
                'selfservice_mod',
                [selfservice1],
                dict(permissions='read'),
            ),
            expected=dict(
                value=selfservice1,
                summary='Modified selfservice "%s"' % selfservice1,
                result=dict(
                    attrs=['street', 'c', 'l', 'st', 'postalcode'],
                    permissions=['read'],
                    selfaci=True,
                    aciname=selfservice1,
                ),
            ),
        ),
        dict(
            desc='Retrieve %r to verify update' % selfservice1,
            command=('selfservice_show', [selfservice1], {}),
            expected=dict(
                value=selfservice1,
                summary=None,
                result={
                    'attrs': ['street', 'c', 'l', 'st', 'postalcode'],
                    'permissions': ['read'],
                    'selfaci': True,
                    'aciname': selfservice1,
                },
            ),
        ),
        dict(
            desc='Try to update %r with empty permissions' % selfservice1,
            command=('selfservice_mod', [selfservice1], dict(permissions=None)),
            expected=errors.RequirementError(name='permissions'),
        ),
        dict(
            desc='Retrieve %r to verify invalid update' % selfservice1,
            command=('selfservice_show', [selfservice1], {}),
            expected=dict(
                value=selfservice1,
                summary=None,
                result={
                    'attrs': ['street', 'c', 'l', 'st', 'postalcode'],
                    'permissions': ['read'],
                    'selfaci': True,
                    'aciname': selfservice1,
                },
            ),
        ),
        dict(
            desc='Delete %r' % selfservice1,
            command=('selfservice_del', [selfservice1], {}),
            expected=dict(
                result=True,
                value=selfservice1,
                summary='Deleted selfservice "%s"' % selfservice1,
            ),
        ),
        dict(
            desc='Create invalid %r' % invalid_selfservice1,
            command=(
                'selfservice_add',
                [invalid_selfservice1],
                dict(
                    attrs=['street', 'c', 'l', 'st', 'postalcode'],
                    permissions='write',
                ),
            ),
            expected=errors.ValidationError(
                name='name',
                error='May only contain letters, numbers, -, _, and space',
            ),
        ),
    ]


@pytest.mark.tier1
class test_selfservice_misc(Declarative):
    """Bugzilla regression tests for selfservice plugin."""

    cleanup_commands = [
        ("selfservice_del", [selfservice1], {}),
    ]

    tests = [
        # BZ 772106: selfservice-add with --raw must not return internal error
        dict(
            desc="Create %r with --raw for BZ 772106" % selfservice1,
            command=(
                "selfservice_add",
                [selfservice1],
                dict(attrs=["l"], raw=True),
            ),
            expected=dict(
                value=selfservice1,
                summary='Added selfservice "%s"' % selfservice1,
                result={
                    "aci": '(targetattr = "l")(version 3.0;acl '
                    '"selfservice:%s";allow (write) '
                    'userdn = "ldap:///self";)' % selfservice1,
                },
            ),
        ),
        # BZ 772675: selfservice-mod with --raw must not return internal error
        dict(
            desc="Modify %r with --raw for BZ 772675" % selfservice1,
            command=(
                "selfservice_mod",
                [selfservice1],
                dict(attrs=["mobile"], raw=True),
            ),
            expected=dict(
                value=selfservice1,
                summary='Modified selfservice "%s"' % selfservice1,
                result={
                    "aci": '(targetattr = "mobile")(version 3.0;acl '
                    '"selfservice:%s";allow (write) '
                    'userdn = "ldap:///self";)' % selfservice1,
                },
            ),
        ),
        # BZ 747730: selfservice-mod --permissions="" must not delete the entry
        dict(
            desc=(
                "Modify %r with empty permissions for BZ 747730"
                % selfservice1
            ),
            command=(
                "selfservice_mod",
                [selfservice1],
                dict(permissions=""),
            ),
            expected=lambda got, output: True,
        ),
        dict(
            desc="Verify %r still exists after BZ 747730" % selfservice1,
            command=("selfservice_show", [selfservice1], {}),
            expected=lambda got, output: (
                got is None
                and output["result"]["aciname"] == selfservice1
            ),
        ),
        # BZ 747741: selfservice-mod --attrs=badattrs must not delete the entry
        dict(
            desc="Modify %r with bad attrs for BZ 747741" % selfservice1,
            command=(
                "selfservice_mod",
                [selfservice1],
                dict(attrs=["badattrs"]),
            ),
            expected=lambda got, output: True,
        ),
        dict(
            desc="Verify %r still exists after BZ 747741" % selfservice1,
            command=("selfservice_show", [selfservice1], {}),
            expected=lambda got, output: (
                got is None
                and output["result"]["aciname"] == selfservice1
            ),
        ),
        # BZ 747720: selfservice-find --permissions="" must not return
        # internal error
        dict(
            desc="BZ 747720: selfservice-find with empty permissions",
            command=("selfservice_find", [], dict(permissions="")),
            expected=lambda got, output: (
                got is None and isinstance(output["result"], (list, tuple))
            ),
        ),
        # BZ 747722: selfservice-find --attrs="" must not return
        # internal error
        dict(
            desc="BZ 747722: selfservice-find with empty attrs",
            command=("selfservice_find", [], dict(attrs="")),
            expected=lambda got, output: (
                got is None and isinstance(output["result"], (list, tuple))
            ),
        ),
    ]


SS_USER1 = 'ssuser0001'
SS_USER1_PASSWORD = 'Passw0rd1'
SS_USER2 = 'ssuser0002'
SS_USER2_PASSWORD = 'Passw0rd2'
SS_GOOD_MANAGER = 'ss_good_manager'
SS_GOOD_MANAGER_PASSWORD = 'Passw0rd3'

SS_DEFAULT_SELFSERVICE = 'User Self service'
SS_CUSTOM_RULE = 'ss_test_rule0001'

SS_DEFAULT_SELFSERVICE_ATTRS = [
    'givenname', 'sn', 'cn', 'displayname', 'title', 'initials',
    'loginshell', 'gecos', 'homephone', 'mobile', 'pager',
    'facsimiletelephonenumber', 'telephonenumber', 'street',
    'roomnumber', 'l', 'st', 'postalcode', 'manager', 'secretary',
    'description', 'carlicense', 'labeleduri', 'inetuserhttpurl',
    'seealso', 'employeetype', 'businesscategory', 'ou',
]

SS_CUSTOM_RULE_ATTRS = [
    'mobile', 'pager',
    'facsimiletelephonenumber', 'telephonenumber',
]


def _safe_del_selfservice(name):
    """Delete a selfservice rule, ignoring NotFound."""
    try:
        api.Command['selfservice_del'](name)
    except errors.NotFound:
        pass


@pytest.fixture
def custom_selfservice_rule(xmlrpc_setup):
    """Replace the default selfservice rule with the narrow custom rule."""
    api.Command['selfservice_del'](SS_DEFAULT_SELFSERVICE)
    api.Command['selfservice_add'](
        SS_CUSTOM_RULE, attrs=SS_CUSTOM_RULE_ATTRS,
    )
    yield
    _safe_del_selfservice(SS_CUSTOM_RULE)
    api.Command['selfservice_add'](
        SS_DEFAULT_SELFSERVICE, attrs=SS_DEFAULT_SELFSERVICE_ATTRS,
    )


@pytest.fixture(scope='class')
def ss_user1(request, xmlrpc_setup):
    tracker = UserTracker(
        name=SS_USER1, givenname='Test', sn='User0001',
        userpassword=SS_USER1_PASSWORD,
    )
    tracker.make_fixture(request)
    tracker.make_create_command()()
    tracker.exists = True
    unlock_principal_password(
        SS_USER1, SS_USER1_PASSWORD, SS_USER1_PASSWORD,
    )
    return tracker


@pytest.fixture(scope='class')
def ss_user2(request, xmlrpc_setup):
    tracker = UserTracker(
        name=SS_USER2, givenname='Test', sn='User0002',
        userpassword=SS_USER2_PASSWORD,
    )
    tracker.make_fixture(request)
    tracker.make_create_command()()
    tracker.exists = True
    unlock_principal_password(
        SS_USER2, SS_USER2_PASSWORD, SS_USER2_PASSWORD,
    )
    return tracker


@pytest.fixture(scope='class')
def ss_good_manager(request, xmlrpc_setup):
    tracker = UserTracker(
        name=SS_GOOD_MANAGER, givenname='Good', sn='Manager',
        userpassword=SS_GOOD_MANAGER_PASSWORD,
    )
    tracker.make_fixture(request)
    tracker.make_create_command()()
    tracker.exists = True
    unlock_principal_password(
        SS_GOOD_MANAGER, SS_GOOD_MANAGER_PASSWORD, SS_GOOD_MANAGER_PASSWORD,
    )
    return tracker


@pytest.mark.tier1
@pytest.mark.usefixtures('ss_user1', 'ss_user2', 'ss_good_manager')
class test_selfservice_users(XMLRPC_test):
    """Test self-service user attribute modification permissions."""

    # usertest_1001: Set all attrs allowed by default self-service rule.
    def test_set_all_default_selfservice_attrs(self):
        """Set all attrs allowed by the default self-service rule."""
        attrs = {
            'givenname': 'Good',
            'sn': 'User',
            'cn': 'gooduser',
            'displayname': 'gooduser',
            'initials': 'GU',
            'gecos': 'gooduser@good.example.com',
            'loginshell': '/bin/bash',
            'street': 'Good_Street_Rd',
            'l': 'Good_City',
            'st': 'Goodstate',
            'postalcode': '33333',
            'telephonenumber': '333-333-3333',
            'mobile': '333-333-3333',
            'pager': '333-333-3333',
            'facsimiletelephonenumber': '333-333-3333',
            'ou': 'good-org',
            'title': 'good_admin',
            'manager': SS_GOOD_MANAGER,
            'carlicense': 'good-3333',
        }

        with change_principal(SS_USER1, SS_USER1_PASSWORD):
            for attr, value in attrs.items():
                api.Command['user_mod'](SS_USER1, **{attr: value})

        entry = api.Command['user_show'](SS_USER1, all=True)['result']
        for attr, value in attrs.items():
            assert_attr_equal(entry, attr, value)

    # usertest_1002: Test that default disallowed attributes are rejected.
    def test_reject_uidnumber_by_default(self):
        """uidnumber change is rejected by default."""
        with change_principal(SS_USER1, SS_USER1_PASSWORD):
            with pytest.raises(errors.ACIError):
                api.Command['user_mod'](SS_USER1, uidnumber=9999)

    def test_reject_gidnumber_by_default(self):
        """gidnumber change is rejected by default."""
        with change_principal(SS_USER1, SS_USER1_PASSWORD):
            with pytest.raises(errors.ACIError):
                api.Command['user_mod'](SS_USER1, gidnumber=9999)

    def test_reject_homedirectory_by_default(self):
        """homedirectory change is rejected by default."""
        with change_principal(SS_USER1, SS_USER1_PASSWORD):
            with pytest.raises(errors.ACIError):
                api.Command['user_mod'](
                    SS_USER1, homedirectory='/home/gooduser')

    def test_reject_email_by_default(self):
        """email change is rejected by default."""
        with change_principal(SS_USER1, SS_USER1_PASSWORD):
            with pytest.raises(errors.ACIError):
                api.Command['user_mod'](
                    SS_USER1, mail='gooduser@good.example.com')

    # usertest_1003: All attrs rejected when the default rule is deleted.
    def test_all_attrs_rejected_without_default_rule(self):
        """All attrs are rejected when the default rule is deleted."""
        attrs = {
            'givenname': 'Bad',
            'sn': 'LUser',
            'cn': 'badluser',
            'displayname': 'badluser',
            'initials': 'BL',
            'gecos': 'badluser@bad.example.com',
            'loginshell': '/bin/tcsh',
            'street': 'Bad_Street_Av',
            'l': 'Bad_City',
            'st': 'Badstate',
            'postalcode': '99999',
            'telephonenumber': '999-999-9999',
            'mobile': '999-999-9999',
            'pager': '999-999-9999',
            'facsimiletelephonenumber': '999-999-9999',
            'ou': 'bad-org',
            'title': 'bad_admin',
            'manager': 'admin',
            'carlicense': 'bad-9999',
        }

        api.Command['selfservice_del'](SS_DEFAULT_SELFSERVICE)
        try:
            with change_principal(SS_USER1, SS_USER1_PASSWORD):
                for attr, value in attrs.items():
                    with pytest.raises(errors.ACIError):
                        api.Command['user_mod'](SS_USER1, **{attr: value})
        finally:
            api.Command['selfservice_add'](
                SS_DEFAULT_SELFSERVICE,
                attrs=SS_DEFAULT_SELFSERVICE_ATTRS,
            )

    # usertest_1004: Custom rule grants write access to its specified attrs.
    def test_custom_rule_grants_write_access(
            self, custom_selfservice_rule):
        """Custom rule grants write access to its specified attrs."""
        with change_principal(SS_USER1, SS_USER1_PASSWORD):
            api.Command['user_mod'](
                SS_USER1, telephonenumber='777-777-7777')
            api.Command['user_mod'](SS_USER1, mobile='777-777-7777')
            api.Command['user_mod'](SS_USER1, pager='777-777-7777')
            api.Command['user_mod'](
                SS_USER1,
                facsimiletelephonenumber='777-777-7777')

    # usertest_1005: Persisted attrs and user-find by phone, fax, manager.
    def test_verify_persisted_attrs(self):
        """Verify attrs set by previous tests are persisted."""
        expected = {
            'givenname': 'Good',
            'sn': 'User',
            'cn': 'gooduser',
            'displayname': 'gooduser',
            'initials': 'GU',
            'gecos': 'gooduser@good.example.com',
            'loginshell': '/bin/bash',
            'street': 'Good_Street_Rd',
            'l': 'Good_City',
            'st': 'Goodstate',
            'postalcode': '33333',
            'telephonenumber': '777-777-7777',
            'mobile': '777-777-7777',
            'pager': '777-777-7777',
            'facsimiletelephonenumber': '777-777-7777',
            'ou': 'good-org',
            'title': 'good_admin',
            'carlicense': 'good-3333',
        }

        entry = api.Command['user_show'](SS_USER1, all=True)['result']
        for attr, value in expected.items():
            assert_attr_equal(entry, attr, value)
        assert_attr_equal(entry, 'manager', SS_GOOD_MANAGER)

    def test_user_find_by_phone(self):
        """BZ 1188195: user-find by phone number returns results."""
        result = api.Command['user_find'](
            telephonenumber='777-777-7777')
        assert result['count'] >= 1
        uids = [e['uid'][0] for e in result['result']]
        assert SS_USER1 in uids

    def test_user_find_by_fax(self):
        """BZ 1188195: user-find by fax number returns results."""
        result = api.Command['user_find'](
            facsimiletelephonenumber='777-777-7777')
        assert result['count'] >= 1
        uids = [e['uid'][0] for e in result['result']]
        assert SS_USER1 in uids

    def test_user_find_by_manager(self):
        """BZ 781208: user-find by manager returns matches."""
        result = api.Command['user_find'](
            SS_USER1, manager=SS_GOOD_MANAGER)
        assert result['count'] >= 1, (
            'BZ 781208: user-find --manager did not find matches'
        )
        uids = [e['uid'][0] for e in result['result']]
        assert SS_USER1 in uids

    # usertest_1006: BZ 985016, 967509: user can modify an allowed attr.
    def test_user_can_modify_allowed_attr(self):
        """BZ 985016, 967509: user can modify an allowed attr."""
        with change_principal(SS_USER1, SS_USER1_PASSWORD):
            api.Command['user_mod'](SS_USER1, mobile='888-888-8888')
        entry = api.Command['user_show'](SS_USER1, all=True)['result']
        assert_attr_equal(entry, 'mobile', '888-888-8888')

    # usertest_1007: BZ 985016, 967509: disallowed attribute is rejected.
    def test_disallowed_attr_rejected_with_custom_rule(
            self, custom_selfservice_rule):
        """BZ 985016, 967509: disallowed attribute is rejected."""
        with change_principal(SS_USER1, SS_USER1_PASSWORD):
            with pytest.raises(errors.ACIError):
                api.Command['user_mod'](SS_USER1, title='Dr')

    # usertest_1008: user-mod fails atomically on mixed attr permissions.
    def test_user_mod_atomic_failure_mixed_perms(
            self, custom_selfservice_rule):
        """user-mod fails atomically when one attr is disallowed."""
        original_title = api.Command['user_show'](
            SS_USER1)['result'].get('title')
        with change_principal(SS_USER1, SS_USER1_PASSWORD):
            with pytest.raises(errors.ACIError):
                api.Command['user_mod'](
                    SS_USER1,
                    title='notgonnawork',
                    telephonenumber='999-999-9990',
                )
        result = api.Command['user_find'](
            SS_USER1, telephonenumber='999-999-9990')
        assert result['count'] == 0, (
            'Phone was changed despite disallowed title in same call'
        )
        after = api.Command['user_show'](SS_USER1)['result']
        assert after.get('title') == original_title, (
            'Title was modified despite being disallowed'
        )

    # usertest_1009: BZ 985013: user can change their own password.
    def test_self_password_change_via_passwd(self):
        """BZ 985013: user can change their own password via passwd."""
        policy = api.Command['pwpolicy_show']()['result']
        orig_minlife = policy.get('krbminpwdlife', ('1',))[0]

        api.Command['pwpolicy_mod'](krbminpwdlife=0)
        try:
            with change_principal(SS_USER1, SS_USER1_PASSWORD):
                api.Command['passwd'](
                    SS_USER1,
                    password='MyN3wP@55',
                    current_password=SS_USER1_PASSWORD,
                )
            # Reset password so the next test can authenticate
            unlock_principal_password(
                SS_USER1, 'MyN3wP@55', SS_USER1_PASSWORD,
            )
        finally:
            api.Command['pwpolicy_mod'](krbminpwdlife=int(orig_minlife))

    def test_self_password_change_via_user_mod(self):
        """BZ 985013: user can change their own password via user_mod."""
        policy = api.Command['pwpolicy_show']()['result']
        orig_minlife = policy.get('krbminpwdlife', ('1',))[0]

        api.Command['pwpolicy_mod'](krbminpwdlife=0)
        try:
            with change_principal(SS_USER1, SS_USER1_PASSWORD):
                api.Command['user_mod'](
                    SS_USER1,
                    userpassword='MyN3wP@55',
                )
        finally:
            api.Command['pwpolicy_mod'](krbminpwdlife=int(orig_minlife))

    # usertest_1010: User cannot modify another user's attributes.
    def test_cross_user_modification_rejected(self):
        """User cannot modify another user's attributes."""
        with change_principal(SS_USER2, SS_USER2_PASSWORD):
            with pytest.raises(errors.ACIError):
                api.Command['user_mod'](SS_USER1, mobile='867-5309')

    def test_verify_cross_user_modification_rejected(self):
        """Verify attrs did not change after cross-user modification."""
        result = api.Command['user_find'](SS_USER1, mobile='867-5309')
        assert result['count'] == 0, (
            'Mobile was changed by a different user'
        )


# Module-level constants for CLI test classes
# selfservice-add / selfservice-del CLI tests
SS_CLI_ADD_1004 = 'selfservice_add_1004'
SS_CLI_ADD_1006 = 'selfservice_add_1006'
SS_CLI_DEL_1001 = 'selfservice_del_1001'


@pytest.mark.tier1
class test_selfservice_cli_add_del(Declarative):
    """CLI tests for selfservice-add and selfservice-del commands."""

    cleanup_commands = [
        ('selfservice_del', [SS_CLI_ADD_1004], {}),
        ('selfservice_del', [SS_CLI_ADD_1006], {}),
    ]

    tests = [

        # add_1002: bad attrs + valid permissions + --all --raw
        dict(
            desc='add_1002: selfservice-add with bad attrs, valid permissions,'
                 ' --all --raw',
            command=(
                'selfservice_add',
                ['selfservice_add_1002'],
                dict(
                    attrs=['badattr'],
                    permissions='write',
                    all=True,
                    raw=True,
                ),
            ),
            expected=errors.InvalidSyntax(
                attr=r'targetattr "badattr" does not exist in schema. '
                     r'Please add attributeTypes "badattr" to '
                     r'schema if necessary. '
                     r'ACL Syntax Error(-5):'
                     r'(targetattr = \22badattr\22)'
                     r'(version 3.0;acl '
                     r'\22selfservice:selfservice_add_1002\22;'
                     r'allow (write) userdn = \22ldap:///self\22;)',
            ),
        ),

        # add_1003: valid attrs + bad permissions + --all --raw
        dict(
            desc='add_1003: selfservice-add with valid attrs, bad permissions,'
                 ' --all --raw',
            command=(
                'selfservice_add',
                ['selfservice_add_1003'],
                dict(
                    attrs=[
                        'telephonenumber', 'mobile',
                        'pager', 'facsimiletelephonenumber',
                    ],
                    permissions='badperm',
                    all=True,
                    raw=True,
                ),
            ),
            expected=errors.ValidationError(
                name='permissions',
                error='"badperm" is not a valid permission',
            ),
        ),

        # add_1004: valid attrs + valid permissions + --all --raw (BZ 772106)
        # selfservice-add with --raw must not return "internal error" message.
        dict(
            desc='add_1004: selfservice-add with valid attrs and permissions,'
                 ' --all --raw (BZ 772106)',
            command=(
                'selfservice_add',
                [SS_CLI_ADD_1004],
                dict(
                    attrs=[
                        'telephonenumber', 'mobile',
                        'pager', 'facsimiletelephonenumber',
                    ],
                    permissions='write',
                    all=True,
                    raw=True,
                ),
            ),
            expected=dict(
                value=SS_CLI_ADD_1004,
                summary='Added selfservice "%s"' % SS_CLI_ADD_1004,
                result={
                    'aci': (
                        '(targetattr = "telephonenumber || mobile || pager'
                        ' || facsimiletelephonenumber")'
                        '(version 3.0;acl "selfservice:%s";'
                        'allow (write) userdn = "ldap:///self";)'
                        % SS_CLI_ADD_1004
                    ),
                },
            ),
        ),

        # add_1005: bad attrs only
        dict(
            desc='add_1005: selfservice-add with bad attrs only',
            command=(
                'selfservice_add',
                ['selfservice_add_1005'],
                dict(attrs=['badattrs']),
            ),
            expected=errors.InvalidSyntax(
                attr=r'targetattr "badattrs" does not exist in schema. '
                     r'Please add attributeTypes "badattrs" to '
                     r'schema if necessary. '
                     r'ACL Syntax Error(-5):'
                     r'(targetattr = \22badattrs\22)'
                     r'(version 3.0;acl '
                     r'\22selfservice:selfservice_add_1005\22;'
                     r'allow (write) userdn = \22ldap:///self\22;)',
            ),
        ),

        # add_1006: valid attrs only
        dict(
            desc='add_1006: selfservice-add with valid attrs only',
            command=(
                'selfservice_add',
                [SS_CLI_ADD_1006],
                dict(attrs=[
                    'telephonenumber', 'mobile',
                    'pager', 'facsimiletelephonenumber',
                ]),
            ),
            expected=dict(
                value=SS_CLI_ADD_1006,
                summary='Added selfservice "%s"' % SS_CLI_ADD_1006,
                result=dict(
                    attrs=[
                        'telephonenumber', 'mobile',
                        'pager', 'facsimiletelephonenumber',
                    ],
                    permissions=['write'],
                    selfaci=True,
                    aciname=SS_CLI_ADD_1006,
                ),
            ),
        ),

        # Setup for del tests: create the rule that del_1001 will delete.
        dict(
            desc=(
                'Setup: create %r for selfservice-del tests'
                % SS_CLI_DEL_1001
            ),
            command=(
                'selfservice_add',
                [SS_CLI_DEL_1001],
                dict(attrs=['l'], permissions='write'),
            ),
            expected=dict(
                value=SS_CLI_DEL_1001,
                summary='Added selfservice "%s"' % SS_CLI_DEL_1001,
                result=dict(
                    attrs=['l'],
                    permissions=['write'],
                    selfaci=True,
                    aciname=SS_CLI_DEL_1001,
                ),
            ),
        ),

        # del_1001: delete an existing rule
        dict(
            desc='del_1001: selfservice-del of an existing rule',
            command=('selfservice_del', [SS_CLI_DEL_1001], {}),
            expected=dict(
                result=True,
                value=SS_CLI_DEL_1001,
                summary='Deleted selfservice "%s"' % SS_CLI_DEL_1001,
            ),
        ),

        # del_1002: delete a non-existent rule
        dict(
            desc='del_1002: selfservice-del of a non-existent rule',
            command=('selfservice_del', ['badname'], {}),
            expected=errors.NotFound(
                reason='ACI with name "badname" not found',
            ),
        ),

    ]
