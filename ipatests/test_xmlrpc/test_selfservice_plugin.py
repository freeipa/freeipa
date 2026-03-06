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
from ipatests.util import change_principal, unlock_principal_password
import pytest

selfservice1 = u'testself'
invalid_selfservice1 = u'bad+name'

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
                reason=u'ACI with name "%s" not found' % selfservice1),
        ),


        dict(
            desc='Try to update non-existent %r' % selfservice1,
            command=('selfservice_mod', [selfservice1],
                dict(permissions=u'write')),
            expected=errors.NotFound(
                reason=u'ACI with name "%s" not found' % selfservice1),
        ),


        dict(
            desc='Try to delete non-existent %r' % selfservice1,
            command=('selfservice_del', [selfservice1], {}),
            expected=errors.NotFound(
                reason=u'ACI with name "%s" not found' % selfservice1),
        ),


        dict(
            desc='Search for non-existent %r' % selfservice1,
            command=('selfservice_find', [selfservice1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 selfservices matched',
                result=[],
            ),
        ),


        # Note that we add postalCode but expect postalcode. This tests
        # the attrs normalizer.
        dict(
            desc='Create %r' % selfservice1,
            command=(
                'selfservice_add', [selfservice1], dict(
                    attrs=[u'street', u'c', u'l', u'st', u'postalcode'],
                    permissions=u'write',
                )
            ),
            expected=dict(
                value=selfservice1,
                summary=u'Added selfservice "%s"' % selfservice1,
                result=dict(
                    attrs=[u'street', u'c', u'l', u'st', u'postalcode'],
                    permissions=[u'write'],
                    selfaci=True,
                    aciname=selfservice1,
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % selfservice1,
            command=(
                'selfservice_add', [selfservice1], dict(
                    attrs=[u'street', u'c', u'l', u'st', u'postalcode'],
                    permissions=u'write',
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
                    'attrs': [u'street', u'c', u'l', u'st', u'postalcode'],
                    'permissions': [u'write'],
                    'selfaci': True,
                    'aciname': selfservice1,
                },
            ),
        ),


        dict(
            desc='Retrieve %r with --raw' % selfservice1,
            command=('selfservice_show', [selfservice1], {'raw':True}),
            expected=dict(
                value=selfservice1,
                summary=None,
                result={
                    'aci': u'(targetattr = "street || c || l || st || postalcode")(version 3.0;acl "selfservice:testself";allow (write) userdn = "ldap:///self";)',
                },
            ),
        ),


        dict(
            desc='Search for %r' % selfservice1,
            command=('selfservice_find', [selfservice1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 selfservice matched',
                result=[
                    {
                        'attrs': [u'street', u'c', u'l', u'st', u'postalcode'],
                        'permissions': [u'write'],
                        'selfaci': True,
                        'aciname': selfservice1,
                    },
                ],
            ),
        ),

        dict(
            desc='Search for %r with --pkey-only' % selfservice1,
            command=('selfservice_find', [selfservice1], {'pkey_only' : True}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 selfservice matched',
                result=[
                    {
                        'aciname': selfservice1,
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r with empty attrs and permissions' % selfservice1,
            command=('selfservice_find', [selfservice1], {'attrs' : None, 'permissions' : None}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 selfservice matched',
                result=[
                    {
                        'attrs': [u'street', u'c', u'l', u'st', u'postalcode'],
                        'permissions': [u'write'],
                        'selfaci': True,
                        'aciname': selfservice1,
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r with --raw' % selfservice1,
            command=('selfservice_find', [selfservice1], {'raw':True}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 selfservice matched',
                result=[
                    {
                        'aci': u'(targetattr = "street || c || l || st || postalcode")(version 3.0;acl "selfservice:testself";allow (write) userdn = "ldap:///self";)'
                    },
                ],
            ),
        ),


        dict(
            desc='Update %r' % selfservice1,
            command=(
                'selfservice_mod', [selfservice1], dict(permissions=u'read')
            ),
            expected=dict(
                value=selfservice1,
                summary=u'Modified selfservice "%s"' % selfservice1,
                result=dict(
                    attrs=[u'street', u'c', u'l', u'st', u'postalcode'],
                    permissions=[u'read'],
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
                        'attrs': [u'street', u'c', u'l', u'st', u'postalcode'],
                        'permissions': [u'read'],
                        'selfaci': True,
                        'aciname': selfservice1,
                },
            ),
        ),


        dict(
            desc='Try to update %r with empty permissions' % selfservice1,
            command=(
                'selfservice_mod', [selfservice1], dict(permissions=None)
            ),
            expected=errors.RequirementError(name='permissions'),
        ),


        dict(
            desc='Retrieve %r to verify invalid update' % selfservice1,
            command=('selfservice_show', [selfservice1], {}),
            expected=dict(
                value=selfservice1,
                summary=None,
                result={
                        'attrs': [u'street', u'c', u'l', u'st', u'postalcode'],
                        'permissions': [u'read'],
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
                summary=u'Deleted selfservice "%s"' % selfservice1,
            )
        ),

        dict(
            desc='Create invalid %r' % invalid_selfservice1,
            command=(
                'selfservice_add', [invalid_selfservice1], dict(
                    attrs=[u'street', u'c', u'l', u'st', u'postalcode'],
                    permissions=u'write',
                )
            ),
            expected=errors.ValidationError(name='name',
                error='May only contain letters, numbers, -, _, and space'),
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


@pytest.mark.tier1
class test_selfservice_users(XMLRPC_test):
    """
    Test self-service user attribute modification permissions.

    (test cases 1001-1010).
    """

    user1 = u'ssuser0001'
    user1_password = u'Passw0rd1'
    user2 = u'ssuser0002'
    user2_password = u'Passw0rd2'
    good_manager = u'ss_good_manager'
    good_manager_password = u'Passw0rd3'

    default_selfservice = u'User Self service'
    custom_rule = u'ss_test_rule0001'

    default_selfservice_attrs = [
        u'givenname', u'sn', u'cn', u'displayname', u'title', u'initials',
        u'loginshell', u'gecos', u'homephone', u'mobile', u'pager',
        u'facsimiletelephonenumber', u'telephonenumber', u'street',
        u'roomnumber', u'l', u'st', u'postalcode', u'manager', u'secretary',
        u'description', u'carlicense', u'labeleduri', u'inetuserhttpurl',
        u'seealso', u'employeetype', u'businesscategory', u'ou',
    ]

    custom_rule_attrs = [
        u'mobile', u'pager',
        u'facsimiletelephonenumber', u'telephonenumber',
    ]

    @classmethod
    def setup_class(cls):
        """Clean up leftovers and create all test users."""
        if not api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.connect()
        cls.failsafe_del(api.Object.user, cls.user1)
        cls.failsafe_del(api.Object.user, cls.user2)
        cls.failsafe_del(api.Object.user, cls.good_manager)
        cls._safe_del_selfservice(cls.custom_rule)

        cls._create_user(cls.user1, u'Test', u'User0001', cls.user1_password)
        cls._create_user(cls.user2, u'Test', u'User0002', cls.user2_password)
        cls._create_user(
            cls.good_manager, u'Good', u'Manager', cls.good_manager_password,
        )

    @classmethod
    def teardown_class(cls):
        """Delete all test users and any leftover custom rules."""
        if not api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.connect()
        cls.failsafe_del(api.Object.user, cls.user1)
        cls.failsafe_del(api.Object.user, cls.user2)
        cls.failsafe_del(api.Object.user, cls.good_manager)
        cls._safe_del_selfservice(cls.custom_rule)

    @classmethod
    def _create_user(cls, login, givenname, sn, password):
        """Add a user and unlock their password for Kerberos auth."""
        api.Command['user_add'](
            login, givenname=givenname, sn=sn, userpassword=password,
        )
        unlock_principal_password(login, password, password)

    @classmethod
    def _safe_del_selfservice(cls, name):
        """Delete a selfservice rule, ignoring NotFound."""
        try:
            api.Command['selfservice_del'](name)
        except errors.NotFound:
            pass

    @classmethod
    def _delete_default_and_add_custom(cls):
        """Replace the default selfservice rule with the narrow custom rule."""
        api.Command['selfservice_del'](cls.default_selfservice)
        api.Command['selfservice_add'](
            cls.custom_rule, attrs=cls.custom_rule_attrs,
        )

    @classmethod
    def _restore_default_rule(cls):
        """Remove custom rule and re-create the default selfservice rule."""
        cls._safe_del_selfservice(cls.custom_rule)
        api.Command['selfservice_add'](
            cls.default_selfservice, attrs=cls.default_selfservice_attrs,
        )

    # usertest_1001: Set all attrs allowed by default self-service rule.
    def test_1001(self):
        """Set all attrs allowed by the default self-service rule."""
        with change_principal(self.user1, self.user1_password):
            api.Command['user_mod'](self.user1, givenname=u'Good')
            api.Command['user_mod'](self.user1, sn=u'User')
            api.Command['user_mod'](self.user1, cn=u'gooduser')
            api.Command['user_mod'](self.user1, displayname=u'gooduser')
            api.Command['user_mod'](self.user1, initials=u'GU')
            api.Command['user_mod'](
                self.user1, gecos=u'gooduser@good.example.com')
            api.Command['user_mod'](self.user1, loginshell=u'/bin/bash')
            api.Command['user_mod'](self.user1, street=u'Good_Street_Rd')
            api.Command['user_mod'](self.user1, l=u'Good_City')
            api.Command['user_mod'](self.user1, st=u'Goodstate')
            api.Command['user_mod'](self.user1, postalcode=u'33333')
            api.Command['user_mod'](
                self.user1, telephonenumber=u'333-333-3333')
            api.Command['user_mod'](self.user1, mobile=u'333-333-3333')
            api.Command['user_mod'](self.user1, pager=u'333-333-3333')
            api.Command['user_mod'](
                self.user1, facsimiletelephonenumber=u'333-333-3333')
            api.Command['user_mod'](self.user1, ou=u'good-org')
            api.Command['user_mod'](self.user1, title=u'good_admin')
            api.Command['user_mod'](self.user1, manager=self.good_manager)
            api.Command['user_mod'](self.user1, carlicense=u'good-3333')

    # usertest_1002: Test that default disallowed attributes are rejected.
    def test_1002_1(self):
        """uidnumber change is rejected by default."""
        with change_principal(self.user1, self.user1_password):
            with pytest.raises(errors.ACIError):
                api.Command['user_mod'](self.user1, uidnumber=9999)

    def test_1002_2(self):
        """gidnumber change is rejected by default."""
        with change_principal(self.user1, self.user1_password):
            with pytest.raises(errors.ACIError):
                api.Command['user_mod'](self.user1, gidnumber=9999)

    def test_1002_3(self):
        """homedirectory change is rejected by default."""
        with change_principal(self.user1, self.user1_password):
            with pytest.raises(errors.ACIError):
                api.Command['user_mod'](
                    self.user1, homedirectory=u'/home/gooduser')

    def test_1002_4(self):
        """email change is rejected by default."""
        with change_principal(self.user1, self.user1_password):
            with pytest.raises(errors.ACIError):
                api.Command['user_mod'](
                    self.user1, mail=u'gooduser@good.example.com')

    # usertest_1003: All attrs rejected when the default rule is deleted.
    def test_1003(self):
        """All attrs are rejected when the default rule is deleted."""
        api.Command['selfservice_del'](self.default_selfservice)
        try:
            with change_principal(self.user1, self.user1_password):
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](self.user1, givenname=u'Bad')
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](self.user1, sn=u'LUser')
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](self.user1, cn=u'badluser')
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](
                        self.user1, displayname=u'badluser')
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](self.user1, initials=u'BL')
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](
                        self.user1, gecos=u'badluser@bad.example.com')
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](
                        self.user1, loginshell=u'/bin/tcsh')
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](
                        self.user1, street=u'Bad_Street_Av')
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](self.user1, l=u'Bad_City')
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](self.user1, st=u'Badstate')
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](self.user1, postalcode=u'99999')
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](
                        self.user1, telephonenumber=u'999-999-9999')
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](
                        self.user1, mobile=u'999-999-9999')
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](
                        self.user1, pager=u'999-999-9999')
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](
                        self.user1,
                        facsimiletelephonenumber=u'999-999-9999')
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](self.user1, ou=u'bad-org')
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](self.user1, title=u'bad_admin')
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](
                        self.user1, manager=u'admin')
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](
                        self.user1, carlicense=u'bad-9999')
        finally:
            api.Command['selfservice_add'](
                self.default_selfservice,
                attrs=self.default_selfservice_attrs,
            )

    # usertest_1004: Custom rule grants write access to its specified attrs.
    def test_1004(self):
        """Custom rule grants write access to its specified attrs."""
        self._delete_default_and_add_custom()
        try:
            with change_principal(self.user1, self.user1_password):
                api.Command['user_mod'](
                    self.user1, telephonenumber=u'777-777-7777')
                api.Command['user_mod'](self.user1, mobile=u'777-777-7777')
                api.Command['user_mod'](self.user1, pager=u'777-777-7777')
                api.Command['user_mod'](
                    self.user1,
                    facsimiletelephonenumber=u'777-777-7777')
        finally:
            self._restore_default_rule()

    # usertest_1005: Persisted attrs and user-find by phone, fax, manager.
    def test_1005_1(self):
        """Verify attrs set in test_1001 and test_1004 are persisted."""
        entry = api.Command['user_show'](self.user1, all=True)['result']
        assert_attr_equal(entry, 'givenname', u'Good')
        assert_attr_equal(entry, 'sn', u'User')
        assert_attr_equal(entry, 'cn', u'gooduser')
        assert_attr_equal(entry, 'displayname', u'gooduser')
        assert_attr_equal(entry, 'initials', u'GU')
        assert_attr_equal(entry, 'gecos', u'gooduser@good.example.com')
        assert_attr_equal(entry, 'loginshell', u'/bin/bash')
        assert_attr_equal(entry, 'street', u'Good_Street_Rd')
        assert_attr_equal(entry, 'l', u'Good_City')
        assert_attr_equal(entry, 'st', u'Goodstate')
        assert_attr_equal(entry, 'postalcode', u'33333')
        assert_attr_equal(entry, 'telephonenumber', u'777-777-7777')
        assert_attr_equal(entry, 'mobile', u'777-777-7777')
        assert_attr_equal(entry, 'pager', u'777-777-7777')
        assert_attr_equal(entry, 'facsimiletelephonenumber', u'777-777-7777')
        assert_attr_equal(entry, 'ou', u'good-org')
        assert_attr_equal(entry, 'title', u'good_admin')
        assert_attr_equal(entry, 'carlicense', u'good-3333')
        # manager is stored as a full DN, so
        # assert_attr_equal cannot match the plain uid;
        # test_1005_4 verifies it via user_find --manager.
        assert u'manager' in entry

    def test_1005_2(self):
        """BZ 1188195: user-find by phone number returns results."""
        result = api.Command['user_find'](
            telephonenumber=u'777-777-7777')
        assert result['count'] >= 1
        uids = [e['uid'][0] for e in result['result']]
        assert self.user1 in uids

    def test_1005_3(self):
        """BZ 1188195: user-find by fax number returns results."""
        result = api.Command['user_find'](
            facsimiletelephonenumber=u'777-777-7777')
        assert result['count'] >= 1
        uids = [e['uid'][0] for e in result['result']]
        assert self.user1 in uids

    def test_1005_4(self):
        """BZ 781208: user-find by manager returns matches."""
        result = api.Command['user_find'](
            self.user1, manager=self.good_manager)
        assert result['count'] >= 1, (
            'BZ 781208: user-find --manager did not find matches'
        )
        uids = [e['uid'][0] for e in result['result']]
        assert self.user1 in uids

    # usertest_1006: BZ 985016, 967509: user can modify an allowed attr.
    def test_1006(self):
        """BZ 985016, 967509: user can modify an allowed attr."""
        with change_principal(self.user1, self.user1_password):
            api.Command['user_mod'](self.user1, mobile=u'888-888-8888')
        entry = api.Command['user_show'](self.user1, all=True)['result']
        assert_attr_equal(entry, 'mobile', u'888-888-8888')

    # usertest_1007: BZ 985016, 967509: disallowed attribute is rejected.
    def test_1007(self):
        """BZ 985016, 967509: disallowed attribute is rejected."""
        self._delete_default_and_add_custom()
        try:
            with change_principal(self.user1, self.user1_password):
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](self.user1, title=u'Dr')
        finally:
            self._restore_default_rule()

    # usertest_1008: user-mod fails atomically on mixed attr permissions.
    def test_1008(self):
        """user-mod fails atomically when one attr is disallowed."""
        self._delete_default_and_add_custom()
        original_title = api.Command['user_show'](
            self.user1)['result'].get('title')
        try:
            with change_principal(self.user1, self.user1_password):
                with pytest.raises(errors.ACIError):
                    api.Command['user_mod'](
                        self.user1,
                        title=u'notgonnawork',
                        telephonenumber=u'999-999-9990',
                    )
            result = api.Command['user_find'](
                self.user1, telephonenumber=u'999-999-9990')
            assert result['count'] == 0, (
                'Phone was changed despite disallowed title in same call'
            )
            after = api.Command['user_show'](self.user1)['result']
            assert after.get('title') == original_title, (
                'Title was modified despite being disallowed'
            )
        finally:
            self._restore_default_rule()

    # usertest_1009: BZ 985013: user can change their own password.
    def test_1009_passwd(self):
        """BZ 985013: user can change their own password via passwd."""
        policy = api.Command['pwpolicy_show']()['result']
        orig_minlife = policy.get('krbminpwdlife', (u'1',))[0]

        api.Command['pwpolicy_mod'](krbminpwdlife=0)
        try:
            with change_principal(self.user1, self.user1_password):
                api.Command['passwd'](
                    self.user1,
                    password=u'MyN3wP@55',
                    current_password=self.user1_password,
                )
            # Reset password back so test_1009_user_mod can authenticate
            api.Command['passwd'](self.user1, password=self.user1_password)
        finally:
            api.Command['pwpolicy_mod'](krbminpwdlife=int(orig_minlife))

    def test_1009_user_mod(self):
        """BZ 985013: user can change their own password via user_mod."""
        policy = api.Command['pwpolicy_show']()['result']
        orig_minlife = policy.get('krbminpwdlife', (u'1',))[0]

        api.Command['pwpolicy_mod'](krbminpwdlife=0)
        try:
            with change_principal(self.user1, self.user1_password):
                api.Command['user_mod'](
                    self.user1,
                    userpassword=u'MyN3wP@55',
                )
        finally:
            api.Command['pwpolicy_mod'](krbminpwdlife=int(orig_minlife))

    # usertest_1010: User cannot modify another user's attributes.
    def test_1010_1(self):
        """User cannot modify another user's attributes."""
        with change_principal(self.user2, self.user2_password):
            with pytest.raises(errors.ACIError):
                api.Command['user_mod'](self.user1, mobile=u'867-5309')

    def test_1010_2(self):
        """Verify attrs did not change after cross-user modification."""
        result = api.Command['user_find'](self.user1, mobile=u'867-5309')
        assert result['count'] == 0, (
            'Mobile was changed by a different user'
        )
