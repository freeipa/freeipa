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
from ipatests.test_xmlrpc.xmlrpc_test import Declarative, XMLRPC_test
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


def _selfservice_del_if_exists(name):
    """Remove selfservice entry if it exists."""
    try:
        api.Command.selfservice_del(name)
    except errors.NotFound:
        pass


@pytest.mark.tier1
class TestSelfserviceBZs(XMLRPC_test):

    # Verify selfservice-add with --raw does not trigger an internal error
    def test_add_raw_no_internal_error_bz772106(self):
        """BZ 772106: selfservice-add --raw must not return internal error."""
        name = u"selfservice_bz_772106"
        try:
            result = api.Command.selfservice_add(
                name, attrs=[u'l'], raw=True
            )
            assert 'result' in result
        except Exception as e:
            if "internal error" in str(e).lower():
                pytest.fail(
                    "BZ 772106: selfservice-add --raw returns "
                    "internal error message"
                )
            raise
        finally:
            _selfservice_del_if_exists(name)

    # Verify selfservice-mod with --raw does not trigger an internal error
    def test_mod_raw_no_internal_error_bz772675(self):
        """BZ 772675: selfservice-mod --raw must not return internal error."""
        name = u"selfservice_bz_772675"
        try:
            api.Command.selfservice_add(name, attrs=[u'l'])
            result = api.Command.selfservice_mod(
                name, attrs=[u'mobile'], raw=True
            )
            assert 'result' in result
        except Exception as e:
            if "internal error" in str(e).lower():
                pytest.fail(
                    "BZ 772675: selfservice-mod --raw returns "
                    "internal error message"
                )
            raise
        finally:
            _selfservice_del_if_exists(name)

    # Verify selfservice-mod with empty permissions does not delete the ACI
    def test_mod_empty_permissions_does_not_delete_bz747730(self):
        """BZ 747730: selfservice-mod --permissions="" must not delete
        the selfservice."""
        name = u"selfservice_bz_747730"
        try:
            api.Command.selfservice_add(name, attrs=[u'l'])
            try:
                api.Command.selfservice_mod(name, permissions=u'')
            except Exception:
                pass  # mod may fail; we only care it does not delete the ACI
            # The selfservice must still exist after the mod attempt
            try:
                result = api.Command.selfservice_show(name)
                assert result['result']['aciname'] == name
            except errors.NotFound:
                pytest.fail(
                    "BZ 747730: selfservice-mod with empty permissions "
                    "deleted the selfservice"
                )
        finally:
            _selfservice_del_if_exists(name)

    # Verify selfservice-mod with invalid attrs does not delete the ACI
    def test_mod_bad_attrs_does_not_delete_bz747741(self):
        """BZ 747741: selfservice-mod --attrs=badattrs must not delete
        the selfservice."""
        name = u"selfservice_bz_747741"
        try:
            api.Command.selfservice_add(name, attrs=[u'l'])
            try:
                api.Command.selfservice_mod(name, attrs=[u'badattrs'])
            except Exception:
                pass  # mod may fail; we only care it does not delete the ACI
            # The selfservice must still exist after the mod attempt
            try:
                result = api.Command.selfservice_show(name)
                assert result['result']['aciname'] == name
            except errors.NotFound:
                pytest.fail(
                    "BZ 747741: selfservice-mod with wrong attrs "
                    "deleted the selfservice"
                )
        finally:
            _selfservice_del_if_exists(name)

    # Verify selfservice-find with --raw does not trigger an internal error
    def test_find_raw_no_internal_error_bz747693(self):
        """BZ 747693: selfservice-find --raw must not return internal error."""
        name = u"selfservice_bz_747693"
        try:
            api.Command.selfservice_add(name, attrs=[u'l'])
            result = api.Command.selfservice_find(name, raw=True)
            assert 'result' in result
        except Exception as e:
            if "internal error" in str(e).lower():
                pytest.fail(
                    "BZ 747693: selfservice-find --raw returns "
                    "internal error"
                )
            raise
        finally:
            _selfservice_del_if_exists(name)

    # Verify selfservice-find with empty permission does not return internal error
    def test_find_empty_permission_no_internal_error_bz747720(self):
        """BZ 747720: selfservice-find --permission="" must not return
        internal error."""
        try:
            result = api.Command.selfservice_find(permissions=u'')
            assert 'result' in result
        except Exception as e:
            if "internal error" in str(e).lower():
                pytest.fail(
                    "BZ 747720: selfservice-find with empty permission "
                    "returns internal error"
                )
            raise

    # Verify selfservice-find with empty attrs does not return internal error
    def test_find_empty_attrs_no_internal_error_bz747722(self):
        """BZ 747722: selfservice-find --attrs="" must not return
        internal error."""
        try:
            result = api.Command.selfservice_find(attrs=u'')
            assert 'result' in result
        except Exception as e:
            if "internal error" in str(e).lower():
                pytest.fail(
                    "BZ 747722: selfservice-find with empty attrs "
                    "returns internal error"
                )
            raise
