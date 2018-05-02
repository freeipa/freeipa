# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Petr Viktorin <pviktori@redhat.com>
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
Test the `ipalib.aci` module.
"""
from __future__ import print_function

from ipalib.aci import ACI

import pytest

pytestmark = pytest.mark.tier0

def check_aci_parsing(source, expected):
    a = ACI(source)
    print('ACI was: ', a)
    print('Expected:', expected)
    assert str(ACI(source)) == expected

def test_aci_parsing_1():
    check_aci_parsing('(targetattr="title")(targetfilter="(memberOf=cn=bar,cn=groups,cn=accounts ,dc=example,dc=com)")(version 3.0;acl "foobar";allow (write) groupdn="ldap:///cn=foo,cn=groups,cn=accounts,dc=example,dc=com";)',
        '(targetattr = "title")(targetfilter = "(memberOf=cn=bar,cn=groups,cn=accounts ,dc=example,dc=com)")(version 3.0;acl "foobar";allow (write) groupdn = "ldap:///cn=foo,cn=groups,cn=accounts,dc=example,dc=com";)')

def test_aci_parsing_1_with_aci_keyword():
    check_aci_parsing('(targetattr="title")(targetfilter="(memberOf=cn=bar,cn=groups,cn=accounts ,dc=example,dc=com)")(version 3.0;aci "foobar";allow (write) groupdn="ldap:///cn=foo,cn=groups,cn=accounts,dc=example,dc=com";)',
        '(targetattr = "title")(targetfilter = "(memberOf=cn=bar,cn=groups,cn=accounts ,dc=example,dc=com)")(version 3.0;acl "foobar";allow (write) groupdn = "ldap:///cn=foo,cn=groups,cn=accounts,dc=example,dc=com";)')

def test_aci_parsing_2():
    check_aci_parsing('(target="ldap:///uid=bjensen,dc=example,dc=com")(targetattr=*) (version 3.0;acl "aci1";allow (write) userdn="ldap:///self";)',
        '(target = "ldap:///uid=bjensen,dc=example,dc=com")(targetattr = "*")(version 3.0;acl "aci1";allow (write) userdn = "ldap:///self";)')

def test_aci_parsing_3():
    check_aci_parsing(' (targetattr = "givenName || sn || cn || displayName || title || initials || loginShell || gecos || homePhone || mobile || pager || facsimileTelephoneNumber || telephoneNumber || street || roomNumber || l || st || postalCode || manager || secretary || description || carLicense || labeledURI || inetUserHTTPURL || seeAlso || employeeType  || businessCategory || ou")(version 3.0;acl "Self service";allow (write) userdn = "ldap:///self";)',
        '(targetattr = "givenName || sn || cn || displayName || title || initials || loginShell || gecos || homePhone || mobile || pager || facsimileTelephoneNumber || telephoneNumber || street || roomNumber || l || st || postalCode || manager || secretary || description || carLicense || labeledURI || inetUserHTTPURL || seeAlso || employeeType || businessCategory || ou")(version 3.0;acl "Self service";allow (write) userdn = "ldap:///self";)')

def test_aci_parsing_4():
    check_aci_parsing('(target="ldap:///uid=*,cn=users,cn=accounts,dc=example,dc=com")(version 3.0;acl "add_user";allow (add) groupdn="ldap:///cn=add_user,cn=taskgroups,dc=example,dc=com";)',
        '(target = "ldap:///uid=*,cn=users,cn=accounts,dc=example,dc=com")(version 3.0;acl "add_user";allow (add) groupdn = "ldap:///cn=add_user,cn=taskgroups,dc=example,dc=com";)')

def test_aci_parsing_5():
    check_aci_parsing('(targetattr=member)(target="ldap:///cn=ipausers,cn=groups,cn=accounts,dc=example,dc=com")(version 3.0;acl "add_user_to_default_group";allow (write) groupdn="ldap:///cn=add_user_to_default_group,cn=taskgroups,dc=example,dc=com";)',
        '(target = "ldap:///cn=ipausers,cn=groups,cn=accounts,dc=example,dc=com")(targetattr = "member")(version 3.0;acl "add_user_to_default_group";allow (write) groupdn = "ldap:///cn=add_user_to_default_group,cn=taskgroups,dc=example,dc=com";)')

def test_aci_parsing_6():
    check_aci_parsing('(targetattr!=member)(targe="ldap:///cn=ipausers,cn=groups,cn=accounts,dc=example,dc=com")(version 3.0;acl "add_user_to_default_group";allow (write) groupdn="ldap:///cn=add_user_to_default_group,cn=taskgroups,dc=example,dc=com";)',
        '(targe = "ldap:///cn=ipausers,cn=groups,cn=accounts,dc=example,dc=com")(targetattr != "member")(version 3.0;acl "add_user_to_default_group";allow (write) groupdn = "ldap:///cn=add_user_to_default_group,cn=taskgroups,dc=example,dc=com";)')

def test_aci_parsing_7():
    check_aci_parsing('(targetattr = "userPassword || krbPrincipalKey || sambaLMPassword || sambaNTPassword || passwordHistory")(version 3.0; acl "change_password"; allow (write) groupdn = "ldap:///cn=change_password,cn=taskgroups,dc=example,dc=com";)',
        '(targetattr = "userPassword || krbPrincipalKey || sambaLMPassword || sambaNTPassword || passwordHistory")(version 3.0;acl "change_password";allow (write) groupdn = "ldap:///cn=change_password,cn=taskgroups,dc=example,dc=com";)')


def make_test_aci():
    a = ACI()
    a.name ="foo"
    a.set_target_attr(['title','givenname'], "!=")
    a.set_bindrule_keyword("groupdn")
    a.set_bindrule_operator("=")
    a.set_bindrule_expression("\"ldap:///cn=foo,cn=groups,cn=accounts,dc=example,dc=com\"")
    a.permissions = ['read','write','add']
    return a


def test_aci_equality():
    a = make_test_aci()
    print(a)

    b = ACI()
    b.name ="foo"
    b.set_target_attr(['givenname','title'], "!=")
    b.set_bindrule_keyword("groupdn")
    b.set_bindrule_operator("=")
    b.set_bindrule_expression("\"ldap:///cn=foo,cn=groups,cn=accounts,dc=example,dc=com\"")
    b.permissions = ['add','read','write']
    print(b)

    assert a.isequal(b)
    assert a == b
    assert not a != b  # pylint: disable=unneeded-not


def check_aci_inequality(b):
    a = make_test_aci()
    print(a)
    print(b)

    assert not a.isequal(b)
    assert not a == b
    assert a != b


def test_aci_inequality_targetattr_expression():
    b = make_test_aci()
    b.set_target_attr(['givenname'], "!=")
    check_aci_inequality(b)


def test_aci_inequality_targetattr_op():
    b = make_test_aci()
    b.set_target_attr(['givenname', 'title'], "=")
    check_aci_inequality(b)


def test_aci_inequality_targetfilter():
    b = make_test_aci()
    b.set_target_filter('(objectclass=*)', "=")
    check_aci_inequality(b)


def test_aci_inequality_target():
    b = make_test_aci()
    b.set_target("ldap:///cn=bar,cn=groups,cn=accounts,dc=example,dc=com", "=")
    check_aci_inequality(b)


def test_aci_inequality_bindrule_keyword():
    b = make_test_aci()
    b.set_bindrule_keyword("userdn")
    check_aci_inequality(b)


def test_aci_inequality_bindrule_op():
    b = make_test_aci()
    b.set_bindrule_operator("!=")
    check_aci_inequality(b)


def test_aci_inequality_bindrule_expression():
    b = make_test_aci()
    b.set_bindrule_expression("\"ldap:///cn=bar,cn=groups,cn=accounts,dc=example,dc=com\"")
    check_aci_inequality(b)


def test_aci_inequality_permissions():
    b = make_test_aci()
    b.permissions = ['read', 'search', 'compare']
    check_aci_inequality(b)


def test_aci_parsing_8():
    check_aci_parsing('(targetattr != "userPassword || krbPrincipalKey || sambaLMPassword || sambaNTPassword || passwordHistory || krbMKey")(version 3.0; acl "Enable Anonymous access"; allow (read, search, compare) userdn = "ldap:///anyone";)',
        '(targetattr != "userPassword || krbPrincipalKey || sambaLMPassword || sambaNTPassword || passwordHistory || krbMKey")(version 3.0;acl "Enable Anonymous access";allow (read,search,compare) userdn = "ldap:///anyone";)')

def test_aci_parsing_9():
    check_aci_parsing('(targetfilter = "(|(objectClass=person)(objectClass=krbPrincipalAux)(objectClass=posixAccount)(objectClass=groupOfNames)(objectClass=posixGroup))")(targetattr != "aci || userPassword || krbPrincipalKey || sambaLMPassword || sambaNTPassword || passwordHistory")(version 3.0; acl "Account Admins can manage Users and Groups"; allow (add, delete, read, write) groupdn = "ldap:///cn=admins,cn=groups,cn=accounts,dc=greyoak,dc=com";)',
        '(targetattr != "aci || userPassword || krbPrincipalKey || sambaLMPassword || sambaNTPassword || passwordHistory")(targetfilter = "(|(objectClass=person)(objectClass=krbPrincipalAux)(objectClass=posixAccount)(objectClass=groupOfNames)(objectClass=posixGroup))")(version 3.0;acl "Account Admins can manage Users and Groups";allow (add,delete,read,write) groupdn = "ldap:///cn=admins,cn=groups,cn=accounts,dc=greyoak,dc=com";)')


def test_aci_parsing_10():
    """test subtypes"""
    check_aci_parsing('(targetattr="ipaProtectedOperation;read_keys")'
                      '(version 3.0; acl "Allow trust agents to retrieve '
                      'keytab keys for cross realm principals"; allow(read) '
                      'userattr="ipaAllowedToPerform;read_keys#GROUPDN";)',
                      '(targetattr = "ipaProtectedOperation;read || keys")'
                      '(version 3.0;acl "Allow trust agents to retrieve '
                      'keytab keys for cross realm principals";allow (read) '
                      'userattr = "ipaAllowedToPerform;read_keys#GROUPDN";)')
