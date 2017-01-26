#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

from contextlib import contextmanager
import itertools
from nose.tools import assert_raises
import pytest

from ipalib import api, errors
from ipapython.dn import DN
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipatests.test_xmlrpc.tracker.certmap_plugin import (CertmapruleTracker,
                                                         CertmapconfigTracker)
from ipatests.util import assert_deepequal
from ipatests.util import change_principal, unlock_principal_password


certmaprule_create_params = {
        u'cn': u'test_rule',
        u'description': u'Certificate mapping and matching rule for test '
                        u'purposes',
        u'ipacertmapissuer': DN('CN=CA,O=EXAMPLE.ORG'),
        u'ipacertmapmaprule': u'arbitrary free-form mapping rule defined and '
                              u'consumed by SSSD',
        u'ipacertmapmatchrule': u'arbitrary free-form matching rule defined '
                                u'and consumed by SSSD',
        u'associateddomain': u'example.org',
        u'ipacertmappriority': u'1',
}

certmaprule_update_params = {
        u'description': u'Changed description',
        u'ipacertmapissuer': DN('CN=Changed CA,O=OTHER.ORG'),
        u'ipacertmapmaprule': u'changed arbitrary mapping rule',
        u'ipacertmapmatchrule': u'changed arbitrary maching rule',
        u'associateddomain': u'changed.example.org',
        u'ipacertmappriority': u'5',
}

certmaprule_optional_params = (
    'description',
    'ipacertmapissuer',
    'ipacertmapmaprule',
    'ipacertmapmatchrule',
    'ipaassociateddomain',
    'ipacertmappriority',
)

certmapconfig_update_params = {u'ipacertmappromptusername': u'TRUE'}

CREATE_PERM = u'System: Add Certmap Rules'
READ_PERM = u'System: Read Certmap Rules'
UPDATE_PERM = u'System: Modify Certmap Rules'
DELETE_PERM = u'System: Delete Certmap Rules'

certmaprule_permissions = {
    u'C': CREATE_PERM,
    u'R': READ_PERM,
    u'U': UPDATE_PERM,
    u'D': DELETE_PERM,
}

CERTMAP_USER = u'cuser'
CERTMAP_PASSWD = 'Secret123'


def dontfill_idfn(dont_fill):
    return u"dont_fill=({})".format(', '.join([
        u"{}".format(d) for d in dont_fill
    ]))


def update_idfn(update):
    return ', '.join(["{}: {}".format(k, v) for k, v in update.items()])


@pytest.fixture(scope='class')
def certmap_rule(request):
    tracker = CertmapruleTracker(**certmaprule_create_params)
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def certmap_config(request):
    tracker = CertmapconfigTracker()
    return tracker.make_fixture(request)


class TestCRUD(XMLRPC_test):
    @pytest.mark.parametrize(
        'dont_fill',
        itertools.chain(*[
            itertools.combinations(certmaprule_optional_params, l)
            for l in range(len(certmaprule_optional_params)+1)
        ]),
        ids=dontfill_idfn,
    )
    def test_create(self, dont_fill, certmap_rule):
        certmap_rule.ensure_missing()
        try:
            certmap_rule.create(dont_fill)
        finally:
            certmap_rule.ensure_missing()

    def test_retrieve(self, certmap_rule):
        certmap_rule.ensure_exists()
        certmap_rule.retrieve()

    def test_find(self, certmap_rule):
        certmap_rule.ensure_exists()
        certmap_rule.find()

    @pytest.mark.parametrize('update', [
            dict(u) for l in range(1, len(certmaprule_update_params)+1)
            for u in itertools.combinations(
                certmaprule_update_params.items(), l)
        ],
        ids=update_idfn,
    )
    def test_update(self, update, certmap_rule):
        certmap_rule.ensure_missing()
        certmap_rule.ensure_exists()
        certmap_rule.update(update, {o: [v] for o, v in update.items()})

    def test_delete(self, certmap_rule):
        certmap_rule.ensure_exists()
        certmap_rule.delete()


class TestEnableDisable(XMLRPC_test):
    def test_disable(self, certmap_rule):
        certmap_rule.ensure_exists()
        certmap_rule.disable()

    def test_enable(self, certmap_rule):
        certmap_rule.ensure_exists()
        certmap_rule.enable()


class TestConfig(XMLRPC_test):
    def test_config_mod(self, certmap_config):
        certmap_config.update(
            certmapconfig_update_params,
            {k: [v] for k, v in certmapconfig_update_params.items()}
        )

    def test_config_show(self, certmap_config):
        certmap_config.retrieve()


@contextmanager
def execute_with_expected(user, password, perms, exps, ok_expected=None):
    """
    Run command as specified user. Check exception or return value
    according provided rules.

    @param user     Change to this user before calling the command
    @param password User to change user
    @param perms    User has those permissions
    @param exps     Iterable containing tuple
                    (permission, exception_class, expected_result,)
                    If permission is missing command must raise exception of
                    exception_class. If exception class is None command must
                    raise Result(expected_result)
    @param ok_expected  When no permission is missing command must raise
                        Result(ok_expected)
    """
    for perm, exception, expected in exps:
        if perm not in perms:
            break
    else:
        exception = None
        expected = ok_expected

    with change_principal(user, password):
        if exception:
            with assert_raises(exception):
                yield
        else:
            got = yield
            if expected:
                if got:
                    assert_deepequal(expected, got)
                else:
                    assert("Command didn't returned")


def permissions_idfn(perms):
    i = []
    for short_name, long_name in certmaprule_permissions.items():
        if long_name in perms:
            i.append(short_name)
        else:
            i.append('-')
    return ''.join(i)


def change_permissions_bindtype(perm, bindtype):
    orig = api.Command.permission_show(perm)['result']['ipapermbindruletype']
    if orig != (bindtype,):
        api.Command.permission_mod(perm, ipapermbindruletype=bindtype)

    return orig


@pytest.fixture(scope='class')
def bindtype_permission(request):
    orig_bindtype = {}
    # set bindtype to permission to actually test the permission
    for perm_name in certmaprule_permissions.values():
        orig_bindtype[perm_name] = change_permissions_bindtype(
            perm_name, u'permission')

    def finalize():
        for perm_name, bindtype in orig_bindtype.items():
            change_permissions_bindtype(perm_name, bindtype[0])

    request.addfinalizer(finalize)


@pytest.fixture(
    scope='class',
    params=itertools.chain(*[
            itertools.combinations(certmaprule_permissions.values(), l)
            for l in range(len(certmaprule_permissions.values())+1)
    ]),
    ids=permissions_idfn,
)
def certmap_user_permissions(request, bindtype_permission):
    tmp_password = u'Initial123'

    priv_name = u'test_certmap_privilege'
    role_name = u'test_certmap_role'

    api.Command.user_add(CERTMAP_USER, givenname=u'Certmap', sn=u'User',
                         userpassword=tmp_password)
    unlock_principal_password(CERTMAP_USER, tmp_password,
                              CERTMAP_PASSWD)

    api.Command.privilege_add(priv_name)
    for perm_name in request.param:
        # add to privilege for user
        api.Command.privilege_add_permission(priv_name, permission=perm_name)
    api.Command.role_add(role_name)
    api.Command.role_add_privilege(role_name, privilege=priv_name)
    api.Command.role_add_member(role_name, user=CERTMAP_USER)

    def finalize():
        try:
            api.Command.user_del(CERTMAP_USER)
        except Exception:
            pass
        try:
            api.Command.role_del(role_name)
        except Exception:
            pass
        try:
            api.Command.privilege_del(priv_name)
        except Exception:
            pass

    request.addfinalizer(finalize)

    return request.param


class TestPermission(XMLRPC_test):
    def test_create(self, certmap_rule, certmap_user_permissions):
        certmap_rule.ensure_missing()

        with execute_with_expected(
            CERTMAP_USER,
            CERTMAP_PASSWD,
            certmap_user_permissions,
            [
                (CREATE_PERM, errors.ACIError, None,),
                (READ_PERM, errors.NotFound, None,),
            ],
        ):
            certmap_rule.create()

        # Tracker sets 'exists' to True even when the create does not
        # succeed so ensure_missing wouldn't be reliable here
        try:
            certmap_rule.delete()
        except Exception:
            pass

    def test_retrieve(self, certmap_rule, certmap_user_permissions):
        certmap_rule.ensure_exists()

        with execute_with_expected(
            CERTMAP_USER,
            CERTMAP_PASSWD,
            certmap_user_permissions,
            [
                (READ_PERM, errors.NotFound, None,),
            ],
        ):
            certmap_rule.retrieve()

    def test_find(self, certmap_rule, certmap_user_permissions):
        certmap_rule.ensure_exists()

        expected_without_read = {
            u'count': 0,
            u'result': (),
            u'summary': u'0 Certificate Identity Mapping Rules matched',
            u'truncated': False,
        }
        expected_ok = {
            u'count': 1,
            u'result': [{
                k: (v,) for k, v in certmaprule_create_params.items()
            }],
            u'summary': u'1 Certificate Identity Mapping Rule matched',
            u'truncated': False,
        }
        expected_ok[u'result'][0][u'dn'] = DN(
            (u'cn', expected_ok[u'result'][0][u'cn'][0]),
            api.env.container_certmaprules,
            api.env.basedn,
        )
        expected_ok[u'result'][0][u'ipaenabledflag'] = (u'TRUE',)
        with execute_with_expected(
            CERTMAP_USER,
            CERTMAP_PASSWD,
            certmap_user_permissions,
            [
                (READ_PERM, None, expected_without_read,),
            ],
            expected_ok,
        ):
            find = certmap_rule.make_find_command()
            find(**{k: v for k, v in certmaprule_create_params.items()
                    if k is not u'dn'})

    def test_update(self, certmap_rule, certmap_user_permissions):
        certmap_rule.ensure_missing()
        certmap_rule.ensure_exists()

        with execute_with_expected(
            CERTMAP_USER,
            CERTMAP_PASSWD,
            certmap_user_permissions,
            [
                (READ_PERM, errors.NotFound, None,),
                (UPDATE_PERM, errors.ACIError, None,),
            ],
        ):
            certmap_rule.update(
                certmaprule_update_params,
                {o: [v] for o, v in certmaprule_update_params.items()},
            )

    def test_delete(self, certmap_rule, certmap_user_permissions):
        certmap_rule.ensure_exists()

        with execute_with_expected(
            CERTMAP_USER,
            CERTMAP_PASSWD,
            certmap_user_permissions,
            [
                (DELETE_PERM, errors.ACIError, None,),
            ],
        ):
            certmap_rule.delete()

        # Tracker sets 'exists' to False even when the delete does not
        # succeed so ensure_missing wouldn't be reliable here
        try:
            certmap_rule.delete()
        except Exception:
            pass

    def test_enable(self, certmap_rule, certmap_user_permissions):
        certmap_rule.ensure_exists()
        certmap_rule.disable()

        with execute_with_expected(
            CERTMAP_USER,
            CERTMAP_PASSWD,
            certmap_user_permissions,
            [
                (READ_PERM, errors.NotFound, None,),
                (UPDATE_PERM, errors.ACIError, None,),
            ],
        ):
            certmap_rule.enable()

    def test_disable(self, certmap_rule, certmap_user_permissions):
        certmap_rule.ensure_exists()
        certmap_rule.enable()

        with execute_with_expected(
            CERTMAP_USER,
            CERTMAP_PASSWD,
            certmap_user_permissions,
            [
                (READ_PERM, errors.NotFound, None,),
                (UPDATE_PERM, errors.ACIError, None,),
            ],
        ):
            certmap_rule.disable()
