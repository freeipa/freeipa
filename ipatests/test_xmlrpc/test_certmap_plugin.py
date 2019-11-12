#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

import itertools
import pytest

from ipalib import api, errors
from ipapython.dn import DN
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, raises_exact
from ipatests.test_xmlrpc.tracker.certmap_plugin import (CertmapruleTracker,
                                                         CertmapconfigTracker)
from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker
from ipatests.util import assert_deepequal
from ipatests.util import change_principal, unlock_principal_password


certmaprule_create_params = {
        u'cn': u'test_rule',
        u'description': u'Certificate mapping and matching rule for test '
                        u'purposes',
        u'ipacertmapmaprule': u'arbitrary free-form mapping rule defined and '
                              u'consumed by SSSD',
        u'ipacertmapmatchrule': u'arbitrary free-form matching rule defined '
                                u'and consumed by SSSD',
        u'associateddomain': api.env.domain,
        u'ipacertmappriority': u'1',
}

certmaprule_create_trusted_params = {
    u'cn': u'test_trusted_rule',
    u'description': u'Certificate mapping and matching rule for test '
                    u'purposes for trusted domain',
    u'ipacertmapmaprule': u'altsecurityidentities=X509:<some map>',
    u'ipacertmapmatchrule': u'arbitrary free-form matching rule defined '
                            u'and consumed by SSSD',
    u'associateddomain': api.env.domain,
    u'ipacertmappriority': u'1',
}

certmaprule_update_params = {
        u'description': u'Changed description',
        u'ipacertmapmaprule': u'changed arbitrary mapping rule',
        u'ipacertmapmatchrule': u'changed arbitrary maching rule',
        u'ipacertmappriority': u'5',
}

certmaprule_optional_params = (
    'description',
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
def certmap_rule_trusted_domain(request):
    tracker = CertmapruleTracker(**certmaprule_create_trusted_params)
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
                list(certmaprule_update_params.items()), l)
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

    def test_failed_create(self, certmap_rule_trusted_domain):
        certmap_rule_trusted_domain.ensure_missing()
        try:
            certmap_rule_trusted_domain.create([])
        except errors.ValidationError:
            certmap_rule_trusted_domain.exists = False
        else:
            certmap_rule_trusted_domain.exists = True
            certmap_rule_trusted_domain.ensure_missing()
            raise AssertionError("Expected validation error for "
                                 "altSecurityIdentities used for IPA domain")


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


certmapdata_create_params = {
    u'issuer': u'CN=CA,O=EXAMPLE.ORG',
    u'subject': u'CN={},O=EXAMPLE.ORG'.format(CERTMAP_USER),
    u'ipacertmapdata': (u'X509:<I>O=EXAMPLE.ORG,CN=CA'
                        u'<S>O=EXAMPLE.ORG,CN={}'.format(CERTMAP_USER)),
    u'certificate': (
        u'MIICwzCCAaugAwIBAgICP9wwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEChMLRVhB\n\r'
        'TVBMRS5PUkcxCzAJBgNVBAMTAkNBMB4XDTE3MDIxMDEzMjAyNVoXDTE3MDUxMDEz\n\r'
        'MjAyNVowJjEUMBIGA1UEChMLRVhBTVBMRS5PUkcxDjAMBgNVBAMTBWN1c2VyMIIB\n\r'
        'IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlEBxZ6RULSZZ+nW1YfJUfCaX\n\r'
        'wHIIWJeAoU98m7dbdUtkZMgLCPXiceIkCkcHu0DLS3wYlsL6VDG+0nIpT56Qkxph\n\r'
        '+qpWGdVptnuVZ5dEthbluoopzxpkAAz3ywM3NqfTCM78G9GQvftUZEOlwnfyEBbY\n\r'
        'XXs2wBhynrVTZcpL+ORXMpzVAallU63/YUExNvBzHlqdGHy+pPJSw1gsRTpLm75p\n\r'
        '36r3bn/5cnIih1WUygC0WnjxXQwqOdGUauBp/Z8JVRuLSe8qbPfcl/voQGnSt3u2\n\r'
        '9CFkDKpMMp6pv/3RbnOmMwSZGO0/n4G13qEdoneIghF1SE9qaxFGWk8mSDYc5QID\n\r'
        'AQABMA0GCSqGSIb3DQEBCwUAA4IBAQCKrvO7AUCt9YOyJ0RioDxgQZVJqQ0/E877\n\r'
        'vBP3HPwN0xkiGgASKtEDi3uLWGQfDgJFX5qXtK1qu7yiM86cbKq9PlkLTC6UowjP\n\r'
        'iaFAaVBwbS3nLVo731gn5cCJqZ0QrDt2NDiXaGxo4tBcqc/Y/taw5Py3f59tMDk6\n\r'
        'TnTmKmFnI+hB4+oxZhpcFj6bX35XMJXnRyekraE5VWtSbq57SXiRnINW4gNS5B6w\n\r'
        'dYUGo551tfFq+DOnSl0H7NnnL3q4VzCH/1AMOownorgVsw4LqMgY0NiaD/yqJyKe\n\r'
        'SggODAjRznNYx/Sk/At/eStqDxMHjP9X8AucGFIt76bEwHAAL2uu\n'
    ),
}


@pytest.fixture
def certmap_user(request):
    user = UserTracker(CERTMAP_USER, u'certmap', u'user')
    return user.make_fixture(request)


def addcertmap_id(options):
    if options:
        return u', '.join(list(options))
    else:
        return u' '


class TestAddRemoveCertmap(XMLRPC_test):
    @pytest.mark.parametrize(
        'options', [
            dict(o) for l in range(len(certmapdata_create_params)+1)
            for o in itertools.combinations(
                list(certmapdata_create_params.items()), l)
        ],
        ids=addcertmap_id,
    )
    def test_add_certmap(self, options, certmap_user):
        certmap_user.ensure_exists()
        certmap_user.add_certmap(**options)
        certmap_user.ensure_missing()

    def test_remove_certmap(self, certmap_user):
        certmap_user.ensure_exists()
        certmap_user.add_certmap(ipacertmapdata=u'rawdata')
        certmap_user.remove_certmap(ipacertmapdata=u'rawdata')

    def test_add_certmap_multiple_subject(self, certmap_user):
        certmap_user.ensure_exists()
        cmd = certmap_user.make_command('user_add_certmapdata',
                                        certmap_user.name)
        with raises_exact(errors.ConversionError(
                name='subject',
                error=u"Only one value is allowed")):
            cmd(subject=(u'CN=subject1', u'CN=subject2'), issuer=u'CN=issuer')

    def test_add_certmap_multiple_issuer(self, certmap_user):
        certmap_user.ensure_exists()
        cmd = certmap_user.make_command('user_add_certmapdata',
                                        certmap_user.name)
        with raises_exact(errors.ConversionError(
                name='issuer',
                error=u"Only one value is allowed")):
            cmd(issuer=(u'CN=issuer1', u'CN=issuer2'), subject=u'CN=subject')


class EWE:
    """
    Context manager that checks the outcome of wrapped statement executed
    under specified user against specified expected outcome based on permission
    given to the user.

    """
    def __init__(self, user, password):
        """
        @param user     Change to this user before calling the command
        @param password Password to use for user change
        """
        self.user = user
        self.password = password
        self.returned = False
        self.value = None

    def __call__(self, perms, exps, ok_expected=None):
        """
        @param perms    User has those permissions
        @param exps     Iterable containing tuple
                        (permission, exception_class, expected_result,)
                        If permission is missing command must raise exception
                        of exception_class. If exception class is None command
                        must use send method with the result as the only
                        parameter
        @param ok_expected  When no permission is missing command must send
                            ok_expected
        """
        for perm, exception, expected in exps:
            if perm not in perms:
                break
        else:
            exception = None
            expected = ok_expected

        self.exception = exception
        self.expected = expected

        return self

    def send(self, value):
        """
        Use send method to report result of executed statement to EWE
        """
        self.returned = True
        self.value = value

    def __enter__(self):
        self.returned = False
        self.value = None

        self.change_principal_cm = change_principal(self.user, self.password)
        self.change_principal_cm.__enter__()  # pylint: disable=no-member

        if self.exception:
            self.assert_raises_cm = pytest.raises(self.exception)
            self.assert_raises_cm.__enter__()

        return self

    def __exit__(self, exc_type, exc_value, tb):
        self.change_principal_cm.__exit__(  # pylint: disable=no-member
            exc_type, exc_value, tb)
        if self.exception:
            return self.assert_raises_cm.__exit__(exc_type, exc_value, tb)
        else:
            if self.expected and self.returned:
                assert_deepequal(self.expected, self.value)
            elif self.expected:
                raise AssertionError("Value expected but not provided")
            elif self.returned:
                raise AssertionError("Value provided but not expected")
            return None


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
    params=itertools.chain(
        *[itertools.combinations(list(certmaprule_permissions.values()), l)
          for l in range(len(list(certmaprule_permissions.values())) + 1)]
    ),
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
    execute_with_expected = EWE(CERTMAP_USER, CERTMAP_PASSWD)

    def test_create(self, certmap_rule, certmap_user_permissions):
        certmap_rule.ensure_missing()

        with self.execute_with_expected(
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

        with self.execute_with_expected(
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
        with self.execute_with_expected(
            certmap_user_permissions,
            [
                (READ_PERM, None, expected_without_read,),
            ],
            expected_ok,
        ) as ewe:
            find = certmap_rule.make_find_command()
            res = find(**{k: v for k, v in certmaprule_create_params.items()
                          if k != u'dn'})
            ewe.send(res)

    def test_update(self, certmap_rule, certmap_user_permissions):
        certmap_rule.ensure_missing()
        certmap_rule.ensure_exists()

        with self.execute_with_expected(
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

        with self.execute_with_expected(
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

        with self.execute_with_expected(
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

        with self.execute_with_expected(
            certmap_user_permissions,
            [
                (READ_PERM, errors.NotFound, None,),
                (UPDATE_PERM, errors.ACIError, None,),
            ],
        ):
            certmap_rule.disable()
