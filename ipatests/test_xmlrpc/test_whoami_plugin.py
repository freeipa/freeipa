#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

"""
Test for the `ipaserver/plugins/whoami.py` module.
"""

import pytest

from ipalib import api
from ipatests.util import (unlock_principal_password,
                           get_entity_keytab,
                           change_principal,
                           assert_deepequal,
                           host_keytab)
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker
from ipatests.test_xmlrpc.tracker.host_plugin import HostTracker
from ipatests.test_xmlrpc.tracker.service_plugin import ServiceTracker


@pytest.fixture(scope='function')
def krb_user(request):
    tracker = UserTracker(u'krb_user', u'krb', u'test_user')

    return tracker.make_fixture(request)


@pytest.fixture
def krb_host(request):
    tracker = HostTracker(u'krb-host')

    return tracker.make_fixture(request)


@pytest.fixture(scope='function')
def krb_service(request, krb_host):
    krb_host.ensure_exists()

    tracker = ServiceTracker(name=u'SERVICE', host_fqdn=krb_host.name)

    return tracker.make_fixture(request)


@pytest.mark.tier1
class test_whoami(XMLRPC_test):
    """
    Test the 'whoami' plugin.
    """

    oldpw, newpw = u"Secret1234", u"Secret123"

    def test_whoami_users(self, krb_user):
        """
        Testing whoami as user
        """
        krb_user.ensure_exists()

        pwdmod = krb_user.make_update_command({'userpassword': self.oldpw})
        pwdmod()

        unlock_principal_password(krb_user.name, self.oldpw, self.newpw)

        with change_principal(krb_user.name, self.newpw):
            result = api.Command.whoami()
            expected = {u'object': u'user',
                        u'command': u'user_show/1',
                        u'arguments': (krb_user.name,)}
            assert_deepequal(expected, result)

    def test_whoami_hosts(self, krb_host):
        """
        Testing whoami as a host
        """
        krb_host.ensure_exists()
        with host_keytab(krb_host.name) as keytab_filename:
            with change_principal(krb_host.attrs['krbcanonicalname'][0],
                                  keytab=keytab_filename):
                result = api.Command.whoami()
                expected = {u'object': u'host',
                            u'command': u'host_show/1',
                            u'arguments': (krb_host.fqdn,)}
                assert_deepequal(expected, result)

    def test_whoami_kerberos_services(self, krb_host, krb_service):
        """
        Testing whoami as a kerberos service
        """
        krb_service.ensure_exists()
        with get_entity_keytab(krb_service.name, '-r') as keytab:
            with change_principal(krb_service.attrs['krbcanonicalname'][0],
                                  keytab=keytab):
                result = api.Command.whoami()
                expected = {u'object': u'service',
                            u'command': u'service_show/1',
                            u'arguments': (krb_service.name,)}
                assert_deepequal(expected, result)
