# Copyright (C) 2018  FreeIPA Project Contributors - see LICENSE file

from __future__ import print_function
import ipaserver.install.adtrust as adtr
from ipaserver.install.adtrust import set_and_check_netbios_name
from collections import namedtuple
from unittest import TestCase, mock
from io import StringIO


class ApiMockup:
    Backend = namedtuple('Backend', 'ldap2')
    Calls = namedtuple('Callbacks', 'retrieve_netbios_name')
    env = namedtuple('Environment', 'domain')


class TestNetbiosName(TestCase):
    @classmethod
    def setUpClass(cls):
        api = ApiMockup()
        ldap2 = namedtuple('LDAP', 'isconnected')
        ldap2.isconnected = mock.MagicMock(return_value=True)
        api.Backend.ldap2 = ldap2
        api.Calls.retrieve_netbios_name = adtr.retrieve_netbios_name
        adtr.retrieve_netbios_name = mock.MagicMock(return_value=None)
        cls.api = api

    @classmethod
    def tearDownClass(cls):
        adtr.retrieve_netbios_name = cls.api.Calls.retrieve_netbios_name

    def test_NetbiosName(self):
        """
        Test set_and_check_netbios_name() using permutation of two inputs:
        - predefined and not defined NetBIOS name
        - unattended and interactive run
        As result, the function has to return expected NetBIOS name in
        all cases. For interactive run we override input to force what
        we expect.
        """
        self.api.env.domain = 'example.com'
        expected_nname = 'EXAMPLE'
        # NetBIOS name, unattended, should set the name?
        tests = ((expected_nname, True, False),
                 (None, True, True),
                 (None, False, True),
                 (expected_nname, False, False))
        with mock.patch('sys.stdin', new_callable=StringIO) as stdin:
            stdin.write(expected_nname + '\r')
            for test in tests:
                nname, setname = set_and_check_netbios_name(
                    test[0], test[1], self.api)
                assert expected_nname == nname
                assert setname == test[2]
