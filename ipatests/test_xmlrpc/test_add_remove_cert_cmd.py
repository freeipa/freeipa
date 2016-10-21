#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import base64

import pytest

from ipalib import api, errors
from ipapython.dn import DN
from ipatests.util import assert_deepequal, raises
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipatests.test_xmlrpc.testcert import get_testcert
from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker
from ipatests.test_xmlrpc.tracker.idview_plugin import IdviewTracker


@pytest.fixture(scope='class')
def idview(request):
    tracker = IdviewTracker(cn=u'MyView')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def testuser(request):
    tracker = UserTracker(name=u'testuser', givenname=u'John', sn=u'Donne')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def cert1(request):
    return get_testcert(DN(('CN', u'testuser')), u'testuser')


@pytest.fixture(scope='class')
def cert2(request):
    return get_testcert(DN(('CN', u'testuser')), u'testuser')


@pytest.mark.tier1
class CertManipCmdTestBase(XMLRPC_test):
    entity_class = ''
    entity_pkey = None
    entity_subject = None
    entity_principal = None
    non_existent_entity = None

    profile_store_orig = True
    default_profile_id = u'caIPAserviceCert'
    default_caacl = u'hosts_services_%s' % default_profile_id
    cmd_options = dict(
        entity_add=None,
        caacl=None,
    )
    cert_add_cmd = None
    cert_del_cmd = None

    cert_add_summary = u''
    cert_del_summary = u''

    entity_attrs = None

    @classmethod
    def disable_profile_store(cls):
        try:
            api.Command.certprofile_mod(cls.default_profile_id,
                                        ipacertprofilestoreissued=False)
        except errors.EmptyModlist:
            cls.profile_store_orig = False
        else:
            cls.profile_store_orig = True

    @classmethod
    def restore_profile_store(cls):
        if cls.profile_store_orig:
            api.Command.certprofile_mod(
                cls.default_profile_id,
                ipacertprofilestoreissued=cls.profile_store_orig)

    @classmethod
    def add_entity(cls):
        api.Command['%s_add' % cls.entity_class](
            cls.entity_pkey,
            **cls.cmd_options['entity_add'])

    @classmethod
    def delete_entity(cls):
        try:
            api.Command['%s_del' % cls.entity_class](cls.entity_pkey)
        except errors.NotFound:
            pass

    # optional methods which implement adding CA ACL rule so that we can
    # request cert for the entity. Currently used only for users.
    @classmethod
    def add_caacl(cls):
        pass

    @classmethod
    def remove_caacl(cls):
        pass

    @classmethod
    def setup_class(cls):
        super(CertManipCmdTestBase, cls).setup_class()

        cls.delete_entity()

        cls.add_entity()
        cls.add_caacl()

        cls.disable_profile_store()

        # list of certificates to add to entry
        cls.certs = [
            get_testcert(DN(('CN', cls.entity_subject)), cls.entity_principal)
            for i in range(3)
        ]

        # list of certificates for testing of removal of non-existent certs
        cls.nonexistent_certs = [
            get_testcert(DN(('CN', cls.entity_subject)), cls.entity_principal)
            for j in range(2)
            ]

        # cert subset to remove from entry
        cls.certs_subset = cls.certs[:2]

        # remaining subset
        cls.certs_remainder = cls.certs[2:]

        # mixture of certs which exist and do not exists in the entry
        cls.mixed_certs = cls.certs[:2] + cls.nonexistent_certs[:1]

        # invalid base64 encoding
        cls.invalid_b64 = [u'few4w24gvrae54y6463234f']

        # malformed certificate
        cls.malformed_cert = [base64.b64encode(b'malformed cert')]

        # store entity info for the final test
        cls.entity_attrs = api.Command['%s_show' % cls.entity_class](
            cls.entity_pkey)

    @classmethod
    def teardown_class(cls):
        cls.delete_entity()
        cls.remove_caacl()

        cls.restore_profile_store()
        super(CertManipCmdTestBase, cls).teardown_class()

    def add_certs(self, certs):
        # pylint: disable=E1102
        result = self.cert_add_cmd(self.entity_pkey, usercertificate=certs)
        return dict(
            usercertificate=result['result'].get('usercertificate', []),
            value=result.get('value'),
            summary=result.get('summary')
        )

    def remove_certs(self, certs):
        # pylint: disable=E1102
        result = self.cert_del_cmd(self.entity_pkey, usercertificate=certs)
        return dict(
            usercertificate=result['result'].get('usercertificate', []),
            value=result.get('value'),
            summary=result.get('summary')
        )

    def test_01_add_cert_to_nonexistent_entity(self):
        """
        Tests whether trying to add certificates to a non-existent entry
        raises NotFound error.
        """
        raises(errors.NotFound, self.cert_add_cmd,
               self.non_existent_entity, usercertificate=self.certs)

    def test_02_remove_cert_from_nonexistent_entity(self):
        """
        Tests whether trying to remove certificates from a non-existent entry
        raises NotFound error.
        """
        raises(errors.NotFound, self.cert_add_cmd,
               self.non_existent_entity, usercertificate=self.certs)

    def test_03_remove_cert_from_entity_with_no_certs(self):
        """
        Attempt to remove certificates from an entity that has none raises
        AttrValueNotFound
        """
        raises(errors.AttrValueNotFound, self.remove_certs, self.certs)

    def test_04_add_invalid_b64_blob_to_entity(self):
        raises(errors.Base64DecodeError, self.add_certs, self.invalid_b64)

    def test_05_add_malformed_cert_to_entity(self):
        raises(errors.CertificateFormatError, self.add_certs,
               self.malformed_cert)

    def test_06_add_single_cert_to_entity(self):
        """
        Add single certificate to entry
        """
        assert_deepequal(
            dict(
                usercertificate=[base64.b64decode(self.certs[0])],
                summary=self.cert_add_summary % self.entity_pkey,
                value=self.entity_pkey,
            ),
            self.add_certs([self.certs[0]])
        )

    def test_07_add_more_certs_to_entity(self):
        """
        Add the rest of the certificate set to the entry.
        """
        assert_deepequal(
            dict(
                usercertificate=[base64.b64decode(c) for c in self.certs],
                summary=self.cert_add_summary % self.entity_pkey,
                value=self.entity_pkey,
            ),
            self.add_certs(self.certs[1:])
        )

    def test_08_add_already_present_cert_to_entity(self):
        """
        Tests that ExecutionError is raised when attempting to add certificates
        to the entry that already contains them.
        """
        raises(
            errors.ExecutionError,
            self.add_certs,
            self.certs_subset
        )

    def test_09_remove_nonexistent_certs_from_entity(self):
        """
        Tests that an attempt to remove certificates that are not present in
        the entry raises AttrValueNotFound
        """
        raises(
            errors.AttrValueNotFound,
            self.remove_certs,
            self.nonexistent_certs
        )

    def test_10_remove_valid_and_nonexistent_certs_from_entity(self):
        """
        Try to remove multiple certificates. Some of them are not present in
        the entry. This scenario should raise InvocationError.
        """
        raises(
            errors.AttrValueNotFound,
            self.remove_certs,
            self.mixed_certs
        )

    def test_11_remove_cert_subset_from_entity(self):
        """
        Test correct removal of a subset of entry's certificates.
        """
        assert_deepequal(
            dict(
                usercertificate=[base64.b64decode(c)
                                 for c in self.certs_remainder],
                summary=self.cert_del_summary % self.entity_pkey,
                value=self.entity_pkey,
            ),
            self.remove_certs(self.certs_subset)
        )

    def test_12_remove_remaining_certs_from_entity(self):
        """
        Test correct removal of all the remaining certificates from the entry.
        """
        assert_deepequal(
            dict(
                usercertificate=[],
                summary=self.cert_del_summary % self.entity_pkey,
                value=self.entity_pkey,
            ),
            self.remove_certs(self.certs_remainder)
        )

    def test_99_check_final_entity_consistency(self):
        """
        Tests that all the previous operations do not modify other attributes
        of the entry. Make sure that the show command returns the same
        information as in the beginning of the test suite.
        """
        assert_deepequal(
            self.entity_attrs,
            api.Command['%s_show' % self.entity_class](self.entity_pkey)
        )


@pytest.mark.tier1
class TestCertManipCmdUser(CertManipCmdTestBase):
    entity_class = 'user'
    entity_pkey = u'tuser'
    entity_subject = entity_pkey
    entity_principal = u'tuser'
    non_existent_entity = u'nonexistentuser'

    cmd_options = dict(
        entity_add=dict(givenname=u'Test', sn=u'User'),
        caacl=dict(user=[u'tuser']),
    )

    cert_add_cmd = api.Command.user_add_cert
    cert_del_cmd = api.Command.user_remove_cert

    cert_add_summary = u'Added certificates to user "%s"'
    cert_del_summary = u'Removed certificates from user "%s"'

    @classmethod
    def add_caacl(cls):
        api.Command['caacl_add_%s' % cls.entity_class](
            cls.default_caacl, **cls.cmd_options['caacl'])

    @classmethod
    def remove_caacl(cls):
        api.Command['caacl_remove_%s' % cls.entity_class](
            cls.default_caacl, **cls.cmd_options['caacl'])


@pytest.mark.tier1
class TestCertManipCmdHost(CertManipCmdTestBase):
    entity_class = 'host'
    entity_pkey = u'host.example.com'
    entity_subject = entity_pkey
    entity_principal = u'host/%s' % entity_pkey
    non_existent_entity = u'non.existent.host.com'

    cmd_options = dict(
        entity_add=dict(force=True),
    )

    cert_add_cmd = api.Command.host_add_cert
    cert_del_cmd = api.Command.host_remove_cert

    cert_add_summary = u'Added certificates to host "%s"'
    cert_del_summary = u'Removed certificates from host "%s"'


@pytest.mark.tier1
class TestCertManipCmdService(CertManipCmdTestBase):
    entity_class = 'service'
    entity_pkey = u'testservice/%s@%s' % (TestCertManipCmdHost.entity_pkey,
                                          api.env.realm)
    entity_subject = TestCertManipCmdHost.entity_pkey
    entity_principal = entity_pkey
    non_existent_entity = u'testservice/non.existent.host.com'

    cmd_options = dict(
        entity_add=dict(force=True),
    )

    cert_add_cmd = api.Command.service_add_cert
    cert_del_cmd = api.Command.service_remove_cert

    cert_add_summary = u'Added certificates to service principal "%s"'
    cert_del_summary = u'Removed certificates from service principal "%s"'

    @classmethod
    def add_entity(cls):
        api.Command.host_add(TestCertManipCmdHost.entity_pkey, force=True)
        super(TestCertManipCmdService, cls).add_entity()

    @classmethod
    def delete_entity(cls):
        super(TestCertManipCmdService, cls).delete_entity()
        try:
            api.Command.host_del(TestCertManipCmdHost.entity_pkey)
        except errors.NotFound:
            pass


@pytest.mark.tier1
class TestCertManipIdOverride(XMLRPC_test):
    entity_subject = u'testuser'
    entity_principal = u'testuser'

    def test_00_add_idoverrideuser(self, testuser, idview):
        testuser.create()
        idview.create()
        idview.idoverrideuser_add(testuser)

    def test_01_add_cert_to_idoverride(self, testuser, idview, cert1):
        assert_deepequal(
            dict(usercertificate=(base64.b64decode(cert1),),
                 summary=u'Added certificates to'
                         ' idoverrideuser \"%s\"' % testuser.name,
                 value=testuser.name,
                 ),
            idview.add_cert_to_idoverrideuser(testuser.name, cert1)
        )

    def test_02_add_second_cert_to_idoverride(self, testuser,
                                              idview, cert1, cert2):
        assert_deepequal(
            dict(
                usercertificate=(base64.b64decode(cert1),
                                 base64.b64decode(cert2)),
                summary=u'Added certificates to'
                        ' idoverrideuser \"%s\"' % testuser.name,
                value=testuser.name,
            ),
            idview.add_cert_to_idoverrideuser(testuser.name, cert2)
        )

    def test_03_add_the_same_cert_to_idoverride(self, testuser,
                                                idview, cert1, cert2):
        pytest.raises(errors.ExecutionError,
                      idview.add_cert_to_idoverrideuser,
                      testuser.name, cert1)

    def test_04_user_show_displays_cert(self, testuser, idview, cert1, cert2):
        result = api.Command.idoverrideuser_show(idview.cn, testuser.name)
        assert_deepequal((base64.b64decode(cert1),
                          base64.b64decode(cert2)),
                         result['result']['usercertificate']
                         )

    def test_05_remove_cert(self, testuser, idview, cert1, cert2):
        assert_deepequal(
            dict(
                usercertificate=(base64.b64decode(cert2),),
                value=testuser.name,
                summary=u'Removed certificates from'
                        ' idoverrideuser "%s"' % testuser.name
            ),
            idview.del_cert_from_idoverrideuser(testuser.name, cert1)
        )
