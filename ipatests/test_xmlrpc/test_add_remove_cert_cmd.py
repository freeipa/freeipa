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
def idview(request, xmlrpc_setup):
    tracker = IdviewTracker(cn=u'MyView')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def testuser(request, xmlrpc_setup):
    tracker = UserTracker(name=u'testuser', givenname=u'John', sn=u'Donne')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def cert1(request, xmlrpc_setup):
    return get_testcert(DN(('CN', u'testuser')), u'testuser')


@pytest.fixture(scope='class')
def cert2(request, xmlrpc_setup):
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

    certs = None
    certs_remainder = None
    certs_subset = None
    invalid_b64 = None
    malformed_cert = None
    mixed_certs = None
    nonexistent_certs = None

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

    @pytest.fixture(autouse=True, scope="class")
    def certmanipcmd_setup(self, request, xmlrpc_setup):
        cls = request.cls

        cls.delete_entity()

        cls.add_entity()
        cls.add_caacl()

        cls.disable_profile_store()

        # list of certificates to add to entry
        cls.certs = [
            u"MIICszCCAZugAwIBAgICM24wDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEChML\r\n"
            "RVhBTVBMRS5PUkcxCzAJBgNVBAMTAkNBMB4XDTE3MDExOTEwMjUyOVoXDTE3M\r\n"
            "DQxOTEwMjUyOVowFjEUMBIGA1UEAxMLc3RhZ2V1c2VyLTEwggEiMA0GCSqGSI\r\n"
            "b3DQEBAQUAA4IBDwAwggEKAoIBAQCq03FRQQBvq4HwYMKP8USLZuOkKzuIs2V\r\n"
            "Pt8k/+nO1dADrzMogKDiUDjCwYoG2UM/sj6P+PJUUCNDLh5eRRI+aR5VE5y2a\r\n"
            "K95iCsj1ByDWrugAUXgr8GUUr+UbaGc0XxHCMnQBkYhzbXY3u91KYRRh5l3lx\r\n"
            "RSICcVeJFJ/tiMS14Vsor1DWykHGz1wm0Zjwg1XDV3oea+uwrSz5Pa6RNPlgC\r\n"
            "+GGW6B7+8qC2XdSSEwvY7y1SAGgqyOxN/FLwvqqMDNU0uX7fww587uZ57IfYz\r\n"
            "b8Xn5DAprRFNk40FDc46rMlkPBT+Tij1I0jedD8h2e6WEa7JRU6SGToYDbRm4\r\n"
            "RL9xAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHqm1jXzYer9oSjYs9qh1jWpM\r\n"
            "vTcN+0/z1uuX++Wezh3lG7IzYtypbZNxlXDECyrkUh+9oxzMJqdlZ562ko2br\r\n"
            "uK6X5csbbM9uVsUva8NCsPPfZXDhrYaMKFvQGFY4pO3uhFGhccob037VN5Ifm\r\n"
            "aKGM8aJ40cw2PQh38QPDdemizyVCThQ9Pcr+WgWKiG+t2Gd9NldJRLEhky0bW\r\n"
            "2fc4zWZVbGq5nFXy1k+d/bgkHbVzf255eFZOKKy0NgZwig+uSlhVWPJjS4Z1w\r\n"
            "LbpBKxTZp/xD0yEARs0u1ZcCELO/BkgQM50EDKmahIM4mdCs/7j1B/DdWs2i3\r\n"
            "5lnbjxYYiUiyA=",
            u"MIICszCCAZugAwIBAgICJGMwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEChML\r\n"
            "RVhBTVBMRS5PUkcxCzAJBgNVBAMTAkNBMB4XDTE3MDExOTEwMjcyN1oXDTE3M\r\n"
            "DQxOTEwMjcyN1owFjEUMBIGA1UEAxMLc3RhZ2V1c2VyLTIwggEiMA0GCSqGSI\r\n"
            "b3DQEBAQUAA4IBDwAwggEKAoIBAQDsEuTITzsRiUHXb8LxduokAEHwStCveKV\r\n"
            "i8aVFBYQCRbpoXcoTfBISWvdmF3WOkIUfR1O0qrm0s3CPMAyWdTrnCI/45/Cc\r\n"
            "FNDpGKPf+izN1t+WSrr6gCoz24y5ALyUEG5FSvHdDcIn+hY9Qvg3cRLxY9M4W\r\n"
            "XmtR6p+d48v08nSSJXprgXS6ZiVvN7QGQfNRNDNoQZLmP9tQ/XvgJuiBMPj2N\r\n"
            "aUFM8AwDnxGcvzExgaFlX0OKS6hymsUG60PeF0H0aYDgVH/0DKK+mZEA2FNbR\r\n"
            "JIQt5Vk+c5aBvPrOfRLKrsQQ/zhtNOxk8Q0G+cwlzANCqbV7EzUFEFEtonnOP\r\n"
            "tzY7AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAIPcStKnxv6bdPiL2I7f4B/ME\r\n"
            "BEV+kFnzu1msfkh1iouiKmM4ZkXLiqInKxEBwWNmhpRFoxKWaI3DjYtf/PYH/\r\n"
            "guHipZvLIrVgfxlf/5ldXeoa7IHZ9hzvrG3WuYG6SHoJw6yaA6Vn8j8Q3r/kG\r\n"
            "/1SLZpRpoq0EuhD7V/aHvxr/aiFnU4Fh2VaQd2ICOK2qBFQnoL5QyySVEJ7GA\r\n"
            "RmajT3BqAASoixEqfMWYv2AqZnJ84JoI4reP0uZGjz5Cy32xQuenQckr8Faki\r\n"
            "p28buFp46C34AWifbRERE396xocc9/Oc7dx9DyjeYqa9CuNo/pYlC4r8QCOkm\r\n"
            "0xMWjoGcVUtUw=",
            u"MIICszCCAZugAwIBAgICFpYwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEChML\r\n"
            "RVhBTVBMRS5PUkcxCzAJBgNVBAMTAkNBMB4XDTE3MDExOTEwMjczMVoXDTE3M\r\n"
            "DQxOTEwMjczMVowFjEUMBIGA1UEAxMLc3RhZ2V1c2VyLTMwggEiMA0GCSqGSI\r\n"
            "b3DQEBAQUAA4IBDwAwggEKAoIBAQDEIMvN8aElxMSyfqIj91nDuuvli/RKNhF\r\n"
            "sIU32c7NJVF7kthvltmEwIVKKCE1Yji3GRWXBuZlSz5eSyDaqqpOpdYsVjYaz\r\n"
            "XfWA5kjL8vGkoVt97SQ0TEkSOlinnjuo2unjU33RcruRp4rqeQE8EPBlAXYJr\r\n"
            "+iK5Y+RF9Mz047ba097wUUX85QeEp1LWwYbLZleNFK1BwsmSL5Js+GcKEBEdi\r\n"
            "KS/OfidTz7Hf7KICLo+iZlbG3lNLFQMvWFG8bzTeOgZ5OLDeBRzG6cSZK0Q3A\r\n"
            "18uVg0jf0rv/nsOO/JQRK1FufvmOL2Xp7lqLFaAIuQqH1OuAq6MHfuaxwpdiU\r\n"
            "yzVfAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAAs0K12ugVJ4t7/iUdddTmS+v\r\n"
            "8FEEL92fWgU1bQHR/gMa2by9SIqS1KZVBc5JpJePqVf/S35Gt4o7sE3rbbmZm\r\n"
            "mhGDL8D+BmGHjxdhENLyk6rvHOm+TDgM7nQK0FbPekMzkbsFxfw9R7iq8cnZD\r\n"
            "7Y1T5e2N+WMzx6Jf/ner32V9CTfFbGP84G0+kqyqo7vp59VIwyHpC0L/0bh8W\r\n"
            "YjFKNCPMbnZpO3212dNCaIMp0Kugi9D4kXAeM3unQ2/p5pN7Vgo+Xl9hioN5g\r\n"
            "As+3SQR2pArUmr8RtjvfH/PxE8scWtRCCH4aBhfklrCHK+rpUzh4PXqhXGYJC\r\n"
            "TmYzsAw/Z7vnY=",
        ]

        # list of certificates for testing of removal of non-existent certs
        cls.nonexistent_certs = [
            u"MIICszCCAZugAwIBAgICYDAwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEChML\r\n"
            "RVhBTVBMRS5PUkcxCzAJBgNVBAMTAkNBMB4XDTE3MDExOTEwMjczNVoXDTE3M\r\n"
            "DQxOTEwMjczNVowFjEUMBIGA1UEAxMLc3RhZ2V1c2VyLTQwggEiMA0GCSqGSI\r\n"
            "b3DQEBAQUAA4IBDwAwggEKAoIBAQDAw12yHMBzQd27/Zv5STUlrkgGaClC4/U\r\n"
            "+HxjHSHxFJLStYgK9DrXpRIqnkdwAr7rftlhFiRkqFE4GNGNAlhUlnkn0YTvD\r\n"
            "59ucnpSRC7kjkrHAb1fWDNE3VYQOOF93CObOOAciNEl/K0HXqXxxYkhF6cz+m\r\n"
            "N1gGd6oOtCu+G1vCoM25X3nlQdgOJtI8X2/MDvZ+nJVRqscsjeNnM0+A1Q1Cf\r\n"
            "u2ukiqYgiQVYAa88hpADhXEF+hht3iIiw53GgD1Bb5xFm+OKpwBSegRJOjraj\r\n"
            "XeWpr1ZN44JCTuFmAxwaNzynpYjrDbWXoLzbXEhyPbtT1jui6A1rRhEpc9Tyd\r\n"
            "Wb4rAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMe/xoqCmmSV/8x+hawb216sv\r\n"
            "5CX6+WKMlLJTsmB586fQoJWJecn3Wg7DB1vfLeffayh9b+7g0w0OZnaUJlPNH\r\n"
            "T6x5P29jH9J6fGOu3CIafCpvEXyamJKyQD6tER3l4iRBzoqW74BQh3W6rQnVs\r\n"
            "lvM07LlQA0PB9RXYNvEmTCJKOtzA7wcARukvss9VS9oBfxjFgcGDKfMPPNaH9\r\n"
            "IGEZi8QwEnOsSpLUobWPhRENbxwTMwlMspk9QG7NvTfisqFRXkAov0R/rHPqr\r\n"
            "AXJTZmkPP+MhrsrbnT0CV2f6bxPkvXknuf+7Xi3h900BLQOSY+jqmtmGrYjln\r\n"
            "tsqX1gL4y2e98=",
            u"MIICszCCAZugAwIBAgICeicwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEChML\r\n"
            "RVhBTVBMRS5PUkcxCzAJBgNVBAMTAkNBMB4XDTE3MDExOTEwMjczOVoXDTE3M\r\n"
            "DQxOTEwMjczOVowFjEUMBIGA1UEAxMLc3RhZ2V1c2VyLTUwggEiMA0GCSqGSI\r\n"
            "b3DQEBAQUAA4IBDwAwggEKAoIBAQCd1VDwUwkwieLqngX1q2HoOe/tKnPxnr/\r\n"
            "DrjbXAwFxEDcp7lfIUXALy33YZTAUGaNhlKzL+5sL3O5RcebSywBvw9Cpg9O4\r\n"
            "lLPeAwdgnCHpNMaBjFL9/ySnwrIH0Hpx7chUXt1zz+z4ia1i7ZfVWHlP3D+pu\r\n"
            "dR8MdzKH+1irtLcVL8ESfIqVsLGf0qV3wi2znqFsul6+e1MLE/RVXFoCmEX7J\r\n"
            "5mJ77aFm6GgpXR7O3UAGl1NAfbZUz1Itt/NSrx8lHAYur4tUPQPEEa8XSe/B8\r\n"
            "hG5J1inw6jm94vvpi2a3GOU6eDz4q0nM0/Rbia212tdbpyKdkm4aCQkoyhrJR\r\n"
            "+DhvAgMBAAEwDQYJKoZIhvcNAQELBQADggEBADd5V5BMVY4zBRQiLZ2x+7seD\r\n"
            "oT7ewyYW6Kk9oMlk7JWXgNyAG5/561vSkKIBkQG2CTRD3dAX7SbUwkxP7/a9g\r\n"
            "ozJN3VOrLBUDhxyesr3cMuIU9XVyPezT3KapQjXkxzmJKiRNPc/fope4Xx5uc\r\n"
            "UwYa6lm9QVCD4gnNElf+RexpI3VwkjmAWS3cvsKRFFNbZCS5gpCM/rOX76m4l\r\n"
            "YcBSA8B+jb0FkOJt3u9fwtoMbhv5kdjEDGNWmG1kJ86ybqeWj12BpKGh4G6m4\r\n"
            "E8ROnyuBt8Bolk4jqR3uCPfD4T+HpkttqrznRaGvroD020pEjtU22sAKkhBZQ\r\n"
            "2Wbfkc49wxqpY=",
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
        cls.entity_attrs = api.Command[
            '%s_show' % cls.entity_class](cls.entity_pkey)

        def fin():
            cls.delete_entity()
            cls.remove_caacl()
            cls.restore_profile_store()

        request.addfinalizer(fin)

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
class TestCertManipCmdStageuser(CertManipCmdTestBase):
    entity_class = 'stageuser'
    entity_pkey = u'suser'
    entity_subject = entity_pkey
    entity_principal = u'suser'
    non_existent_entity = u'nonexistentstageuser'

    cmd_options = dict(
        entity_add=dict(givenname=u'Stage', sn=u'User'),
    )

    cert_add_cmd = api.Command.stageuser_add_cert
    cert_del_cmd = api.Command.stageuser_remove_cert

    cert_add_summary = u'Added certificates to stageuser "%s"'
    cert_del_summary = u'Removed certificates from stageuser "%s"'


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
