#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

"""
Test the `ipalib.plugins.ca` module.
"""

import pytest

from ipalib import errors
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, fuzzy_issuer

from ipatests.test_xmlrpc.tracker.certprofile_plugin import CertprofileTracker
from ipatests.test_xmlrpc.tracker.caacl_plugin import CAACLTracker
from ipatests.test_xmlrpc.tracker.ca_plugin import CATracker


@pytest.fixture(scope='module')
def default_profile(request):
    name = 'caIPAserviceCert'
    desc = u'Standard profile for network services'
    tracker = CertprofileTracker(name, store=True, desc=desc)
    tracker.track_create()
    return tracker


@pytest.fixture(scope='module')
def default_acl(request):
    name = u'hosts_services_caIPAserviceCert'
    tracker = CAACLTracker(name, service_category=u'all', host_category=u'all')
    tracker.track_create()
    tracker.attrs.update(
        {u'ipamembercertprofile_certprofile': [u'caIPAserviceCert']})
    return tracker


@pytest.fixture(scope='module')
def default_ca(request):
    name = u'ipa'
    desc = u'IPA CA'
    tracker = CATracker(name, fuzzy_issuer, desc=desc)
    tracker.track_create()
    return tracker


@pytest.fixture(scope='class')
def crud_subca(request):
    name = u'crud-subca'
    subject = u'CN=crud subca test,O=crud testing inc'
    tracker = CATracker(name, subject)

    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def subject_conflict_subca(request):
    name = u'crud-subca-2'
    subject = u'CN=crud subca test,O=crud testing inc'
    tracker = CATracker(name, subject)

    # Should not get created, no need to delete
    return tracker


@pytest.fixture(scope='class')
def unrecognised_subject_dn_attrs_subca(request):
    name = u'crud-subca-3'
    subject = u'CN=crud subca test,DN=example.com,O=crud testing inc'
    tracker = CATracker(name, subject)

    # Should not get created, no need to delete
    return tracker


@pytest.mark.tier0
class TestDefaultCA(XMLRPC_test):
    def test_default_ca_present(self, default_ca):
        default_ca.retrieve()

    def test_default_ca_delete(self, default_ca):
        with pytest.raises(errors.ProtectedEntryError):
            default_ca.delete()


@pytest.mark.tier1
class TestCAbasicCRUD(XMLRPC_test):

    ATTR_ERROR_MSG = u'attribute is not configurable'

    def test_create(self, crud_subca):
        crud_subca.create()

    def test_retrieve(self, crud_subca):
        crud_subca.retrieve()

    def test_retrieve_all(self, crud_subca):
        crud_subca.retrieve(all=True)

    def test_export_ca(self, tmpdir, crud_subca):
        exported_ca = tmpdir.join('exported_ca')
        command = crud_subca.make_retrieve_command(
            certificate_out=u'%s' % exported_ca,
        )
        command()

    def test_delete(self, crud_subca):
        crud_subca.delete()

    def test_find(self, crud_subca):
        crud_subca.ensure_exists()
        crud_subca.find()

    def test_modify_description(self, crud_subca):
        new_desc = u'updated CA description'
        crud_subca.update(
            dict(
                description=new_desc,
            ),
            expected_updates=dict(
                description=[new_desc]
            )
        )

    def test_modify_issuerdn(self, crud_subca):
        bogus_issuer = u'ipacaissuerdn="cn=phony issuer,o=phony industries'
        cmd = crud_subca.make_update_command(
            updates=dict(setattr=bogus_issuer)
        )

        with pytest.raises(errors.ValidationError) as error:
            cmd()

        assert self.ATTR_ERROR_MSG in str(error.value)

    def test_modify_subjectdn(self, crud_subca):
        bogus_subject = u'ipacasubjectdn="cn=phony subject,o=phony industries'
        cmd = crud_subca.make_update_command(
            updates=dict(setattr=bogus_subject)
        )

        with pytest.raises(errors.ValidationError) as error:
            cmd()

        assert self.ATTR_ERROR_MSG in str(error.value)

    def test_delete_subjectdn(self, crud_subca):
        cmd = crud_subca.make_update_command(
            updates=dict(delattr=u'ipacasubjectdn=%s'
                         % crud_subca.ipasubjectdn)
        )

        with pytest.raises(errors.ValidationError) as error:
            cmd()

        assert self.ATTR_ERROR_MSG in str(error.value)

    def test_add_bogus_subjectdn(self, crud_subca):
        bogus_subject = u'ipacasubjectdn="cn=phony subject,o=phony industries'
        cmd = crud_subca.make_update_command(
            updates=dict(addattr=bogus_subject)
        )

        with pytest.raises(errors.ValidationError) as error:
            cmd()

        assert self.ATTR_ERROR_MSG in str(error.value)

    def test_add_bogus_issuerdn(self, crud_subca):
        bogus_issuer = u'ipacaissuerdn="cn=phony issuer,o=phony industries'
        cmd = crud_subca.make_update_command(
            updates=dict(addattr=bogus_issuer)
        )

        with pytest.raises(errors.ValidationError) as error:
            cmd()

        assert self.ATTR_ERROR_MSG in str(error.value)

    def test_create_subca_with_conflicting_name(self, crud_subca):
        crud_subca.ensure_exists()

        cmd = crud_subca.make_create_command()
        with pytest.raises(errors.DuplicateEntry):
            cmd()

    def test_create_subca_with_subject_conflict(
            self, crud_subca, subject_conflict_subca):
        crud_subca.ensure_exists()

        with pytest.raises(errors.DuplicateEntry):
            subject_conflict_subca.create()

    def test_create_subca_with_unrecognised_subject_dn_attrs(
            self, unrecognised_subject_dn_attrs_subca):
        with pytest.raises(errors.ValidationError):
            unrecognised_subject_dn_attrs_subca.create()
