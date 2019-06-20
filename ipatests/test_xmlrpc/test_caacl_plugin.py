#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
Test the `ipalib.plugins.caacl` module.
"""

import pytest

from ipalib import errors
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test

from ipatests.test_xmlrpc.tracker.certprofile_plugin import CertprofileTracker
from ipatests.test_xmlrpc.tracker.caacl_plugin import CAACLTracker
from ipatests.test_xmlrpc.tracker.stageuser_plugin import StageUserTracker
from ipatests.test_xmlrpc.tracker.ca_plugin import CATracker


@pytest.fixture(scope='class')
def default_profile(request, xmlrpc_setup):
    name = 'caIPAserviceCert'
    desc = u'Standard profile for network services'
    tracker = CertprofileTracker(name, store=True, desc=desc)
    tracker.track_create()
    return tracker


@pytest.fixture(scope='class')
def default_acl(request, xmlrpc_setup):
    name = u'hosts_services_caIPAserviceCert'
    tracker = CAACLTracker(name, service_category=u'all', host_category=u'all')
    tracker.track_create()
    tracker.attrs.update(
        {u'ipamembercertprofile_certprofile': [u'caIPAserviceCert']})
    return tracker


@pytest.fixture(scope='class')
def crud_acl(request, xmlrpc_setup):
    name = u'crud-acl'
    tracker = CAACLTracker(name)

    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def category_acl(request, xmlrpc_setup):
    name = u'category_acl'
    tracker = CAACLTracker(name, ipacertprofile_category=u'all',
                           user_category=u'all', service_category=u'all',
                           host_category=u'all', ipaca_category=u'all')

    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def caacl_test_ca(request, xmlrpc_setup):
    name = u'caacl-test-ca'
    subject = u'CN=caacl test subca,O=test industries inc.'
    return CATracker(name, subject).make_fixture(request)


@pytest.fixture(scope='class')
def staged_user(request, xmlrpc_setup):
    name = u'st-user'
    tracker = StageUserTracker(name, u'stage', u'test')

    return tracker.make_fixture(request)


@pytest.mark.tier0
class TestDefaultACL(XMLRPC_test):
    def test_default_acl_present(self, default_acl):
        default_acl.retrieve()


@pytest.mark.tier1
class TestCAACLbasicCRUD(XMLRPC_test):
    def test_create(self, crud_acl):
        crud_acl.create()

    def test_delete(self, crud_acl):
        crud_acl.delete()

    def test_disable(self, crud_acl):
        crud_acl.ensure_exists()
        crud_acl.disable()
        crud_acl.retrieve()

    def test_disable_twice(self, crud_acl):
        crud_acl.disable()
        crud_acl.retrieve()

    def test_enable(self, crud_acl):
        crud_acl.enable()
        crud_acl.retrieve()

    def test_enable_twice(self, crud_acl):
        crud_acl.enable()
        crud_acl.retrieve()

    def test_find(self, crud_acl):
        crud_acl.find()


@pytest.mark.tier1
class TestCAACLMembers(XMLRPC_test):
    def test_category_member_exclusivity(self, category_acl, default_profile):
        category_acl.create()
        default_profile.ensure_exists()
        with pytest.raises(errors.MutuallyExclusiveError):
            category_acl.add_profile(default_profile.name, track=False)

    def test_mod_delete_category(self, category_acl):
        updates = dict(
            hostcategory=None,
            servicecategory=None,
            ipacertprofilecategory=None,
            usercategory=None,
            ipacacategory=None)
        category_acl.update(updates)

    def test_add_profile(self, category_acl, default_profile):
        category_acl.add_profile(certprofile=default_profile.name)
        category_acl.retrieve()

    def test_remove_profile(self, category_acl, default_profile):
        category_acl.remove_profile(certprofile=default_profile.name)
        category_acl.retrieve()

    def test_add_ca(self, category_acl, caacl_test_ca):
        caacl_test_ca.ensure_exists()
        category_acl.add_ca(ca=caacl_test_ca.name)
        category_acl.retrieve()

    def test_remove_ca(self, category_acl, caacl_test_ca):
        category_acl.remove_ca(ca=caacl_test_ca.name)
        category_acl.retrieve()

    def test_add_invalid_value_service(self, category_acl, default_profile):
        res = category_acl.add_service(service=default_profile.name, track=False)
        assert len(res['failed']) == 1
        assert(res['failed']['memberservice']['service'][0][0].startswith(default_profile.name))

    # the same for other types

    def test_add_invalid_value_user(self, category_acl, default_profile):
        res = category_acl.add_user(user=default_profile.name, track=False)
        assert len(res['failed']) == 1

        res = category_acl.add_user(group=default_profile.name, track=False)
        assert len(res['failed']) == 1

    def test_add_invalid_value_host(self, category_acl, default_profile):
        res = category_acl.add_host(host=default_profile.name, track=False)
        assert len(res['failed']) == 1

        res = category_acl.add_host(hostgroup=default_profile.name, track=False)
        assert len(res['failed']) == 1

    def test_add_invalid_value_profile(self, category_acl):
        res = category_acl.add_profile(certprofile=category_acl.name, track=False)
        assert len(res['failed']) == 1

    def test_add_invalid_value_ca(self, category_acl):
        res = category_acl.add_ca(ca=category_acl.name, track=False)
        assert len(res['failed']) == 1

    def test_add_staged_user_to_acl(self, category_acl, staged_user):
        res = category_acl.add_user(user=staged_user.name, track=False)
        assert len(res['failed']) == 1
