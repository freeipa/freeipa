# -*- coding: utf-8 -*-
#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
Test the `ipalib.plugins.certprofile` module.
"""

import os

import pytest
import six

from ipalib import api, errors
from ipatests.util import prepare_config
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, raises_exact
from ipatests.test_xmlrpc.tracker.certprofile_plugin import CertprofileTracker

if six.PY3:
    unicode = str

IPA_CERT_SUBJ_BASE = (
    api.Command.config_show()
    ['result']['ipacertificatesubjectbase'][0]
)

BASE_DIR = os.path.dirname(__file__)
CA_IPA_SERVICE_MODIFIED_TEMPLATE = os.path.join(
    BASE_DIR, 'data/caIPAserviceCert_mod.cfg.tmpl')

CA_IPA_SERVICE_MODIFIED_MALFORMED_TEMPLATE = os.path.join(
    BASE_DIR, 'data/caIPAserviceCert_mod_mal.cfg.tmpl')

CA_IPA_SERVICE_MALFORMED_TEMPLATE = os.path.join(
    BASE_DIR, 'data/caIPAserviceCert_mal.cfg.tmpl')

CA_IPA_SERVICE_XML_TEMPLATE = os.path.join(
    BASE_DIR, 'data/caIPAserviceCert.xml.tmpl')

RENAME_ERR_TEMPL = (
    u'certprofile {} cannot be deleted/modified: '
    'Certificate profiles cannot be renamed')


@pytest.fixture(scope='class')
def default_profile(request, xmlrpc_setup):
    name = 'caIPAserviceCert'
    desc = u'Standard profile for network services'
    tracker = CertprofileTracker(name, store=True, desc=desc)
    tracker.track_create()
    return tracker


@pytest.fixture(scope='class')
def user_profile(request, xmlrpc_setup):
    name = 'caIPAserviceCert_mod'
    profile_path = prepare_config(
        CA_IPA_SERVICE_MODIFIED_TEMPLATE,
        dict(
            ipadomain=api.env.domain,
            ipacertbase=IPA_CERT_SUBJ_BASE))

    tracker = CertprofileTracker(
        name, store=True, desc=u'Storing copy of a profile',
        profile=profile_path
    )

    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def malformed(request, xmlrpc_setup):
    name = u'caIPAserviceCert_mal'
    profile_path = prepare_config(
        CA_IPA_SERVICE_MALFORMED_TEMPLATE,
        dict(
            ipadomain=api.env.domain,
            ipacertbase=IPA_CERT_SUBJ_BASE))

    tracker = CertprofileTracker(name, store=True, desc=u'malformed profile',
                                 profile=profile_path)

    # Do not return with finalizer. There should be nothing to delete
    return tracker


@pytest.fixture(scope='class')
def xmlprofile(request, xmlrpc_setup):
    name = u'caIPAserviceCert_xml'
    profile_path = prepare_config(
        CA_IPA_SERVICE_XML_TEMPLATE,
        dict(
            ipadomain=api.env.domain,
            ipacertbase=IPA_CERT_SUBJ_BASE))

    tracker = CertprofileTracker(name, store=True, desc=u'xml format profile',
                                 profile=profile_path)

    return tracker


@pytest.mark.tier0
class TestDefaultProfile(XMLRPC_test):
    def test_default_profile_present(self, default_profile):
        default_profile.retrieve()

    def test_deleting_default_profile(self, default_profile):
        with pytest.raises(errors.ValidationError):
            default_profile.delete()

    def test_try_rename_by_setattr(self, default_profile):
        command = default_profile.make_update_command(
            updates=dict(setattr=u'cn=bogus'))
        errmsg = RENAME_ERR_TEMPL.format(default_profile.name)

        with raises_exact(errors.ProtectedEntryError(message=errmsg)):
            command()

    def test_try_rename_by_rename_option(self, default_profile):
        command = default_profile.make_update_command(dict(rename=u'bogus_id'))
        with pytest.raises(errors.OptionError):
            command()


@pytest.mark.tier1
class TestProfileCRUD(XMLRPC_test):
    def test_create_duplicate(self, user_profile):
        msg = u'Certificate Profile with name "{}" already exists'
        user_profile.ensure_exists()
        command = user_profile.make_create_command()
        with raises_exact(errors.DuplicateEntry(
                message=msg.format(user_profile.name))):
            command()

    def test_retrieve_simple(self, user_profile):
        user_profile.retrieve()

    def test_retrieve_all(self, user_profile):
        user_profile.retrieve(all=True)

    def test_export_profile(self, tmpdir, user_profile):
        profile = tmpdir.join('{}.cfg'.format(user_profile.name))

        command = user_profile.make_retrieve_command(out=unicode(profile))
        command()

        content = profile.read()
        assert user_profile.name in content

    def test_search_simple(self, user_profile):
        user_profile.find()

    def test_search_all(self, user_profile):
        user_profile.find(all=True)

    def test_update_store(self, user_profile):
        user_profile.update(
            dict(
                ipacertprofilestoreissued=False
            ),
            expected_updates=dict(
                ipacertprofilestoreissued=[u'FALSE']
            )
        )

    def test_update_description(self, user_profile):
        new_desc = u'new description'
        user_profile.update(
            dict(
                description=new_desc
            ),
            expected_updates=dict(
                description=[new_desc]
            )
        )

    def test_update_by_malformed_profile(self, user_profile):
        profile_path = prepare_config(
            CA_IPA_SERVICE_MODIFIED_MALFORMED_TEMPLATE,
            dict(
                ipadomain=api.env.domain,
                ipacertbase=IPA_CERT_SUBJ_BASE))

        with open(profile_path, ) as f:
            profile_content = f.read()
        command = user_profile.make_update_command(
            dict(file=unicode(profile_content)))

        with pytest.raises(errors.ExecutionError):
            command()

    def test_try_rename_by_setattr(self, user_profile):
        user_profile.ensure_exists()
        command = user_profile.make_update_command(
            updates=dict(setattr=u'cn=bogus'))
        errmsg = RENAME_ERR_TEMPL.format(user_profile.name)

        with raises_exact(errors.ProtectedEntryError(message=errmsg)):
            command()

    def test_delete(self, user_profile):
        user_profile.ensure_exists()
        user_profile.delete()

    def test_try_rename_by_rename_option(self, user_profile):
        user_profile.ensure_exists()
        command = user_profile.make_update_command(dict(rename=u'bogus_id'))
        with pytest.raises(errors.OptionError):
            command()


@pytest.mark.tier1
class TestMalformedProfile(XMLRPC_test):
    def test_malformed_import(self, malformed):
        with pytest.raises(errors.ExecutionError):
            malformed.create()


@pytest.mark.tier1
class TestImportFromXML(XMLRPC_test):
    def test_import_xml(self, xmlprofile):
        with pytest.raises(errors.ExecutionError):
            xmlprofile.ensure_exists()


# The initial user_profile configuration does not specify profileId.
# This is fine (it gets derived from the profile-id CLI argument),
# but this case was already tested in TestProfileCRUD.
#
# This test case tests various scenarios where the profileId *is*
# specified in the profile configuration.  These are:
#
# - mismatched profileId property (should fail)
# - multiple profileId properties (should fail)
# - one profileId property, matching given ID (should succeed)
#
@pytest.mark.tier1
class TestImportProfileIdHandling(XMLRPC_test):
    def test_import_with_mismatched_profile_id(self, user_profile):
        command = user_profile.make_create_command(
            extra_lines=['profileId=bogus']
        )
        with pytest.raises(errors.ValidationError):
            command()

    def test_import_with_multiple_profile_id(self, user_profile):
        # correct profile id, but two occurrences
        prop = u'profileId={}'.format(user_profile.name)
        command = user_profile.make_create_command(extra_lines=[prop, prop])
        with pytest.raises(errors.ValidationError):
            command()

    def test_import_with_correct_profile_id(self, user_profile):
        prop = u'profileId={}'.format(user_profile.name)
        command = user_profile.make_create_command(extra_lines=[prop])
        command()
