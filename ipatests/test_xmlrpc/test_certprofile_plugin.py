# -*- coding: utf-8 -*-
#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
Test the `ipalib.plugins.certprofile` module.
"""

import os

import pytest

from ipalib import api, errors
from ipapython.dn import DN
from ipatests.util import prepare_config
from ipatests.test_xmlrpc.ldaptracker import Tracker
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, raises_exact
from ipatests.test_xmlrpc import objectclasses
from ipatests.util import assert_deepequal


class CertprofileTracker(Tracker):
    """Tracker class for certprofile plugin.
    """

    retrieve_keys = {
        'dn', 'cn', 'description', 'ipacertprofilestoreissued'
    }
    retrieve_all_keys = retrieve_keys | {'objectclass'}
    create_keys = retrieve_keys | {'objectclass'}
    update_keys = retrieve_keys - {'dn'}
    managedby_keys = retrieve_keys
    allowedto_keys = retrieve_keys

    def __init__(self, name, store=False, desc='dummy description',
                 profile=None, default_version=None):
        super(CertprofileTracker, self).__init__(
            default_version=default_version
        )

        self.store = store
        self.description = desc
        self._profile_path = profile

        self.dn = DN(('cn', name), 'cn=certprofiles', 'cn=ca',
                     self.api.env.basedn)

    @property
    def profile(self):
        if not self._profile_path:
            return None

        if os.path.isabs(self._profile_path):
            path = self._profile_path
        else:
            path = os.path.join(os.path.dirname(__file__),
                                self._profile_path)

        with open(path, 'r') as f:
            content = f.read()
        return unicode(content)

    def make_create_command(self, force=True):
        if not self.profile:
            raise RuntimeError('Tracker object without path to profile '
                               'cannot be used to create profile entry.')

        return self.make_command('certprofile_import', self.name,
                                 description=self.description,
                                 ipacertprofilestoreissued=self.store,
                                 file=self.profile)

    def check_create(self, result):
        assert_deepequal(dict(
            value=self.name,
            summary=u'Imported profile "{}"'.format(self.name),
            result=dict(self.filter_attrs(self.create_keys))
        ), result)

    def track_create(self):
        self.attrs = dict(
            dn=unicode(self.dn),
            cn=[self.name],
            description=[self.description],
            ipacertprofilestoreissued=[unicode(self.store).upper()],
            objectclass=objectclasses.certprofile
        )
        self.exists = True

    def make_delete_command(self):
        return self.make_command('certprofile_del', self.name)

    def check_delete(self, result):
        assert_deepequal(dict(
            value=[self.name],  # correctly a list?
            summary=u'Deleted profile "{}"'.format(self.name),
            result=dict(failed=[]),
        ), result)

    def make_retrieve_command(self, all=False, raw=False, **options):
        return self.make_command('certprofile_show', self.name, all=all,
                                 raw=raw, **options)

    def check_retrieve(self, result, all=False, raw=False):
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        assert_deepequal(dict(
            value=self.name,
            summary=None,
            result=expected,
        ), result)

    def make_find_command(self, *args, **kwargs):
        return self.make_command('certprofile_find', *args, **kwargs)

    def check_find(self, result, all=False, raw=False):
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary=u'1 profile matched',
            result=[expected]
        ), result)

    def make_update_command(self, updates):
        return self.make_command('certprofile_mod', self.name, **updates)

    def check_update(self, result, extra_keys=()):
        assert_deepequal(dict(
            value=self.name,
            summary=u'Modified Certificate Profile "{}"'.format(self.name),
            result=self.filter_attrs(self.update_keys | set(extra_keys))
        ), result)


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
def default_profile(request):
    name = 'caIPAserviceCert'
    desc = u'Standard profile for network services'
    tracker = CertprofileTracker(name, store=True, desc=desc)
    tracker.track_create()
    return tracker


@pytest.fixture(scope='class')
def user_profile(request):
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
def malformed(request):
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
def xmlprofile(request):
    name = u'caIPAserviceCert_xml'
    profile_path = prepare_config(
        CA_IPA_SERVICE_XML_TEMPLATE,
        dict(
            ipadomain=api.env.domain,
            ipacertbase=IPA_CERT_SUBJ_BASE))

    tracker = CertprofileTracker(name, store=True, desc=u'xml format profile',
                                 profile=profile_path)

    return tracker


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


class TestProfileCRUD(XMLRPC_test):
    def test_create_duplicate(self, user_profile):
        msg = u'Certificate Profile with name "{}" already exists'
        user_profile.ensure_exists()
        command = user_profile.make_create_command(force=True)
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


class TestMalformedProfile(XMLRPC_test):
    def test_malformed_import(self, malformed):
        with pytest.raises(errors.ExecutionError):
            malformed.create()


class TestImportFromXML(XMLRPC_test):
    def test_import_xml(self, xmlprofile):
        with pytest.raises(errors.ExecutionError):
            xmlprofile.ensure_exists()
