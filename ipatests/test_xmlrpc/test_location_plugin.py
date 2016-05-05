#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

import pytest

from ipalib import errors
from ipatests.test_xmlrpc.tracker.location_plugin import LocationTracker
from ipatests.test_xmlrpc.xmlrpc_test import (
    XMLRPC_test,
    raises_exact,
)


@pytest.fixture(scope='class', params=[u'location1', u'sk\xfa\u0161ka.idna'])
def location(request):
    tracker = LocationTracker(request.param)
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def location_invalid(request):
    tracker = LocationTracker(u'invalid..location')
    return tracker


@pytest.fixture(scope='class')
def location_absolute(request):
    tracker = LocationTracker(u'invalid.absolute.')
    return tracker.make_fixture(request)


@pytest.mark.tier1
class TestNonexistentIPALocation(XMLRPC_test):
    def test_retrieve_nonexistent(self, location):
        location.ensure_missing()
        command = location.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: location not found' % location.idnsname)):
            command()

    def test_update_nonexistent(self, location):
        location.ensure_missing()
        command = location.make_update_command(updates=dict(
            description=u'Nope'))
        with raises_exact(errors.NotFound(
                reason=u'%s: location not found' % location.idnsname)):
            command()

    def test_delete_nonexistent(self, location):
        location.ensure_missing()
        command = location.make_delete_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: location not found' % location.idnsname)):
            command()

@pytest.mark.tier1
class TestInvalidIPALocations(XMLRPC_test):
    def test_invalid_name(self, location_invalid):
        command = location_invalid.make_create_command()
        with raises_exact(errors.ConversionError(
                name=u'name',
                error=u"empty DNS label")):
            command()

    def test_invalid_absolute(self, location_absolute):
        command = location_absolute.make_create_command()
        with raises_exact(errors.ValidationError(
                name=u'name', error=u'must be relative')):
            command()


@pytest.mark.tier1
class TestCRUD(XMLRPC_test):
    def test_create_duplicate(self, location):
        location.ensure_exists()
        command = location.make_create_command(force=True)
        with raises_exact(errors.DuplicateEntry(
                message=u'location with name "%s" already exists' %
                        location.idnsname)):
            command()

    def test_retrieve_simple(self, location):
        location.retrieve()

    def test_retrieve_all(self, location):
        location.retrieve(all=True)

    def test_search_simple(self, location):
        location.find()

    def test_search_all(self, location):
        location.find(all=True)

    def test_update_simple(self, location):
        location.update(dict(
                description=u'Updated description',
            ),
            expected_updates=dict(
                description=[u'Updated description'],
            ))
        location.retrieve()

    def test_try_rename(self, location):
        location.ensure_exists()
        command = location.make_update_command(
            updates=dict(setattr=u'idnsname=changed'))
        with raises_exact(errors.NotAllowedOnRDN()):
            command()

    def test_delete_location(self, location):
        location.delete()
