#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

import pytest

from ipalib import errors, api
from ipaplatform.services import knownservices
from ipatests.test_xmlrpc.tracker.location_plugin import LocationTracker
from ipatests.test_xmlrpc.tracker.server_plugin import ServerTracker
from ipatests.test_xmlrpc.xmlrpc_test import (
    XMLRPC_test,
    raises_exact
)
from ipapython.dnsutil import DNSName


@pytest.fixture(scope='class', params=['location1', 'sk\xfa\u0161ka.idna'])
def location(request, xmlrpc_setup):
    tracker = LocationTracker(request.param)
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def location_invalid(request, xmlrpc_setup):
    tracker = LocationTracker('invalid..location')
    return tracker


@pytest.fixture(scope='class')
def location_absolute(request, xmlrpc_setup):
    tracker = LocationTracker('invalid.absolute.')
    return tracker


@pytest.fixture(scope='class')
def server(request, xmlrpc_setup):
    tracker = ServerTracker(api.env.host)
    return tracker.make_fixture_clean_location(request)


@pytest.mark.tier1
class TestNonexistentIPALocation(XMLRPC_test):
    def test_retrieve_nonexistent(self, location):
        location.ensure_missing()
        command = location.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason='%s: location not found' % location.idnsname)):
            command()

    def test_update_nonexistent(self, location):
        location.ensure_missing()
        command = location.make_update_command(updates=dict(
            description='Nope'))
        with raises_exact(errors.NotFound(
                reason='%s: location not found' % location.idnsname)):
            command()

    def test_delete_nonexistent(self, location):
        location.ensure_missing()
        command = location.make_delete_command()
        with raises_exact(errors.NotFound(
                reason='%s: location not found' % location.idnsname)):
            command()

@pytest.mark.tier1
class TestInvalidIPALocations(XMLRPC_test):
    def test_invalid_name(self, location_invalid):
        command = location_invalid.make_create_command()
        with raises_exact(errors.ConversionError(
                name='name',
                error="empty DNS label")):
            command()

    def test_invalid_absolute(self, location_absolute):
        command = location_absolute.make_create_command()
        with raises_exact(errors.ValidationError(
                name='name', error='must be relative')):
            command()


@pytest.mark.tier1
class TestCRUD(XMLRPC_test):
    def test_create_duplicate(self, location):
        location.ensure_exists()
        command = location.make_create_command()
        with raises_exact(errors.DuplicateEntry(
                message='location with name "%s" already exists' %
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
                description='Updated description',
            ),
            expected_updates=dict(
                description=['Updated description'],
            ))
        location.retrieve()

    def test_try_rename(self, location):
        location.ensure_exists()
        command = location.make_update_command(
            updates=dict(setattr='idnsname=changed'))
        with raises_exact(errors.NotAllowedOnRDN()):
            command()

    def test_delete_location(self, location):
        location.delete()


@pytest.mark.tier1
@pytest.mark.skipif(
    not api.Command.dns_is_enabled()['result'], reason='DNS not configured')
class TestLocationsServer(XMLRPC_test):
    messages = [{
        'data': {'service': knownservices.named.systemd_name,
                  'server': api.env.host},
        'message': ('Service %s requires restart '
                     'on IPA server %s to apply configuration '
                     'changes.' % (knownservices.named.systemd_name,
                                    api.env.host)),
        'code': 13025,
        'type': 'warning',
        'name': 'ServiceRestartRequired'}]

    def test_add_nonexistent_location_to_server(self, server):
        nonexistent_loc = DNSName('nonexistent-location')
        command = server.make_update_command(
            updates=dict(
                ipalocation_location=nonexistent_loc,
            )
        )
        with raises_exact(errors.NotFound(
                reason="{location}: location not found".format(
                    location=nonexistent_loc
                ))):
            command()

    def test_add_location_to_server(self, location, server):
        location.ensure_exists()
        server.update(
            updates={'ipalocation_location': location.idnsname_obj},
            expected_updates={'ipalocation_location': [location.idnsname_obj],
                              'enabled_role_servrole': lambda other: True},
            messages=self.messages)
        location.add_server_to_location(server.server_name)
        location.retrieve()
        location.remove_server_from_location(server.server_name)

    def test_retrieve(self, server):
        server.retrieve()

    def test_retrieve_all(self, server):
        server.retrieve(all=True)

    def test_search_server_with_location(self, location, server):
        command = server.make_find_command(
            server.server_name, in_location=location.idnsname_obj)
        result = command()
        server.check_find(result)

    def test_search_server_with_location_with_all(self, location, server):
        command = server.make_find_command(
            server.server_name, in_location=location.idnsname_obj, all=True)
        result = command()
        server.check_find(result, all=True)

    def test_search_server_without_location(self, location, server):
        command = server.make_find_command(
            server.server_name, not_in_location=location.idnsname_obj)
        result = command()
        server.check_find_nomatch(result)

    def test_add_location_to_server_custom_weight(self, location, server):
        location.ensure_exists()

        server.update(
            updates={'ipalocation_location': location.idnsname_obj,
                     'ipaserviceweight': 200},
            expected_updates={'ipalocation_location': [location.idnsname_obj],
                              'enabled_role_servrole': lambda other: True,
                              'ipaserviceweight': ['200']},
            messages=self.messages)

        # remove invalid data from the previous test
        location.remove_server_from_location(server.server_name)

        location.add_server_to_location(server.server_name, weight=200)
        location.retrieve()

    def test_remove_location_from_server(self, location, server):
        server.update(
            updates={'ipalocation_location': None},
            expected_updates={'enabled_role_servrole': lambda other: True},
            messages=self.messages)
        location.remove_server_from_location(server.server_name)
        location.retrieve()

    def test_remove_service_weight_from_server(self, location, server):
        server.update(
            updates={'ipaserviceweight': None},
            expected_updates={'enabled_role_servrole': lambda other: True},
            messages=self.messages)
        location.retrieve()
