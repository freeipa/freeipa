#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

import itertools
import pytest

from ipapython.dn import DN
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipatests.test_xmlrpc.tracker.certmap_plugin import CertmapruleTracker

certmaprule_create_params = {
        u'cn': u'test_rule',
        u'description': u'Certificate mapping and matching rule for test '
                        u'purposes',
        u'ipacertmapissuer': DN('CN=CA,O=EXAMPLE.ORG'),
        u'ipacertmapmaprule': u'arbitrary free-form mapping rule defined and '
                              u'consumed by SSSD',
        u'ipacertmapmatchrule': u'arbitrary free-form matching rule defined '
                                u'and consumed by SSSD',
        u'associateddomain': u'example.org',
        u'ipacertmappriority': u'1',
}

certmaprule_update_params = {
        u'description': u'Changed description',
        u'ipacertmapissuer': DN('CN=Changed CA,O=OTHER.ORG'),
        u'ipacertmapmaprule': u'changed arbitrary mapping rule',
        u'ipacertmapmatchrule': u'changed arbitrary maching rule',
        u'associateddomain': u'changed.example.org',
        u'ipacertmappriority': u'5',
}

certmaprule_optional_params = (
    'description',
    'ipacertmapissuer',
    'ipacertmapmaprule',
    'ipacertmapmatchrule',
    'ipaassociateddomain',
    'ipacertmappriority',
)

def dontfill_idfn(dont_fill):
    return u"dont_fill=({})".format(', '.join([
        u"{}".format(d) for d in dont_fill
    ]))


def update_idfn(update):
    return ', '.join(["{}: {}".format(k, v) for k, v in update.items()])


@pytest.fixture(scope='class')
def certmap_rule(request):
    tracker = CertmapruleTracker(**certmaprule_create_params)
    return tracker.make_fixture(request)


class TestCRUD(XMLRPC_test):
    @pytest.mark.parametrize(
        'dont_fill',
        itertools.chain(*[
            itertools.combinations(certmaprule_optional_params, l)
            for l in range(len(certmaprule_optional_params)+1)
        ]),
        ids=dontfill_idfn,
    )
    def test_create(self, dont_fill, certmap_rule):
        certmap_rule.ensure_missing()
        try:
            certmap_rule.create(dont_fill)
        finally:
            certmap_rule.ensure_missing()

    def test_retrieve(self, certmap_rule):
        certmap_rule.ensure_exists()
        certmap_rule.retrieve()

    def test_find(self, certmap_rule):
        certmap_rule.ensure_exists()
        certmap_rule.find()

    @pytest.mark.parametrize('update', [
            dict(u) for l in range(1, len(certmaprule_update_params)+1)
            for u in itertools.combinations(
                certmaprule_update_params.items(), l)
        ],
        ids=update_idfn,
    )
    def test_update(self, update, certmap_rule):
        certmap_rule.ensure_missing()
        certmap_rule.ensure_exists()
        certmap_rule.update(update, {o: [v] for o, v in update.items()})

    def test_delete(self, certmap_rule):
        certmap_rule.ensure_exists()
        certmap_rule.delete()


class TestEnableDisable(XMLRPC_test):
    def test_disable(self, certmap_rule):
        certmap_rule.ensure_exists()
        certmap_rule.disable()

    def test_enable(self, certmap_rule):
        certmap_rule.ensure_exists()
        certmap_rule.enable()
