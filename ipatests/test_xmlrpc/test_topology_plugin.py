#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

"""
Tests for the topology plugin (topologysuffix and topologysegment).
"""

import pytest

from ipalib import api, errors
from ipalib.constants import DOMAIN_SUFFIX_NAME, CA_SUFFIX_NAME
from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, raises_exact


@pytest.mark.tier1
class TestTopologySuffix(XMLRPC_test):
    """Test topologysuffix commands."""

    tracker = Tracker()

    def test_find_suffixes(self):
        """Both domain and CA suffixes must be present after install."""
        result = self.tracker.run_command('topologysuffix_find')
        suffix_names = [
            entry['cn'][0] for entry in result['result']
        ]
        assert DOMAIN_SUFFIX_NAME in suffix_names
        assert CA_SUFFIX_NAME in suffix_names

    def test_show_domain_suffix(self):
        """Retrieve the domain suffix by name."""
        result = self.tracker.run_command(
            'topologysuffix_show', DOMAIN_SUFFIX_NAME)
        assert result['result']['cn'][0] == DOMAIN_SUFFIX_NAME

    def test_show_nonexistent_suffix(self):
        """Looking up a suffix that does not exist must raise NotFound."""
        with raises_exact(errors.NotFound(
                reason=u'%s: suffix not found' % 'bogus')):
            self.tracker.run_command(
                'topologysuffix_show', u'bogus')

    def test_verify_domain_suffix(self):
        """Verify the domain topology reports no errors."""
        result = self.tracker.run_command(
            'topologysuffix_verify', DOMAIN_SUFFIX_NAME)
        assert result['result']['in_order']

    def test_verify_nonexistent_suffix(self):
        """Verifying a non-existent suffix must raise NotFound."""
        with raises_exact(errors.NotFound(
                reason=u'%s: suffix not found' % 'bogus')):
            self.tracker.run_command(
                'topologysuffix_verify', u'bogus')


@pytest.mark.tier1
class TestTopologySegment(XMLRPC_test):
    """Test topologysegment commands."""

    tracker = Tracker()

    def test_segment_add_nonexistent_node(self):
        """Adding a segment with a non-existent node must be rejected."""
        with raises_exact(errors.ValidationError(
                name='leftnode',
                error='left node is not a topology node: '
                      'bogus.example.com')):
            self.tracker.run_command(
                'topologysegment_add',
                DOMAIN_SUFFIX_NAME,
                iparepltoposegmentleftnode=u'bogus.example.com',
                iparepltoposegmentrightnode=api.env.host)

    def test_segment_add_reflexive(self):
        """Adding a segment where left and right are the same must fail."""
        with raises_exact(errors.ValidationError(
                name='leftnode',
                error='left node and right node must not be the same')):
            self.tracker.run_command(
                'topologysegment_add',
                DOMAIN_SUFFIX_NAME,
                iparepltoposegmentleftnode=api.env.host,
                iparepltoposegmentrightnode=api.env.host)

    def test_show_nonexistent_segment(self):
        """Looking up a segment that does not exist must raise NotFound."""
        with raises_exact(errors.NotFound(
                reason=u'%s: segment not found'
                       % 'bogus-to-bogus')):
            self.tracker.run_command(
                'topologysegment_show',
                DOMAIN_SUFFIX_NAME, u'bogus-to-bogus')
