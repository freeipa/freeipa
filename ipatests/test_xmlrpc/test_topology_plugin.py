#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

"""XML-RPC tests for the topology plugin.

test_topologysuffix:
- topologysuffix_find returns the CA and domain suffixes
- topologysuffix_show returns the domain suffix
- topologysuffix_show of an unknown suffix raises NotFound
- topologysuffix_verify reports the domain topology in order, with no
  connection or agreement errors
- topologysuffix_verify of an unknown suffix raises NotFound

test_topologysegment:
- topologysegment_find on the domain suffix returns no segments
- topologysegment_add rejects a left node that is not an IPA server
- topologysegment_add rejects a segment whose endpoints are the same
- topologysegment_show of an unknown segment raises NotFound
"""

import pytest

from ipalib import api, errors
from ipalib.constants import CA_SUFFIX_NAME, DOMAIN_SUFFIX_NAME
from ipapython.dn import DN
from ipatests.test_xmlrpc.xmlrpc_test import Declarative

MISSING_SUFFIX = 'bogus'
MISSING_SEGMENT = 'bogus-to-bogus'
MISSING_NODE = 'bogus.example.com'
CA_SUFFIX_DN = DN('o=ipaca')


def suffix_dn(name):
    return DN(('cn', name), api.env.container_topology, api.env.basedn)


def suffix_entry(name, root):
    return dict(
        cn=[name],
        iparepltopoconfroot=[root],
        dn=suffix_dn(name),
    )


@pytest.mark.tier1
class test_topologysuffix(Declarative):
    """Test topologysuffix commands."""

    tests = [
        dict(
            desc='Search returns the CA and domain suffixes',
            command=('topologysuffix_find', [], {}),
            expected=dict(
                result=[
                    suffix_entry(CA_SUFFIX_NAME, CA_SUFFIX_DN),
                    suffix_entry(DOMAIN_SUFFIX_NAME, api.env.basedn),
                ],
                count=2,
                truncated=False,
                summary='2 topology suffixes matched',
            ),
        ),

        dict(
            desc='Retrieve the domain suffix',
            command=('topologysuffix_show', [DOMAIN_SUFFIX_NAME], {}),
            expected=dict(
                value=DOMAIN_SUFFIX_NAME,
                summary=None,
                result=suffix_entry(DOMAIN_SUFFIX_NAME, api.env.basedn),
            ),
        ),

        dict(
            desc='Retrieve a suffix that does not exist',
            command=('topologysuffix_show', [MISSING_SUFFIX], {}),
            expected=errors.NotFound(
                reason='%s: suffix not found' % MISSING_SUFFIX),
        ),

        dict(
            desc='Verify the domain topology on a single server',
            command=('topologysuffix_verify', [DOMAIN_SUFFIX_NAME], {}),
            expected=dict(
                result=dict(
                    in_order=True,
                    connect_errors=[],
                    max_agmts_errors=[],
                    max_agmts=api.env.recommended_max_agmts,
                ),
            ),
        ),

        dict(
            desc='Verify a suffix that does not exist',
            command=('topologysuffix_verify', [MISSING_SUFFIX], {}),
            expected=errors.NotFound(
                reason='%s: suffix not found' % MISSING_SUFFIX),
        ),
    ]


@pytest.mark.tier1
class test_topologysegment(Declarative):
    """Test topologysegment commands."""

    tests = [
        dict(
            desc='Search the domain suffix on a single master',
            command=('topologysegment_find', [DOMAIN_SUFFIX_NAME], {}),
            expected=dict(
                result=[],
                count=0,
                truncated=False,
                summary='0 segments matched',
            ),
        ),

        dict(
            desc='Reject a segment whose left node does not exist',
            command=(
                'topologysegment_add',
                [DOMAIN_SUFFIX_NAME],
                dict(
                    iparepltoposegmentleftnode=MISSING_NODE,
                    iparepltoposegmentrightnode=api.env.host,
                ),
            ),
            expected=errors.ValidationError(
                name='leftnode',
                error='left node is not a topology node: %s' % MISSING_NODE,
            ),
        ),

        dict(
            desc='Reject a segment whose left and right nodes are the same',
            command=(
                'topologysegment_add',
                [DOMAIN_SUFFIX_NAME],
                dict(
                    iparepltoposegmentleftnode=api.env.host,
                    iparepltoposegmentrightnode=api.env.host,
                ),
            ),
            expected=errors.ValidationError(
                name='leftnode',
                error='left node and right node must not be the same',
            ),
        ),

        dict(
            desc='Retrieve a segment that does not exist',
            command=(
                'topologysegment_show',
                [DOMAIN_SUFFIX_NAME, MISSING_SEGMENT],
                {},
            ),
            expected=errors.NotFound(
                reason='%s: segment not found' % MISSING_SEGMENT),
        ),
    ]
