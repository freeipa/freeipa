#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#
"""
Test the `ipaserver/plugins/serviceconstraint.py` module.
"""

from ipalib import api, errors
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import Declarative
from ipapython.dn import DN
import pytest

rule1 = u'test1'
rule2 = u'test rule two'
target1 = u'test1-targets'
target2 = u'test2-targets'
princ1 = u'HTTP/%s@%s' % (api.env.host, api.env.realm)
princ2 = u'ldap/%s@%s' % (api.env.host, api.env.realm)


def get_servicedelegation_dn(cn):
    return DN(('cn', cn), api.env.container_s4u2proxy, api.env.basedn)


@pytest.mark.tier1
class test_servicedelegation(Declarative):
    cleanup_commands = [
        ('servicedelegationrule_del', [rule1], {}),
        ('servicedelegationrule_del', [rule2], {}),
        ('servicedelegationtarget_del', [target1], {}),
        ('servicedelegationtarget_del', [target2], {}),
    ]

    tests = [

        ################
        # create rule1:
        dict(
            desc='Try to retrieve non-existent %r' % rule1,
            command=('servicedelegationrule_show', [rule1], {}),
            expected=errors.NotFound(
                reason=u'%s: service delegation rule not found' % rule1
            ),
        ),


        dict(
            desc='Try to delete non-existent %r' % rule1,
            command=('servicedelegationrule_del', [rule1], {}),
            expected=errors.NotFound(
                reason=u'%s: service delegation rule not found' % rule1
            ),
        ),


        dict(
            desc='Create %r' % rule1,
            command=(
                'servicedelegationrule_add', [rule1], {}
            ),
            expected=dict(
                value=rule1,
                summary=u'Added service delegation rule "%s"' % rule1,
                result=dict(
                    cn=[rule1],
                    objectclass=objectclasses.servicedelegationrule,
                    dn=get_servicedelegation_dn(rule1),
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % rule1,
            command=(
                'servicedelegationrule_add', [rule1], {}
            ),
            expected=errors.DuplicateEntry(
                message=u'service delegation rule with name "%s" '
                'already exists' % rule1),
        ),


        dict(
            desc='Retrieve %r' % rule1,
            command=('servicedelegationrule_show', [rule1], {}),
            expected=dict(
                value=rule1,
                summary=None,
                result=dict(
                    cn=[rule1],
                    dn=get_servicedelegation_dn(rule1),
                ),
            ),
        ),


        dict(
            desc='Search for %r' % rule1,
            command=('servicedelegationrule_find', [], dict(cn=rule1)),
            expected=dict(
                count=1,
                truncated=False,
                result=[
                    dict(
                        dn=get_servicedelegation_dn(rule1),
                        cn=[rule1],
                    ),
                ],
                summary=u'1 service delegation rule matched',
            ),
        ),



        ################
        # create rule2:
        dict(
            desc='Create %r' % rule2,
            command=(
                'servicedelegationrule_add', [rule2], {}
            ),
            expected=dict(
                value=rule2,
                summary=u'Added service delegation rule "%s"' % rule2,
                result=dict(
                    cn=[rule2],
                    objectclass=objectclasses.servicedelegationrule,
                    dn=get_servicedelegation_dn(rule2),
                ),
            ),
        ),


        dict(
            desc='Search for all rules with members',
            command=('servicedelegationrule_find', [], {'no_members': False}),
            expected=dict(
                summary=u'3 service delegation rules matched',
                count=3,
                truncated=False,
                result=[
                    {
                        'dn': get_servicedelegation_dn(u'ipa-http-delegation'),
                        'cn': [u'ipa-http-delegation'],
                        'memberprincipal': [princ1],
                        'ipaallowedtarget_servicedelegationtarget':
                            [u'ipa-ldap-delegation-targets',
                             u'ipa-cifs-delegation-targets']
                    },
                    dict(
                        dn=get_servicedelegation_dn(rule2),
                        cn=[rule2],
                    ),
                    dict(
                        dn=get_servicedelegation_dn(rule1),
                        cn=[rule1],
                    ),
                ],
            ),
        ),


        dict(
            desc='Search for all rules',
            command=('servicedelegationrule_find', [], {}),
            expected=dict(
                summary=u'3 service delegation rules matched',
                count=3,
                truncated=False,
                result=[
                    {
                        'dn': get_servicedelegation_dn(u'ipa-http-delegation'),
                        'cn': [u'ipa-http-delegation'],
                        'memberprincipal': [princ1],
                    },
                    dict(
                        dn=get_servicedelegation_dn(rule2),
                        cn=[rule2],
                    ),
                    dict(
                        dn=get_servicedelegation_dn(rule1),
                        cn=[rule1],
                    ),
                ],
            ),
        ),


        dict(
            desc='Create target %r' % target1,
            command=(
                'servicedelegationtarget_add', [target1], {}
            ),
            expected=dict(
                value=target1,
                summary=u'Added service delegation target "%s"' % target1,
                result=dict(
                    cn=[target1],
                    objectclass=objectclasses.servicedelegationtarget,
                    dn=get_servicedelegation_dn(target1),
                ),
            ),
        ),


        dict(
            desc='Create target %r' % target2,
            command=(
                'servicedelegationtarget_add', [target2], {}
            ),
            expected=dict(
                value=target2,
                summary=u'Added service delegation target "%s"' % target2,
                result=dict(
                    cn=[target2],
                    objectclass=objectclasses.servicedelegationtarget,
                    dn=get_servicedelegation_dn(target2),
                ),
            ),
        ),


        dict(
            desc='Search for all targets',
            command=('servicedelegationtarget_find', [], {}),
            expected=dict(
                summary=u'4 service delegation targets matched',
                count=4,
                truncated=False,
                result=[
                    {
                        'dn': get_servicedelegation_dn(
                            u'ipa-cifs-delegation-targets'),
                        'cn': [u'ipa-cifs-delegation-targets'],
                    },
                    {
                        'dn': get_servicedelegation_dn(
                            u'ipa-ldap-delegation-targets'
                        ),
                        'cn': [u'ipa-ldap-delegation-targets'],
                        'memberprincipal': [princ2],
                    },
                    dict(
                        dn=get_servicedelegation_dn(target1),
                        cn=[target1],
                    ),
                    dict(
                        dn=get_servicedelegation_dn(target2),
                        cn=[target2],
                    ),
                ],
            ),
        ),


        ###############
        # member stuff:
        dict(
            desc='Add member %r to %r' % (target1, rule1),
            command=(
                'servicedelegationrule_add_target', [rule1],
                dict(servicedelegationtarget=target1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    ipaallowedtarget=dict(
                        servicedelegationtarget=tuple(),
                    ),
                ),
                result={
                    'dn': get_servicedelegation_dn(rule1),
                    'ipaallowedtarget_servicedelegationtarget': (target1,),
                    'cn': [rule1],
                },
            ),
        ),


        dict(
            desc='Add duplicate target %r to %r' % (target1, rule1),
            command=(
                'servicedelegationrule_add_target', [rule1],
                dict(servicedelegationtarget=target1)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    ipaallowedtarget=dict(
                        servicedelegationtarget=[
                            [target1, u'This entry is already a member']
                        ],
                    ),
                ),
                result={
                    'dn': get_servicedelegation_dn(rule1),
                    'ipaallowedtarget_servicedelegationtarget': (target1,),
                    'cn': [rule1],
                },
            ),
        ),


        dict(
            desc='Add non-existent target %r to %r' % (u'notfound', rule1),
            command=(
                'servicedelegationrule_add_target', [rule1],
                dict(servicedelegationtarget=u'notfound')
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    ipaallowedtarget=dict(
                        servicedelegationtarget=[
                            [u'notfound', u'no such entry']
                        ],
                    ),
                ),
                result={
                    'dn': get_servicedelegation_dn(rule1),
                    'ipaallowedtarget_servicedelegationtarget': (target1,),
                    'cn': [rule1],
                },
            ),
        ),


        dict(
            desc='Remove a target %r from %r' % (target1, rule1),
            command=(
                'servicedelegationrule_remove_target', [rule1],
                dict(servicedelegationtarget=target1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    ipaallowedtarget=dict(
                        servicedelegationtarget=tuple(),
                    ),
                ),
                result={
                    'dn': get_servicedelegation_dn(rule1),
                    'cn': [rule1],
                },
            ),
        ),


        dict(
            desc='Remove non-existent target %r from %r' % (
                u'notfound', rule1
            ),
            command=(
                'servicedelegationrule_remove_target', [rule1],
                dict(servicedelegationtarget=u'notfound')
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    ipaallowedtarget=dict(
                        servicedelegationtarget=[
                            [u'notfound', u'This entry is not a member']
                        ],
                    ),
                ),
                result={
                    'dn': get_servicedelegation_dn(rule1),
                    'cn': [rule1],
                },
            ),
        ),


        ###############
        # memberprincipal member stuff:
        dict(
            desc='Add memberprinc %r to %r' % (princ1, rule1),
            command=(
                'servicedelegationrule_add_member', [rule1],
                dict(principal=princ1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    failed_memberprincipal=dict(
                        memberprincipal=tuple(),
                    ),
                ),
                result={
                    'dn': get_servicedelegation_dn(rule1),
                    'memberprincipal': (princ1,),
                    'cn': [rule1],
                },
            ),
        ),


        dict(
            desc='Add duplicate member %r to %r' % (princ1, rule1),
            command=(
                'servicedelegationrule_add_member', [rule1],
                dict(principal=princ1)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    failed_memberprincipal=dict(
                        memberprincipal=[
                            [princ1, u'This entry is already a member']
                        ],
                    ),
                ),
                result={
                    'dn': get_servicedelegation_dn(rule1),
                    'memberprincipal': (princ1,),
                    'cn': [rule1],
                },
            ),
        ),


        dict(
            desc='Add non-existent member %r to %r' % (
                u'HTTP/notfound', rule1
            ),
            command=(
                'servicedelegationrule_add_member', [rule1],
                dict(principal=u'HTTP/notfound@%s' % api.env.realm)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    failed_memberprincipal=dict(
                        memberprincipal=[
                            [u'HTTP/notfound@%s' % api.env.realm,
                             u'no such entry']
                            ],
                    ),
                ),
                result={
                    'dn': get_servicedelegation_dn(rule1),
                    'memberprincipal': (princ1,),
                    'cn': [rule1],
                },
            ),
        ),


        dict(
            desc='Remove a member %r from %r' % (princ1, rule1),
            command=(
                'servicedelegationrule_remove_member', [rule1],
                dict(principal=princ1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    failed_memberprincipal=dict(
                        memberprincipal=tuple(),
                    ),
                ),
                result={
                    'dn': get_servicedelegation_dn(rule1),
                    'memberprincipal': [],
                    'cn': [rule1],
                },
            ),
        ),


        dict(
            desc='Remove non-existent member %r from %r' % (
                 u'HTTP/notfound', rule1
            ),
            command=(
                'servicedelegationrule_remove_member', [rule1],
                dict(principal=u'HTTP/notfound@%s' % api.env.realm)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    failed_memberprincipal=dict(
                        memberprincipal=[
                            [u'HTTP/notfound@%s' % api.env.realm,
                             u'This entry is not a member']
                        ],
                    ),
                ),
                result={
                    'dn': get_servicedelegation_dn(rule1),
                    'cn': [rule1],
                },
            ),
        ),


        dict(
            desc='Add memberprinc %r to %r' % (princ1, target1),
            command=(
                'servicedelegationtarget_add_member', [target1],
                dict(principal=princ1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    failed_memberprincipal=dict(
                        memberprincipal=tuple(),
                    ),
                ),
                result={
                    'dn': get_servicedelegation_dn(target1),
                    'memberprincipal': (princ1,),
                    'cn': [target1],
                },
            ),
        ),


        dict(
            desc='Add duplicate member %r to %r' % (princ1, target1),
            command=(
                'servicedelegationtarget_add_member', [target1],
                dict(principal=princ1)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    failed_memberprincipal=dict(
                        memberprincipal=[
                            [princ1, u'This entry is already a member']
                        ],
                    ),
                ),
                result={
                    'dn': get_servicedelegation_dn(target1),
                    'memberprincipal': (princ1,),
                    'cn': [target1],
                },
            ),
        ),


        dict(
            desc='Add non-existent member %r to %r' % (
                u'HTTP/notfound', target1
            ),
            command=(
                'servicedelegationtarget_add_member', [target1],
                dict(principal=u'HTTP/notfound@%s' % api.env.realm)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    failed_memberprincipal=dict(
                        memberprincipal=[
                            [u'HTTP/notfound@%s' % api.env.realm,
                             u'no such entry']
                        ],
                    ),
                ),
                result={
                    'dn': get_servicedelegation_dn(target1),
                    'memberprincipal': (princ1,),
                    'cn': [target1],
                },
            ),
        ),


        dict(
            desc='Remove a member %r from %r' % (princ1, target1),
            command=(
                'servicedelegationtarget_remove_member', [target1],
                dict(principal=princ1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    failed_memberprincipal=dict(
                        memberprincipal=tuple(),
                    ),
                ),
                result={
                    'dn': get_servicedelegation_dn(target1),
                    'memberprincipal': [],
                    'cn': [target1],
                },
            ),
        ),


        dict(
            desc='Remove non-existent member %r from %r' % (
                u'HTTP/notfound', target1
            ),
            command=(
                'servicedelegationtarget_remove_member', [target1],
                dict(principal=u'HTTP/notfound@%s' % api.env.realm)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    failed_memberprincipal=dict(
                        memberprincipal=[
                            [u'HTTP/notfound@%s' % api.env.realm,
                             u'This entry is not a member']
                        ],
                    ),
                ),
                result={
                    'dn': get_servicedelegation_dn(target1),
                    'cn': [target1],
                },
            ),
        ),

    ]
