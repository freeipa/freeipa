# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008, 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
Test the `ipalib.plugins.hostgroup` module.
"""

from ipalib import api, errors
from tests.test_xmlrpc.xmlrpc_test import Declarative
from tests.test_xmlrpc import objectclasses


fqdn1 = u'testhost1.%s' % api.env.domain


class test_hostgroup(Declarative):

    cleanup_commands = [
        ('hostgroup_del', [u'testhostgroup1'], {}),
        ('host_del', [fqdn1], {}),
    ]

    tests=[

        dict(
            desc='Try to retrieve non-existent testhostgroup1',
            command=('hostgroup_show', [u'testhostgroup1'], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent testhostgroup1',
            command=('hostgroup_mod', [u'testhostgroup1'],
                dict(description=u'Updated hostgroup 1')
            ),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to delete non-existent testhostgroup1',
            command=('hostgroup_del', [u'testhostgroup1'], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Create hostgroup testhostgroup1',
            command=('hostgroup_add', [u'testhostgroup1'],
                dict(description=u'Test hostgroup 1')
            ),
            expected=dict(
                value=u'testhostgroup1',
                summary=u'Added hostgroup "testhostgroup1"',
                result=dict(
                    cn=(u'testhostgroup1',),
                    objectclass=objectclasses.hostgroup,
                    description=(u'Test hostgroup 1',),
                ),
            ),
            ignore_values=['ipauniqueid', 'dn'],
        ),


        dict(
            desc='Try to create duplicate testhostgroup1',
            command=('hostgroup_add', [u'testhostgroup1'],
                dict(description=u'Test hostgroup 1')
            ),
            expected=errors.DuplicateEntry(),
        ),


        dict(
            desc='Create host %r' % fqdn1,
            command=('host_add', [fqdn1],
                dict(
                    description=u'Test host 1',
                    localityname=u'Undisclosed location 1',
                ),
            ),
            expected=dict(
                value=fqdn1,
                summary=u'Added host "%s"' % fqdn1,
                result=dict(
                    cn=(fqdn1,),  # FIXME: we should only return fqdn
                    fqdn=(fqdn1,),
                    description=(u'Test host 1',),
                    localityname=(u'Undisclosed location 1',),
                    krbprincipalname=(u'host/%s@%s' % (fqdn1, api.env.realm),),
                    serverhostname=(u'testhost1',),
                    objectclass=objectclasses.host,
                ),
            ),
            ignore_values=['ipauniqueid', 'dn'],
        ),


        dict(
            desc=u'Add %r to testhostgroup1' % fqdn1,
            command=(
                'hostgroup_add_member', [u'testhostgroup1'], dict(host=fqdn1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        host=tuple(),
                        hostgroup=tuple(),
                    ),
                ),
                result={
                    'member host': (fqdn1,),
                },
            ),
        ),


        dict(
            desc='Retrieve testhostgroup1',
            command=('hostgroup_show', [u'testhostgroup1'], {}),
            expected=dict(
                value=u'testhostgroup1',
                summary=None,
                result={
                    'member host': (u'testhost1.example.com',),
                    'cn': (u'testhostgroup1',),
                    'description': (u'Test hostgroup 1',)
                },
            ),
            ignore_values=['dn'],
        ),


        dict(
            desc='Search for testhostgroup1',
            command=('hostgroup_find', [], dict(cn=u'testhostgroup1')),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 hostgroup matched',
                result=(
                    {
                        'member host': (u'testhost1.example.com',),
                        'cn': (u'testhostgroup1',),
                        'description': (u'Test hostgroup 1',),
                    },
                ),
            ),
        ),


        dict(
            desc='Update testhostgroup1',
            command=('hostgroup_mod', [u'testhostgroup1'],
                dict(description=u'Updated hostgroup 1')
            ),
            expected=dict(
                value=u'testhostgroup1',
                summary=u'Modified hostgroup "testhostgroup1"',
                result=dict(
                    description=(u'Updated hostgroup 1',),
                ),
            ),
        ),


        dict(
            desc='Retrieve testhostgroup1 to verify update',
            command=('hostgroup_show', [u'testhostgroup1'], {}),
            expected=dict(
                value=u'testhostgroup1',
                summary=None,
                result={
                    'member host': (u'testhost1.example.com',),
                    'cn': (u'testhostgroup1',),
                    'description': (u'Updated hostgroup 1',)
                },
            ),
            ignore_values=['dn'],
        ),


        dict(
            desc='Remove %s from testhostgroup1',
            command=('hostgroup_remove_member', [u'testhostgroup1'],
                dict(host=fqdn1)
            ),
            expected=dict(
                failed=dict(
                    member=dict(
                        host=tuple(),
                        hostgroup=tuple(),
                    ),
                ),
                completed=1,
                result={},
            ),
        ),


        dict(
            desc='Delete testhostgroup1',
            command=('hostgroup_del', [u'testhostgroup1'], {}),
            expected=dict(
                value=u'testhostgroup1',
                summary=u'Deleted hostgroup "testhostgroup1"',
                result=True,
            ),
        ),


        dict(
            desc='Delete %s' % fqdn1,
            command=('host_del', [fqdn1], {}),
            expected=dict(
                value=fqdn1,
                summary=u'Deleted host "%s"' % fqdn1,
                result=True,
            ),
        )

    ]
