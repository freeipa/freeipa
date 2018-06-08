# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2013  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import six

from ipalib import errors, api, _
from ipapython.dn import DN
from ipatests.test_xmlrpc.xmlrpc_test import Declarative
from ipatests.test_xmlrpc.test_user_plugin import get_user_result
from ipatests.test_xmlrpc import objectclasses
import pytest

if six.PY3:
    unicode = str

radius1 = u'testradius'
radius1_fqdn = u'testradius.test'
radius1_dn = DN(('cn=testradius'), ('cn=radiusproxy'), api.env.basedn)
user1 = u'tuser1'
password1 = u'very*secure123'
password1_bytes = password1.encode('ascii')


@pytest.mark.tier1
class test_raduisproxy(Declarative):

    cleanup_commands = [
        ('radiusproxy_del', [radius1], {}),
        ('user_del', [user1], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent %r' % radius1,
            command=('radiusproxy_show', [radius1], {}),
            expected=errors.NotFound(
                reason=u'%s: RADIUS proxy server not found' % radius1),
        ),


        dict(
            desc='Try to update non-existent %r' % radius1,
            command=('radiusproxy_mod', [radius1], {}),
            expected=errors.NotFound(
                reason=_('%s: RADIUS proxy server not found') % radius1),
        ),


        dict(
            desc='Try to delete non-existent %r' % radius1,
            command=('radiusproxy_del', [radius1], {}),
            expected=errors.NotFound(
                reason=_('%s: RADIUS proxy server not found') % radius1),
        ),


        dict(
            desc='Try to add multiple radius proxy server %r' % radius1,
            command=('radiusproxy_add', [radius1],
                     dict(
                     ipatokenradiusserver=radius1_fqdn,
                     addattr=u'ipatokenradiusserver=radius1_fqdn',
                     ipatokenradiussecret=password1,
                     ),
                     ),
            expected=errors.OnlyOneValueAllowed(attr='ipatokenradiusserver')
        ),


        dict(
            desc='Create %r' % radius1,
            command=('radiusproxy_add', [radius1],
                dict(
                    ipatokenradiusserver=radius1_fqdn,
                    ipatokenradiussecret=password1,
                ),
            ),
            expected=dict(
                value=radius1,
                summary=u'Added RADIUS proxy server "%s"' % radius1,
                result=dict(
                    cn=[radius1],
                    dn=radius1_dn,
                    ipatokenradiussecret=[password1_bytes],
                    ipatokenradiusserver=[radius1_fqdn],
                    objectclass=objectclasses.radiusproxy,

                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % radius1,
            command=('radiusproxy_add', [radius1],
                dict(
                    ipatokenradiusserver=radius1_fqdn,
                    ipatokenradiussecret=password1,
                ),
            ),
            expected=errors.DuplicateEntry(message=_('RADIUS proxy server '
                'with name "%s" already exists') % radius1),
        ),


        dict(
            desc='Retrieve %r' % radius1,
            command=('radiusproxy_show', [radius1], {}),
            expected=dict(
                value=radius1,
                summary=None,
                result=dict(
                    cn=[radius1],
                    dn=radius1_dn,
                    ipatokenradiusserver=[radius1_fqdn],
                ),
            ),
        ),


        dict(
            desc='Retrieve %r with all=True' % radius1,
            command=('radiusproxy_show', [radius1], dict(all=True)),
            expected=dict(
                value=radius1,
                summary=None,
                result=dict(
                    cn=[radius1],
                    dn=radius1_dn,
                    ipatokenradiussecret=[password1_bytes],
                    ipatokenradiusserver=[radius1_fqdn],
                    objectclass=objectclasses.radiusproxy,
                ),
            ),
        ),

    ] + [
        dict(
            desc='Set timeout of %s to %s (valid)' % (radius1, num),
            command=('radiusproxy_mod', [radius1],
                     dict(ipatokenradiustimeout=num)),
            expected=dict(
                value=radius1,
                summary=u'Modified RADIUS proxy server "%s"' % radius1,
                result=dict(
                    cn=[radius1],
                    ipatokenradiusserver=[radius1_fqdn],
                    ipatokenradiustimeout=[unicode(num)],
                ),
            ),
        )
        for num in (1, 100)
    ] + [

        dict(
            desc='Set timeout of %s to 0 (invalid)' % radius1,
            command=('radiusproxy_mod', [radius1],
                     dict(ipatokenradiustimeout=0)),
            expected=errors.ValidationError(
                name='timeout', error=_('must be at least 1')),
        ),

        dict(
            desc='Unset timeout of %s' % radius1,
            command=('radiusproxy_mod', [radius1],
                     dict(ipatokenradiustimeout=None)),
            expected=dict(
                value=radius1,
                summary=u'Modified RADIUS proxy server "%s"' % radius1,
                result=dict(
                    cn=[radius1],
                    ipatokenradiusserver=[radius1_fqdn],
                ),
            ),
        ),

    ] + [
        dict(
            desc='Set retries of %s to %s (valid)' % (radius1, num),
            command=('radiusproxy_mod', [radius1],
                     dict(ipatokenradiusretries=num)),
            expected=dict(
                value=radius1,
                summary=u'Modified RADIUS proxy server "%s"' % radius1,
                result=dict(
                    cn=[radius1],
                    ipatokenradiusserver=[radius1_fqdn],
                    ipatokenradiusretries=[unicode(num)],
                ),
            ),
        )
        for num in (0, 4, 10)
    ] + [
        dict(
            desc='Set retries of %s to %s (invalid)' % (radius1, num),
            command=('radiusproxy_mod', [radius1],
                     dict(ipatokenradiusretries=num)),
            expected=errors.ValidationError(
                name='retries', error=reason),
        )
        for num, reason in ((-1, 'must be at least 0'),
                            (11, 'can be at most 10'),
                            (100, 'can be at most 10'))
    ] + [

        dict(
            desc='Unset retries of %s' % radius1,
            command=('radiusproxy_mod', [radius1],
                     dict(ipatokenradiusretries=None)),
            expected=dict(
                value=radius1,
                summary=u'Modified RADIUS proxy server "%s"' % radius1,
                result=dict(
                    cn=[radius1],
                    ipatokenradiusserver=[radius1_fqdn],
                ),
            ),
        ),

    ] + [
        dict(
            desc='Set server string of %s to %s (valid)' % (radius1, fqdn),
            command=('radiusproxy_mod', [radius1],
                     dict(ipatokenradiusserver=fqdn)),
            expected=dict(
                value=radius1,
                summary=u'Modified RADIUS proxy server "%s"' % radius1,
                result=dict(
                    cn=[radius1],
                    ipatokenradiusserver=[fqdn],
                ),
            ),
        )
        for fqdn in (radius1_fqdn + u':12345', radius1_fqdn)
    ] + [
        dict(
            desc='Set server string of %s to %s (invalid)' % (radius1, fqdn),
            command=('radiusproxy_mod', [radius1],
                     dict(ipatokenradiusserver=fqdn)),
            expected=errors.ValidationError(name='ipatokenradiusserver',
                                            error=error),
        )
        for fqdn, error in (
            (radius1_fqdn + u':0x5a', 'invalid port number'),
            (radius1_fqdn + u':1:2:3',
             "only letters, numbers, '_', '-' are allowed. DNS label may not "
             "start or end with '-'"),
            (u'bogus', 'not fully qualified'),
        )
    ] + [

        dict(
            desc='Try to unset server string of %s' % radius1,
            command=('radiusproxy_mod', [radius1],
                     dict(ipatokenradiusserver=None)),
            expected=errors.RequirementError(name='server'),
        ),

        dict(
            desc='Set userattr of %s to %s (valid)' % (radius1, u'cn'),
            command=('radiusproxy_mod', [radius1],
                     dict(ipatokenusermapattribute=u'cn')),
            expected=dict(
                value=radius1,
                summary=u'Modified RADIUS proxy server "%s"' % radius1,
                result=dict(
                    cn=[radius1],
                    ipatokenradiusserver=[radius1_fqdn],
                    ipatokenusermapattribute=[u'cn'],
                ),
            ),
        ),

        dict(
            desc='Set userattr of %s to %s (invalid)' % (radius1, u'$%^&*'),
            command=('radiusproxy_mod', [radius1],
                     dict(ipatokenusermapattribute=u'$%^&*')),
            expected=errors.ValidationError(name='ipatokenusermapattribute',
                                            error=u'invalid attribute name'),
        ),

        dict(
            desc='Unset userattr of %s' % radius1,
            command=('radiusproxy_mod', [radius1],
                     dict(ipatokenusermapattribute=None)),
            expected=dict(
                value=radius1,
                summary=u'Modified RADIUS proxy server "%s"' % radius1,
                result=dict(
                    cn=[radius1],
                    ipatokenradiusserver=[radius1_fqdn],
                ),
            ),
        ),

        dict(
            desc='Set desc of %s' % radius1,
            command=('radiusproxy_mod', [radius1],
                     dict(description=u'a virtual radius server')),
            expected=dict(
                value=radius1,
                summary=u'Modified RADIUS proxy server "%s"' % radius1,
                result=dict(
                    cn=[radius1],
                    ipatokenradiusserver=[radius1_fqdn],
                    description=[u'a virtual radius server'],
                ),
            ),
        ),

        dict(
            desc='Unset desc of %s' % radius1,
            command=('radiusproxy_mod', [radius1],
                     dict(description=None)),
            expected=dict(
                value=radius1,
                summary=u'Modified RADIUS proxy server "%s"' % radius1,
                result=dict(
                    cn=[radius1],
                    ipatokenradiusserver=[radius1_fqdn],
                ),
            ),
        ),

        dict(
            desc='Create "%s"' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=get_user_result(user1, u'Test', u'User1', 'add'),
            ),
        ),


        dict(
            desc='Set radiusconfiglink of %r' % user1,
            command=('user_mod', [user1],
                dict(ipatokenradiusconfiglink=radius1,)),
            expected=dict(
                result=get_user_result(user1, u'Test', u'User1', 'mod',
                                       ipatokenradiusconfiglink=[radius1]),
                value=user1,
                summary='Modified user "%s"' % user1,
            ),
        ),

        dict(
            desc='Retrieve %r to verify %s is output' % (radius1, user1),
            command=('radiusproxy_show', [radius1], {}),
            expected=dict(
                value=radius1,
                summary=None,
                result=dict(
                    cn=[radius1],
                    dn=radius1_dn,
                    ipatokenradiusserver=[radius1_fqdn],
                ),
            ),
        ),

        dict(
            desc='Retrieve %r to verify %s is output' % (user1, radius1),
            command=('user_show', [user1], {}),
            expected=dict(
                value=user1,
                summary=None,
                result=get_user_result(user1, u'Test', u'User1', 'show',
                                       ipatokenradiusconfiglink=[radius1]),
            ),
        ),

        dict(
            desc='Delete %r' % radius1,
            command=('radiusproxy_del', [radius1], {}),
            expected=dict(
                value=[radius1],
                summary=u'Deleted RADIUS proxy server "%s"' % radius1,
                result=dict(failed=[]),
            ),
        ),

        dict(
            desc='Retrieve %s to verify link is deleted' % user1,
            command=('user_show', [user1], {}),
            expected=dict(
                value=user1,
                summary=None,
                result=get_user_result(user1, u'Test', u'User1', 'show'),
            ),
        ),

    ]
