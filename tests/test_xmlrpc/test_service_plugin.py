# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
Test the `ipalib/plugins/service.py` module.
"""

from ipalib import api, errors
from tests.test_xmlrpc.xmlrpc_test import Declarative, fuzzy_uuid
from tests.test_xmlrpc import objectclasses


fqdn1 = u'testhost1.%s' % api.env.domain
fqdn2 = u'testhost2.%s' % api.env.domain
service1 = u'HTTP/%s@%s' % (fqdn1, api.env.realm)
hostprincipal1 = u'host/%s@%s'  % (fqdn1, api.env.realm)
service1dn = u'krbprincipalname=%s,cn=services,cn=accounts,%s' % (service1.lower(), api.env.basedn)
host1dn = u'fqdn=%s,cn=computers,cn=accounts,%s' % (fqdn1, api.env.basedn)
host2dn = u'fqdn=%s,cn=computers,cn=accounts,%s' % (fqdn2, api.env.basedn)


class test_host(Declarative):

    cleanup_commands = [
        ('host_del', [fqdn1], {}),
        ('host_del', [fqdn2], {}),
        ('service_del', [service1], {}),
    ]

    tests = [
        dict(
            desc='Try to retrieve non-existent %r' % service1,
            command=('service_show', [service1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % service1,
            command=('service_mod', [service1], dict(usercertificate='Nope')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to delete non-existent %r' % service1,
            command=('service_del', [service1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Create %r' % fqdn1,
            command=('host_add', [fqdn1],
                dict(
                    description=u'Test host 1',
                    l=u'Undisclosed location 1',
                    force=True,
                ),
            ),
            expected=dict(
                value=fqdn1,
                summary=u'Added host "%s"' % fqdn1,
                result=dict(
                    dn=host1dn,
                    fqdn=[fqdn1],
                    description=[u'Test host 1'],
                    l=[u'Undisclosed location 1'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),


        dict(
            desc='Create %r' % fqdn2,
            command=('host_add', [fqdn2],
                dict(
                    description=u'Test host 2',
                    l=u'Undisclosed location 2',
                    force=True,
                ),
            ),
            expected=dict(
                value=fqdn2,
                summary=u'Added host "%s"' % fqdn2,
                result=dict(
                    dn=host2dn,
                    fqdn=[fqdn2],
                    description=[u'Test host 2'],
                    l=[u'Undisclosed location 2'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn2, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),


        dict(
            desc='Create %r' % service1,
            command=('service_add', [service1],
                dict(
                    force=True,
                ),
            ),
            expected=dict(
                value=service1,
                summary=u'Added service "%s"' % service1,
                result=dict(
                    dn=service1dn,
                    krbprincipalname=[service1],
                    objectclass=objectclasses.service,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[fqdn1],
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % service1,
            command=('service_add', [service1],
                dict(
                    force=True,
                ),
            ),
            expected=errors.DuplicateEntry(),
        ),


        dict(
            desc='Retrieve %r' % service1,
            command=('service_show', [service1], {}),
            expected=dict(
                value=service1,
                summary=None,
                result=dict(
                    dn=service1dn,
                    krbprincipalname=[service1],
                    has_keytab=False,
                    managedby_host=[fqdn1],
                ),
            ),
        ),


        dict(
            desc='Retrieve %r with all=True' % service1,
            command=('service_show', [service1], dict(all=True)),
            expected=dict(
                value=service1,
                summary=None,
                result=dict(
                    dn=service1dn,
                    krbprincipalname=[service1],
                    objectclass=objectclasses.service,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[fqdn1],
                    has_keytab=False
                ),
            ),
        ),


        dict(
            desc='Search for %r' % service1,
            command=('service_find', [service1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 service matched',
                result=[
                    dict(
                        dn=service1dn,
                        krbprincipalname=[service1],
                        managedby_host=[fqdn1],
                        has_keytab=False,
                    ),
                ],
            ),
        ),


        dict(
            desc='Search for %r with all=True' % service1,
            command=('service_find', [service1], dict(all=True)),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 service matched',
                result=[
                    dict(
                        dn=service1dn,
                        krbprincipalname=[service1],
                        objectclass=objectclasses.service,
                        ipauniqueid=[fuzzy_uuid],
                        has_keytab=False,
                        managedby_host=[fqdn1],
                    ),
                ],
            ),
        ),


        dict(
            desc='Update %r' % service1,
            command=('service_mod', [service1], dict(usercertificate='aGVsbG8=')),
            expected=dict(
                value=service1,
                summary=u'Modified service "%s"' % service1,
                result=dict(
                    usercertificate=['hello'],
                    krbprincipalname=[service1],
                    managedby_host=[fqdn1],
                ),
            ),
        ),


        dict(
            desc='Retrieve %r to verify update' % service1,
            command=('service_show', [service1], {}),
            expected=dict(
                value=service1,
                summary=None,
                result=dict(
                    dn=service1dn,
                    usercertificate=['hello'],
                    krbprincipalname=[service1],
                    has_keytab=False,
                    managedby_host=[fqdn1],
                ),
            ),
        ),


        dict(
            desc='Delete %r' % service1,
            command=('service_del', [service1], {}),
            expected=dict(
                value=service1,
                summary=u'Deleted service "%s"' % service1,
                result=True,
            ),
        ),


        dict(
            desc='Try to retrieve non-existent %r' % service1,
            command=('service_show', [service1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % service1,
            command=('service_mod', [service1], dict(usercertificate='Nope')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to delete non-existent %r' % service1,
            command=('service_del', [service1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Create service with malformed principal "foo"',
            command=('service_add', [u'foo'], {}),
            expected=errors.MalformedServicePrincipal(reason='missing service')
        ),


        dict(
            desc='Create service with bad realm "HTTP/foo@FOO.NET"',
            command=('service_add', [u'HTTP/foo@FOO.NET'], {}),
            expected=errors.RealmMismatch(),
        ),


        dict(
            desc='Create a host service %r' % hostprincipal1,
            command=('service_add', [hostprincipal1], {}),
            expected=errors.HostService()
        ),

    ]
