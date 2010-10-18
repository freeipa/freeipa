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
Test the `ipalib.plugins.host` module.
"""

from ipalib import api, errors
from tests.test_xmlrpc.xmlrpc_test import Declarative, fuzzy_uuid
from tests.test_xmlrpc import objectclasses


fqdn1 = u'testhost1.%s' % api.env.domain
short1 = u'testhost1'
dn1 = u'fqdn=%s,cn=computers,cn=accounts,%s' % (fqdn1, api.env.basedn)
service1 = u'dns/%s@%s' % (fqdn1, api.env.realm)
service1dn = u'krbprincipalname=%s,cn=services,cn=accounts,%s' % (service1.lower(), api.env.basedn)
fqdn2 = u'shouldnotexist.%s' % api.env.domain
dn2 = u'fqdn=%s,cn=computers,cn=accounts,%s' % (fqdn2, api.env.basedn)


class test_host(Declarative):

    cleanup_commands = [
        ('host_del', [fqdn1], {}),
        ('host_del', [fqdn2], {}),
        ('service_del', [service1], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent %r' % fqdn1,
            command=('host_show', [fqdn1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % fqdn1,
            command=('host_mod', [fqdn1], dict(description=u'Nope')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to delete non-existent %r' % fqdn1,
            command=('host_del', [fqdn1], {}),
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
                    dn=dn1,
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
            desc='Try to create duplicate %r' % fqdn1,
            command=('host_add', [fqdn1],
                dict(
                    description=u'Test host 1',
                    localityname=u'Undisclosed location 1',
                    force=True,
                ),
            ),
            expected=errors.DuplicateEntry(),
        ),


        dict(
            desc='Retrieve %r' % fqdn1,
            command=('host_show', [fqdn1], {}),
            expected=dict(
                value=fqdn1,
                summary=None,
                result=dict(
                    dn=dn1,
                    fqdn=[fqdn1],
                    description=[u'Test host 1'],
                    l=[u'Undisclosed location 1'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                    has_keytab=False
                ),
            ),
        ),


        dict(
            desc='Retrieve %r with all=True' % fqdn1,
            command=('host_show', [fqdn1], dict(all=True)),
            expected=dict(
                value=fqdn1,
                summary=None,
                result=dict(
                    dn=dn1,
                    cn=[fqdn1],
                    fqdn=[fqdn1],
                    description=[u'Test host 1'],
                    # FIXME: Why is 'localalityname' returned as 'l' with --all?
                    # It is intuitive for --all to return additional attributes,
                    # but not to return existing attributes under different
                    # names.
                    l=[u'Undisclosed location 1'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                    serverhostname=[u'testhost1'],
                    objectclass=objectclasses.host,
                    managedby=[dn1],
                    ipauniqueid=[fuzzy_uuid],
                    has_keytab=False
                ),
            ),
        ),


        dict(
            desc='Search for %r' % fqdn1,
            command=('host_find', [fqdn1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 host matched',
                result=[
                    dict(
                        dn=dn1,
                        fqdn=[fqdn1],
                        description=[u'Test host 1'],
                        l=[u'Undisclosed location 1'],
                        krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                    ),
                ],
            ),
        ),


        dict(
            desc='Search for %r with all=True' % fqdn1,
            command=('host_find', [fqdn1], dict(all=True)),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 host matched',
                result=[
                    dict(
                        dn=dn1,
                        cn=[fqdn1],
                        fqdn=[fqdn1],
                        description=[u'Test host 1'],
                        # FIXME: Why is 'localalityname' returned as 'l' with --all?
                        # It is intuitive for --all to return additional attributes,
                        # but not to return existing attributes under different
                        # names.
                        l=[u'Undisclosed location 1'],
                        krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                        serverhostname=[u'testhost1'],
                        objectclass=objectclasses.host,
                        managedby=[dn1],
                        ipauniqueid=[fuzzy_uuid],
                    ),
                ],
            ),
        ),


        dict(
            desc='Update %r' % fqdn1,
            command=('host_mod', [fqdn1], dict(description=u'Updated host 1')),
            expected=dict(
                value=fqdn1,
                summary=u'Modified host "%s"' % fqdn1,
                result=dict(
                    description=[u'Updated host 1'],
                    fqdn=[fqdn1],
                    l=[u'Undisclosed location 1'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                ),
            ),
        ),


        dict(
            desc='Retrieve %r to verify update' % fqdn1,
            command=('host_show', [fqdn1], {}),
            expected=dict(
                value=fqdn1,
                summary=None,
                result=dict(
                    dn=dn1,
                    fqdn=[fqdn1],
                    description=[u'Updated host 1'],
                    l=[u'Undisclosed location 1'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                    has_keytab=False
                ),
            ),
        ),


        dict(
            desc='Try to rename %r' % fqdn1,
            command=('host_mod', [fqdn1], dict(setattr=u'fqdn=changed')),
            expected=errors.NotAllowedOnRDN()
        ),


        dict(
            desc='Delete %r' % fqdn1,
            command=('host_del', [fqdn1], {}),
            expected=dict(
                value=fqdn1,
                summary=u'Deleted host "%s"' % fqdn1,
                result=True,
            ),
        ),


        dict(
            desc='Try to retrieve non-existent %r' % fqdn1,
            command=('host_show', [fqdn1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % fqdn1,
            command=('host_mod', [fqdn1], dict(description=u'Nope')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to delete non-existent %r' % fqdn1,
            command=('host_del', [fqdn1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),

        # Test deletion using a non-fully-qualified hostname. Services
        # associated with this host should also be removed.
        dict(
            desc='Re-create %r' % fqdn1,
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
                    dn=dn1,
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
            desc='Add a service to host %r' % fqdn1,
            command=('service_add', [service1], {'force': True}),
            expected=dict(
                value=service1,
                summary=u'Added service "%s"' % service1,
                result=dict(
                    dn=service1dn,
                    krbprincipalname=[service1],
                    objectclass=objectclasses.service,
                    managedby_host=[fqdn1],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),

        dict(
            desc='Delete using host name %r' % short1,
            command=('host_del', [short1], {}),
            expected=dict(
                value=short1,
                summary=u'Deleted host "%s"' % short1,
                result=True,
            ),
        ),

        dict(
            desc='Search for services for %r' % fqdn1,
            command=('service_find', [fqdn1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 services matched',
                result=[
                ],
            ),
        ),


        dict(
            desc='Try to add host not in DNS %r without force' % fqdn2,
            command=('host_add', [fqdn2], {}),
            expected=errors.DNSNotARecordError(reason='Host does not have corresponding DNS A record'),
        ),


        dict(
            desc='Try to add host not in DNS %r with force' % fqdn2,
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
                    dn=dn2,
                    fqdn=[fqdn2],
                    description=[u'Test host 2'],
                    l=[u'Undisclosed location 2'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn2, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),

    ]
