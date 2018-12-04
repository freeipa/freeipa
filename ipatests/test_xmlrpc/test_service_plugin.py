# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
"""
Test the `ipaserver/plugins/service.py` module.
"""

from ipalib import api, errors
from ipatests.test_xmlrpc.xmlrpc_test import Declarative, fuzzy_uuid, fuzzy_hash
from ipatests.test_xmlrpc.xmlrpc_test import fuzzy_digits, fuzzy_date, fuzzy_issuer
from ipatests.test_xmlrpc.xmlrpc_test import fuzzy_hex, XMLRPC_test
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.testcert import get_testcert, subject_base
from ipatests.test_xmlrpc.test_user_plugin import get_user_result, get_group_dn

from ipatests.test_xmlrpc.tracker.service_plugin import ServiceTracker
from ipatests.test_xmlrpc.tracker.host_plugin import HostTracker
from ipatests.util import change_principal, host_keytab

import base64
from ipapython.dn import DN
import pytest

fqdn1 = u'testhost1.%s' % api.env.domain
fqdn2 = u'testhost2.%s' % api.env.domain
fqdn3 = u'TestHost3.%s' % api.env.domain
service1_no_realm = u'HTTP/%s' % fqdn1
service1 = u'%s@%s' % (service1_no_realm, api.env.realm)
badservice = u'badservice@%s' % api.env.realm  # no hostname
hostprincipal1 = u'host/%s@%s'  % (fqdn1, api.env.realm)
service1dn = DN(('krbprincipalname',service1),('cn','services'),('cn','accounts'),api.env.basedn)
host1dn = DN(('fqdn',fqdn1),('cn','computers'),('cn','accounts'),api.env.basedn)
host2dn = DN(('fqdn',fqdn2),('cn','computers'),('cn','accounts'),api.env.basedn)
host3dn = DN(('fqdn',fqdn3),('cn','computers'),('cn','accounts'),api.env.basedn)
d_service_no_realm = u'some/at.some.arbitrary.name'
d_service = u'%s@%s' % (d_service_no_realm, api.env.realm)
d_servicedn = DN(('krbprincipalname', d_service),
                 ('cn', 'services'), ('cn', 'accounts'),
                 api.env.basedn)

role1 = u'Test Role'
role1_dn = DN(('cn', role1), api.env.container_rolegroup, api.env.basedn)

servercert = get_testcert(DN(('CN', api.env.host), subject_base()),
                          'unittest/%s@%s' % (api.env.host, api.env.realm))
randomissuercert = (
    "MIICbzCCAdigAwIBAgICA/4wDQYJKoZIhvcNAQEFBQAwKTEnMCUGA1UEAxMeSVBBIFRlc3Q"
    "gQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTEwMDgwOTE1MDIyN1oXDTIwMDgwOTE1MDIyN1"
    "owKTEMMAoGA1UEChMDSVBBMRkwFwYDVQQDExBwdW1hLmdyZXlvYWsuY29tMIIBIjANBgkqh"
    "kiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwYbfEOQPgGenPn9vt1JFKvWm/Je3y2tawGWA3LXD"
    "uqfFJyYtZ8ib3TcBUOnLk9WK5g2qCwHaNlei7bj8ggIfr5hegAVe10cun+wYErjnYo7hsHY"
    "d+57VZezeipWrXu+7NoNd4+c4A5lk4A/xJay9j3bYx2oOM8BEox4xWYoWge1ljPrc5JK46f"
    "0X7AGW4F2VhnKPnf8rwSuzI1U8VGjutyM9TWNy3m9KMWeScjyG/ggIpOjUDMV7HkJL0Di61"
    "lznR9jXubpiEC7gWGbTp84eGl/Nn9bgK1AwHfJ2lHwfoY4uiL7ge1gyP6EvuUlHoBzdb7pe"
    "kiX28iePjW3iEG9IawIDAQABoyIwIDARBglghkgBhvhCAQEEBAMCBkAwCwYDVR0PBAQDAgU"
    "gMA0GCSqGSIb3DQEBBQUAA4GBACRESLemRV9BPxfEgbALuxH5oE8jQm8WZ3pm2pALbpDlAd"
    "9wQc3yVf6RtkfVthyDnM18bg7IhxKpd77/p3H8eCnS8w5MLVRda6ktUC6tGhFTS4QKAf0Wy"
    "DGTcIgkXbeDw0OPAoNHivoXbIXIIRxlw/XgaSaMzJQDBG8iROsN4kCv")
randomissuer = DN(('CN', 'puma.greyoak.com'), 'O=IPA')

user1 = u'tuser1'
user2 = u'tuser2'
group1 = u'group1'
group1_dn = get_group_dn(group1)
group2 = u'group2'
group2_dn = get_group_dn(group2)
hostgroup1 = u'testhostgroup1'
hostgroup1_dn = DN(('cn',hostgroup1),('cn','hostgroups'),('cn','accounts'),
                    api.env.basedn)


@pytest.mark.tier1
class test_service(Declarative):

    cleanup_commands = [
        ('host_del', [fqdn1], {}),
        ('host_del', [fqdn2], {}),
        ('host_del', [fqdn3], {}),
        ('service_del', [service1], {}),
        ('service_del', [d_service], {}),
    ]

    tests = [
        dict(
            desc='Try to retrieve non-existent %r' % service1,
            command=('service_show', [service1], {}),
            expected=errors.NotFound(
                reason=u'%s: service not found' % service1),
        ),


        dict(
            desc='Try to update non-existent %r' % service1,
            command=('service_mod', [service1], dict(usercertificate=servercert)),
            expected=errors.NotFound(
                reason=u'%s: service not found' % service1),
        ),


        dict(
            desc='Try to delete non-existent %r' % service1,
            command=('service_del', [service1], {}),
            expected=errors.NotFound(
                reason=u'%s: service not found' % service1),
        ),

        dict(
            desc='Try to delete service without hostname %r' % badservice,
            command=('service_del', [badservice], {}),
            expected=errors.NotFound(
                reason=u'%s: service not found' % badservice),
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
                    krbcanonicalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[u'%s' % fqdn1],
                    has_keytab=False,
                    has_password=False,
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
                    krbcanonicalname=[u'host/%s@%s' % (fqdn2, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[u'%s' % fqdn2],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),


        dict(
            desc='Create %r' % fqdn3,
            command=('host_add', [fqdn3],
                dict(
                    description=u'Test host 3',
                    l=u'Undisclosed location 3',
                    force=True,
                ),
            ),
            expected=dict(
                value=fqdn3.lower(),
                summary=u'Added host "%s"' % fqdn3.lower(),
                result=dict(
                    dn=host3dn,
                    fqdn=[fqdn3.lower()],
                    description=[u'Test host 3'],
                    l=[u'Undisclosed location 3'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn3.lower(), api.env.realm)],
                    krbcanonicalname=[u'host/%s@%s' % (
                        fqdn3.lower(), api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[u'%s' % fqdn3.lower()],
                    has_keytab=False,
                    has_password=False,
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
                    krbcanonicalname=[service1],
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
            expected=errors.DuplicateEntry(
                message=u'service with name "%s" already exists' % service1),
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
                    krbcanonicalname=[service1],
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
                    ipakrbprincipalalias=[service1],
                    krbcanonicalname=[service1],
                    objectclass=objectclasses.service,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[fqdn1],
                    has_keytab=False,
                    ipakrbrequirespreauth=True,
                    ipakrbokasdelegate=False,
                    ipakrboktoauthasdelegate=False,
                    krbpwdpolicyreference=[DN(
                        u'cn=Default Service Password Policy',
                        api.env.container_service,
                        api.env.basedn,
                    )],
                ),
            ),
        ),

        dict(
            desc='Allow admin to create keytab for %r' % service1,
            command=('service_allow_create_keytab', [service1],
                     dict(user=u'admin'),
                     ),
            expected=dict(
                completed=1,
                failed=dict(
                    ipaallowedtoperform_write_keys=dict(
                        group=[],
                        host=[],
                        hostgroup=[],
                        user=[]
                    )
                ),
                result=dict(
                    dn=service1dn,
                    ipaallowedtoperform_write_keys_user=[u'admin'],
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                ),
            ),
        ),

        dict(
            desc='Retrieve %r with all=True and keytab allowed' % service1,
            command=('service_show', [service1], dict(all=True)),
            expected=dict(
                value=service1,
                summary=None,
                result=dict(
                    dn=service1dn,
                    ipaallowedtoperform_write_keys_user=[u'admin'],
                    krbprincipalname=[service1],
                    ipakrbprincipalalias=[service1],
                    krbcanonicalname=[service1],
                    objectclass=objectclasses.service + [
                        u'ipaallowedoperations'
                    ],
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[fqdn1],
                    has_keytab=False,
                    ipakrbrequirespreauth=True,
                    ipakrbokasdelegate=False,
                    ipakrboktoauthasdelegate=False,
                    krbpwdpolicyreference=[DN(
                        u'cn=Default Service Password Policy',
                        api.env.container_service,
                        api.env.basedn,
                    )],
                ),
            ),
        ),

        dict(
            desc='Search for %r with members' % service1,
            command=('service_find', [service1], {'no_members': False}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 service matched',
                result=[
                    dict(
                        dn=service1dn,
                        ipaallowedtoperform_write_keys_user=[u'admin'],
                        krbprincipalname=[service1],
                        krbcanonicalname=[service1],
                        managedby_host=[fqdn1],
                        has_keytab=False,
                    ),
                ],
            ),
        ),

        dict(
            desc='Disallow admin to create keytab for %r' % service1,
            command=(
                'service_disallow_create_keytab', [service1],
                dict(user=u'admin'),
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    ipaallowedtoperform_write_keys=dict(
                        group=[],
                        host=[],
                        hostgroup=[],
                        user=[]
                    )
                ),
                result=dict(
                    dn=service1dn,
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
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
                        krbcanonicalname=[service1],
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
                        ipakrbprincipalalias=[service1],
                        krbcanonicalname=[service1],
                        objectclass=objectclasses.service + [
                            u'ipaallowedoperations'
                        ],
                        ipauniqueid=[fuzzy_uuid],
                        has_keytab=False,
                        managedby_host=[fqdn1],
                        ipakrbrequirespreauth=True,
                        ipakrbokasdelegate=False,
                        ipakrboktoauthasdelegate=False,
                        krbpwdpolicyreference=[DN(
                            u'cn=Default Service Password Policy',
                            api.env.container_service,
                            api.env.basedn,
                        )],
                    ),
                ],
            ),
        ),


        dict(
            desc='Add non-existent host to %r' % service1,
            command=('service_add_host', [service1], dict(host=u'notfound')),
            expected=dict(
                failed=dict(managedby=dict(host=[(u'notfound', u'no such entry')])),
                completed=0,
                result=dict(
                    dn=service1dn,
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                ),
            ),
        ),


        dict(
            desc='Remove non-existent host from %r' % service1,
            command=('service_remove_host', [service1], dict(host=u'notfound')),
            expected=dict(
                failed=dict(managedby=dict(host=[(u'notfound', u'This entry is not a member')])),
                completed=0,
                result=dict(
                    dn=service1dn,
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                ),
            ),
        ),


        dict(
            desc='Add host to %r' % service1,
            command=('service_add_host', [service1], dict(host=fqdn2)),
            expected=dict(
                failed=dict(managedby=dict(host=[])),
                completed=1,
                result=dict(
                    dn=service1dn,
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1, fqdn2],
                ),
            ),
        ),


        dict(
            desc='Remove host from %r' % service1,
            command=('service_remove_host', [service1], dict(host=fqdn2)),
            expected=dict(
                failed=dict(managedby=dict(host=[])),
                completed=1,
                result=dict(
                    dn=service1dn,
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                ),
            ),
        ),


        dict(
            desc='Add mixed-case host to %r' % service1,
            command=('service_add_host', [service1], dict(host=fqdn3)),
            expected=dict(
                failed=dict(managedby=dict(host=[])),
                completed=1,
                result=dict(
                    dn=service1dn,
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1, fqdn3.lower()],
                ),
            ),
        ),


        dict(
            desc='Remove mixed-case host from %r' % service1,
            command=('service_remove_host', [service1], dict(host=fqdn3)),
            expected=dict(
                failed=dict(managedby=dict(host=[])),
                completed=1,
                result=dict(
                    dn=service1dn,
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                ),
            ),
        ),


        dict(
            desc='Update %r with a random issuer certificate' % service1,
            command=(
                'service_mod',
                [service1],
                dict(usercertificate=base64.b64decode(randomissuercert))),
            expected=dict(
                value=service1,
                summary=u'Modified service "%s"' % service1,
                result=dict(
                    usercertificate=[base64.b64decode(randomissuercert)],
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                    valid_not_before=fuzzy_date,
                    valid_not_after=fuzzy_date,
                    subject=randomissuer,
                    serial_number=fuzzy_digits,
                    serial_number_hex=fuzzy_hex,
                    sha1_fingerprint=fuzzy_hash,
                    sha256_fingerprint=fuzzy_hash,
                    issuer=fuzzy_issuer,
                ),
            ),
        ),

        dict(
            desc='Update %r' % service1,
            command=('service_mod', [service1], dict(usercertificate=servercert)),
            expected=dict(
                value=service1,
                summary=u'Modified service "%s"' % service1,
                result=dict(
                    usercertificate=[base64.b64decode(servercert)],
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                    valid_not_before=fuzzy_date,
                    valid_not_after=fuzzy_date,
                    subject=DN(('CN', api.env.host), subject_base()),
                    serial_number=fuzzy_digits,
                    serial_number_hex=fuzzy_hex,
                    sha1_fingerprint=fuzzy_hash,
                    sha256_fingerprint=fuzzy_hash,
                    issuer=fuzzy_issuer,
                ),
            ),
        ),


        dict(
            desc='Try to update %r with invalid ipakrbauthz data '
                 'combination' % service1,
            command=('service_mod', [service1],
                dict(ipakrbauthzdata=[u'MS-PAC', u'NONE'])),
            expected=errors.ValidationError(name='ipakrbauthzdata',
                error=u'NONE value cannot be combined with other PAC types')
        ),


        dict(
            desc='Update %r with valid ipakrbauthz data '
                 'combination' % service1,
            command=('service_mod', [service1],
                dict(ipakrbauthzdata=[u'MS-PAC'])),
            expected=dict(
                value=service1,
                summary=u'Modified service "%s"' % service1,
                result=dict(
                    usercertificate=[base64.b64decode(servercert)],
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                    ipakrbauthzdata=[u'MS-PAC'],
                    valid_not_before=fuzzy_date,
                    valid_not_after=fuzzy_date,
                    subject=DN(('CN', api.env.host), subject_base()),
                    serial_number=fuzzy_digits,
                    serial_number_hex=fuzzy_hex,
                    sha1_fingerprint=fuzzy_hash,
                    sha256_fingerprint=fuzzy_hash,
                    issuer=fuzzy_issuer,
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
                    usercertificate=[base64.b64decode(servercert)],
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    has_keytab=False,
                    managedby_host=[fqdn1],
                    ipakrbauthzdata=[u'MS-PAC'],
                    # These values come from the servercert that is in this
                    # test case.
                    valid_not_before=fuzzy_date,
                    valid_not_after=fuzzy_date,
                    subject=DN(('CN', api.env.host), subject_base()),
                    serial_number=fuzzy_digits,
                    serial_number_hex=fuzzy_hex,
                    sha1_fingerprint=fuzzy_hash,
                    sha256_fingerprint=fuzzy_hash,
                    issuer=fuzzy_issuer,
                ),
            ),
        ),


        dict(
            desc='Enable %r OK_AS_DELEGATE Kerberos ticket flag' % service1,
            command=('service_mod', [service1], dict(ipakrbokasdelegate=True)),
            expected=dict(
                value=service1,
                summary=u'Modified service "%s"' % service1,
                result=dict(
                    usercertificate=[base64.b64decode(servercert)],
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                    ipakrbauthzdata=[u'MS-PAC'],
                    valid_not_before=fuzzy_date,
                    valid_not_after=fuzzy_date,
                    subject=DN(('CN', api.env.host), subject_base()),
                    serial_number=fuzzy_digits,
                    serial_number_hex=fuzzy_hex,
                    sha1_fingerprint=fuzzy_hash,
                    sha256_fingerprint=fuzzy_hash,
                    issuer=fuzzy_issuer,
                    krbticketflags=[u'1048704'],
                    ipakrbokasdelegate=True,
                ),
            ),
        ),


        dict(
            desc='Update %r Kerberos ticket flags with setattr' % service1,
            command=('service_mod', [service1],
                     dict(setattr=[u'krbTicketFlags=1048577'])),
            expected=dict(
                value=service1,
                summary=u'Modified service "%s"' % service1,
                result=dict(
                    usercertificate=[base64.b64decode(servercert)],
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                    ipakrbauthzdata=[u'MS-PAC'],
                    valid_not_before=fuzzy_date,
                    valid_not_after=fuzzy_date,
                    subject=DN(('CN', api.env.host), subject_base()),
                    serial_number=fuzzy_digits,
                    serial_number_hex=fuzzy_hex,
                    sha1_fingerprint=fuzzy_hash,
                    sha256_fingerprint=fuzzy_hash,
                    issuer=fuzzy_issuer,
                    krbticketflags=[u'1048577'],
                ),
            ),
        ),


        dict(
            desc='Disable %r OK_AS_DELEGATE Kerberos ticket flag' % service1,
            command=('service_mod', [service1], dict(ipakrbokasdelegate=False)),
            expected=dict(
                value=service1,
                summary=u'Modified service "%s"' % service1,
                result=dict(
                    usercertificate=[base64.b64decode(servercert)],
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                    ipakrbauthzdata=[u'MS-PAC'],
                    valid_not_before=fuzzy_date,
                    valid_not_after=fuzzy_date,
                    subject=DN(('CN', api.env.host), subject_base()),
                    serial_number=fuzzy_digits,
                    serial_number_hex=fuzzy_hex,
                    sha1_fingerprint=fuzzy_hash,
                    sha256_fingerprint=fuzzy_hash,
                    issuer=fuzzy_issuer,
                    krbticketflags=[u'1'],
                    ipakrbokasdelegate=False,
                ),
            ),
        ),


        dict(
            desc='Delete %r' % service1,
            command=('service_del', [service1], {}),
            expected=dict(
                value=[service1],
                summary=u'Deleted service "%s"' % service1,
                result=dict(failed=[]),
            ),
        ),


        dict(
            desc='Try to retrieve non-existent %r' % service1,
            command=('service_show', [service1], {}),
            expected=errors.NotFound(
                reason=u'%s: service not found' % service1),
        ),


        dict(
            desc='Try to update non-existent %r' % service1,
            command=('service_mod', [service1], dict(usercertificate=servercert)),
            expected=errors.NotFound(
                reason=u'%s: service not found' % service1),
        ),

        dict(
            desc='Try to update service without hostname %r' % badservice,
            command=(
                'service_mod',
                [badservice],
                dict(usercertificate=servercert)
            ),
            expected=errors.NotFound(
                reason=u'%s: service not found' % badservice),
        ),

        dict(
            desc='Try to delete non-existent %r' % service1,
            command=('service_del', [service1], {}),
            expected=errors.NotFound(
                reason=u'%s: service not found' % service1),
        ),


        dict(
            desc='Create service with malformed principal "foo"',
            command=('service_add', [u'foo'], {}),
            expected=errors.ValidationError(
                name='canonical_principal',
                error='Service principal is required')
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


        # These tests will only succeed when running against lite-server.py
        # on same box as IPA install.
        dict(
            desc='Delete the current host (master?) %s HTTP service, should be caught' % api.env.host,
            command=('service_del', ['HTTP/%s' % api.env.host], {}),
            expected=errors.ValidationError(name='principal', error='This principal is required by the IPA master'),
        ),


        dict(
            desc='Delete the current host (master?) %s ldap service, should be caught' % api.env.host,
            command=('service_del', ['ldap/%s' % api.env.host], {}),
            expected=errors.ValidationError(name='principal', error='This principal is required by the IPA master'),
        ),


        dict(
            desc='Disable the current host (master?) %s HTTP service, should be caught' % api.env.host,
            command=('service_disable', ['HTTP/%s' % api.env.host], {}),
            expected=errors.ValidationError(name='principal', error='This principal is required by the IPA master'),
        ),


        dict(
            desc='Disable the current host (master?) %s ldap service, should be caught' % api.env.host,
            command=('service_disable', ['ldap/%s' % api.env.host], {}),
            expected=errors.ValidationError(name='principal', error='This principal is required by the IPA master'),
        ),


        # Create a service disconnected from any host
        dict(
            desc='Try to create service %r without any host' % d_service,
            command=('service_add', [d_service_no_realm],
                     dict(force=True, skip_host_check=True),),
            expected=dict(
                value=d_service,
                summary=u'Added service "%s"' % d_service,
                result=dict(
                    dn=d_servicedn,
                    krbprincipalname=[d_service],
                    krbcanonicalname=[d_service],
                    objectclass=objectclasses.service,
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),
    ]


@pytest.mark.tier1
class test_service_in_role(Declarative):
    cleanup_commands = [
        ('host_del', [fqdn1], {}),
        ('service_del', [service1], {}),
        ('role_del', [role1], {}),
    ]

    tests = [
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
                    krbcanonicalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[u'%s' % fqdn1],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),

        dict(
            desc='Create %r' % service1,
            command=('service_add', [service1_no_realm], dict(force=True)),
            expected=dict(
                value=service1,
                summary=u'Added service "%s"' % service1,
                result=dict(
                    dn=service1dn,
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    objectclass=objectclasses.service,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[fqdn1],
                ),
            ),
        ),

        dict(
            desc='Create %r' % role1,
            command=('role_add', [role1], dict(description=u'role desc 1')),
            expected=dict(
                value=role1,
                summary=u'Added role "%s"' % role1,
                result=dict(
                    dn=role1_dn,
                    cn=[role1],
                    description=[u'role desc 1'],
                    objectclass=objectclasses.role,
                ),
            ),
        ),

        dict(
            desc='Add %r to %r' % (service1, role1),
            command=('role_add_member', [role1],
                     dict(service=service1_no_realm)),
            expected=dict(
                failed=dict(
                    member=dict(
                        host=[],
                        group=[],
                        hostgroup=[],
                        service=[],
                        user=[],
                    ),
                ),
                completed=1,
                result=dict(
                    dn=role1_dn,
                    cn=[role1],
                    description=[u'role desc 1'],
                    member_service=[service1],
                ),
            ),
        ),

        dict(
            desc='Verify %r is member of %r' % (service1, role1),
            command=('service_show', [service1_no_realm], {}),
            expected=dict(
                value=service1,
                summary=None,
                result=dict(
                    dn=service1dn,
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                    memberof_role=[role1],
                    has_keytab=False,
                ),
            ),
        ),

        dict(
            desc='Verify %r has member %r' % (role1, service1),
            command=('role_show', [role1], {}),
            expected=dict(
                value=role1,
                summary=None,
                result=dict(
                    dn=role1_dn,
                    cn=[role1],
                    description=[u'role desc 1'],
                    member_service=[service1],
                ),
            ),
        ),
    ]


@pytest.mark.tier1
class test_service_allowed_to(Declarative):
    cleanup_commands = [
        ('user_del', [user1], {}),
        ('user_del', [user2], {}),
        ('service_del', [d_service], {}),
        ('group_del', [group1], {}),
        ('group_del', [group2], {}),
        ('host_del', [fqdn1], {}),
        ('service_del', [service1], {}),
        ('hostgroup_del', [hostgroup1], {}),
    ]

    tests = [
        # prepare entries
        dict(
            desc='Create %r' % user1,
            command=(
                'user_add', [], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=get_user_result(user1, u'Test', u'User1', 'add'),
            ),
        ),
        dict(
            desc='Create %r' % user2,
            command=(
                'user_add', [], dict(givenname=u'Test', sn=u'User2')
            ),
            expected=dict(
                value=user2,
                summary=u'Added user "%s"' % user2,
                result=get_user_result(user2, u'Test', u'User2', 'add'),
            ),
        ),
        dict(
            desc='Create group: %r' % group1,
            command=(
                'group_add', [group1], dict()
            ),
            expected=dict(
                value=group1,
                summary=u'Added group "%s"' % group1,
                result=dict(
                    cn=[group1],
                    objectclass=objectclasses.group + [u'posixgroup'],
                    ipauniqueid=[fuzzy_uuid],
                    gidnumber=[fuzzy_digits],
                    dn=group1_dn
                ),
            ),
        ),
        # Create a service disconnected from any host
        dict(
            desc='Try to create service %r without any host' % d_service,
            command=('service_add', [d_service],
                     dict(force=True, skip_host_check=True)),
            expected=dict(
                value=d_service,
                summary=u'Added service "%s"' % d_service,
                result=dict(
                    dn=d_servicedn,
                    krbprincipalname=[d_service],
                    krbcanonicalname=[d_service],
                    objectclass=objectclasses.service,
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),
        dict(
            desc='Add service %r to a group: %r' % (d_service, group1),
            command=('group_add_member', [group1],
                     dict(service=[d_service_no_realm])),
            expected=dict(
                completed=1,
                failed=dict(member=dict(group=[],
                                        service=[],
                                        user=[])),
                result=dict(
                    cn=[group1],
                    gidnumber=[fuzzy_digits],
                    dn=group1_dn,
                    member_service=[d_service],
                ),
            ),
        ),
        dict(
            desc='Create group: %r' % group2,
            command=(
                'group_add', [group2], dict()
            ),
            expected=dict(
                value=group2,
                summary=u'Added group "%s"' % group2,
                result=dict(
                    cn=[group2],
                    objectclass=objectclasses.group + [u'posixgroup'],
                    ipauniqueid=[fuzzy_uuid],
                    gidnumber=[fuzzy_digits],
                    dn=group2_dn
                ),
            ),
        ),
        dict(
            desc='Create %r' % fqdn1,
            command=(
                'host_add', [fqdn1],
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
                    krbcanonicalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[u'%s' % fqdn1],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),
        dict(
            desc='Create %r' % hostgroup1,
            command=('hostgroup_add', [hostgroup1],
                dict(description=u'Test hostgroup 1')
            ),
            expected=dict(
                value=hostgroup1,
                summary=u'Added hostgroup "testhostgroup1"',
                result=dict(
                    dn=hostgroup1_dn,
                    cn=[hostgroup1],
                    objectclass=objectclasses.hostgroup,
                    description=[u'Test hostgroup 1'],
                    ipauniqueid=[fuzzy_uuid],
                    mepmanagedentry=[DN(('cn',hostgroup1),('cn','ng'),('cn','alt'),
                                        api.env.basedn)],
                ),
            ),
        ),
        dict(
            desc='Create %r' % service1,
            command=('service_add', [service1_no_realm], dict(force=True)),
            expected=dict(
                value=service1,
                summary=u'Added service "%s"' % service1,
                result=dict(
                    dn=service1dn,
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    objectclass=objectclasses.service,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[fqdn1],
                ),
            ),
        ),

        # verify
        dict(
            desc='Allow %r to a retrieve keytab of %r' % (user1, service1),
            command=('service_allow_retrieve_keytab', [service1],
                     dict(user=user1)),
            expected=dict(
                failed=dict(
                    ipaallowedtoperform_read_keys=dict(
                        group=[],
                        host=[],
                        hostgroup=[],
                        user=[],
                    ),
                ),
                completed=1,
                result=dict(
                    dn=service1dn,
                    ipaallowedtoperform_read_keys_user=[user1],
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                ),
            ),
        ),

        dict(
            desc='Duplicate add: user %r' % (user1),
            command=('service_allow_retrieve_keytab', [service1],
                     dict(user=user1)),
            expected=dict(
                failed=dict(
                    ipaallowedtoperform_read_keys=dict(
                        group=[],
                        host=[],
                        hostgroup=[],
                        user=[[user1, u'This entry is already a member']],
                    ),
                ),
                completed=0,
                result=dict(
                    dn=service1dn,
                    ipaallowedtoperform_read_keys_user=[user1],
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                ),
            ),
        ),

        dict(
            desc='Allow %r, %r, %r to a retrieve keytab of %r' % (
                group1, group2, fqdn1, service1),
            command=('service_allow_retrieve_keytab', [service1],
                     dict(group=[group1, group2], host=[fqdn1],
                          hostgroup=[hostgroup1])),
            expected=dict(
                failed=dict(
                    ipaallowedtoperform_read_keys=dict(
                        group=[],
                        host=[],
                        hostgroup=[],
                        user=[],
                    ),
                ),
                completed=4,
                result=dict(
                    dn=service1dn,
                    ipaallowedtoperform_read_keys_user=[user1],
                    ipaallowedtoperform_read_keys_group=[group1, group2],
                    ipaallowedtoperform_read_keys_host=[fqdn1],
                    ipaallowedtoperform_read_keys_hostgroup=[hostgroup1],
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                ),
            ),
        ),

        dict(
            desc='Invalid removal of retrieve keytab %r' % (user2),
            command=('service_disallow_retrieve_keytab', [service1],
                     dict(user=[user2])),
            expected=dict(
                failed=dict(
                    ipaallowedtoperform_read_keys=dict(
                        group=[],
                        host=[],
                        hostgroup=[],
                        user=[[user2, u'This entry is not a member']],
                    ),
                ),
                completed=0,
                result=dict(
                    dn=service1dn,
                    ipaallowedtoperform_read_keys_user=[user1],
                    ipaallowedtoperform_read_keys_group=[group1, group2],
                    ipaallowedtoperform_read_keys_host=[fqdn1],
                    ipaallowedtoperform_read_keys_hostgroup=[hostgroup1],
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                ),
            ),
        ),

        dict(
            desc='Removal of retrieve keytab %r' % (group2),
            command=('service_disallow_retrieve_keytab', [service1],
                     dict(group=[group2])),
            expected=dict(
                failed=dict(
                    ipaallowedtoperform_read_keys=dict(
                        group=[],
                        host=[],
                        hostgroup=[],
                        user=[],
                    ),
                ),
                completed=1,
                result=dict(
                    dn=service1dn,
                    ipaallowedtoperform_read_keys_user=[user1],
                    ipaallowedtoperform_read_keys_group=[group1],
                    ipaallowedtoperform_read_keys_host=[fqdn1],
                    ipaallowedtoperform_read_keys_hostgroup=[hostgroup1],
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                ),
            ),
        ),

        dict(
            desc='Allow %r, %r, %r to a create keytab of %r' % (
                group1, user1, fqdn1, service1),
            command=('service_allow_create_keytab', [service1],
                     dict(group=[group1, group2], user=[user1], host=[fqdn1],
                          hostgroup=[hostgroup1])),
            expected=dict(
                failed=dict(
                    ipaallowedtoperform_write_keys=dict(
                        group=[],
                        host=[],
                        hostgroup=[],
                        user=[],
                    ),
                ),
                completed=5,
                result=dict(
                    dn=service1dn,
                    ipaallowedtoperform_read_keys_user=[user1],
                    ipaallowedtoperform_read_keys_group=[group1],
                    ipaallowedtoperform_read_keys_host=[fqdn1],
                    ipaallowedtoperform_read_keys_hostgroup=[hostgroup1],
                    ipaallowedtoperform_write_keys_user=[user1],
                    ipaallowedtoperform_write_keys_group=[group1, group2],
                    ipaallowedtoperform_write_keys_host=[fqdn1],
                    ipaallowedtoperform_write_keys_hostgroup=[hostgroup1],
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                ),
            ),
        ),

        dict(
            desc='Duplicate add: %r, %r' % (user1, group1),
            command=('service_allow_create_keytab', [service1],
                     dict(group=[group1], user=[user1], host=[fqdn1],
                          hostgroup=[hostgroup1])),
            expected=dict(
                failed=dict(
                    ipaallowedtoperform_write_keys=dict(
                        group=[[group1, u'This entry is already a member']],
                        host=[[fqdn1, u'This entry is already a member']],
                        user=[[user1, u'This entry is already a member']],
                        hostgroup=[[hostgroup1, u'This entry is already a member']],
                    ),
                ),
                completed=0,
                result=dict(
                    dn=service1dn,
                    ipaallowedtoperform_read_keys_user=[user1],
                    ipaallowedtoperform_read_keys_group=[group1],
                    ipaallowedtoperform_read_keys_host=[fqdn1],
                    ipaallowedtoperform_read_keys_hostgroup=[hostgroup1],
                    ipaallowedtoperform_write_keys_user=[user1],
                    ipaallowedtoperform_write_keys_group=[group1, group2],
                    ipaallowedtoperform_write_keys_host=[fqdn1],
                    ipaallowedtoperform_write_keys_hostgroup=[hostgroup1],
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                ),
            ),
        ),

        dict(
            desc='Invalid removal of create keytab %r' % (user2),
            command=('service_disallow_create_keytab', [service1],
                     dict(user=[user2])),
            expected=dict(
                failed=dict(
                    ipaallowedtoperform_write_keys=dict(
                        group=[],
                        host=[],
                        hostgroup=[],
                        user=[[user2, u'This entry is not a member']],
                    ),
                ),
                completed=0,
                result=dict(
                    dn=service1dn,
                    ipaallowedtoperform_read_keys_user=[user1],
                    ipaallowedtoperform_read_keys_group=[group1],
                    ipaallowedtoperform_read_keys_host=[fqdn1],
                    ipaallowedtoperform_read_keys_hostgroup=[hostgroup1],
                    ipaallowedtoperform_write_keys_user=[user1],
                    ipaallowedtoperform_write_keys_group=[group1, group2],
                    ipaallowedtoperform_write_keys_host=[fqdn1],
                    ipaallowedtoperform_write_keys_hostgroup=[hostgroup1],
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                ),
            ),
        ),

        dict(
            desc='Removal of create keytab %r' % (group2),
            command=('service_disallow_create_keytab', [service1],
                     dict(group=[group2])),
            expected=dict(
                failed=dict(
                    ipaallowedtoperform_write_keys=dict(
                        group=[],
                        host=[],
                        hostgroup=[],
                        user=[],
                    ),
                ),
                completed=1,
                result=dict(
                    dn=service1dn,
                    ipaallowedtoperform_read_keys_user=[user1],
                    ipaallowedtoperform_read_keys_group=[group1],
                    ipaallowedtoperform_read_keys_host=[fqdn1],
                    ipaallowedtoperform_read_keys_hostgroup=[hostgroup1],
                    ipaallowedtoperform_write_keys_user=[user1],
                    ipaallowedtoperform_write_keys_group=[group1],
                    ipaallowedtoperform_write_keys_host=[fqdn1],
                    ipaallowedtoperform_write_keys_hostgroup=[hostgroup1],
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                ),
            ),
        ),

        dict(
            desc='Presence of ipaallowedtoperform in show output',
            command=('service_show', [service1_no_realm], {}),
            expected=dict(
                value=service1,
                summary=None,
                result=dict(
                    dn=service1dn,
                    has_keytab=False,
                    ipaallowedtoperform_read_keys_user=[user1],
                    ipaallowedtoperform_read_keys_group=[group1],
                    ipaallowedtoperform_read_keys_host=[fqdn1],
                    ipaallowedtoperform_read_keys_hostgroup=[hostgroup1],
                    ipaallowedtoperform_write_keys_user=[user1],
                    ipaallowedtoperform_write_keys_group=[group1],
                    ipaallowedtoperform_write_keys_host=[fqdn1],
                    ipaallowedtoperform_write_keys_hostgroup=[hostgroup1],
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    managedby_host=[fqdn1],
                ),
            ),
        ),

        dict(
            desc='Presence of ipaallowedtoperform in mod output',
            command=(
                'service_mod', [service1_no_realm],
                dict(ipakrbokasdelegate=True)),
            expected=dict(
                value=service1,
                summary=u'Modified service "%s"' % service1,
                result=dict(
                    ipaallowedtoperform_read_keys_user=[user1],
                    ipaallowedtoperform_read_keys_group=[group1],
                    ipaallowedtoperform_read_keys_host=[fqdn1],
                    ipaallowedtoperform_read_keys_hostgroup=[hostgroup1],
                    ipaallowedtoperform_write_keys_user=[user1],
                    ipaallowedtoperform_write_keys_group=[group1],
                    ipaallowedtoperform_write_keys_host=[fqdn1],
                    ipaallowedtoperform_write_keys_hostgroup=[hostgroup1],
                    ipakrbokasdelegate=True,
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    krbticketflags=[u'1048704'],
                    managedby_host=[fqdn1],
                ),
            ),
        ),
    ]


@pytest.fixture(scope='function')
def indicators_host(request):
    tracker = HostTracker(name=u'testhost1', fqdn=fqdn1)
    return tracker.make_fixture(request)


@pytest.fixture(scope='function')
def indicators_service(request):
    tracker = ServiceTracker(
        name=u'SRV1', host_fqdn=fqdn1, options={
            u'krbprincipalauthind': u'otp'})
    return tracker.make_fixture(request)


@pytest.mark.tier1
class TestAuthenticationIndicators(XMLRPC_test):
    def test_create_service_with_otp_indicator(
            self, indicators_host, indicators_service):
        """ Since range of authentication indicator values is not limited,
        only 'otp' option is tested """
        indicators_host.create()
        indicators_service.create()

    def test_adding_second_indicator(
            self, indicators_host, indicators_service):
        indicators_host.create()
        indicators_service.create()
        indicators_service.update(
            updates={u'krbprincipalauthind': [u'otp', u'radius']})

    def test_update_indicator(self, indicators_host, indicators_service):
        indicators_host.create()
        indicators_service.create()
        indicators_service.update(
            updates={u'krbprincipalauthind': u'radius'},
            expected_updates={u'krbprincipalauthind': [u'radius']}
        )


@pytest.fixture(scope='function')
def managing_host(request):
    tracker = HostTracker(name=u'managinghost2', fqdn=fqdn2)
    return tracker.make_fixture(request)


@pytest.fixture(scope='function')
def managed_service(request):
    tracker = ServiceTracker(
        name=u'managed-service', host_fqdn=fqdn2)
    return tracker.make_fixture(request)


@pytest.mark.tier1
class TestManagedServices(XMLRPC_test):
    def test_managed_service(
            self, managing_host, managed_service):
        """ Add a host and then add a service as a host
            Finally, remove the service as a host """
        managing_host.ensure_exists()
        with host_keytab(managing_host.name) as keytab_filename:
            with change_principal(managing_host.attrs['krbcanonicalname'][0],
                                  keytab=keytab_filename):
                managed_service.create()
                managed_service.delete()
