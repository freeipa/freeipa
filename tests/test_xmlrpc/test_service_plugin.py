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
Test the `ipalib/plugins/service.py` module.
"""

from ipalib import api, errors, x509
from tests.test_xmlrpc.xmlrpc_test import Declarative, fuzzy_uuid, fuzzy_hash
from tests.test_xmlrpc.xmlrpc_test import fuzzy_digits, fuzzy_date, fuzzy_issuer
from tests.test_xmlrpc.xmlrpc_test import fuzzy_hex
from tests.test_xmlrpc import objectclasses
import base64
from ipapython.dn import DN

fqdn1 = u'testhost1.%s' % api.env.domain
fqdn2 = u'testhost2.%s' % api.env.domain
fqdn3 = u'TestHost3.%s' % api.env.domain
service1 = u'HTTP/%s@%s' % (fqdn1, api.env.realm)
hostprincipal1 = u'host/%s@%s'  % (fqdn1, api.env.realm)
service1dn = DN(('krbprincipalname',service1),('cn','services'),('cn','accounts'),api.env.basedn)
host1dn = DN(('fqdn',fqdn1),('cn','computers'),('cn','accounts'),api.env.basedn)
host2dn = DN(('fqdn',fqdn2),('cn','computers'),('cn','accounts'),api.env.basedn)
host3dn = DN(('fqdn',fqdn3),('cn','computers'),('cn','accounts'),api.env.basedn)

fd = open('tests/test_xmlrpc/service.crt', 'r')
servercert = fd.readlines()
servercert = ''.join(servercert)
servercert = x509.strip_header(servercert)
fd.close()

badservercert = 'MIICbzCCAdigAwIBAgICA/4wDQYJKoZIhvcNAQEFBQAwKTEnMCUGA1UEAxMeSVBBIFRlc3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTEwMDgwOTE1MDIyN1oXDTIwMDgwOTE1MDIyN1owKTEMMAoGA1UEChMDSVBBMRkwFwYDVQQDExBwdW1hLmdyZXlvYWsuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwYbfEOQPgGenPn9vt1JFKvWm/Je3y2tawGWA3LXDuqfFJyYtZ8ib3TcBUOnLk9WK5g2qCwHaNlei7bj8ggIfr5hegAVe10cun+wYErjnYo7hsHYd+57VZezeipWrXu+7NoNd4+c4A5lk4A/xJay9j3bYx2oOM8BEox4xWYoWge1ljPrc5JK46f0X7AGW4F2VhnKPnf8rwSuzI1U8VGjutyM9TWNy3m9KMWeScjyG/ggIpOjUDMV7HkJL0Di61lznR9jXubpiEC7gWGbTp84eGl/Nn9bgK1AwHfJ2lHwfoY4uiL7ge1gyP6EvuUlHoBzdb7pekiX28iePjW3iEG9IawIDAQABoyIwIDARBglghkgBhvhCAQEEBAMCBkAwCwYDVR0PBAQDAgUgMA0GCSqGSIb3DQEBBQUAA4GBACRESLemRV9BPxfEgbALuxH5oE8jQm8WZ3pm2pALbpDlAd9wQc3yVf6RtkfVthyDnM18bg7IhxKpd77/p3H8eCnS8w5MLVRda6ktUC6tGhFTS4QKAf0WyDGTcIgkXbeDw0OPAoNHivoXbIXIIRxlw/XgaSaMzJQDBG8iROsN4kCv'


class test_service(Declarative):

    cleanup_commands = [
        ('host_del', [fqdn1], {}),
        ('host_del', [fqdn2], {}),
        ('host_del', [fqdn3], {}),
        ('service_del', [service1], {}),
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
                        ipakrbprincipalalias=[service1],
                        objectclass=objectclasses.service,
                        ipauniqueid=[fuzzy_uuid],
                        has_keytab=False,
                        managedby_host=[fqdn1],
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
                    managedby_host=[fqdn1],
                ),
            ),
        ),


        dict(
            desc='Update %r with a bad certificate' % service1,
            command=('service_mod', [service1], dict(usercertificate=badservercert)),
            expected=errors.CertificateOperationError(
                error=u'Issuer "CN=IPA Test Certificate Authority" does not ' +
                    u'match the expected issuer'),
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
                    managedby_host=[fqdn1],
                    valid_not_before=fuzzy_date,
                    valid_not_after=fuzzy_date,
                    subject=DN(('CN',api.env.host),x509.subject_base()),
                    serial_number=fuzzy_digits,
                    serial_number_hex=fuzzy_hex,
                    md5_fingerprint=fuzzy_hash,
                    sha1_fingerprint=fuzzy_hash,
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
                    managedby_host=[fqdn1],
                    ipakrbauthzdata=[u'MS-PAC'],
                    valid_not_before=fuzzy_date,
                    valid_not_after=fuzzy_date,
                    subject=DN(('CN',api.env.host),x509.subject_base()),
                    serial_number=fuzzy_digits,
                    serial_number_hex=fuzzy_hex,
                    md5_fingerprint=fuzzy_hash,
                    sha1_fingerprint=fuzzy_hash,
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
                    has_keytab=False,
                    managedby_host=[fqdn1],
                    ipakrbauthzdata=[u'MS-PAC'],
                    # These values come from the servercert that is in this
                    # test case.
                    valid_not_before=fuzzy_date,
                    valid_not_after=fuzzy_date,
                    subject=DN(('CN',api.env.host),x509.subject_base()),
                    serial_number=fuzzy_digits,
                    serial_number_hex=fuzzy_hex,
                    md5_fingerprint=fuzzy_hash,
                    sha1_fingerprint=fuzzy_hash,
                    issuer=fuzzy_issuer,
                ),
            ),
        ),


        dict(
            desc='Delete %r' % service1,
            command=('service_del', [service1], {}),
            expected=dict(
                value=service1,
                summary=u'Deleted service "%s"' % service1,
                result=dict(failed=u''),
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
            desc='Try to delete non-existent %r' % service1,
            command=('service_del', [service1], {}),
            expected=errors.NotFound(
                reason=u'%s: service not found' % service1),
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


    ]
