# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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
Test --setattr and --addattr and other attribute-specific issues
"""

from ipalib import api, errors, x509
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import (Declarative, fuzzy_digits, fuzzy_uuid, fuzzy_date,
    fuzzy_hex, fuzzy_hash, fuzzy_issuer)
from ipalib.dn import *
import base64

user1 = u'tuser1'
fqdn1 = u'testhost1.%s' % api.env.domain

# We can use the same cert we generated for the service tests
fd = open('tests/test_xmlrpc/service.crt', 'r')
servercert = fd.readlines()
servercert = u''.join(servercert)
servercert = x509.strip_header(servercert)
servercert = servercert.replace('\n', '')
fd.close()

class test_attr(Declarative):

    cleanup_commands = [
        ('user_del', [user1], {}),
        ('host_del', [fqdn1], {}),
    ]

    tests = [

        dict(
            desc='Create %r' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1',
                    setattr=None)
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "tuser1"',
                result=dict(
                    gecos=[u'Test User1'],
                    givenname=[u'Test'],
                    homedirectory=[u'/home/tuser1'],
                    krbprincipalname=[u'tuser1@' + api.env.realm],
                    loginshell=[u'/bin/sh'],
                    objectclass=objectclasses.user,
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    displayname=[u'Test User1'],
                    cn=[u'Test User1'],
                    initials=[u'TU'],
                    ipauniqueid=[fuzzy_uuid],
                    krbpwdpolicyreference=lambda x: [DN(i) for i in x] == \
                        [DN(('cn','global_policy'),('cn',api.env.realm),
                            ('cn','kerberos'),api.env.basedn)],
                    mepmanagedentry=lambda x: [DN(i) for i in x] == \
                        [DN(('cn',user1),('cn','groups'),('cn','accounts'),
                            api.env.basedn)],
                    memberof_group=[u'ipausers'],
                    dn=lambda x: DN(x) == \
                        DN(('uid','tuser1'),('cn','users'),('cn','accounts'),
                           api.env.basedn),
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),


        dict(
            desc='Change givenname, add mail %r' % user1,
            command=(
                'user_mod', [user1], dict(setattr=(u'givenname=Finkle', u'mail=test@example.com'))
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com'],
                    memberof_group=[u'ipausers'],
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Add another mail %r' % user1,
            command=(
                'user_mod', [user1], dict(addattr=u'mail=test2@example.com')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com', u'test2@example.com'],
                    memberof_group=[u'ipausers'],
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Add two phone numbers at once %r' % user1,
            command=(
                'user_mod', [user1], dict(setattr=u'telephoneNumber=410-555-1212', addattr=u'telephoneNumber=301-555-1212')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com', u'test2@example.com'],
                    memberof_group=[u'ipausers'],
                    telephonenumber=[u'410-555-1212', u'301-555-1212'],
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Go from two phone numbers to one %r' % user1,
            command=(
                'user_mod', [user1], dict(setattr=u'telephoneNumber=301-555-1212')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com', u'test2@example.com'],
                    memberof_group=[u'ipausers'],
                    telephonenumber=[u'301-555-1212'],
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Add two more phone numbers %r' % user1,
            command=(
                'user_mod', [user1], dict(addattr=(u'telephoneNumber=703-555-1212', u'telephoneNumber=202-888-9833'))
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com', u'test2@example.com'],
                    memberof_group=[u'ipausers'],
                    telephonenumber=[u'301-555-1212', u'202-888-9833', u'703-555-1212'],
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Delete one phone number for %r' % user1,
            command=(
                'user_mod', [user1], dict(delattr=u'telephoneNumber=301-555-1212')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com', u'test2@example.com'],
                    memberof_group=[u'ipausers'],
                    telephonenumber=[u'202-888-9833', u'703-555-1212'],
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Try deleting the number again for %r' % user1,
            command=(
                'user_mod', [user1], dict(delattr=u'telephoneNumber=301-555-1212')
            ),
            expected=errors.AttrValueNotFound(attr=u'telephonenumber',
                value=u'301-555-1212')
        ),


        dict(
            desc='Add and delete one phone number for %r' % user1,
            command=(
                'user_mod', [user1], dict(addattr=u'telephoneNumber=301-555-1212',
                                          delattr=u'telephoneNumber=202-888-9833')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com', u'test2@example.com'],
                    memberof_group=[u'ipausers'],
                    telephonenumber=[u'301-555-1212', u'703-555-1212'],
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Add and delete the same phone number for %r' % user1,
            command=(
                'user_mod', [user1], dict(addattr=(u'telephoneNumber=301-555-1212',
                                                   u'telephoneNumber=202-888-9833'),
                                          delattr=u'telephoneNumber=301-555-1212')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com', u'test2@example.com'],
                    memberof_group=[u'ipausers'],
                    telephonenumber=[u'703-555-1212', u'301-555-1212', u'202-888-9833'],
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Set and delete the a phone number for %r' % user1,
            command=(
                'user_mod', [user1], dict(setattr=(u'telephoneNumber=301-555-1212',
                                                   u'telephoneNumber=202-888-9833'),
                                          delattr=u'telephoneNumber=301-555-1212')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com', u'test2@example.com'],
                    memberof_group=[u'ipausers'],
                    telephonenumber=[u'202-888-9833'],
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Try setting givenname to None with setattr in %r' % user1,
            command=(
                'user_mod', [user1], dict(setattr=(u'givenname='))
            ),
            expected=errors.RequirementError(name='givenname'),
        ),


        dict(
            desc='Try setting givenname to None with option in %r' % user1,
            command=(
                'user_mod', [user1], dict(givenname=None)
            ),
            expected=errors.RequirementError(name='first'),
        ),


        dict(
            desc='Make sure setting givenname works with option in %r' % user1,
            command=(
                'user_mod', [user1], dict(givenname=u'Fred')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Fred'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com', u'test2@example.com'],
                    memberof_group=[u'ipausers'],
                    telephonenumber=[u'202-888-9833'],
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Make sure setting givenname works with setattr in %r' % user1,
            command=(
                'user_mod', [user1], dict(setattr=u'givenname=Finkle')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com', u'test2@example.com'],
                    memberof_group=[u'ipausers'],
                    telephonenumber=[u'202-888-9833'],
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),

        dict(
            desc='Lock %r using setattr' % user1,
            command=(
                'user_mod', [user1], dict(setattr=u'nsaccountlock=TrUe')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com', u'test2@example.com'],
                    memberof_group=[u'ipausers'],
                    telephonenumber=[u'202-888-9833'],
                    nsaccountlock=True,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),

        dict(
            desc='Unlock %r using addattr&delattr' % user1,
            command=(
                'user_mod', [user1], dict(
                    addattr=u'nsaccountlock=FaLsE',
                    delattr=u'nsaccountlock=TRUE')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com', u'test2@example.com'],
                    memberof_group=[u'ipausers'],
                    telephonenumber=[u'202-888-9833'],
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),

        dict(
            desc='Try adding a new group search fields config entry',
            command=(
                'config_mod', [], dict(addattr=u'ipagroupsearchfields=newattr')
            ),
            expected=errors.OnlyOneValueAllowed(attr='ipagroupsearchfields'),
        ),

        dict(
            desc='Try adding a new cert subject base config entry',
            command=(
                'config_mod', [], dict(addattr=u'ipacertificatesubjectbase=0=DOMAIN.COM')
            ),
            expected=errors.ValidationError(name='ipacertificatesubjectbase',
                error='attribute is not configurable'),
        ),

        dict(
            desc='Try deleting a required config entry',
            command=(
                'config_mod', [], dict(delattr=u'ipasearchrecordslimit=100')
            ),
            expected=errors.RequirementError(name='ipasearchrecordslimit'),
        ),

        dict(
            desc='Try setting nonexistent attribute',
            command=('config_mod', [], dict(setattr=u'invalid_attr=false')),
            expected=errors.ObjectclassViolation(
                info='attribute "invalid_attr" not allowed'),
        ),

        dict(
            desc='Try setting out-of-range krbpwdmaxfailure',
            command=('pwpolicy_mod', [], dict(setattr=u'krbpwdmaxfailure=-1')),
            expected=errors.ValidationError(name='krbpwdmaxfailure',
                error='must be at least 0'),
        ),

        dict(
            desc='Try setting out-of-range maxfail',
            command=('pwpolicy_mod', [], dict(krbpwdmaxfailure=u'-1')),
            expected=errors.ValidationError(name='maxfail',
                error='must be at least 0'),
        ),

        dict(
            desc='Try setting non-numeric krbpwdmaxfailure',
            command=('pwpolicy_mod', [], dict(setattr=u'krbpwdmaxfailure=abc')),
            expected=errors.ConversionError(name='krbpwdmaxfailure',
                error='must be an integer'),
        ),

        dict(
            desc='Try setting non-numeric maxfail',
            command=('pwpolicy_mod', [], dict(krbpwdmaxfailure=u'abc')),
            expected=errors.ConversionError(name='maxfail',
                error='must be an integer'),
        ),

        dict(
            desc='Try deleting bogus attribute',
            command=('config_mod', [], dict(delattr=u'bogusattribute=xyz')),
            expected=errors.ValidationError(name='bogusattribute',
                error='No such attribute on this entry'),
        ),

        dict(
            desc='Try deleting empty attribute',
            command=('config_mod', [],
                dict(delattr=u'ipaCustomFields=See Also,seealso,false')),
            expected=errors.ValidationError(name='ipacustomfields',
                error='No such attribute on this entry'),
        ),

        dict(
            desc='Set and delete one value, plus try deleting a missing one',
            command=('config_mod', [], dict(
                delattr=[u'ipaCustomFields=See Also,seealso,false',
                    u'ipaCustomFields=Country,c,false'],
                addattr=u'ipaCustomFields=See Also,seealso,false')),
            expected=errors.AttrValueNotFound(attr='ipacustomfields',
                value='Country,c,false'),
        ),

        dict(
            desc='Try to delete an operational attribute with --delattr',
            command=('config_mod', [], dict(
                delattr=u'creatorsName=cn=directory manager')),
            expected=errors.DatabaseError(
                desc='Server is unwilling to perform', info=''),
        ),

        dict(
            desc='Try to create %r with description and --addattr description' % fqdn1,
            command=('host_add', [fqdn1],
                dict(
                    description=u'Test host 1',
                    addattr=u'description=Test host 2',
                    force=True,
                ),
            ),
            expected=errors.OnlyOneValueAllowed(attr='description'),
        ),

        dict(
            desc='Create %r with a certificate' % fqdn1,
            command=('host_add', [fqdn1],
                dict(
                    usercertificate=servercert,
                    force=True,
                ),
            ),
            expected=dict(
                value=fqdn1,
                summary=u'Added host "%s"' % fqdn1,
                result=dict(
                    dn=lambda x: DN(x) == DN(('fqdn',fqdn1),('cn','computers'),
                        ('cn','accounts'),api.env.basedn),
                    fqdn=[fqdn1],
                    krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[fqdn1],
                    usercertificate=[base64.b64decode(servercert)],
                    valid_not_before=fuzzy_date,
                    valid_not_after=fuzzy_date,
                    subject=lambda x: DN(x) == \
                        DN(('CN',api.env.host),x509.subject_base()),
                    serial_number=fuzzy_digits,
                    serial_number_hex=fuzzy_hex,
                    md5_fingerprint=fuzzy_hash,
                    sha1_fingerprint=fuzzy_hash,
                    issuer=fuzzy_issuer,
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),

        dict(
            desc='Remove %r certificate using --delattr' % fqdn1,
            command=('host_mod', [fqdn1],
                dict(
                    delattr=u'usercertificate=%s' % servercert,
                ),
            ),
            expected=dict(
                value=fqdn1,
                summary=u'Modified host "%s"' % fqdn1,
                result=dict(
                    fqdn=[fqdn1],
                    krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                    managedby_host=[fqdn1],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),

    ]
