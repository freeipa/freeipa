# Authors:
#    Alexander Bokovoy <abokovoy@redhat.com>
#
# Copyright (C) 2012  Red Hat
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
Test the `ipaserver/plugins/idrange.py` module, and XML-RPC in general.
"""

from __future__ import absolute_import

import six

from ipalib import api, errors, messages
from ipaplatform import services
from ipatests.test_xmlrpc.xmlrpc_test import Declarative, fuzzy_uuid
from ipatests.test_xmlrpc import objectclasses
from ipatests.util import MockLDAP
from ipapython.dn import DN
from ipatests.test_xmlrpc.test_user_plugin import get_user_result
from ipatests.test_xmlrpc.mock_trust import (
    get_range_dn, get_trusted_dom_dict, get_trusted_dom_range_dict,
    get_trust_dn)
import pytest

if six.PY3:
    unicode = str

# Determine the test shift used

id_shift = 0
rid_shift = 0

for idrange in api.Command['idrange_find']()['result']:
    size = int(idrange['ipaidrangesize'][0])
    base_id = int(idrange['ipabaseid'][0])

    id_end = base_id + size
    rid_end = 0

    if 'ipabaserid' in idrange:
        base_rid = int(idrange['ipabaserid'][0])
        rid_end = base_rid + size

    if 'ipasecondarybaserid' in idrange:
        secondary_base_rid = int(idrange['ipasecondarybaserid'][0])
        rid_end = max(base_rid, secondary_base_rid) + size

    if id_shift < id_end:
        id_shift = id_end + 1000000

    if rid_shift < rid_end:
        rid_shift = rid_end + 1000000

# Local ranges definitions

testrange1 = u'testrange1'
testrange1_base_id = id_shift + 900000
testrange1_size = 99999
testrange1_base_rid = rid_shift + 10000
testrange1_secondary_base_rid = rid_shift + 200000

testrange2 = u'testrange2'
testrange2_base_id = id_shift + 100
testrange2_size = 50
testrange2_base_rid = rid_shift + 100
testrange2_secondary_base_rid = rid_shift + 1000

testrange3 = u'testrange3'
testrange3_base_id = id_shift + 200
testrange3_size = 50
testrange3_base_rid = rid_shift + 70
testrange3_secondary_base_rid = rid_shift + 1100

testrange4 = u'testrange4'
testrange4_base_id = id_shift + 300
testrange4_size = 50
testrange4_base_rid = rid_shift + 200
testrange4_secondary_base_rid = rid_shift + 1030

testrange5 = u'testrange5'
testrange5_base_id = id_shift + 400
testrange5_size = 50
testrange5_base_rid = rid_shift + 1020
testrange5_secondary_base_rid = rid_shift + 1200

testrange6 = u'testrange6'
testrange6_base_id = id_shift + 130
testrange6_size = 50
testrange6_base_rid = rid_shift + 500
testrange6_secondary_base_rid = rid_shift + 1300

testrange7 = u'testrange7'
testrange7_base_id = id_shift + 600
testrange7_size = 50
testrange7_base_rid = rid_shift + 600
testrange7_secondary_base_rid = rid_shift + 649

testrange8 = u'testrange8'
testrange8_base_id = id_shift + 700
testrange8_size = 50
testrange8_base_rid = rid_shift + 700
testrange8_secondary_base_rid = rid_shift + 800

testrange9 = u'testrange9'
testrange9_base_id = id_shift + 800
testrange9_size = 50
testrange9_base_rid = rid_shift + 800
testrange9_secondary_base_rid = rid_shift + 1800

# Domain ranges definitions

# Domain1 - AD domain nonactive (not present in LDAP)
domain1_sid = u'S-1-5-21-259319770-2312917334-591429603'

domain1range1 = u'domain1range1'
domain1range1_base_id = id_shift + 10000
domain1range1_size = 50
domain1range1_base_rid = rid_shift + 10000
domain1range1_type = u'ipa-ad-trust'

domain1range1_dn = get_range_dn(name=domain1range1)

domain1range1_add = get_trusted_dom_range_dict(
    name=domain1range1,
    base_id=domain1range1_base_id,
    size=domain1range1_size,
    rangetype=domain1range1_type,
    base_rid=domain1range1_base_rid,
    sid=domain1_sid
)

# Domain2 - AD domain active (present in LDAP)
domain2 = u'domain2'
domain2_dn = get_trust_dn(domain2)
domain2_sid = u'S-1-5-21-2997650941-1802118864-3094776726'

domain2_add = get_trusted_dom_dict(domain2, domain2_sid)

domain2range1 = u'domain2range1'
domain2range1_base_id = id_shift + 10100
domain2range1_size = 50
domain2range1_base_rid = rid_shift + 10100
domain2range1_type = u'ipa-ad-trust'

domain2range1_dn = get_range_dn(name=domain2range1)

domain2range1_add = get_trusted_dom_range_dict(
    name=domain2range1,
    base_id=domain2range1_base_id,
    size=domain2range1_size,
    rangetype=domain2range1_type,
    base_rid=domain2range1_base_rid,
    sid=domain2_sid
)

domain2range2 = u'domain2range2'
domain2range2_base_id = id_shift + 10200
domain2range2_size = 50
domain2range2_base_rid = rid_shift + 10200
domain2range2_type = u'ipa-ad-trust'

domain2range2_dn = get_range_dn(name=domain2range2)

domain2range2_add = get_trusted_dom_range_dict(
    name=domain2range2,
    base_id=domain2range2_base_id,
    size=domain2range2_size,
    rangetype=domain2range2_type,
    base_rid=domain2range2_base_rid,
    sid=domain2_sid
)


# Domain3 - Posix active AD domain, two posix ranges
domain3 = u'domain3'
domain3_dn = get_trust_dn(domain3)
domain3_sid = u'S-1-5-21-1980929950-1830687243-1002863068'

domain3_add = get_trusted_dom_dict(domain3, domain3_sid)

domain3range1 = u'domain3range1'
domain3range1_base_id = id_shift + 10300
domain3range1_size = 50
domain3range1_base_rid = 0
domain3range1_type = u'ipa-ad-trust-posix'

domain3range1_dn = get_range_dn(name=domain3range1)

domain3range1_add = get_trusted_dom_range_dict(
    name=domain3range1,
    base_id=domain3range1_base_id,
    size=domain3range1_size,
    rangetype=domain3range1_type,
    base_rid=domain3range1_base_rid,
    sid=domain3_sid
)

domain3range2 = u'domain3range2'
domain3range2_base_id = id_shift + 10400
domain3range2_size = 50
domain3range2_base_rid = 0
domain3range2_type = u'ipa-ad-trust-posix'

domain3range2_dn = get_range_dn(name=domain3range2)

domain3range2_add = get_trusted_dom_range_dict(
    name=domain3range2,
    base_id=domain3range2_base_id,
    size=domain3range2_size,
    rangetype=domain3range2_type,
    base_rid=domain3range2_base_rid,
    sid=domain3_sid
)

# Domain4 - Posix active AD domain, one posix range
domain4 = u'domain4'
domain4_dn = get_trust_dn(domain4)
domain4_sid = u'S-1-5-21-2630044516-2228086573-3500008130'

domain4_add = get_trusted_dom_dict(domain4, domain4_sid)

domain4range1 = u'domain4range1'
domain4range1_base_id = id_shift + 10500
domain4range1_size = 50
domain4range1_base_rid = 0
domain4range1_type = u'ipa-ad-trust-posix'

domain4range1_dn = get_range_dn(name=domain4range1)

domain4range1_add = get_trusted_dom_range_dict(
    name=domain4range1,
    base_id=domain4range1_base_id,
    size=domain4range1_size,
    rangetype=domain4range1_type,
    base_rid=domain4range1_base_rid,
    sid=domain4_sid
)

# Domain5 - NonPosix active AD domain, two nonposix ranges
domain5 = u'domain5'
domain5_dn = get_trust_dn(domain5)
domain5_sid = u'S-1-5-21-2936727573-1940715531-2353349748'

domain5_add = get_trusted_dom_dict(domain5, domain5_sid)

domain5range1 = u'domain5range1'
domain5range1_base_id = id_shift + 10600
domain5range1_size = 50
domain5range1_base_rid = rid_shift + 10600
domain5range1_type = u'ipa-ad-trust'

domain5range1_dn = get_range_dn(name=domain5range1)

domain5range1_add = get_trusted_dom_range_dict(
    name=domain5range1,
    base_id=domain5range1_base_id,
    size=domain5range1_size,
    rangetype=domain5range1_type,
    base_rid=domain5range1_base_rid,
    sid=domain5_sid
)

domain5range2 = u'domain5range2'
domain5range2_base_id = id_shift + 10700
domain5range2_size = 50
domain5range2_base_rid = rid_shift + 10700
domain5range2_type = u'ipa-ad-trust'

domain5range2_dn = get_range_dn(name=domain5range2)

domain5range2_add = get_trusted_dom_range_dict(
    name=domain5range2,
    base_id=domain5range2_base_id,
    size=domain5range2_size,
    rangetype=domain5range2_type,
    base_rid=domain5range2_base_rid,
    sid=domain5_sid
)

# Domain6 - NonPosix active AD domain, one nonposix ranges
domain6 = u'domain6'
domain6_dn = get_trust_dn(domain6)
domain6_sid = u'S-1-5-21-2824814446-180299986-1494994477'

domain6_add = get_trusted_dom_dict(domain6, domain6_sid)

domain6range1 = u'domain6range1'
domain6range1_base_id = id_shift + 10800
domain6range1_size = 50
domain6range1_base_rid = rid_shift + 10800
domain6range1_type = u'ipa-ad-trust'

domain6range1_dn = get_range_dn(name=domain6range1)

domain6range1_add = get_trusted_dom_range_dict(
    name=domain6range1,
    base_id=domain6range1_base_id,
    size=domain6range1_size,
    rangetype=domain6range1_type,
    base_rid=domain6range1_base_rid,
    sid=domain6_sid
)

# Domain7 - Posix active AD domain, invalid(defined) RID
domain7 = u'domain7'
domain7_dn = get_trust_dn(domain7)
domain7_sid = u'S-1-5-21-2714542333-175454564-1645457223'
domain7_add = get_trusted_dom_dict(domain7, domain7_sid)

domain7range1 = u'domain7range1'
domain7range1_base_id = id_shift + 10900
domain7range1_size = 50
domain7range1_base_rid = rid_shift + 10900
domain7range1_type = u'ipa-ad-trust-posix'
domain7range1_dn = get_range_dn(name=domain7range1)

# Container for all trusted objects

trust_container_dn = "cn=ad,cn=trusts,{basedn}".format(basedn=api.env.basedn)
trust_container_add = dict(
    objectClass=[b"nsContainer", b"top"]
    )

# Convince Domain Validator that adtrust-install was run in order to test
# adding of ipa-trust-posix range

smb_cont_dn = "{cifsdomains},{basedn}".format(
    cifsdomains=api.env.container_cifsdomains,
    basedn=api.env.basedn)
smb_cont_add = dict(
    objectClass=[b"nsContainer", b"top"]
    )

trust_local_dn = "cn={domain},{smbcont}".format(
    domain=api.env.domain,
    smbcont=smb_cont_dn)

trust_local_add = dict(
    objectClass=[b"ipaNTDomainAttrs", b"nsContainer", b"top"],
    ipaNTFlatName=[b"UNITTESTS"],
    ipaNTDomainGUID=[b"4ed70def-bff4-464c-889f-6cd2cfa4dbb7"],
    ipaNTSecurityIdentifier=[b"S-1-5-21-2568409255-1212639194-836868319"]
    )

user1 = u'tuser1'
user1_uid = id_shift + 900000
group1 = u'group1'
group1_gid = id_shift + 900100

IPA_LOCAL_RANGE_MOD_ERR = (
    u"This command can not be used to change ID allocation for local IPA "
    "domain. Run `ipa help idrange` for more information"
)


@pytest.mark.tier1
class test_range(Declarative):
    @classmethod
    def setup_class(cls):
        super(test_range, cls).setup_class()
        cls.teardown_class()
        cls.mockldap = MockLDAP()
        cls.mockldap.add_entry(trust_container_dn, trust_container_add)
        cls.mockldap.add_entry(smb_cont_dn, smb_cont_add)
        cls.mockldap.add_entry(trust_local_dn, trust_local_add)

        cls.mockldap.add_entry(domain2_dn, domain2_add)
        cls.mockldap.add_entry(domain3_dn, domain3_add)
        cls.mockldap.add_entry(domain4_dn, domain4_add)
        cls.mockldap.add_entry(domain5_dn, domain5_add)
        cls.mockldap.add_entry(domain6_dn, domain6_add)
        cls.mockldap.add_entry(domain7_dn, domain7_add)

        cls.mockldap.add_entry(domain1range1_dn, domain1range1_add)
        cls.mockldap.add_entry(domain2range1_dn, domain2range1_add)
        cls.mockldap.add_entry(domain2range2_dn, domain2range2_add)
        cls.mockldap.add_entry(domain3range1_dn, domain3range1_add)
        cls.mockldap.add_entry(domain3range2_dn, domain3range2_add)
        cls.mockldap.add_entry(domain4range1_dn, domain4range1_add)
        cls.mockldap.add_entry(domain5range1_dn, domain5range1_add)
        cls.mockldap.add_entry(domain5range2_dn, domain5range2_add)
        cls.mockldap.add_entry(domain6range1_dn, domain6range1_add)
        cls.mockldap.unbind()

    @classmethod
    def teardown_class(cls):
        cls.mockldap = MockLDAP()

        cls.mockldap.del_entry(domain2_dn)
        cls.mockldap.del_entry(domain3_dn)
        cls.mockldap.del_entry(domain4_dn)
        cls.mockldap.del_entry(domain5_dn)
        cls.mockldap.del_entry(domain6_dn)
        cls.mockldap.del_entry(domain7_dn)

        cls.mockldap.del_entry(domain1range1_dn)
        cls.mockldap.del_entry(domain2range1_dn)
        cls.mockldap.del_entry(domain2range2_dn)
        cls.mockldap.del_entry(domain3range1_dn)
        cls.mockldap.del_entry(domain3range2_dn)
        cls.mockldap.del_entry(domain4range1_dn)
        cls.mockldap.del_entry(domain5range1_dn)
        cls.mockldap.del_entry(domain5range2_dn)
        cls.mockldap.del_entry(domain6range1_dn)
        cls.mockldap.del_entry(domain7range1_dn)
        cls.mockldap.del_entry(trust_container_dn)
        cls.mockldap.del_entry(trust_local_dn)
        cls.mockldap.del_entry(smb_cont_dn)
        cls.mockldap.unbind()

    cleanup_commands = [
        ('idrange_del', [testrange1, testrange2, testrange3, testrange4,
                         testrange5, testrange6, testrange7, testrange8,
                         testrange9],
                        {'continue': True}),
        ('user_del', [user1], {}),
        ('group_del', [group1], {}),
    ]

    # Basic tests.

    tests = [
        dict(
            desc='Create ID range %r' % (testrange1),
            command=('idrange_add', [testrange1],
                      dict(ipabaseid=testrange1_base_id, ipaidrangesize=testrange1_size,
                           ipabaserid=testrange1_base_rid, ipasecondarybaserid=testrange1_secondary_base_rid)),
            expected=dict(
                result=dict(
                    dn=DN(('cn',testrange1),('cn','ranges'),('cn','etc'),
                          api.env.basedn),
                    cn=[testrange1],
                    objectclass=[u'ipaIDrange', u'ipadomainidrange'],
                    ipabaseid=[unicode(testrange1_base_id)],
                    ipabaserid=[unicode(testrange1_base_rid)],
                    ipasecondarybaserid=[unicode(testrange1_secondary_base_rid)],
                    ipaidrangesize=[unicode(testrange1_size)],
                    iparangetyperaw=[u'ipa-local'],
                    iparangetype=[u'local domain range'],
                ),
                value=testrange1,
                summary=u'Added ID range "%s"' % (testrange1),
            ),
        ),

        dict(
            desc='Retrieve ID range %r' % (testrange1),
            command=('idrange_show', [testrange1], dict()),
            expected=dict(
                result=dict(
                    dn=DN(('cn',testrange1),('cn','ranges'),('cn','etc'),
                          api.env.basedn),
                    cn=[testrange1],
                    ipabaseid=[unicode(testrange1_base_id)],
                    ipabaserid=[unicode(testrange1_base_rid)],
                    ipasecondarybaserid=[unicode(testrange1_secondary_base_rid)],
                    ipaidrangesize=[unicode(testrange1_size)],
                    iparangetyperaw=[u'ipa-local'],
                    iparangetype=[u'local domain range'],
                ),
                value=testrange1,
                summary=None,
            ),
        ),

        # Checks for modifications leaving objects outside of the range.

        dict(
            desc='Create user %r in ID range %r' % (user1, testrange1),
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1',
                                          uidnumber=user1_uid)
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=get_user_result(
                    user1, u'Test', u'User1', 'add',
                    uidnumber=[unicode(user1_uid)],
                    gidnumber=[unicode(user1_uid)],
                ),
            ),
        ),


        dict(
            desc='Create group %r in ID range %r' % (group1, testrange1),
            command=(
                'group_add', [group1], dict(description=u'Test desc 1',
                                            gidnumber=group1_gid)
            ),
            expected=dict(
                value=group1,
                summary=u'Added group "%s"' % group1,
                result=dict(
                    cn=[group1],
                    description=[u'Test desc 1'],
                    gidnumber=[unicode(group1_gid)],
                    objectclass=objectclasses.group + [u'posixgroup'],
                    ipauniqueid=[fuzzy_uuid],
                    dn=DN(('cn',group1),('cn','groups'),('cn','accounts'), api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Try to modify ID range %r to get out bounds object #1' % (testrange1),
            command=(
                'idrange_mod', [testrange1], dict(ipabaseid=user1_uid + 1)
            ),
            expected=errors.ExecutionError(message=IPA_LOCAL_RANGE_MOD_ERR),
        ),


        dict(
            desc='Try to modify ID range %r to get out bounds object #2' % (testrange1),
            command=('idrange_mod', [testrange1], dict(ipaidrangesize=100)),
            expected=errors.ExecutionError(message=IPA_LOCAL_RANGE_MOD_ERR),
        ),


        dict(
            desc='Try to modify ID range %r to get out bounds object #3' % (testrange1),
            command=('idrange_mod', [testrange1], dict(ipabaseid=100, ipaidrangesize=100)),
            expected=errors.ExecutionError(message=IPA_LOCAL_RANGE_MOD_ERR),
        ),


        dict(
            desc='Modify ID range %r' % (testrange1),
            command=('idrange_mod', [testrange1], dict(ipaidrangesize=90000)),
            expected=errors.ExecutionError(message=IPA_LOCAL_RANGE_MOD_ERR)
        ),


        dict(
            desc='Try to delete ID range %r with active IDs inside it' % testrange1,
            command=('idrange_del', [testrange1], {}),
            expected=errors.ValidationError(name='ipabaseid,ipaidrangesize',
                error=u'range modification leaving objects with ID out of the'
                      u' defined range is not allowed'),
        ),


        dict(
            desc='Delete user %r' % user1,
            command=('user_del', [user1], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[user1],
                summary=u'Deleted user "%s"' % user1,
            ),
        ),


        dict(
            desc='Delete group %r' % group1,
            command=('group_del', [group1], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[group1],
                summary=u'Deleted group "%s"' % group1,
            ),
        ),


        dict(
            desc='Delete ID range %r' % testrange1,
            command=('idrange_del', [testrange1], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[testrange1],
                summary=u'Deleted ID range "%s"' % testrange1,
            ),
        ),

        # Tests for overlapping local ranges.

        dict(
            desc='Create ID range %r' % (testrange2),
            command=('idrange_add', [testrange2],
                      dict(ipabaseid=testrange2_base_id,
                          ipaidrangesize=testrange2_size,
                          ipabaserid=testrange2_base_rid,
                          ipasecondarybaserid=testrange2_secondary_base_rid)),
            expected=dict(
                result=dict(
                    dn=DN(('cn',testrange2),('cn','ranges'),('cn','etc'),
                          api.env.basedn),
                    cn=[testrange2],
                    objectclass=[u'ipaIDrange', u'ipadomainidrange'],
                    ipabaseid=[unicode(testrange2_base_id)],
                    ipabaserid=[unicode(testrange2_base_rid)],
                    ipasecondarybaserid=[unicode(testrange2_secondary_base_rid)],
                    ipaidrangesize=[unicode(testrange2_size)],
                    iparangetyperaw=[u'ipa-local'],
                    iparangetype=[u'local domain range'],
                ),
                value=testrange2,
                summary=u'Added ID range "%s"' % (testrange2),
            ),
        ),

        dict(
            desc='Try to modify ID range %r so that its rid ranges are overlapping themselves' % (testrange2),
            command=('idrange_mod', [testrange2],
                      dict(ipabaserid=(testrange2_secondary_base_rid))),
            expected=errors.ExecutionError(message=IPA_LOCAL_RANGE_MOD_ERR),
        ),

        dict(
            desc='Try to create ID range %r with overlapping rid range' % (testrange3),
            command=('idrange_add', [testrange3],
                      dict(ipabaseid=testrange3_base_id,
                          ipaidrangesize=testrange3_size,
                          ipabaserid=testrange3_base_rid,
                          ipasecondarybaserid=testrange3_secondary_base_rid)),
            expected=errors.DatabaseError(
                desc='Constraint violation', info='New primary rid range overlaps with existing primary rid range.'),
        ),

       dict(
            desc='Try to create ID range %r with overlapping secondary rid range' % (testrange4),
            command=('idrange_add', [testrange4],
                      dict(ipabaseid=testrange4_base_id,
                          ipaidrangesize=testrange4_size,
                          ipabaserid=testrange4_base_rid,
                          ipasecondarybaserid=testrange4_secondary_base_rid)),
            expected=errors.DatabaseError(
                desc='Constraint violation', info='New secondary rid range overlaps with existing secondary rid range.'),
        ),

        dict(
            desc='Try to create ID range %r with primary range overlapping secondary rid range' % (testrange5),
            command=('idrange_add', [testrange5],
                      dict(ipabaseid=testrange5_base_id,
                          ipaidrangesize=testrange5_size,
                          ipabaserid=testrange5_base_rid,
                          ipasecondarybaserid=testrange5_secondary_base_rid)),
            expected=errors.DatabaseError(
                desc='Constraint violation', info='New primary rid range overlaps with existing secondary rid range.'),
        ),

        dict(
            desc='Try to create ID range %r with overlapping id range' % (testrange6),
            command=('idrange_add', [testrange6],
                      dict(ipabaseid=testrange6_base_id,
                          ipaidrangesize=testrange6_size,
                          ipabaserid=testrange6_base_rid,
                          ipasecondarybaserid=testrange6_secondary_base_rid)),
            expected=errors.DatabaseError(
                desc='Constraint violation', info='New base range overlaps with existing base range.'),
        ),

        dict(
            desc='Try to create ID range %r with rid ranges overlapping themselves' % (testrange7),
            command=('idrange_add', [testrange7],
                      dict(ipabaseid=testrange7_base_id,
                          ipaidrangesize=testrange7_size,
                          ipabaserid=testrange7_base_rid,
                          ipasecondarybaserid=testrange7_secondary_base_rid)),
            expected=errors.ValidationError(
                name='ID Range setup', error='Primary RID range and secondary RID range cannot overlap'),
        ),

        dict(
            desc='Delete ID range %r' % testrange2,
            command=('idrange_del', [testrange2], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[testrange2],
                summary=u'Deleted ID range "%s"' % testrange2,
            ),
        ),

        # Testing framework validation: --dom-sid/--dom-name and secondary RID
        #                               base cannot be used together

        dict(
            desc='Create ID range %r' % (testrange8),
            command=('idrange_add', [testrange8],
                      dict(ipabaseid=testrange8_base_id,
                          ipaidrangesize=testrange8_size,
                          ipabaserid=testrange8_base_rid,
                          ipasecondarybaserid=testrange8_secondary_base_rid,
                          ipanttrusteddomainsid=domain1_sid)),
            expected=errors.ValidationError(
                name='ID Range setup', error='Options dom-sid/dom-name and '
                     'secondary-rid-base cannot be used together'),
        ),

        # Testing framework validation: --rid-base is prohibited with ipa-ad-posix

        dict(
            desc='Try to create ipa-ad-trust-posix ID range %r with base RID' % (domain7range1),
            command=('idrange_add', [domain7range1],
                     dict(ipabaseid=domain7range1_base_id,
                          ipaidrangesize=domain7range1_size,
                          ipabaserid=domain7range1_base_rid,
                          iparangetype=domain7range1_type,
                          ipanttrusteddomainsid=domain7_sid)),
            expected=errors.ValidationError(
                name='ID Range setup',
                error='Option rid-base must not be used when IPA range '
                      'type is ipa-ad-trust-posix'),
        ),

        dict(
            desc='Create ID range %r' % (domain7range1),
            command=('idrange_add', [domain7range1],
                     dict(ipabaseid=domain7range1_base_id,
                          ipaidrangesize=domain7range1_size,
                          iparangetype=domain7range1_type,
                          ipanttrusteddomainsid=domain7_sid)),
            expected=dict(
                result=dict(
                    dn=unicode(domain7range1_dn),
                    cn=[domain7range1],
                    objectclass=[u'ipaIDrange', u'ipatrustedaddomainrange'],
                    ipabaseid=[unicode(domain7range1_base_id)],
                    ipaidrangesize=[unicode(domain7range1_size)],
                    ipanttrusteddomainsid=[unicode(domain7_sid)],
                    iparangetyperaw=[u'ipa-ad-trust-posix'],
                    iparangetype=[u'Active Directory trust range with POSIX attributes'],
                ),
                value=unicode(domain7range1),
                summary=u'Added ID range "%s"' % (domain7range1),
            ),
        ),

        dict(
            desc='Try to modify ipa-ad-trust-posix ID range %r with base RID' % (domain7range1),
            command=('idrange_mod', [domain7range1], dict(ipabaserid=domain7range1_base_rid)),
            expected=errors.ValidationError(
                name='ID Range setup',
                error='Option rid-base must not be used when IPA range '
                      'type is ipa-ad-trust-posix'),
        ),

        # Testing prohibition of deletion of ranges belonging to active
        # trusted domains.

        dict(
            desc='Delete non-active AD trusted range %r' % domain1range1,
            command=('idrange_del', [domain1range1], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[domain1range1],
                summary=u'Deleted ID range "%s"' % domain1range1,
            ),
        ),

        dict(
            desc='Try to delete active AD trusted range %r' % domain2range1,
            command=('idrange_del', [domain2range1], {}),
            expected=errors.DependentEntry(
                    label='Active Trust domain',
                    key=domain2range1,
                    dependent=domain2),
        ),

        # Testing base range overlaps for ranges of different types and
        # different domains

        # - Base range overlaps

        # 1. ipa-ad-trust-posix type ranges from the same forest can overlap
        # on base ranges, use domain3range1 and domain3range2

        dict(
            desc=('Modify ipa-ad-trust-posix range %r to overlap on base range'
                  ' with posix range from the same domain' % (domain3range2)),
            command=('idrange_mod', [domain3range2],
                     dict(ipabaseid=domain3range1_base_id)),
            expected=dict(
                messages=(
                    messages.ServiceRestartRequired(
                        service=services.knownservices['sssd'].systemd_name,
                        server=domain3range2
                    ).to_dict(),
                ),
                result=dict(
                    cn=[domain3range2],
                    ipabaseid=[unicode(domain3range1_base_id)],
                    ipaidrangesize=[unicode(domain3range2_size)],
                    ipanttrusteddomainsid=[unicode(domain3_sid)],
                    iparangetyperaw=[u'ipa-ad-trust-posix'],
                    iparangetype=[u'Active Directory trust range with POSIX '
                                   'attributes'],
                ),
                value=domain3range2,
                summary=u'Modified ID range "%s"' % (domain3range2),
            ),
        ),

        # 2. ipa-ad-trust-posix type ranges from different forests cannot
        # overlap on base ranges, use domain3range1 and domain4range1

        dict(
            desc=('Modify ipa-ad-trust-posix range %r to overlap on base range'
                  ' with posix range from different domain' % (domain3range1)),
            command=('idrange_mod', [domain3range1],
                     dict(ipabaseid=domain4range1_base_id)),
            expected=errors.DatabaseError(
                desc='Constraint violation',
                info='New base range overlaps with existing base range.'),
        ),

        # 3. ipa-ad-trust ranges from same forest cannot overlap on base ranges,
        # use domain5range1 and domain5range2

        dict(
            desc=('Modify ipa-ad-trust range %r to overlap on base range'
                  ' with posix range from the same domain' % (domain5range1)),
            command=('idrange_mod', [domain5range1],
                     dict(ipabaseid=domain5range2_base_id)),
            expected=errors.DatabaseError(
                desc='Constraint violation',
                info='New base range overlaps with existing base range.'),
        ),

        # 4. ipa-ad-trust ranges from different forests cannot overlap on base
        # ranges, use domain5range1 and domain6range1

        dict(
            desc=('Modify ipa-ad-trust range %r to overlap on base range'
                  ' with posix range from different domain' % (domain5range1)),
            command=('idrange_mod', [domain5range1],
                     dict(ipabaseid=domain6range1_base_id)),
            expected=errors.DatabaseError(
                desc='Constraint violation',
                info='New base range overlaps with existing base range.'),
        ),

        # - RID range overlaps

        # 1. Overlaps on base RID ranges are allowed for ranges from different
        # domains, use domain2range1 and domain5range1

        dict(
            desc=('Modify ipa-ad-trust range %r to overlap on base RID'
                  ' range with nonposix range from different domain'
                  % (domain2range1)),
            command=('idrange_mod', [domain2range1],
                     dict(ipabaserid=domain5range1_base_rid)),
            expected=dict(
                messages=(
                    messages.ServiceRestartRequired(
                        service=services.knownservices['sssd'].systemd_name,
                        server=domain2range1
                    ).to_dict(),
                ),
                result=dict(
                    cn=[domain2range1],
                    ipabaseid=[unicode(domain2range1_base_id)],
                    ipabaserid=[unicode(domain5range1_base_rid)],
                    ipaidrangesize=[unicode(domain2range1_size)],
                    ipanttrusteddomainsid=[unicode(domain2_sid)],
                    iparangetyperaw=[u'ipa-ad-trust'],
                    iparangetype=[u'Active Directory domain range'],
                ),
                value=domain2range1,
                summary=u'Modified ID range "%s"' % (domain2range1),
            ),
        ),

        # 2. ipa-ad-trust ranges from the same forest cannot overlap on base
        # RID ranges, use domain5range1 and domain5range2

        dict(
            desc=('Modify ipa-ad-trust range %r to overlap on base RID range'
                  ' with range from the same domain' % (domain2range1)),
            command=('idrange_mod', [domain2range1],
                     dict(ipabaserid=domain2range2_base_rid)),
            expected=errors.DatabaseError(
                desc='Constraint violation',
                info='New primary rid range overlaps with existing primary rid '
                     'range.'),
        ),

        # Test for bug 6404
        # if dom-name is empty, add should not fail

        dict(
            desc='Create ID range %r' % (testrange9),
            command=('idrange_add', [testrange9],
                     dict(ipanttrusteddomainname=None,
                          ipabaseid=testrange9_base_id,
                          ipaidrangesize=testrange9_size,
                          ipabaserid=testrange9_base_rid,
                          ipasecondarybaserid=testrange9_secondary_base_rid)),
            expected=dict(
                result=dict(
                    dn=DN(('cn', testrange9), ('cn', 'ranges'), ('cn', 'etc'),
                          api.env.basedn),
                    cn=[testrange9],
                    objectclass=[u'ipaIDrange', u'ipadomainidrange'],
                    ipabaseid=[unicode(testrange9_base_id)],
                    ipabaserid=[unicode(testrange9_base_rid)],
                    ipasecondarybaserid=[
                        unicode(testrange9_secondary_base_rid)],
                    ipaidrangesize=[unicode(testrange9_size)],
                    iparangetyperaw=[u'ipa-local'],
                    iparangetype=[u'local domain range'],
                ),
                value=testrange9,
                summary=u'Added ID range "%s"' % (testrange9),
            ),
        ),

        dict(
            desc='Delete ID range %r' % testrange9,
            command=('idrange_del', [testrange9], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[testrange9],
                summary=u'Deleted ID range "%s"' % testrange9,
            ),
        ),

    ]
