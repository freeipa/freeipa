# Authors:
#   Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2014  Red Hat
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
Test the `ipalib.plugins.idviews` module.
"""

import re


from ipalib import api, errors
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import (Declarative, uuid_re,
                                              fuzzy_set_optional_oc,
                                              fuzzy_uuid, fuzzy_digits)
from ipatests.test_xmlrpc.test_user_plugin import get_user_result
from ipatests.test_xmlrpc.test_group_plugin import get_group_dn
from ipatests.util import Fuzzy
from ipapython.dn import DN
import pytest

unicode = str


idview1 = 'idview1'
idview2 = 'idview2'

hostgroup1 = 'hostgroup1'
hostgroup2 = 'hostgroup2'

idoverrideuser1 = 'testuser'
idoverridegroup1 = 'testgroup'

idoverrideuser_removed = 'testuser-removed'
idoverridegroup_removed = 'testgroup-removed'

nonexistentuser = 'nonexistentuser'
nonexistentgroup = 'nonexistentgroup'

host1 = 'testhost1'
host2 = 'testhost2'
host3 = 'testhost3'
host4 = 'testhost4'

sshpubkey = ('ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGAX3xAeLeaJggwTqMjxNwa6X'
              'HBUAikXPGMzEpVrlLDCZtv00djsFTBi38PkgxBJVkgRWMrcBsr/35lq7P6w8KGI'
              'wA8GI48Z0qBS2NBMJ2u9WQ2hjLN6GdMlo77O0uJY3251p12pCVIS/bHRSq8kHO2'
              'No8g7KA9fGGcagPfQH+ee3t7HUkpbQkFTmbPPN++r3V8oVUk5LxbryB3UIIVzNm'
              'cSIn3JrXynlvui4MixvrtX6zx+O/bBo68o8/eZD26QrahVbA09fivrn/4h3TM01'
              '9Eu/c2jOdckfU3cHUV/3Tno5d6JicibyaoDDK7S/yjdn5jhaz8MSEayQvFkZkiF'
              '0L public key test')
sshpubkeyfp = ('SHA256:cStA9o5TRSARbeketEOooMUMSWRSsArIAXloBZ4vNsE '
                'public key test (ssh-rsa)')


# Test helpers
def get_idview_dn(name):
    return "cn={name},cn=views,cn=accounts,{suffix}".format(
            name=name,
            suffix=api.env.basedn,
        )


def get_override_dn(view, anchor):
    return Fuzzy("ipaanchoruuid=:IPA:{domain}:{uuid},"
                  "cn={view},"
                  "cn=views,cn=accounts,{suffix}"
                  .format(uuid=uuid_re,
                          domain=re.escape(unicode(api.env.domain)),
                          view=re.escape(view),
                          suffix=re.escape(unicode(api.env.basedn)),
    ))


def get_fqdn(host):
    return '{short}.{domain}'.format(short=host, domain=api.env.domain)


def get_host_principal(host):
    return 'host/%s@%s' % (get_fqdn(host), api.env.realm)


def get_host_dn(host):
    return DN(('fqdn', get_fqdn(host)),
              ('cn', 'computers'),
              ('cn', 'accounts'),
              api.env.basedn)


def get_hostgroup_dn(hostgroup):
    return DN(('cn', hostgroup),
              ('cn', 'hostgroups'),
              ('cn', 'accounts'),
              api.env.basedn)


def get_hostgroup_netgroup_dn(hostgroup):
    return DN(('cn', hostgroup),
              ('cn', 'ng'),
              ('cn', 'alt'),
              api.env.basedn)


@pytest.mark.tier1
class test_idviews(Declarative):

    cleanup_commands = [
        ('idview_del', [idview1, idview2], {'continue': True}),
        ('host_del', [host1, host2, host3, host4], {'continue': True}),
        ('hostgroup_del', [hostgroup1, hostgroup2], {'continue': True}),
        ('idview_del', [idview1], {'continue': True}),
        ('user_del', [idoverrideuser1, idoverrideuser_removed], {'continue': True}),
        ('group_del', [idoverridegroup1, idoverridegroup_removed], {'continue': True}),
    ]

    tests = [

        # ID View object management

        dict(
            desc='Try to retrieve non-existent ID View "%s"' % idview1,
            command=('idview_show', [idview1], {}),
            expected=errors.NotFound(
                reason='%s: ID View not found' % idview1
            ),
        ),

        dict(
            desc='Try to update non-existent ID View "%s"' % idview1,
            command=('idview_mod', [idview1], dict(description='description')),
            expected=errors.NotFound(
                reason='%s: ID View not found' % idview1
            ),
        ),

        dict(
            desc='Try to delete non-existent ID View "%s"' % idview1,
            command=('idview_del', [idview1], {}),
            expected=errors.NotFound(
                reason='%s: ID View not found' % idview1
            ),
        ),

        dict(
            desc='Try to rename non-existent ID View "%s"' % idview1,
            command=('idview_mod', [idview1], dict(setattr='cn=renamedview')),
            expected=errors.NotFound(
                reason='%s: ID View not found' % idview1
            ),
        ),

        dict(
            desc='Create ID View "%s"' % idview1,
            command=(
                'idview_add',
                [idview1],
                {}
            ),
            expected=dict(
                value=idview1,
                summary='Added ID View "%s"' % idview1,
                result=dict(
                    dn=get_idview_dn(idview1),
                    objectclass=objectclasses.idview,
                    cn=[idview1]
                )
            ),
        ),

        dict(
            desc='Try to create duplicate ID View "%s"' % idview1,
            command=(
                'idview_add',
                [idview1],
                {}
            ),
            expected=errors.DuplicateEntry(
                message='ID View with name "%s" already exists' % idview1
            ),
        ),

        # Create some users and groups for id override object management tests

        dict(
            desc='Create "%s"' % idoverrideuser1,
            command=(
                'user_add',
                [idoverrideuser1],
                dict(
                    givenname='Test',
                    sn='User1',
                )
            ),
            expected=dict(
                value=idoverrideuser1,
                summary='Added user "%s"' % idoverrideuser1,
                result=get_user_result(
                    idoverrideuser1,
                    'Test',
                    'User1',
                    'add',
                    objectclass=fuzzy_set_optional_oc(
                        objectclasses.user, 'ipantuserattrs'),
                ),
            ),
        ),

        dict(
            desc='Create group %r' % idoverridegroup1,
            command=(
                'group_add',
                [idoverridegroup1],
                dict(description='Test desc 1')
            ),
            expected=dict(
                value=idoverridegroup1,
                summary='Added group "%s"' % idoverridegroup1,
                result=dict(
                    cn=[idoverridegroup1],
                    description=['Test desc 1'],
                    objectclass=fuzzy_set_optional_oc(
                        objectclasses.posixgroup, 'ipantgroupattrs'),
                    ipauniqueid=[fuzzy_uuid],
                    gidnumber=[fuzzy_digits],
                    dn=get_group_dn(idoverridegroup1),
                ),
            ),
        ),

        # ID override object management negative tests for nonexisting objects

        dict(
            desc='Try to retrieve non-existent User ID override '
                 'for non-existent object "%s"' % nonexistentuser,
            command=('idoverrideuser_show', [idview1, nonexistentuser], {}),
            expected=errors.NotFound(
                reason="%s: user not found" % nonexistentuser
            ),
        ),

        dict(
            desc='Try to update non-existent User ID override '
                 'for non-existent object "%s"' % nonexistentuser,
            command=('idoverrideuser_mod',
                     [idview1, nonexistentuser],
                     dict(uid='randomuser')),
            expected=errors.NotFound(
                reason="%s: user not found" % nonexistentuser
            ),
        ),

        dict(
            desc='Try to delete non-existent User ID override '
                 'for non-existent object "%s"' % nonexistentuser,
            command=('idoverrideuser_del',
                     [idview1, nonexistentuser],
                     {}),
            expected=errors.NotFound(
                reason="%s: user not found" % nonexistentuser
            ),
        ),

        dict(
            desc='Try to rename non-existent User ID override '
                 'for non-existent object "%s"' % nonexistentuser,
            command=('idoverrideuser_mod',
                     [idview1, nonexistentuser],
                     dict(setattr='ipaanchoruuid=:IPA:dom:renamedoverride')),
            expected=errors.NotFound(
                reason="%s: user not found" % nonexistentuser
            ),
        ),

        dict(
            desc='Try to retrieve non-existent Group ID override '
                 'for non-existent object "%s"' % nonexistentgroup,
            command=('idoverridegroup_show', [idview1, nonexistentgroup], {}),
            expected=errors.NotFound(
                reason="%s: group not found" % nonexistentgroup
            ),
        ),

        dict(
            desc='Try to update non-existent Group ID override '
                 'for non-existent object "%s"' % nonexistentgroup,
            command=('idoverridegroup_mod',
                     [idview1, nonexistentgroup],
                     dict(cn='randomnewname')),
            expected=errors.NotFound(
                reason="%s: group not found" % nonexistentgroup
            ),
        ),

        dict(
            desc='Try to delete non-existent Gruop ID override '
                 'for non-existent object "%s"' % nonexistentgroup,
            command=('idoverridegroup_del',
                     [idview1, nonexistentgroup],
                     {}),
            expected=errors.NotFound(
                reason="%s: group not found" % nonexistentgroup
            ),
        ),

        dict(
            desc='Try to rename non-existent Group ID override '
                 'for non-existent object "%s"' % nonexistentgroup,
            command=('idoverridegroup_mod',
                     [idview1, nonexistentgroup],
                     dict(setattr='ipaanchoruuid=:IPA:dom:renamedoverride')),
            expected=errors.NotFound(
                reason="%s: group not found" % nonexistentgroup
            ),
        ),


        # ID override object management for existing objects

        dict(
            desc='Try to retrieve non-existent User ID override "%s"'
                  % idoverrideuser1,
            command=('idoverrideuser_show', [idview1, idoverrideuser1], {}),
            expected=errors.NotFound(
                reason='%s: User ID override not found' % idoverrideuser1
            ),
        ),

        dict(
            desc='Try to update non-existent User ID override "%s"'
                  % idoverrideuser1,
            command=('idoverrideuser_mod',
                     [idview1, idoverrideuser1],
                     dict(uid='randomuser')),
            expected=errors.NotFound(reason='no such entry'),
        ),

        dict(
            desc='Try to delete non-existent User ID override "%s"'
                  % idoverrideuser1,
            command=('idoverrideuser_del',
                     [idview1, idoverrideuser1],
                     {}),
            expected=errors.NotFound(
                reason='%s: User ID override not found' % idoverrideuser1
            ),
        ),

        dict(
            desc='Try to rename non-existent User ID override "%s"'
                  % idoverrideuser1,
            command=('idoverrideuser_mod',
                     [idview1, idoverrideuser1],
                     dict(setattr='ipaanchoruuid=:IPA:dom:renamedoverride')),
            expected=errors.NotFound(reason='no such entry'),
        ),

        dict(
            desc='Try to retrieve non-existent Group ID override "%s"'
                  % idoverridegroup1,
            command=('idoverridegroup_show', [idview1, idoverridegroup1], {}),
            expected=errors.NotFound(
                reason='%s: Group ID override not found' % idoverridegroup1
            ),
        ),

        dict(
            desc='Try to update non-existent Group ID override "%s"'
                  % idoverridegroup1,
            command=('idoverridegroup_mod',
                     [idview1, idoverridegroup1],
                     dict(cn='randomnewname')),
            expected=errors.NotFound(
                reason='%s: Group ID override not found' % idoverridegroup1
            ),
        ),

        dict(
            desc='Try to delete non-existent Gruop ID override "%s"'
                  % idoverridegroup1,
            command=('idoverridegroup_del',
                     [idview1, idoverridegroup1],
                     {}),
            expected=errors.NotFound(
                reason='%s: Group ID override not found' % idoverridegroup1
            ),
        ),

        dict(
            desc='Try to rename non-existent Group ID override "%s"'
                  % idoverridegroup1,
            command=('idoverridegroup_mod',
                     [idview1, idoverridegroup1],
                     dict(setattr='ipaanchoruuid=:IPA:dom:renamedoverride')),
            expected=errors.NotFound(
                reason='%s: Group ID override not found' % idoverridegroup1
            ),
        ),

        # ID override tests

        dict(
            desc='Create User ID override "%s"' % idoverrideuser1,
            command=(
                'idoverrideuser_add',
                [idview1, idoverrideuser1],
                dict(description='description')
            ),
            expected=dict(
                value=idoverrideuser1,
                summary='Added User ID override "%s"' % idoverrideuser1,
                result=dict(
                    dn=get_override_dn(idview1, idoverrideuser1),
                    objectclass=objectclasses.idoverrideuser,
                    ipaanchoruuid=[idoverrideuser1],
                    ipaoriginaluid=[idoverrideuser1],
                    description=['description']
                )
            ),
        ),

        dict(
            desc='Try to create duplicate ID override "%s"' % idoverrideuser1,
            command=(
                'idoverrideuser_add',
                [idview1, idoverrideuser1],
                dict(description='description')
            ),
            expected=errors.DuplicateEntry(
                message=('User ID override with name "%s" '
                          'already exists' % idoverrideuser1)
            ),
        ),

        dict(
            desc='Modify User ID override "%s" to override uidnumber'
                  % idoverrideuser1,
            command=(
                'idoverrideuser_mod',
                [idview1, idoverrideuser1],
                dict(uidnumber=12345, all=True)
            ),
            expected=dict(
                value=idoverrideuser1,
                summary='Modified an User ID override "%s"' % idoverrideuser1,
                result=dict(
                    dn=get_override_dn(idview1, idoverrideuser1),
                    objectclass=objectclasses.idoverrideuser,
                    ipaanchoruuid=[idoverrideuser1],
                    ipaoriginaluid=[idoverrideuser1],
                    description=['description'],
                    uidnumber=['12345'],
                )
            ),
        ),

        dict(
            desc='Modify ID override "%s" to not override '
                 'uidnumber' % idoverrideuser1,
            command=(
                'idoverrideuser_mod',
                [idview1, idoverrideuser1],
                dict(uidnumber=None, all=True)
            ),
            expected=dict(
                value=idoverrideuser1,
                summary='Modified an User ID override "%s"' % idoverrideuser1,
                result=dict(
                    dn=get_override_dn(idview1, idoverrideuser1),
                    objectclass=objectclasses.idoverrideuser,
                    ipaanchoruuid=[idoverrideuser1],
                    ipaoriginaluid=[idoverrideuser1],
                    description=['description']
                )
            ),
        ),

        dict(
            desc='Modify ID override "%s" to override login' % idoverrideuser1,
            command=(
                'idoverrideuser_mod',
                [idview1, idoverrideuser1],
                dict(uid='newlogin', all=True)
            ),
            expected=dict(
                value=idoverrideuser1,
                summary='Modified an User ID override "%s"' % idoverrideuser1,
                result=dict(
                    dn=get_override_dn(idview1, idoverrideuser1),
                    objectclass=objectclasses.idoverrideuser,
                    ipaanchoruuid=[idoverrideuser1],
                    ipaoriginaluid=[idoverrideuser1],
                    description=['description'],
                    uid=['newlogin'],
                )
            ),
        ),


        dict(
            desc='Modify User ID override "%s" to override home '
                 'directory' % idoverrideuser1,
            command=(
                'idoverrideuser_mod',
                [idview1, idoverrideuser1],
                dict(homedirectory='/home/newhome', all=True)
            ),
            expected=dict(
                value=idoverrideuser1,
                summary='Modified an User ID override "%s"' % idoverrideuser1,
                result=dict(
                    dn=get_override_dn(idview1, idoverrideuser1),
                    objectclass=objectclasses.idoverrideuser,
                    ipaanchoruuid=[idoverrideuser1],
                    ipaoriginaluid=[idoverrideuser1],
                    description=['description'],
                    homedirectory=['/home/newhome'],
                    uid=['newlogin'],
                )
            ),
        ),

        dict(
            desc='Modify User ID override "%s" to override '
                 'sshpubkey' % idoverrideuser1,
            command=(
                'idoverrideuser_mod',
                [idview1, idoverrideuser1],
                dict(ipasshpubkey=sshpubkey, all=True)
            ),
            expected=dict(
                value=idoverrideuser1,
                summary='Modified an User ID override "%s"' % idoverrideuser1,
                result=dict(
                    dn=get_override_dn(idview1, idoverrideuser1),
                    objectclass=objectclasses.idoverrideuser,
                    ipaanchoruuid=[idoverrideuser1],
                    ipaoriginaluid=[idoverrideuser1],
                    description=['description'],
                    homedirectory=['/home/newhome'],
                    uid=['newlogin'],
                    ipasshpubkey=[sshpubkey],
                    sshpubkeyfp=[sshpubkeyfp],
                )
            ),
        ),

        dict(
            desc='Modify User ID override "%s" to not override '
                 'sshpubkey' % idoverrideuser1,
            command=(
                'idoverrideuser_mod',
                [idview1, idoverrideuser1],
                dict(ipasshpubkey=None, all=True)
            ),
            expected=dict(
                value=idoverrideuser1,
                summary='Modified an User ID override "%s"' % idoverrideuser1,
                result=dict(
                    dn=get_override_dn(idview1, idoverrideuser1),
                    objectclass=objectclasses.idoverrideuser,
                    ipaanchoruuid=[idoverrideuser1],
                    ipaoriginaluid=[idoverrideuser1],
                    description=['description'],
                    homedirectory=['/home/newhome'],
                    uid=['newlogin'],
                )
            ),
        ),

        dict(
            desc='Remove User ID override "%s"' % idoverrideuser1,
            command=('idoverrideuser_del', [idview1, idoverrideuser1], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[idoverrideuser1],
                summary='Deleted User ID override "%s"' % idoverrideuser1,
            ),
        ),

        dict(
            desc='Create User ID override "%s"' % idoverrideuser1,
            command=(
                'idoverrideuser_add',
                [idview1, idoverrideuser1],
                dict(description='description',
                     homedirectory='/home/newhome',
                     uid='newlogin',
                     uidnumber=12345,
                     ipasshpubkey=sshpubkey,
                )
            ),
            expected=dict(
                value=idoverrideuser1,
                summary='Added User ID override "%s"' % idoverrideuser1,
                result=dict(
                    dn=get_override_dn(idview1, idoverrideuser1),
                    objectclass=objectclasses.idoverrideuser,
                    ipaanchoruuid=[idoverrideuser1],
                    ipaoriginaluid=[idoverrideuser1],
                    description=['description'],
                    homedirectory=['/home/newhome'],
                    uidnumber=['12345'],
                    uid=['newlogin'],
                    ipasshpubkey=[sshpubkey],
                    sshpubkeyfp=[sshpubkeyfp],
                )
            ),
        ),

        dict(
            desc='Create Group ID override "%s"' % idoverridegroup1,
            command=(
                'idoverridegroup_add',
                [idview1, idoverridegroup1],
                dict(description='description')
            ),
            expected=dict(
                value=idoverridegroup1,
                summary='Added Group ID override "%s"' % idoverridegroup1,
                result=dict(
                    dn=get_override_dn(idview1, idoverridegroup1),
                    objectclass=objectclasses.idoverridegroup,
                    ipaanchoruuid=[idoverridegroup1],
                    description=['description']
                )
            ),
        ),

        dict(
            desc='Try to create duplicate Group ID override "%s"'
                 % idoverridegroup1,
            command=(
                'idoverridegroup_add',
                [idview1, idoverridegroup1],
                dict(description='description')
            ),
            expected=errors.DuplicateEntry(
                message=('Group ID override with name "%s" '
                          'already exists' % idoverridegroup1)
            ),
        ),

        dict(
            desc='Modify Group ID override "%s" to override gidnumber'
                  % idoverridegroup1,
            command=(
                'idoverridegroup_mod',
                [idview1, idoverridegroup1],
                dict(gidnumber=54321, all=True)
            ),
            expected=dict(
                value=idoverridegroup1,
                summary='Modified an Group ID override "%s"'
                        % idoverridegroup1,
                result=dict(
                    dn=get_override_dn(idview1, idoverridegroup1),
                    objectclass=objectclasses.idoverridegroup,
                    ipaanchoruuid=[idoverridegroup1],
                    description=['description'],
                    gidnumber=['54321'],
                )
            ),
        ),

        dict(
            desc='Modify Group ID override "%s" to not override '
                 'gidnumber' % idoverridegroup1,
            command=(
                'idoverridegroup_mod',
                [idview1, idoverridegroup1],
                dict(gidnumber=None, all=True)
            ),
            expected=dict(
                value=idoverridegroup1,
                summary='Modified an Group ID override "%s"'
                        % idoverridegroup1,
                result=dict(
                    dn=get_override_dn(idview1, idoverridegroup1),
                    objectclass=objectclasses.idoverridegroup,
                    ipaanchoruuid=[idoverridegroup1],
                    description=['description']
                )
            ),
        ),

        dict(
            desc='Modify Group ID override "%s" to override group name'
                 % idoverridegroup1,
            command=(
                'idoverridegroup_mod',
                [idview1, idoverridegroup1],
                dict(cn='newgroup', all=True)
            ),
            expected=dict(
                value=idoverridegroup1,
                summary='Modified an Group ID override "%s"'
                        % idoverridegroup1,
                result=dict(
                    dn=get_override_dn(idview1, idoverridegroup1),
                    objectclass=objectclasses.idoverridegroup,
                    ipaanchoruuid=[idoverridegroup1],
                    description=['description'],
                    cn=['newgroup'],
                )
            ),
        ),

        dict(
            desc='Remove Group ID override "%s"' % idoverridegroup1,
            command=('idoverridegroup_del', [idview1, idoverridegroup1], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[idoverridegroup1],
                summary='Deleted Group ID override "%s"' % idoverridegroup1,
            ),
        ),

        dict(
            desc='Create Group ID override "%s"' % idoverridegroup1,
            command=(
                'idoverridegroup_add',
                [idview1, idoverridegroup1],
                dict(description='description',
                     cn='newgroup',
                     gidnumber=12345,
                )
            ),
            expected=dict(
                value=idoverridegroup1,
                summary='Added Group ID override "%s"' % idoverridegroup1,
                result=dict(
                    dn=get_override_dn(idview1, idoverridegroup1),
                    objectclass=objectclasses.idoverridegroup,
                    ipaanchoruuid=[idoverridegroup1],
                    description=['description'],
                    gidnumber=['12345'],
                    cn=['newgroup'],
                )
            ),
        ),

        dict(
            desc='See that ID View "%s" enumerates overrides' % idview1,
            command=(
                'idview_show',
                [idview1],
                dict(all=True)
            ),
            expected=dict(
                value=idview1,
                summary=None,
                result=dict(
                    cn=[idview1],
                    dn=get_idview_dn(idview1),
                    objectclass=objectclasses.idview,
                    useroverrides=[idoverrideuser1],
                    groupoverrides=[idoverridegroup1],
                )
            ),
        ),


        # Test ID View applying to a master
        # Try to apply to the localhost = master
        dict(
            desc='Apply %s to %s' % (idview1, api.env.host),
            command=(
                'idview_apply',
                [idview1],
                dict(host=api.env.host)
            ),
            expected=dict(
                completed=0,
                succeeded=dict(
                    host=tuple(),
                ),
                failed=dict(
                    memberhost=dict(
                        host=([api.env.host,
                               'ID View cannot be applied to IPA master'],),
                        hostgroup=tuple(),
                    ),
                ),
                summary='Applied ID View "%s"' % idview1,
            ),
        ),
        # Try to apply to the group ipaservers = all masters
        dict(
            desc='Apply %s to %s' % (idview1, 'ipaservers'),
            command=(
                'idview_apply',
                [idview1],
                dict(hostgroup='ipaservers')
            ),
            expected=dict(
                completed=0,
                succeeded=dict(
                    host=tuple(),
                ),
                failed=dict(
                    memberhost=dict(
                        host=([api.env.host,
                               'ID View cannot be applied to IPA master'],),
                        hostgroup=tuple(),
                    ),
                ),
                summary='Applied ID View "%s"' % idview1,
            ),
        ),

        # Test ID View applying

        dict(
            desc='Create %r' % host1,
            command=('host_add', [get_fqdn(host1)],
                dict(
                    description='Test host 1',
                    l='Undisclosed location 1',
                    force=True,
                ),
            ),
            expected=dict(
                value=get_fqdn(host1),
                summary='Added host "%s"' % get_fqdn(host1),
                result=dict(
                    dn=get_host_dn(host1),
                    fqdn=[get_fqdn(host1)],
                    description=['Test host 1'],
                    l=['Undisclosed location 1'],
                    krbprincipalname=[
                        'host/%s@%s' % (get_fqdn(host1), api.env.realm)],
                    krbcanonicalname=[
                        'host/%s@%s' % (get_fqdn(host1), api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[get_fqdn(host1)],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),

        dict(
            desc='Create %r' % host2,
            command=('host_add', [get_fqdn(host2)],
                dict(
                    description='Test host 2',
                    l='Undisclosed location 2',
                    force=True,
                ),
            ),
            expected=dict(
                value=get_fqdn(host2),
                summary='Added host "%s"' % get_fqdn(host2),
                result=dict(
                    dn=get_host_dn(host2),
                    fqdn=[get_fqdn(host2)],
                    description=['Test host 2'],
                    l=['Undisclosed location 2'],
                    krbprincipalname=[
                        'host/%s@%s' % (get_fqdn(host2), api.env.realm)],
                    krbcanonicalname=[
                        'host/%s@%s' % (get_fqdn(host2), api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[get_fqdn(host2)],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),

        dict(
            desc='Create %r' % host3,
            command=('host_add', [get_fqdn(host3)],
                dict(
                    description='Test host 3',
                    l='Undisclosed location 3',
                    force=True,
                ),
            ),
            expected=dict(
                value=get_fqdn(host3),
                summary='Added host "%s"' % get_fqdn(host3),
                result=dict(
                    dn=get_host_dn(host3),
                    fqdn=[get_fqdn(host3)],
                    description=['Test host 3'],
                    l=['Undisclosed location 3'],
                    krbprincipalname=[
                        'host/%s@%s' % (get_fqdn(host3), api.env.realm)],
                    krbcanonicalname=[
                        'host/%s@%s' % (get_fqdn(host3), api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[get_fqdn(host3)],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),

        dict(
            desc='Create %r' % hostgroup1,
            command=('hostgroup_add', [hostgroup1],
                dict(description='Test hostgroup 1')
            ),
            expected=dict(
                value=hostgroup1,
                summary='Added hostgroup "%s"' % hostgroup1,
                result=dict(
                    dn=get_hostgroup_dn(hostgroup1),
                    cn=[hostgroup1],
                    objectclass=objectclasses.hostgroup,
                    description=['Test hostgroup 1'],
                    ipauniqueid=[fuzzy_uuid],
                    mepmanagedentry=[get_hostgroup_netgroup_dn(hostgroup1)],
                ),
            ),
        ),

        dict(
            desc='Create %r' % hostgroup1,
            command=('hostgroup_add', [hostgroup2],
                dict(description='Test hostgroup 2')
            ),
            expected=dict(
                value=hostgroup2,
                summary='Added hostgroup "%s"' % hostgroup2,
                result=dict(
                    dn=get_hostgroup_dn(hostgroup2),
                    cn=[hostgroup2],
                    objectclass=objectclasses.hostgroup,
                    description=['Test hostgroup 2'],
                    ipauniqueid=[fuzzy_uuid],
                    mepmanagedentry=[get_hostgroup_netgroup_dn(hostgroup2)],
                ),
            ),
        ),

        dict(
            desc='Add host %r to %r' % (host1, hostgroup1),
            command=(
                'hostgroup_add_member',
                [hostgroup1],
                dict(host=get_fqdn(host1))
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
                    'dn': get_hostgroup_dn(hostgroup1),
                    'cn': [hostgroup1],
                    'description': ['Test hostgroup 1'],
                    'member_host': [get_fqdn(host1)],
                },
            ),
        ),

        dict(
            desc='Add host %r to %r' % (host2, hostgroup2),
            command=(
                'hostgroup_add_member',
                [hostgroup2],
                dict(host=get_fqdn(host2))
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
                    'dn': get_hostgroup_dn(hostgroup2),
                    'cn': [hostgroup2],
                    'description': ['Test hostgroup 2'],
                    'member_host': [get_fqdn(host2)],
                },
            ),
        ),

        dict(
            desc='Add hostgroup %r to %r' % (hostgroup2, hostgroup1),
            command=(
                'hostgroup_add_member',
                [hostgroup1],
                dict(hostgroup=hostgroup2)
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
                    'dn': get_hostgroup_dn(hostgroup1),
                    'cn': [hostgroup1],
                    'description': ['Test hostgroup 1'],
                    'member_host': [get_fqdn(host1)],
                    'memberindirect_host': [get_fqdn(host2)],
                    'member_hostgroup': [hostgroup2],
                },
            ),
        ),

        dict(
            desc='Apply %s to %s' % (idview1, host3),
            command=(
                'idview_apply',
                [idview1],
                dict(host=get_fqdn(host3))
            ),
            expected=dict(
                completed=1,
                succeeded=dict(
                    host=[get_fqdn(host3)],
                ),
                failed=dict(
                    memberhost=dict(
                        host=tuple(),
                        hostgroup=tuple(),
                    ),
                ),
                summary='Applied ID View "%s"' % idview1,
            ),
        ),

        dict(
            desc='Check that %s has %s applied' % (host3, idview1),
            command=('host_show', [get_fqdn(host3)], {'all': True}),
            expected=dict(
                value=get_fqdn(host3),
                summary=None,
                result=dict(
                    cn=[get_fqdn(host3)],
                    dn=get_host_dn(host3),
                    fqdn=[get_fqdn(host3)],
                    description=['Test host 3'],
                    l=['Undisclosed location 3'],
                    krbprincipalname=[get_host_principal(host3)],
                    krbcanonicalname=[get_host_principal(host3)],
                    has_keytab=False,
                    has_password=False,
                    managedby_host=[get_fqdn(host3)],
                    ipakrbokasdelegate=False,
                    ipakrbrequirespreauth=True,
                    ipauniqueid=[fuzzy_uuid],
                    managing_host=[get_fqdn(host3)],
                    objectclass=objectclasses.host,
                    serverhostname=[host3],
                    ipaassignedidview=[idview1],
                    ipakrboktoauthasdelegate=False,
                    krbpwdpolicyreference=[DN(
                        'cn=Default Host Password Policy',
                        api.env.container_host,
                        api.env.basedn,
                    )],
                ),
            ),
        ),

        dict(
            desc='Check that %s has not %s applied' % (host2, idview1),
            command=('host_show', [get_fqdn(host2)], {'all': True}),
            expected=dict(
                value=get_fqdn(host2),
                summary=None,
                result=dict(
                    cn=[get_fqdn(host2)],
                    dn=get_host_dn(host2),
                    fqdn=[get_fqdn(host2)],
                    description=['Test host 2'],
                    l=['Undisclosed location 2'],
                    krbprincipalname=[get_host_principal(host2)],
                    krbcanonicalname=[get_host_principal(host2)],
                    has_keytab=False,
                    has_password=False,
                    managedby_host=[get_fqdn(host2)],
                    ipakrbokasdelegate=False,
                    ipakrbrequirespreauth=True,
                    ipauniqueid=[fuzzy_uuid],
                    managing_host=[get_fqdn(host2)],
                    objectclass=objectclasses.host,
                    serverhostname=[host2],
                    memberof_hostgroup=[hostgroup2],
                    memberofindirect_hostgroup=[hostgroup1],
                    ipakrboktoauthasdelegate=False,
                    krbpwdpolicyreference=[DN(
                        'cn=Default Host Password Policy',
                        api.env.container_host,
                        api.env.basedn,
                    )],
                ),
            ),
        ),


        dict(
            desc='Apply %s to %s' % (idview1, hostgroup1),
            command=(
                'idview_apply',
                [idview1],
                dict(hostgroup=hostgroup1)
            ),
            expected=dict(
                completed=2,
                succeeded=dict(
                    host=[get_fqdn(host1), get_fqdn(host2)],
                ),
                failed=dict(
                    memberhost=dict(
                        host=tuple(),
                        hostgroup=tuple(),
                    ),
                ),
                summary='Applied ID View "%s"' % idview1,
            ),
        ),

        dict(
            desc='Check that %s has %s applied' % (host2, idview1),
            command=('host_show', [get_fqdn(host2)], {'all': True}),
            expected=dict(
                value=get_fqdn(host2),
                summary=None,
                result=dict(
                    cn=[get_fqdn(host2)],
                    dn=get_host_dn(host2),
                    fqdn=[get_fqdn(host2)],
                    description=['Test host 2'],
                    l=['Undisclosed location 2'],
                    krbprincipalname=[get_host_principal(host2)],
                    krbcanonicalname=[get_host_principal(host2)],
                    has_keytab=False,
                    has_password=False,
                    managedby_host=[get_fqdn(host2)],
                    ipakrbokasdelegate=False,
                    ipakrbrequirespreauth=True,
                    ipauniqueid=[fuzzy_uuid],
                    managing_host=[get_fqdn(host2)],
                    objectclass=objectclasses.host,
                    serverhostname=[host2],
                    memberof_hostgroup=[hostgroup2],
                    memberofindirect_hostgroup=[hostgroup1],
                    ipaassignedidview=[idview1],
                    ipakrboktoauthasdelegate=False,
                    krbpwdpolicyreference=[DN(
                        'cn=Default Host Password Policy',
                        api.env.container_host,
                        api.env.basedn,
                    )],
                ),
            ),
        ),

        dict(
            desc='Check that %s has %s applied' % (host1, idview1),
            command=('host_show', [get_fqdn(host1)], {'all': True}),
            expected=dict(
                value=get_fqdn(host1),
                summary=None,
                result=dict(
                    cn=[get_fqdn(host1)],
                    dn=get_host_dn(host1),
                    fqdn=[get_fqdn(host1)],
                    description=['Test host 1'],
                    l=['Undisclosed location 1'],
                    krbprincipalname=[get_host_principal(host1)],
                    krbcanonicalname=[get_host_principal(host1)],
                    has_keytab=False,
                    has_password=False,
                    managedby_host=[get_fqdn(host1)],
                    ipakrbokasdelegate=False,
                    ipakrbrequirespreauth=True,
                    ipauniqueid=[fuzzy_uuid],
                    managing_host=[get_fqdn(host1)],
                    objectclass=objectclasses.host,
                    serverhostname=[host1],
                    memberof_hostgroup=[hostgroup1],
                    ipaassignedidview=[idview1],
                    ipakrboktoauthasdelegate=False,
                    krbpwdpolicyreference=[DN(
                        'cn=Default Host Password Policy',
                        api.env.container_host,
                        api.env.basedn,
                    )],
                ),
            ),
        ),

        dict(
            desc='See that ID View "%s" enumerates hosts' % idview1,
            command=(
                'idview_show',
                [idview1],
                dict(all=True, show_hosts=True)
            ),
            expected=dict(
                value=idview1,
                summary=None,
                result=dict(
                    cn=[idview1],
                    dn=get_idview_dn(idview1),
                    objectclass=objectclasses.idview,
                    useroverrides=[idoverrideuser1],
                    groupoverrides=[idoverridegroup1],
                    appliedtohosts=[get_fqdn(host)
                                    for host in (host1, host2, host3)]
                )
            ),
        ),

        dict(
            desc='Unapply %s from %s and %s' % (idview1, host1, host3),
            command=(
                'idview_unapply',
                [],
                dict(host=[get_fqdn(host1), get_fqdn(host3)]),
            ),
            expected=dict(
                completed=2,
                succeeded=dict(
                    host=[get_fqdn(host1), get_fqdn(host3)],
                ),
                failed=dict(
                    memberhost=dict(
                        host=tuple(),
                        hostgroup=tuple(),
                    ),
                ),
                summary='Cleared ID Views',
            ),
        ),

        dict(
            desc='Check that %s has not %s applied' % (host1, idview1),
            command=('host_show', [get_fqdn(host1)], {'all': True}),
            expected=dict(
                value=get_fqdn(host1),
                summary=None,
                result=dict(
                    cn=[get_fqdn(host1)],
                    dn=get_host_dn(host1),
                    fqdn=[get_fqdn(host1)],
                    description=['Test host 1'],
                    l=['Undisclosed location 1'],
                    krbprincipalname=[get_host_principal(host1)],
                    krbcanonicalname=[get_host_principal(host1)],
                    has_keytab=False,
                    has_password=False,
                    managedby_host=[get_fqdn(host1)],
                    ipakrbokasdelegate=False,
                    ipakrbrequirespreauth=True,
                    ipauniqueid=[fuzzy_uuid],
                    managing_host=[get_fqdn(host1)],
                    objectclass=objectclasses.host,
                    serverhostname=[host1],
                    memberof_hostgroup=[hostgroup1],
                    ipakrboktoauthasdelegate=False,
                    krbpwdpolicyreference=[DN(
                        'cn=Default Host Password Policy',
                        api.env.container_host,
                        api.env.basedn,
                    )],
                ),
            ),
        ),

        dict(
            desc='Check that %s has not %s applied' % (host3, idview1),
            command=('host_show', [get_fqdn(host3)], {'all': True}),
            expected=dict(
                value=get_fqdn(host3),
                summary=None,
                result=dict(
                    cn=[get_fqdn(host3)],
                    dn=get_host_dn(host3),
                    fqdn=[get_fqdn(host3)],
                    description=['Test host 3'],
                    l=['Undisclosed location 3'],
                    krbprincipalname=[get_host_principal(host3)],
                    krbcanonicalname=[get_host_principal(host3)],
                    has_keytab=False,
                    has_password=False,
                    managedby_host=[get_fqdn(host3)],
                    ipakrbokasdelegate=False,
                    ipakrbrequirespreauth=True,
                    ipauniqueid=[fuzzy_uuid],
                    managing_host=[get_fqdn(host3)],
                    objectclass=objectclasses.host,
                    serverhostname=[host3],
                    ipakrboktoauthasdelegate=False,
                    krbpwdpolicyreference=[DN(
                        'cn=Default Host Password Policy',
                        api.env.container_host,
                        api.env.basedn,
                    )],
                ),
            ),
        ),

        dict(
            desc='See that ID View "%s" enumerates only one host' % idview1,
            command=(
                'idview_show',
                [idview1],
                dict(all=True, show_hosts=True)
            ),
            expected=dict(
                value=idview1,
                summary=None,
                result=dict(
                    cn=[idview1],
                    dn=get_idview_dn(idview1),
                    objectclass=objectclasses.idview,
                    useroverrides=[idoverrideuser1],
                    groupoverrides=[idoverridegroup1],
                    appliedtohosts=[get_fqdn(host2)]
                )
            ),
        ),

        dict(
            desc='Unapply %s from %s' % (idview1, hostgroup2),
            command=(
                'idview_unapply',
                [],
                dict(hostgroup=hostgroup2),
            ),
            expected=dict(
                completed=1,
                succeeded=dict(
                    host=[get_fqdn(host2)],
                ),
                failed=dict(
                    memberhost=dict(
                        host=tuple(),
                        hostgroup=tuple(),
                    ),
                ),
                summary='Cleared ID Views',
            ),
        ),

        dict(
            desc='See that ID View "%s" enumerates no host' % idview1,
            command=(
                'idview_show',
                [idview1],
                dict(all=True, show_hosts=True)
            ),
            expected=dict(
                value=idview1,
                summary=None,
                result=dict(
                    cn=[idview1],
                    dn=get_idview_dn(idview1),
                    objectclass=objectclasses.idview,
                    useroverrides=[idoverrideuser1],
                    groupoverrides=[idoverridegroup1],
                )
            ),
        ),

        # Deleting ID overrides

        dict(
            desc='Delete User ID override "%s"' % idoverrideuser1,
            command=('idoverrideuser_del', [idview1, idoverrideuser1], {}),
            expected=dict(
                result=dict(failed=[]),
                summary='Deleted User ID override "%s"' % idoverrideuser1,
                value=[idoverrideuser1],
            ),
        ),

        dict(
            desc='Delete Group ID override "%s"' % idoverridegroup1,
            command=('idoverridegroup_del', [idview1, idoverridegroup1], {}),
            expected=dict(
                result=dict(failed=[]),
                summary='Deleted Group ID override "%s"' % idoverridegroup1,
                value=[idoverridegroup1],
            ),
        ),

        # Delete the ID View

        dict(
            desc='Delete empty ID View "%s"' % idview1,
            command=('idview_del', [idview1], {}),
            expected=dict(
                result=dict(failed=[]),
                summary='Deleted ID View "%s"' % idview1,
                value=[idview1],
            ),
        ),

        # Recreate the view and delete it when it contains overrides

        dict(
            desc='Create ID View "%s"' % idview1,
            command=(
                'idview_add',
                [idview1],
                {}
            ),
            expected=dict(
                value=idview1,
                summary='Added ID View "%s"' % idview1,
                result=dict(
                    dn=get_idview_dn(idview1),
                    objectclass=objectclasses.idview,
                    cn=[idview1]
                )
            ),
        ),

         dict(
                desc='Recreate User ID override "%s"' % idoverrideuser1,
                command=(
                    'idoverrideuser_add',
                    [idview1, idoverrideuser1],
                    dict(description='description')
                ),
                expected=dict(
                    value=idoverrideuser1,
                    summary='Added User ID override "%s"' % idoverrideuser1,
                    result=dict(
                        dn=get_override_dn(idview1, idoverrideuser1),
                        objectclass=objectclasses.idoverrideuser,
                        ipaanchoruuid=[idoverrideuser1],
                        ipaoriginaluid=[idoverrideuser1],
                        description=['description']
                    )
                ),
            ),

        dict(
            desc='Recreate Group ID override "%s"' % idoverridegroup1,
            command=(
                'idoverridegroup_add',
                [idview1, idoverridegroup1],
                dict(description='description')
            ),
            expected=dict(
                value=idoverridegroup1,
                summary='Added Group ID override "%s"' % idoverridegroup1,
                result=dict(
                    dn=get_override_dn(idview1, idoverridegroup1),
                    objectclass=objectclasses.idoverridegroup,
                    ipaanchoruuid=[idoverridegroup1],
                    description=['description'],
                )
            ),
        ),

        dict(
            desc='Delete full ID View "%s"' % idview1,
            command=('idview_del', [idview1], {}),
            expected=dict(
                result=dict(failed=[]),
                summary='Deleted ID View "%s"' % idview1,
                value=[idview1],
            ),
        ),

        # Recreate the view, assign it to a host and then delete the view
        # Check that the host no longer references the view

        dict(
            desc='Create ID View "%s"' % idview1,
            command=(
                'idview_add',
                [idview1],
                {}
            ),
            expected=dict(
                value=idview1,
                summary='Added ID View "%s"' % idview1,
                result=dict(
                    dn=get_idview_dn(idview1),
                    objectclass=objectclasses.idview,
                    cn=[idview1]
                )
            ),
        ),

        dict(
            desc='Create %r' % host4,
            command=('host_add', [get_fqdn(host4)],
                dict(
                    description='Test host 4',
                    l='Undisclosed location 4',
                    force=True,
                ),
            ),
            expected=dict(
                value=get_fqdn(host4),
                summary='Added host "%s"' % get_fqdn(host4),
                result=dict(
                    dn=get_host_dn(host4),
                    fqdn=[get_fqdn(host4)],
                    description=['Test host 4'],
                    l=['Undisclosed location 4'],
                    krbprincipalname=[
                        'host/%s@%s' % (get_fqdn(host4), api.env.realm)],
                    krbcanonicalname=[
                        'host/%s@%s' % (get_fqdn(host4), api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[get_fqdn(host4)],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),

        dict(
            desc='Delete ID View that is assigned "%s"' % idview1,
            command=('idview_del', [idview1], {}),
            expected=dict(
                result=dict(failed=[]),
                summary='Deleted ID View "%s"' % idview1,
                value=[idview1],
            ),
        ),

        dict(
            desc='Check that %s has not %s applied' % (host4, idview1),
            command=('host_show', [get_fqdn(host4)], {'all': True}),
            expected=dict(
                value=get_fqdn(host4),
                summary=None,
                result=dict(
                    cn=[get_fqdn(host4)],
                    dn=get_host_dn(host4),
                    fqdn=[get_fqdn(host4)],
                    description=['Test host 4'],
                    l=['Undisclosed location 4'],
                    krbprincipalname=[get_host_principal(host4)],
                    krbcanonicalname=[get_host_principal(host4)],
                    has_keytab=False,
                    has_password=False,
                    managedby_host=[get_fqdn(host4)],
                    ipakrbokasdelegate=False,
                    ipakrbrequirespreauth=True,
                    ipauniqueid=[fuzzy_uuid],
                    managing_host=[get_fqdn(host4)],
                    objectclass=objectclasses.host,
                    serverhostname=[host4],
                    ipakrboktoauthasdelegate=False,
                    krbpwdpolicyreference=[DN(
                        'cn=Default Host Password Policy',
                        api.env.container_host,
                        api.env.basedn,
                    )],
                ),
            ),
        ),

        # Test integrity of idoverride objects agains their references

        dict(
            desc='Create ID View "%s"' % idview1,
            command=(
                'idview_add',
                [idview1],
                {}
            ),
            expected=dict(
                value=idview1,
                summary='Added ID View "%s"' % idview1,
                result=dict(
                    dn=get_idview_dn(idview1),
                    objectclass=objectclasses.idview,
                    cn=[idview1]
                )
            ),
        ),

        dict(
            desc='Create "%s"' % idoverrideuser_removed,
            command=(
                'user_add',
                [idoverrideuser_removed],
                dict(
                    givenname='Removed',
                    sn='User',
                )
            ),
            expected=dict(
                value=idoverrideuser_removed,
                summary='Added user "%s"' % idoverrideuser_removed,
                result=get_user_result(
                    idoverrideuser_removed,
                    'Removed',
                    'User',
                    'add',
                    objectclass=fuzzy_set_optional_oc(
                        objectclasses.user, 'ipantuserattrs'),
                ),
            ),
        ),

        dict(
            desc='Create group %r' % idoverridegroup_removed,
            command=(
                'group_add',
                [idoverridegroup_removed],
                dict(description='Removed group')
            ),
            expected=dict(
                value=idoverridegroup_removed,
                summary='Added group "%s"' % idoverridegroup_removed,
                result=dict(
                    cn=[idoverridegroup_removed],
                    description=['Removed group'],
                    objectclass=fuzzy_set_optional_oc(
                        objectclasses.posixgroup, 'ipantgroupattrs'),
                    ipauniqueid=[fuzzy_uuid],
                    gidnumber=[fuzzy_digits],
                    dn=get_group_dn(idoverridegroup_removed),
                ),
            ),
        ),

        dict(
            desc='Create User ID override "%s"' % idoverrideuser_removed,
            command=(
                'idoverrideuser_add',
                [idview1, idoverrideuser_removed],
                dict(description='description',
                     homedirectory='/home/newhome',
                     uid='newlogin',
                     uidnumber=12345,
                     ipasshpubkey=sshpubkey,
                )
            ),
            expected=dict(
                value=idoverrideuser_removed,
                summary='Added User ID override "%s"' % idoverrideuser_removed,
                result=dict(
                    dn=get_override_dn(idview1, idoverrideuser_removed),
                    objectclass=objectclasses.idoverrideuser,
                    ipaanchoruuid=[idoverrideuser_removed],
                    ipaoriginaluid=[idoverrideuser_removed],
                    description=['description'],
                    homedirectory=['/home/newhome'],
                    uidnumber=['12345'],
                    uid=['newlogin'],
                    ipasshpubkey=[sshpubkey],
                    sshpubkeyfp=[sshpubkeyfp],
                )
            ),
        ),

        dict(
            desc='Create Group ID override "%s"' % idoverridegroup_removed,
            command=(
                'idoverridegroup_add',
                [idview1, idoverridegroup_removed],
                dict(description='description')
            ),
            expected=dict(
                value=idoverridegroup_removed,
                summary='Added Group ID override "%s"' % idoverridegroup_removed,
                result=dict(
                    dn=get_override_dn(idview1, idoverridegroup_removed),
                    objectclass=objectclasses.idoverridegroup,
                    ipaanchoruuid=[idoverridegroup_removed],
                    description=['description'],
                )
            ),
        ),

        dict(
            desc='Delete "%s"' % idoverrideuser_removed,
            command=('user_del', [idoverrideuser_removed], {}),
            expected=dict(
                result=dict(failed=[]),
                summary='Deleted user "%s"' % idoverrideuser_removed,
                value=[idoverrideuser_removed],
            ),
        ),

        dict(
            desc='Delete "%s"' % idoverridegroup_removed,
            command=('group_del', [idoverridegroup_removed], {}),
            expected=dict(
                result=dict(failed=[]),
                summary='Deleted group "%s"' % idoverridegroup_removed,
                value=[idoverridegroup_removed],
            ),
        ),

        dict(
            desc='Make sure idoverrideuser objects have been cleaned',
            command=(
                'idoverrideuser_find',
                [idview1],
                dict(),
            ),
            expected=dict(
                result=[],
                summary='0 User ID overrides matched',
                count=0,
                truncated=False,
            ),
        ),

        dict(
            desc='Make sure idoverridegroup objects have been cleaned',
            command=(
                'idoverridegroup_find',
                [idview1],
                dict(),
            ),
            expected=dict(
                result=[],
                summary='0 Group ID overrides matched',
                count=0,
                truncated=False,
            ),
        ),

        # Delete the ID View

        dict(
            desc='Delete ID View "%s"' % idview1,
            command=('idview_del', [idview1], {}),
            expected=dict(
                result=dict(failed=[]),
                summary='Deleted ID View "%s"' % idview1,
                value=[idview1],
            ),
        ),

        # Test the creation of ID view with domain resolution order
        # Non-regression test for issue 7350

        dict(
            desc='Create ID View "%s"' % idview1,
            command=(
                'idview_add',
                [idview1],
                dict(ipadomainresolutionorder='%s' % api.env.domain)
            ),
            expected=dict(
                value=idview1,
                summary='Added ID View "%s"' % idview1,
                result=dict(
                    dn=get_idview_dn(idview1),
                    objectclass=objectclasses.idview +
                    ['ipanameresolutiondata'],
                    cn=[idview1],
                    ipadomainresolutionorder=[api.env.domain]
                )
            ),
        ),

    ]
