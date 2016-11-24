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

import six

from ipalib import api, errors
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import (Declarative, uuid_re, add_oc,
                                              fuzzy_uuid, fuzzy_digits)
from ipatests.test_xmlrpc.test_user_plugin import get_user_result
from ipatests.test_xmlrpc.test_group_plugin import get_group_dn
from ipatests.util import Fuzzy
from ipapython.dn import DN
import pytest

if six.PY3:
    unicode = str


idview1 = u'idview1'
idview2 = u'idview2'

hostgroup1 = u'hostgroup1'
hostgroup2 = u'hostgroup2'

idoverrideuser1 = u'testuser'
idoverridegroup1 = u'testgroup'

idoverrideuser_removed = u'testuser-removed'
idoverridegroup_removed = u'testgroup-removed'

nonexistentuser = u'nonexistentuser'
nonexistentgroup = u'nonexistentgroup'

host1 = u'testhost1'
host2 = u'testhost2'
host3 = u'testhost3'
host4 = u'testhost4'

sshpubkey = (u'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGAX3xAeLeaJggwTqMjxNwa6X'
              'HBUAikXPGMzEpVrlLDCZtv00djsFTBi38PkgxBJVkgRWMrcBsr/35lq7P6w8KGI'
              'wA8GI48Z0qBS2NBMJ2u9WQ2hjLN6GdMlo77O0uJY3251p12pCVIS/bHRSq8kHO2'
              'No8g7KA9fGGcagPfQH+ee3t7HUkpbQkFTmbPPN++r3V8oVUk5LxbryB3UIIVzNm'
              'cSIn3JrXynlvui4MixvrtX6zx+O/bBo68o8/eZD26QrahVbA09fivrn/4h3TM01'
              '9Eu/c2jOdckfU3cHUV/3Tno5d6JicibyaoDDK7S/yjdn5jhaz8MSEayQvFkZkiF'
              '0L public key test')
sshpubkeyfp = (u'13:67:6B:BF:4E:A2:05:8E:AE:25:8B:A1:31:DE:6F:1B '
                'public key test (ssh-rsa)')


# Test helpers
def get_idview_dn(name):
    return u"cn={name},cn=views,cn=accounts,{suffix}".format(
            name=name,
            suffix=api.env.basedn,
        )


def get_override_dn(view, anchor):
    return Fuzzy(u"ipaanchoruuid=:IPA:{domain}:{uuid},"
                  "cn={view},"
                  "cn=views,cn=accounts,{suffix}"
                  .format(uuid=uuid_re,
                          domain=re.escape(unicode(api.env.domain)),
                          view=re.escape(view),
                          suffix=re.escape(unicode(api.env.basedn)),
    ))


def get_fqdn(host):
    return u'{short}.{domain}'.format(short=host, domain=api.env.domain)


def get_host_principal(host):
    return u'host/%s@%s' % (get_fqdn(host), api.env.realm)


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
                reason=u'%s: ID View not found' % idview1
            ),
        ),

        dict(
            desc='Try to update non-existent ID View "%s"' % idview1,
            command=('idview_mod', [idview1], dict(description=u'description')),
            expected=errors.NotFound(
                reason=u'%s: ID View not found' % idview1
            ),
        ),

        dict(
            desc='Try to delete non-existent ID View "%s"' % idview1,
            command=('idview_del', [idview1], {}),
            expected=errors.NotFound(
                reason=u'%s: ID View not found' % idview1
            ),
        ),

        dict(
            desc='Try to rename non-existent ID View "%s"' % idview1,
            command=('idview_mod', [idview1], dict(setattr=u'cn=renamedview')),
            expected=errors.NotFound(
                reason=u'%s: ID View not found' % idview1
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
                summary=u'Added ID View "%s"' % idview1,
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
                message=u'ID View with name "%s" already exists' % idview1
            ),
        ),

        # Create some users and groups for id override object management tests

        dict(
            desc='Create "%s"' % idoverrideuser1,
            command=(
                'user_add',
                [idoverrideuser1],
                dict(
                    givenname=u'Test',
                    sn=u'User1',
                )
            ),
            expected=dict(
                value=idoverrideuser1,
                summary=u'Added user "%s"' % idoverrideuser1,
                result=get_user_result(
                    idoverrideuser1,
                    u'Test',
                    u'User1',
                    'add',
                    objectclass=add_oc(
                        objectclasses.user,
                        u'ipantuserattrs'
                    )
                ),
            ),
        ),

        dict(
            desc='Create group %r' % idoverridegroup1,
            command=(
                'group_add',
                [idoverridegroup1],
                dict(description=u'Test desc 1')
            ),
            expected=dict(
                value=idoverridegroup1,
                summary=u'Added group "%s"' % idoverridegroup1,
                result=dict(
                    cn=[idoverridegroup1],
                    description=[u'Test desc 1'],
                    objectclass=objectclasses.posixgroup,
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
                     dict(uid=u'randomuser')),
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
                     dict(setattr=u'ipaanchoruuid=:IPA:dom:renamedoverride')),
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
                     dict(cn=u'randomnewname')),
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
                     dict(setattr=u'ipaanchoruuid=:IPA:dom:renamedoverride')),
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
                reason=u'%s: User ID override not found' % idoverrideuser1
            ),
        ),

        dict(
            desc='Try to update non-existent User ID override "%s"'
                  % idoverrideuser1,
            command=('idoverrideuser_mod',
                     [idview1, idoverrideuser1],
                     dict(uid=u'randomuser')),
            expected=errors.NotFound(reason=u'no such entry'),
        ),

        dict(
            desc='Try to delete non-existent User ID override "%s"'
                  % idoverrideuser1,
            command=('idoverrideuser_del',
                     [idview1, idoverrideuser1],
                     {}),
            expected=errors.NotFound(
                reason=u'%s: User ID override not found' % idoverrideuser1
            ),
        ),

        dict(
            desc='Try to rename non-existent User ID override "%s"'
                  % idoverrideuser1,
            command=('idoverrideuser_mod',
                     [idview1, idoverrideuser1],
                     dict(setattr=u'ipaanchoruuid=:IPA:dom:renamedoverride')),
            expected=errors.NotFound(reason=u'no such entry'),
        ),

        dict(
            desc='Try to retrieve non-existent Group ID override "%s"'
                  % idoverridegroup1,
            command=('idoverridegroup_show', [idview1, idoverridegroup1], {}),
            expected=errors.NotFound(
                reason=u'%s: Group ID override not found' % idoverridegroup1
            ),
        ),

        dict(
            desc='Try to update non-existent Group ID override "%s"'
                  % idoverridegroup1,
            command=('idoverridegroup_mod',
                     [idview1, idoverridegroup1],
                     dict(cn=u'randomnewname')),
            expected=errors.NotFound(
                reason=u'%s: Group ID override not found' % idoverridegroup1
            ),
        ),

        dict(
            desc='Try to delete non-existent Gruop ID override "%s"'
                  % idoverridegroup1,
            command=('idoverridegroup_del',
                     [idview1, idoverridegroup1],
                     {}),
            expected=errors.NotFound(
                reason=u'%s: Group ID override not found' % idoverridegroup1
            ),
        ),

        dict(
            desc='Try to rename non-existent Group ID override "%s"'
                  % idoverridegroup1,
            command=('idoverridegroup_mod',
                     [idview1, idoverridegroup1],
                     dict(setattr=u'ipaanchoruuid=:IPA:dom:renamedoverride')),
            expected=errors.NotFound(
                reason=u'%s: Group ID override not found' % idoverridegroup1
            ),
        ),

        # ID override tests

        dict(
            desc='Create User ID override "%s"' % idoverrideuser1,
            command=(
                'idoverrideuser_add',
                [idview1, idoverrideuser1],
                dict(description=u'description')
            ),
            expected=dict(
                value=idoverrideuser1,
                summary=u'Added User ID override "%s"' % idoverrideuser1,
                result=dict(
                    dn=get_override_dn(idview1, idoverrideuser1),
                    objectclass=objectclasses.idoverrideuser,
                    ipaanchoruuid=[idoverrideuser1],
                    ipaoriginaluid=[idoverrideuser1],
                    description=[u'description']
                )
            ),
        ),

        dict(
            desc='Try to create duplicate ID override "%s"' % idoverrideuser1,
            command=(
                'idoverrideuser_add',
                [idview1, idoverrideuser1],
                dict(description=u'description')
            ),
            expected=errors.DuplicateEntry(
                message=(u'User ID override with name "%s" '
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
                summary=u'Modified an User ID override "%s"' % idoverrideuser1,
                result=dict(
                    dn=get_override_dn(idview1, idoverrideuser1),
                    objectclass=objectclasses.idoverrideuser,
                    ipaanchoruuid=[idoverrideuser1],
                    ipaoriginaluid=[idoverrideuser1],
                    description=[u'description'],
                    uidnumber=[u'12345'],
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
                summary=u'Modified an User ID override "%s"' % idoverrideuser1,
                result=dict(
                    dn=get_override_dn(idview1, idoverrideuser1),
                    objectclass=objectclasses.idoverrideuser,
                    ipaanchoruuid=[idoverrideuser1],
                    ipaoriginaluid=[idoverrideuser1],
                    description=[u'description']
                )
            ),
        ),

        dict(
            desc='Modify ID override "%s" to override login' % idoverrideuser1,
            command=(
                'idoverrideuser_mod',
                [idview1, idoverrideuser1],
                dict(uid=u'newlogin', all=True)
            ),
            expected=dict(
                value=idoverrideuser1,
                summary=u'Modified an User ID override "%s"' % idoverrideuser1,
                result=dict(
                    dn=get_override_dn(idview1, idoverrideuser1),
                    objectclass=objectclasses.idoverrideuser,
                    ipaanchoruuid=[idoverrideuser1],
                    ipaoriginaluid=[idoverrideuser1],
                    description=[u'description'],
                    uid=[u'newlogin'],
                )
            ),
        ),


        dict(
            desc='Modify User ID override "%s" to override home '
                 'directory' % idoverrideuser1,
            command=(
                'idoverrideuser_mod',
                [idview1, idoverrideuser1],
                dict(homedirectory=u'/home/newhome', all=True)
            ),
            expected=dict(
                value=idoverrideuser1,
                summary=u'Modified an User ID override "%s"' % idoverrideuser1,
                result=dict(
                    dn=get_override_dn(idview1, idoverrideuser1),
                    objectclass=objectclasses.idoverrideuser,
                    ipaanchoruuid=[idoverrideuser1],
                    ipaoriginaluid=[idoverrideuser1],
                    description=[u'description'],
                    homedirectory=[u'/home/newhome'],
                    uid=[u'newlogin'],
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
                summary=u'Modified an User ID override "%s"' % idoverrideuser1,
                result=dict(
                    dn=get_override_dn(idview1, idoverrideuser1),
                    objectclass=objectclasses.idoverrideuser,
                    ipaanchoruuid=[idoverrideuser1],
                    ipaoriginaluid=[idoverrideuser1],
                    description=[u'description'],
                    homedirectory=[u'/home/newhome'],
                    uid=[u'newlogin'],
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
                summary=u'Modified an User ID override "%s"' % idoverrideuser1,
                result=dict(
                    dn=get_override_dn(idview1, idoverrideuser1),
                    objectclass=objectclasses.idoverrideuser,
                    ipaanchoruuid=[idoverrideuser1],
                    ipaoriginaluid=[idoverrideuser1],
                    description=[u'description'],
                    homedirectory=[u'/home/newhome'],
                    uid=[u'newlogin'],
                )
            ),
        ),

        dict(
            desc='Remove User ID override "%s"' % idoverrideuser1,
            command=('idoverrideuser_del', [idview1, idoverrideuser1], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[idoverrideuser1],
                summary=u'Deleted User ID override "%s"' % idoverrideuser1,
            ),
        ),

        dict(
            desc='Create User ID override "%s"' % idoverrideuser1,
            command=(
                'idoverrideuser_add',
                [idview1, idoverrideuser1],
                dict(description=u'description',
                     homedirectory=u'/home/newhome',
                     uid=u'newlogin',
                     uidnumber=12345,
                     ipasshpubkey=sshpubkey,
                )
            ),
            expected=dict(
                value=idoverrideuser1,
                summary=u'Added User ID override "%s"' % idoverrideuser1,
                result=dict(
                    dn=get_override_dn(idview1, idoverrideuser1),
                    objectclass=objectclasses.idoverrideuser,
                    ipaanchoruuid=[idoverrideuser1],
                    ipaoriginaluid=[idoverrideuser1],
                    description=[u'description'],
                    homedirectory=[u'/home/newhome'],
                    uidnumber=[u'12345'],
                    uid=[u'newlogin'],
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
                dict(description=u'description')
            ),
            expected=dict(
                value=idoverridegroup1,
                summary=u'Added Group ID override "%s"' % idoverridegroup1,
                result=dict(
                    dn=get_override_dn(idview1, idoverridegroup1),
                    objectclass=objectclasses.idoverridegroup,
                    ipaanchoruuid=[idoverridegroup1],
                    description=[u'description']
                )
            ),
        ),

        dict(
            desc='Try to create duplicate Group ID override "%s"'
                 % idoverridegroup1,
            command=(
                'idoverridegroup_add',
                [idview1, idoverridegroup1],
                dict(description=u'description')
            ),
            expected=errors.DuplicateEntry(
                message=(u'Group ID override with name "%s" '
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
                summary=u'Modified an Group ID override "%s"'
                        % idoverridegroup1,
                result=dict(
                    dn=get_override_dn(idview1, idoverridegroup1),
                    objectclass=objectclasses.idoverridegroup,
                    ipaanchoruuid=[idoverridegroup1],
                    description=[u'description'],
                    gidnumber=[u'54321'],
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
                summary=u'Modified an Group ID override "%s"'
                        % idoverridegroup1,
                result=dict(
                    dn=get_override_dn(idview1, idoverridegroup1),
                    objectclass=objectclasses.idoverridegroup,
                    ipaanchoruuid=[idoverridegroup1],
                    description=[u'description']
                )
            ),
        ),

        dict(
            desc='Modify Group ID override "%s" to override group name'
                 % idoverridegroup1,
            command=(
                'idoverridegroup_mod',
                [idview1, idoverridegroup1],
                dict(cn=u'newgroup', all=True)
            ),
            expected=dict(
                value=idoverridegroup1,
                summary=u'Modified an Group ID override "%s"'
                        % idoverridegroup1,
                result=dict(
                    dn=get_override_dn(idview1, idoverridegroup1),
                    objectclass=objectclasses.idoverridegroup,
                    ipaanchoruuid=[idoverridegroup1],
                    description=[u'description'],
                    cn=[u'newgroup'],
                )
            ),
        ),

        dict(
            desc='Remove Group ID override "%s"' % idoverridegroup1,
            command=('idoverridegroup_del', [idview1, idoverridegroup1], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[idoverridegroup1],
                summary=u'Deleted Group ID override "%s"' % idoverridegroup1,
            ),
        ),

        dict(
            desc='Create Group ID override "%s"' % idoverridegroup1,
            command=(
                'idoverridegroup_add',
                [idview1, idoverridegroup1],
                dict(description=u'description',
                     cn=u'newgroup',
                     gidnumber=12345,
                )
            ),
            expected=dict(
                value=idoverridegroup1,
                summary=u'Added Group ID override "%s"' % idoverridegroup1,
                result=dict(
                    dn=get_override_dn(idview1, idoverridegroup1),
                    objectclass=objectclasses.idoverridegroup,
                    ipaanchoruuid=[idoverridegroup1],
                    description=[u'description'],
                    gidnumber=[u'12345'],
                    cn=[u'newgroup'],
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


        # Test ID View applying

        dict(
            desc='Create %r' % host1,
            command=('host_add', [get_fqdn(host1)],
                dict(
                    description=u'Test host 1',
                    l=u'Undisclosed location 1',
                    force=True,
                ),
            ),
            expected=dict(
                value=get_fqdn(host1),
                summary=u'Added host "%s"' % get_fqdn(host1),
                result=dict(
                    dn=get_host_dn(host1),
                    fqdn=[get_fqdn(host1)],
                    description=[u'Test host 1'],
                    l=[u'Undisclosed location 1'],
                    krbprincipalname=[
                        u'host/%s@%s' % (get_fqdn(host1), api.env.realm)],
                    krbcanonicalname=[
                        u'host/%s@%s' % (get_fqdn(host1), api.env.realm)],
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
                    description=u'Test host 2',
                    l=u'Undisclosed location 2',
                    force=True,
                ),
            ),
            expected=dict(
                value=get_fqdn(host2),
                summary=u'Added host "%s"' % get_fqdn(host2),
                result=dict(
                    dn=get_host_dn(host2),
                    fqdn=[get_fqdn(host2)],
                    description=[u'Test host 2'],
                    l=[u'Undisclosed location 2'],
                    krbprincipalname=[
                        u'host/%s@%s' % (get_fqdn(host2), api.env.realm)],
                    krbcanonicalname=[
                        u'host/%s@%s' % (get_fqdn(host2), api.env.realm)],
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
                    description=u'Test host 3',
                    l=u'Undisclosed location 3',
                    force=True,
                ),
            ),
            expected=dict(
                value=get_fqdn(host3),
                summary=u'Added host "%s"' % get_fqdn(host3),
                result=dict(
                    dn=get_host_dn(host3),
                    fqdn=[get_fqdn(host3)],
                    description=[u'Test host 3'],
                    l=[u'Undisclosed location 3'],
                    krbprincipalname=[
                        u'host/%s@%s' % (get_fqdn(host3), api.env.realm)],
                    krbcanonicalname=[
                        u'host/%s@%s' % (get_fqdn(host3), api.env.realm)],
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
                dict(description=u'Test hostgroup 1')
            ),
            expected=dict(
                value=hostgroup1,
                summary=u'Added hostgroup "%s"' % hostgroup1,
                result=dict(
                    dn=get_hostgroup_dn(hostgroup1),
                    cn=[hostgroup1],
                    objectclass=objectclasses.hostgroup,
                    description=[u'Test hostgroup 1'],
                    ipauniqueid=[fuzzy_uuid],
                    mepmanagedentry=[get_hostgroup_netgroup_dn(hostgroup1)],
                ),
            ),
        ),

        dict(
            desc='Create %r' % hostgroup1,
            command=('hostgroup_add', [hostgroup2],
                dict(description=u'Test hostgroup 2')
            ),
            expected=dict(
                value=hostgroup2,
                summary=u'Added hostgroup "%s"' % hostgroup2,
                result=dict(
                    dn=get_hostgroup_dn(hostgroup2),
                    cn=[hostgroup2],
                    objectclass=objectclasses.hostgroup,
                    description=[u'Test hostgroup 2'],
                    ipauniqueid=[fuzzy_uuid],
                    mepmanagedentry=[get_hostgroup_netgroup_dn(hostgroup2)],
                ),
            ),
        ),

        dict(
            desc=u'Add host %r to %r' % (host1, hostgroup1),
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
                    'description': [u'Test hostgroup 1'],
                    'member_host': [get_fqdn(host1)],
                },
            ),
        ),

        dict(
            desc=u'Add host %r to %r' % (host2, hostgroup2),
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
                    'description': [u'Test hostgroup 2'],
                    'member_host': [get_fqdn(host2)],
                },
            ),
        ),

        dict(
            desc=u'Add hostgroup %r to %r' % (hostgroup2, hostgroup1),
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
                    'description': [u'Test hostgroup 1'],
                    'member_host': [get_fqdn(host1)],
                    'memberindirect_host': [get_fqdn(host2)],
                    'member_hostgroup': [hostgroup2],
                },
            ),
        ),

        dict(
            desc=u'Apply %s to %s' % (idview1, host3),
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
                summary=u'Applied ID View "%s"' % idview1,
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
                    description=[u'Test host 3'],
                    l=[u'Undisclosed location 3'],
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
                        u'cn=Default Host Password Policy',
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
                    description=[u'Test host 2'],
                    l=[u'Undisclosed location 2'],
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
                        u'cn=Default Host Password Policy',
                        api.env.container_host,
                        api.env.basedn,
                    )],
                ),
            ),
        ),


        dict(
            desc=u'Apply %s to %s' % (idview1, hostgroup1),
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
                summary=u'Applied ID View "%s"' % idview1,
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
                    description=[u'Test host 2'],
                    l=[u'Undisclosed location 2'],
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
                        u'cn=Default Host Password Policy',
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
                    description=[u'Test host 1'],
                    l=[u'Undisclosed location 1'],
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
                        u'cn=Default Host Password Policy',
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
            desc=u'Unapply %s from %s and %s' % (idview1, host1, host3),
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
                summary=u'Cleared ID Views',
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
                    description=[u'Test host 1'],
                    l=[u'Undisclosed location 1'],
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
                        u'cn=Default Host Password Policy',
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
                    description=[u'Test host 3'],
                    l=[u'Undisclosed location 3'],
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
                        u'cn=Default Host Password Policy',
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
            desc=u'Unapply %s from %s' % (idview1, hostgroup2),
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
                summary=u'Cleared ID Views',
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
                summary=u'Deleted User ID override "%s"' % idoverrideuser1,
                value=[idoverrideuser1],
            ),
        ),

        dict(
            desc='Delete Group ID override "%s"' % idoverridegroup1,
            command=('idoverridegroup_del', [idview1, idoverridegroup1], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted Group ID override "%s"' % idoverridegroup1,
                value=[idoverridegroup1],
            ),
        ),

        # Delete the ID View

        dict(
            desc='Delete empty ID View "%s"' % idview1,
            command=('idview_del', [idview1], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted ID View "%s"' % idview1,
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
                summary=u'Added ID View "%s"' % idview1,
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
                    dict(description=u'description')
                ),
                expected=dict(
                    value=idoverrideuser1,
                    summary=u'Added User ID override "%s"' % idoverrideuser1,
                    result=dict(
                        dn=get_override_dn(idview1, idoverrideuser1),
                        objectclass=objectclasses.idoverrideuser,
                        ipaanchoruuid=[idoverrideuser1],
                        ipaoriginaluid=[idoverrideuser1],
                        description=[u'description']
                    )
                ),
            ),

        dict(
            desc='Recreate Group ID override "%s"' % idoverridegroup1,
            command=(
                'idoverridegroup_add',
                [idview1, idoverridegroup1],
                dict(description=u'description')
            ),
            expected=dict(
                value=idoverridegroup1,
                summary=u'Added Group ID override "%s"' % idoverridegroup1,
                result=dict(
                    dn=get_override_dn(idview1, idoverridegroup1),
                    objectclass=objectclasses.idoverridegroup,
                    ipaanchoruuid=[idoverridegroup1],
                    description=[u'description'],
                )
            ),
        ),

        dict(
            desc='Delete full ID View "%s"' % idview1,
            command=('idview_del', [idview1], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted ID View "%s"' % idview1,
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
                summary=u'Added ID View "%s"' % idview1,
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
                    description=u'Test host 4',
                    l=u'Undisclosed location 4',
                    force=True,
                ),
            ),
            expected=dict(
                value=get_fqdn(host4),
                summary=u'Added host "%s"' % get_fqdn(host4),
                result=dict(
                    dn=get_host_dn(host4),
                    fqdn=[get_fqdn(host4)],
                    description=[u'Test host 4'],
                    l=[u'Undisclosed location 4'],
                    krbprincipalname=[
                        u'host/%s@%s' % (get_fqdn(host4), api.env.realm)],
                    krbcanonicalname=[
                        u'host/%s@%s' % (get_fqdn(host4), api.env.realm)],
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
                summary=u'Deleted ID View "%s"' % idview1,
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
                    description=[u'Test host 4'],
                    l=[u'Undisclosed location 4'],
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
                        u'cn=Default Host Password Policy',
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
                summary=u'Added ID View "%s"' % idview1,
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
                    givenname=u'Removed',
                    sn=u'User',
                )
            ),
            expected=dict(
                value=idoverrideuser_removed,
                summary=u'Added user "%s"' % idoverrideuser_removed,
                result=get_user_result(
                    idoverrideuser_removed,
                    u'Removed',
                    u'User',
                    'add',
                    objectclass=add_oc(
                        objectclasses.user,
                        u'ipantuserattrs'
                    )
                ),
            ),
        ),

        dict(
            desc='Create group %r' % idoverridegroup_removed,
            command=(
                'group_add',
                [idoverridegroup_removed],
                dict(description=u'Removed group')
            ),
            expected=dict(
                value=idoverridegroup_removed,
                summary=u'Added group "%s"' % idoverridegroup_removed,
                result=dict(
                    cn=[idoverridegroup_removed],
                    description=[u'Removed group'],
                    objectclass=objectclasses.posixgroup,
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
                dict(description=u'description',
                     homedirectory=u'/home/newhome',
                     uid=u'newlogin',
                     uidnumber=12345,
                     ipasshpubkey=sshpubkey,
                )
            ),
            expected=dict(
                value=idoverrideuser_removed,
                summary=u'Added User ID override "%s"' % idoverrideuser_removed,
                result=dict(
                    dn=get_override_dn(idview1, idoverrideuser_removed),
                    objectclass=objectclasses.idoverrideuser,
                    ipaanchoruuid=[idoverrideuser_removed],
                    ipaoriginaluid=[idoverrideuser_removed],
                    description=[u'description'],
                    homedirectory=[u'/home/newhome'],
                    uidnumber=[u'12345'],
                    uid=[u'newlogin'],
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
                dict(description=u'description')
            ),
            expected=dict(
                value=idoverridegroup_removed,
                summary=u'Added Group ID override "%s"' % idoverridegroup_removed,
                result=dict(
                    dn=get_override_dn(idview1, idoverridegroup_removed),
                    objectclass=objectclasses.idoverridegroup,
                    ipaanchoruuid=[idoverridegroup_removed],
                    description=[u'description'],
                )
            ),
        ),

        dict(
            desc='Delete "%s"' % idoverrideuser_removed,
            command=('user_del', [idoverrideuser_removed], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted user "%s"' % idoverrideuser_removed,
                value=[idoverrideuser_removed],
            ),
        ),

        dict(
            desc='Delete "%s"' % idoverridegroup_removed,
            command=('group_del', [idoverridegroup_removed], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted group "%s"' % idoverridegroup_removed,
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
                summary=u'0 User ID overrides matched',
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
                summary=u'0 Group ID overrides matched',
                count=0,
                truncated=False,
            ),
        ),

    ]
