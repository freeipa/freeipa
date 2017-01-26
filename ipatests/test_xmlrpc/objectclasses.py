# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
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
Defines the expected objectclass for various entries.
"""

user_base = [
    u'top',
    u'person',
    u'organizationalperson',
    u'inetorgperson',
    u'inetuser',
    u'posixaccount',
    u'krbprincipalaux',
    u'krbticketpolicyaux',
    u'ipaobject',
    u'ipasshuser',
    u'ipaSshGroupOfPubKeys',
]

user = user_base + [u'mepOriginEntry']

group = [
    u'top',
    u'groupofnames',
    u'nestedgroup',
    u'ipausergroup',
    u'ipaobject',
]

externalgroup = group + [u'ipaexternalgroup']
posixgroup = group + [u'posixgroup']

host = [
    u'ipasshhost',
    u'ipaSshGroupOfPubKeys',
    u'ieee802device',
    u'ipaobject',
    u'nshost',
    u'ipahost',
    u'pkiuser',
    u'ipaservice',
    u'krbprincipalaux',
    u'krbprincipal',
    u'top',
]

hostgroup = [
    u'ipaobject',
    u'ipahostgroup',
    u'nestedGroup',
    u'groupOfNames',
    u'top',
    u'mepOriginEntry',
]

role = [
    u'groupofnames',
    u'nestedgroup',
    u'top',
]

system_permission = [
    u'groupofnames',
    u'ipapermission',
    u'top'
]

permission = system_permission + [
    u'ipapermissionv2',
]

privilege = [
    u'nestedgroup',
    u'groupofnames',
    u'top'
]

service = [
    u'krbprincipal',
    u'krbprincipalaux',
    u'krbticketpolicyaux',
    u'ipaobject',
    u'ipaservice',
    u'pkiuser',
    u'ipakrbprincipal',
    u'top',
]

hbacsvc = [
    u'ipaobject',
    u'ipahbacservice',
]

hbacsvcgroup = [
    u'ipaobject',
    u'ipahbacservicegroup',
    u'groupOfNames',
    u'top',
]

sudocmd = [
    u'ipaobject',
    u'ipasudocmd',
]

sudocmdgroup = [
    u'ipaobject',
    u'ipasudocmdgrp',
    u'groupOfNames',
    u'top',
]

netgroup = [
    u'ipaobject',
    u'ipaassociation',
    u'ipanisnetgroup',
]

automember = [
    u'top',
    u'automemberregexrule',
]

selinuxusermap = [
    u'ipaassociation',
    u'ipaselinuxusermap',
]

hbacrule = [
    u'ipaassociation',
    u'ipahbacrule',
]

dnszone = [
    u'top',
    u'idnsrecord',
    u'idnszone',
]

dnsforwardzone = [
    u'top',
    u'idnsforwardzone',
]

dnsrecord = [
    u'top',
    u'idnsrecord',
]

realmdomains = [
    u'top',
    u'nsContainer',
    u'domainRelatedObject',
]

radiusproxy = [
    u'ipatokenradiusconfiguration',
    u'top',
]

pwpolicy = [
    u'krbpwdpolicy',
    u'nscontainer',
    u'top',
]

idview = [
    u'ipaIDView',
    u'nsContainer',
    u'top'
]

idoverrideuser = [
    u'ipaOverrideAnchor',
    u'top',
    u'ipaUserOverride',
    u'ipasshuser',
    u'ipaSshGroupOfPubKeys'
]

idoverridegroup = [
    u'ipaOverrideAnchor',
    u'top',
    u'ipaGroupOverride',
]

servicedelegationrule = [
    u'top',
    u'groupofprincipals',
    u'ipakrb5delegationacl',
]

servicedelegationtarget = [
    u'top',
    u'groupofprincipals',
]

certprofile = [
    u'top',
    u'ipacertprofile',
]

caacl = [
    u'ipaassociation',
    u'ipacaacl'
]

ca = [
    u'top',
    u'ipaca',
]

certmaprule = [
    u'top',
    u'ipacertmaprule',
]

certmapconfig = [
    u'top',
    u'ipaConfigObject',
    u'nsContainer',
    u'ipaCertMapContainer',
    u'ipaCertMapConfigObject',
]
