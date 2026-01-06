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
    'top',
    'person',
    'organizationalperson',
    'inetorgperson',
    'inetuser',
    'posixaccount',
    'krbprincipalaux',
    'krbticketpolicyaux',
    'ipaobject',
    'ipasshuser',
    'ipaSshGroupOfPubKeys',
]

user = user_base + ['mepOriginEntry', 'ipantuserattrs',]

group = [
    'top',
    'groupofnames',
    'nestedgroup',
    'ipausergroup',
    'ipaobject',
]

externalgroup = group + ['ipaexternalgroup']
posixgroup = group + ['posixgroup', 'ipantgroupattrs']

host = [
    'ipasshhost',
    'ipaSshGroupOfPubKeys',
    'ieee802device',
    'ipaobject',
    'nshost',
    'ipahost',
    'pkiuser',
    'ipaservice',
    'krbprincipalaux',
    'krbprincipal',
    'top',
]

hostgroup = [
    'ipaobject',
    'ipahostgroup',
    'nestedGroup',
    'groupOfNames',
    'top',
    'mepOriginEntry',
]

role = [
    'groupofnames',
    'nestedgroup',
    'top',
]

system_permission = [
    'groupofnames',
    'ipapermission',
    'top'
]

permission = system_permission + [
    'ipapermissionv2',
]

privilege = [
    'nestedgroup',
    'groupofnames',
    'top'
]

service = [
    'krbprincipal',
    'krbprincipalaux',
    'krbticketpolicyaux',
    'ipaobject',
    'ipaservice',
    'pkiuser',
    'ipakrbprincipal',
    'top',
]

hbacsvc = [
    'ipaobject',
    'ipahbacservice',
]

hbacsvcgroup = [
    'ipaobject',
    'ipahbacservicegroup',
    'groupOfNames',
    'top',
]

sudocmd = [
    'ipaobject',
    'ipasudocmd',
]

sudocmdgroup = [
    'ipaobject',
    'ipasudocmdgrp',
    'groupOfNames',
    'top',
]

netgroup = [
    'ipaobject',
    'ipaassociation',
    'ipanisnetgroup',
]

automember = [
    'top',
    'automemberregexrule',
]

selinuxusermap = [
    'ipaassociation',
    'ipaselinuxusermap',
]

hbacrule = [
    'ipaassociation',
    'ipahbacrule',
]

dnszone = [
    'top',
    'idnsrecord',
    'idnszone',
]

dnsforwardzone = [
    'top',
    'idnsforwardzone',
]

dnsrecord = [
    'top',
    'idnsrecord',
]

realmdomains = [
    'top',
    'nsContainer',
    'domainRelatedObject',
]

radiusproxy = [
    'ipatokenradiusconfiguration',
    'top',
]

pwpolicy = [
    'krbpwdpolicy',
    'ipapwdpolicy',
    'nscontainer',
    'top',
]

idview = [
    'ipaIDView',
    'nsContainer',
    'top'
]

idoverrideuser = [
    'ipaOverrideAnchor',
    'top',
    'ipaUserOverride',
    'ipasshuser',
    'ipaSshGroupOfPubKeys'
]

idoverridegroup = [
    'ipaOverrideAnchor',
    'top',
    'ipaGroupOverride',
]

servicedelegationrule = [
    'top',
    'groupofprincipals',
    'ipakrb5delegationacl',
]

servicedelegationtarget = [
    'top',
    'groupofprincipals',
]

certprofile = [
    'top',
    'ipacertprofile',
]

caacl = [
    'ipaassociation',
    'ipacaacl'
]

ca = [
    'top',
    'ipaca',
]

certmaprule = [
    'top',
    'ipacertmaprule',
]

certmapconfig = [
    'top',
    'nsContainer',
    'ipaCertMapConfigObject',
]

idp = [
    'top',
    'ipaidp',
]

passkeyconfig = [
    'top',
    'nscontainer',
    'ipapasskeyconfigobject',
]
