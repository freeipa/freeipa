# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
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
Defines the expected objectclass for various entries.
"""

user = [
    u'top',
    u'person',
    u'organizationalperson',
    u'inetorgperson',
    u'inetuser',
    u'posixaccount',
    u'krbprincipalaux',
    u'radiusprofile',
    u'ipaobject',
]

group = [
    u'top',
    u'groupofnames',
    u'nestedgroup',
    u'ipausergroup',
    u'ipaobject',
]

host = [
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
]
