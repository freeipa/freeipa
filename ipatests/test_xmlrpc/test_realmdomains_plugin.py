# Authors:
#   Ana Krivokapic <akrivoka@redhat.com>
#
# Copyright (C) 2013  Red Hat
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
Test the `ipalib/plugins/realmdomains.py` module.
"""

from ipalib import api, errors
from ipapython.dn import DN
from ipatests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative


cn = u'Realm Domains'
dn = DN(('cn', cn), ('cn', 'ipa'), ('cn', 'etc'), api.env.basedn)
our_domain = api.env.domain
new_domain_1 = u'example1.com'
new_domain_2 = u'example2.com'
bad_domain = u'doesnotexist.test'


class test_realmdomains(Declarative):

    cleanup_commands = [
        ('realmdomains_mod', [], {'associateddomain': [our_domain]}),
    ]

    tests = [
        dict(
            desc='Retrieve realm domains',
            command=('realmdomains_show', [], {}),
            expected=dict(
                value=None,
                summary=None,
                result=dict(
                    dn=dn,
                    associateddomain=[our_domain],
                ),
            ),
        ),
        dict(
            desc='Retrieve realm domains - print all attributes',
            command=('realmdomains_show', [], {'all': True}),
            expected=dict(
                value=None,
                summary=None,
                result=dict(
                    dn=dn,
                    associateddomain=[our_domain],
                    cn=[cn],
                    objectclass=objectclasses.realmdomains,
                    aci=[
                        u'(targetattr = "associateddomain || cn || '
                            u'createtimestamp || entryusn || '
                            u'modifytimestamp || objectclass")'
                        u'(targetfilter = "(objectclass=domainrelatedobject)")'
                        u'(version 3.0;acl '
                            u'"permission:System: Read Realm Domains";'
                            u'allow (compare,read,search) '
                            u'userdn = "ldap:///all";)',

                        u'(targetattr = "associateddomain")'
                        u'(targetfilter = "(objectclass=domainrelatedobject)")'
                        u'(version 3.0;acl '
                            u'"permission:System: Modify Realm Domains";'
                            u'allow (write) groupdn = "ldap:///%s";)' %
                                DN('cn=System: Modify Realm Domains',
                                   api.env.container_permission,
                                   api.env.basedn),

                    ],
                ),
            ),
        ),
        dict(
            desc='Replace list of realm domains with "%s"' % [our_domain, new_domain_1],
            command=('realmdomains_mod', [], {'associateddomain': [our_domain, new_domain_1]}),
            expected=dict(
                value=None,
                summary=None,
                result=dict(
                    associateddomain=[our_domain, new_domain_1],
                ),
            ),
        ),
        dict(
            desc='Add domain "%s" to list' % new_domain_2,
            command=('realmdomains_mod', [], {'add_domain': new_domain_2}),
            expected=dict(
                value=None,
                summary=None,
                result=dict(
                    associateddomain=[our_domain, new_domain_1, new_domain_2],
                ),
            ),
        ),
        dict(
            desc='Delete domain "%s" from list' % new_domain_2,
            command=('realmdomains_mod', [], {'del_domain': new_domain_2}),
            expected=dict(
                value=None,
                summary=None,
                result=dict(
                    associateddomain=[our_domain, new_domain_1],
                ),
            ),
        ),
        dict(
            desc='Add domain "%s" and delete domain "%s"' % (new_domain_2, new_domain_1),
            command=('realmdomains_mod', [], {'add_domain': new_domain_2, 'del_domain': new_domain_1}),
            expected=dict(
                value=None,
                summary=None,
                result=dict(
                    associateddomain=[our_domain, new_domain_2],
                ),
            ),
        ),
        dict(
            desc='Try to specify --domain and --add-domain options together',
            command=('realmdomains_mod', [], {
                    'associateddomain': [our_domain, new_domain_1],
                    'add_domain': new_domain_1,
                    }),
            expected=errors.MutuallyExclusiveError(
                reason='you cannot specify the --domain option together with --add-domain or --del-domain'),
        ),
        dict(
            desc='Try to replace list of realm domains with a list without our domain',
            command=('realmdomains_mod', [], {'associateddomain': [new_domain_1]}),
            expected=errors.ValidationError(
                name='domain', error='cannot delete domain of IPA server'),
        ),
        dict(
            desc='Try to replace list of realm domains with a list with an invalid domain "%s"' % bad_domain,
            command=('realmdomains_mod', [], {'associateddomain': [our_domain, bad_domain]}),
            expected=errors.ValidationError(
                name='domain', error='no SOA or NS records found for domains: %s' % bad_domain),
        ),
        dict(
            desc='Try to add an invalid domain "%s"' % bad_domain,
            command=('realmdomains_mod', [], {'add_domain': bad_domain}),
            expected=errors.ValidationError(
                name='add_domain', error='no SOA or NS records found for domain %s' % bad_domain),
        ),
        dict(
            desc='Try to delete our domain',
            command=('realmdomains_mod', [], {'del_domain': our_domain}),
            expected=errors.ValidationError(
                name='del_domain', error='cannot delete domain of IPA server'),
        ),
        dict(
            desc='Try to delete domain which is not in list',
            command=('realmdomains_mod', [], {'del_domain': new_domain_1}),
            expected=errors.AttrValueNotFound(
                attr='associateddomain', value=new_domain_1),
        ),
        dict(
            desc='Add an invalid domain "%s" with --force option' % bad_domain,
            command=('realmdomains_mod', [], {'add_domain': bad_domain, 'force': True}),
            expected=dict(
                value=None,
                summary=None,
                result=dict(
                    associateddomain=[our_domain, new_domain_2, bad_domain],
                ),
            ),
        ),
    ]
