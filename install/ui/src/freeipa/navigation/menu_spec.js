/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2012 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

define([], function() {

/**
 * Specification of menu
 * @singleton
 * @class navigation.menu_spec
 */
var nav = {};
    /**
     * Admin menu
     */
    nav.admin = {
    name: 'admin',
    items: [
        {
            name: 'identity',
            label: '@i18n:tabs.identity',
            children: [
                {
                    entity: 'user',
                    facet: 'search',
                    children: [
                        {
                            entity: 'stageuser',
                            facet: 'search',
                            hidden: true
                        },
                        {
                            entity: 'user',
                            facet: 'search_preserved',
                            hidden: true
                        }
                    ]
                },
                { entity: 'host' },
                { entity: 'service' },
                {
                    entity: 'group',
                    label: '@i18n:objects.group.groups',
                    facet: 'search',
                    children: [
                        {
                            entity: 'hostgroup',
                            facet: 'search',
                            hidden: true
                        },
                        {
                            entity: 'netgroup',
                            facet: 'search',
                            hidden: true
                        }
                    ]
                },
                { entity: 'idview' },
                {
                    name: 'automember',
                    label: '@i18n:tabs.automember',
                    children: [
                        {
                            name: 'amgroup',
                            entity: 'automember',
                            facet: 'searchgroup',
                            label: '@i18n:objects.automember.usergrouprules',
                            children: [
                                {
                                    entity: 'automember',
                                    facet: 'usergrouprule',
                                    hidden: true
                                }
                            ]
                        },
                        {
                            name: 'amhostgroup',
                            entity: 'automember',
                            facet: 'searchhostgroup',
                            label: '@i18n:objects.automember.hostgrouprules',
                            children: [
                                {
                                    entity: 'automember',
                                    facet: 'hostgrouprule',
                                    hidden: true
                                }
                            ]
                        }
                    ]
                }
            ]
        },
        {
            name: 'policy',
            label: '@i18n:tabs.policy',
            children: [
                {
                    name: 'hbac',
                    label: '@i18n:tabs.hbac',
                    children: [
                        { entity: 'hbacrule' },
                        { entity: 'hbacsvc' },
                        { entity: 'hbacsvcgroup' },
                        { entity: 'hbactest' }
                    ]
                },
                {
                    name: 'sudo',
                    label: '@i18n:tabs.sudo',
                    children: [
                        { entity: 'sudorule' },
                        { entity: 'sudocmd' },
                        { entity: 'sudocmdgroup' }
                    ]
                },
                { entity: 'selinuxusermap' },
                { entity: 'pwpolicy' },
                { entity: 'krbtpolicy' }
            ]
        },
        {
            name: 'authentication',
            label: '@i18n:tabs.authentication',
            children: [
                {
                    entity: 'cert',
                    facet: 'search',
                    label: '@i18n:tabs.cert',
                    children: [
                        {
                            entity: 'certprofile',
                            facet: 'search',
                            hidden: true
                        },
                        {
                            entity: 'cert',
                            facet: 'search',
                            hidden: true
                        },
                        {
                            entity: 'caacl',
                            facet: 'search',
                            hidden: true
                        },
                        {
                            entity: 'ca',
                            facet: 'search',
                            hidden: true
                        }
                    ]
                },
                { entity: 'otptoken' },
                { entity: 'radiusproxy' }
            ]
        },
        {
            name: 'network_services',
            label: '@i18n:tabs.network_services',
            children: [
                {
                    name:'automount',
                    label: '@i18n:tabs.automount',
                    entity: 'automountlocation',
                    children: [
                        { entity: 'automountlocation', hidden: true },
                        { entity: 'automountmap', hidden: true },
                        { entity: 'automountkey', hidden: true }
                    ]
                },
                {
                    name:'dns',
                    label: '@i18n:tabs.dns',
                    children: [
                        {
                            entity: 'dnszone',
                            children: [
                                { entity: 'dnsrecord', hidden: true }
                            ]
                        },
                        { entity: 'dnsforwardzone' },
                        { entity: 'dnsserver' },
                        { entity: 'dnsconfig' }
                    ]
                }
            ]
        },
        {
            name: 'ipaserver',
            label: '@i18n:tabs.ipaserver',
            children: [
                {
                    name: 'rbac',
                    label: '@i18n:tabs.role',
                    children: [
                        { entity: 'role' },
                        { entity: 'privilege' },
                        { entity: 'permission' },
                        { entity: 'selfservice' },
                        { entity: 'delegation' }
                    ]
                },
                { entity: 'idrange' },
                { entity: 'realmdomains' },
                {
                    name: 'trusts',
                    label: '@i18n:tabs.trust',
                    children: [
                        { entity: 'trust' },
                        { entity: 'trustconfig' }
                    ]
                },
                {
                    entity: 'server',
                    label: '@i18n:tabs.topology',
                    facet: 'search',
                    children: [
                        {
                            entity: 'topologysuffix',
                            facet: 'search',
                            hidden: true
                        },
                        {
                            entity: 'server',
                            facet: 'search',
                            hidden: true
                        },
                        {
                            entity: 'server_role',
                            facet: 'search',
                            hidden: true
                        },
                        {
                            entity: 'domainlevel',
                            facet: 'details',
                            hidden: true
                        },
                        {
                            entity: 'location',
                            facet: 'search',
                            hidden: true
                        },
                        {
                            facet: 'topology-graph',
                            hidden: true
                        }
                    ]
                },
                {
                    name: 'apibrowser',
                    label: '@i18n:widget.api_browser',
                    facet: 'apibrowser',
                    args: { 'type': 'command' }
                },
                { entity: 'config' }
            ]
        }
    ]
};

/**
 * Self-service menu
 */
nav.self_service = {
    name: 'self-service',
    items: [
        { entity: 'user' },
        { entity: 'otptoken' }
    ]
};

return nav;
});
