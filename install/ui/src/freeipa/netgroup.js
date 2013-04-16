/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
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

define(['./ipa', './jquery', './details', './search', './association',
       './entity'], function(IPA, $) {

IPA.netgroup = {
    remove_method_priority: IPA.config.default_priority - 1,
    enable_priority: IPA.config.default_priority + 1
};

IPA.netgroup.entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.facet_groups(['settings', 'member', 'memberof']).
        search_facet({
            columns: [
                'cn',
                'description'
            ]
        }).
        details_facet({
            $factory: IPA.netgroup.details_facet,
            entity: that,
            command_mode: 'info'
        }).
        association_facet({
            name: 'memberof_netgroup',
            associator: IPA.serial_associator
        }).
        standard_association_facets().
        adder_dialog({
            fields: [
                'cn',
                {
                    $type: 'textarea',
                    name: 'description'
                }
            ]
        });
    };

    return that;
};

IPA.netgroup.details_facet = function(spec) {

    var entity_name = spec.entity.name;

    //
    // Identity
    //

    spec.fields = [
        {
            name: 'cn',
            widget: 'identity.cn'
        },
        {
            $type: 'textarea',
            name: 'description',
            widget: 'identity.description'
        },
        {
            name: 'nisdomainname',
            widget: 'identity.nisdomainname'
        }
    ];

    spec.widgets = [
        {
            $type: 'details_table_section',
            name: 'identity',
            label: '@i18n:details.general',
            widgets: [
                {
                    name: 'cn'
                },
                {
                    $type: 'textarea',
                    name: 'description'
                },
                {
                    name: 'nisdomainname',
                    widget: 'general.nisdomainname'
                }
            ]
        }
    ];

    //
    // Users
    //

    spec.fields.push(
        {
            $type: 'radio',
            name: 'usercategory',
            widget: 'user.rule.usercategory'
        },
        {
            $type: 'rule_association_table',
            name: 'memberuser_user',
            widget: 'user.rule.memberuser_user',
            priority: IPA.netgroup.remove_method_priority
        },
        {
            $type: 'rule_association_table',
            name: 'memberuser_group',
            widget: 'user.rule.memberuser_group',
            priority: IPA.netgroup.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            $factory: IPA.collapsible_section,
            name: 'user',
            label: '@i18n:objects.netgroup.user',
            widgets: [
                {
                    $factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'usercategory',
                    options: [
                        { value: 'all',
                        label: '@i18n:objects.netgroup.anyone' },
                        { value: '',
                        label: '@i18n:objects.netgroup.specified_users' }
                    ],
                    tables: [
                        { name: 'memberuser_user' },
                        { name: 'memberuser_group' }
                    ],
                    widgets: [
                        {
                            $type: 'rule_association_table',
                            id: entity_name+'-memberuser_user',
                            name: 'memberuser_user',
                            add_method: 'add_member',
                            remove_method: 'remove_member',
                            add_title: '@i18n:association.add.member',
                            remove_title: '@i18n:association.remove.member',
                            columns: [
                                {
                                    name: 'memberuser_user',
                                    label: '@i18n:objects.netgroup.users',
                                    link: true
                                }
                            ]
                        },
                        {
                            $type: 'rule_association_table',
                            id: entity_name+'-memberuser_group',
                            name: 'memberuser_group',
                            add_method: 'add_member',
                            remove_method: 'remove_member',
                            add_title: '@i18n:association.add.member',
                            remove_title: '@i18n:association.remove.member',
                            columns: [
                                {
                                    name: 'memberuser_group',
                                    label: '@i18n:objects.netgroup.usergroups',
                                    link: true
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    );

    //
    // Hosts
    //

    spec.fields.push(
        {
            $type: 'radio',
            name: 'hostcategory',
            widget: 'host.rule.hostcategory'
        },
        {
            $type: 'rule_association_table',
            name: 'memberhost_host',
            widget: 'host.rule.memberhost_host',
            priority: IPA.netgroup.remove_method_priority,
            external: 'externalhost'
        },
        {
            $type: 'rule_association_table',
            name: 'memberhost_hostgroup',
            widget: 'host.rule.memberhost_hostgroup',
            priority: IPA.netgroup.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            $factory: IPA.collapsible_section,
            name: 'host',
            label: '@i18n:objects.netgroup.host',
            widgets: [
                {
                    $factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'hostcategory',
                    options: [
                        {
                            'value': 'all',
                            label: '@i18n:objects.netgroup.any_host'
                        },
                        {
                            'value': '',
                            label: '@i18n:objects.netgroup.specified_hosts'
                        }
                    ],
                    tables: [
                        { 'name': 'memberhost_host' },
                        { 'name': 'memberhost_hostgroup' }
                    ],
                    widgets: [
                        {
                            $type: 'rule_association_table',
                            id: entity_name+'-memberhost_host',
                            name: 'memberhost_host',
                            add_method: 'add_member',
                            remove_method: 'remove_member',
                            external: 'externalhost',
                            add_title: '@i18n:association.add.member',
                            remove_title: '@i18n:association.remove.member',
                            columns: [
                                {
                                    name: 'memberhost_host',
                                    label: '@i18n:objects.netgroup.hosts',
                                    link: true
                                },
                                {
                                    name: 'externalhost',
                                    label: '@i18n:objects.netgroup.external',
                                    formatter: 'boolean',
                                    width: '200px'
                                }
                            ]
                        },
                        {
                            $type: 'rule_association_table',
                            id: entity_name+'-memberhost_hostgroup',
                            name: 'memberhost_hostgroup',
                            add_method: 'add_member',
                            remove_method: 'remove_member',
                            add_title: '@i18n:association.add.member',
                            remove_title: '@i18n:association.remove.member',
                            columns: [
                                {
                                    name: 'memberhost_hostgroup',
                                    label: '@i18n:objects.netgroup.hostgroups',
                                    link: true
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    );

    var that = IPA.details_facet(spec);

    that.update_on_success = function(data, text_status, xhr) {
        that.refresh();
        that.on_update.notify();
        that.nofify_update_success();
    };

    that.update_on_error = function(xhr, text_status, error_thrown) {
        that.refresh();
    };

    return that;
};

IPA.register('netgroup', IPA.netgroup.entity);

return {};
});