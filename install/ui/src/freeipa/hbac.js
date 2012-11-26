/*jsl:import ipa.js */

/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
 *    Adam Young <ayoung@redhat.com>
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

/* REQUIRES: ipa.js, details.js, search.js, add.js, facet.js, entity.js */

IPA.hbac = {
    //priority of commands in details facet
    remove_method_priority: IPA.config.default_priority - 1
};

IPA.hbac.rule_entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.search_facet({
            row_enabled_attribute: 'ipaenabledflag',
            search_all_attributes: true,
            columns: [
                'cn',
                {
                    name: 'ipaenabledflag',
                    label: IPA.messages.status.label,
                    formatter: IPA.boolean_status_formatter()
                },
                'description'
            ],
            actions: [
                IPA.batch_disable_action,
                IPA.batch_enable_action
            ],
            control_buttons: [
                {
                    name: 'disable',
                    label: IPA.messages.buttons.disable,
                    icon: 'disabled-icon'
                },
                {
                    name: 'enable',
                    label: IPA.messages.buttons.enable,
                    icon: 'enabled-icon'
                }
            ]
        }).
        details_facet({
            factory: IPA.hbacrule_details_facet,
            entity: that,
            command_mode: 'info',
            actions: [
                IPA.select_action,
                IPA.enable_action,
                IPA.disable_action,
                IPA.delete_action
            ],
            header_actions: ['select_action', 'enable', 'disable', 'delete'],
            state: {
                evaluators: [
                    {
                        factory: IPA.enable_state_evaluator,
                        field: 'ipaenabledflag'
                    }
                ],
                summary_conditions: [
                    IPA.enabled_summary_cond(),
                    IPA.disabled_summary_cond()
                ]
            }
        }).
        adder_dialog({
            fields: [ 'cn' ]
        });
    };

    return that;
};

IPA.hbac.service_entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.search_facet({
            columns: [
                'cn',
                'description'
            ]
        }).
        details_facet({
            sections: [
                {
                    name: 'general',
                    label: IPA.messages.details.general,
                    fields: [
                        'cn',
                        {
                            type: 'textarea',
                            name: 'description'
                        }
                    ]
                }
            ]
        }).
        association_facet({
            name: 'memberof_hbacsvcgroup',
            associator: IPA.serial_associator,
            columns:[
                'cn',
                'description'
            ],
            adder_columns: [
                {
                    name: 'cn',
                    primary_key: true,
                    width: '100px'
                },
                {
                    name: 'description',
                    width: '100px'
                }
            ]
        }).
        standard_association_facets().
        adder_dialog({
            fields: [
                'cn',
                {
                    type: 'textarea',
                    name: 'description'
                }
            ]
        });
    };

    return that;
};

IPA.hbac.service_group_entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.search_facet({
            columns: [
                'cn',
                'description'
            ]
        }).
        details_facet({
            sections: [
                {
                    name: 'general',
                    label: IPA.messages.details.general,
                    fields: [
                        'cn',
                        {
                            type: 'textarea',
                            name: 'description'
                        }
                    ]
                }
            ]
        }).
        association_facet({
            name: 'member_hbacsvc',
            columns:[
                'cn',
                'description'
            ],
            adder_columns: [
                {
                    name: 'cn',
                    primary_key: true,
                    width: '100px'
                },
                {
                    name: 'description',
                    width: '100px'
                }
            ]
        }).
        standard_association_facets().
        adder_dialog({
            fields: [
                'cn',
                {
                    type: 'textarea',
                    name: 'description'
                }
            ]
        });
    };

    return that;
};

IPA.hbacrule_details_facet = function(spec) {

    var entity_name = spec.entity.name;

    //
    // General
    //

    spec.fields = [
        {
            name: 'cn',
            read_only: true,
            widget: 'general.cn'
        },
        {
            type: 'textarea',
            name: 'description',
            widget: 'general.description'
        }
    ];

    spec.widgets = [
        {
            type: 'details_table_section',
            name: 'general',
            label: IPA.messages.details.general,
            widgets: [
                {
                    name: 'cn'
                },
                {
                    type: 'textarea',
                    name: 'description'
                }
            ]
        }
    ];

    //
    // Users
    //

    spec.fields.push(
        {
            type: 'radio',
            name: 'usercategory',
            widget: 'user.rule.usercategory'
        },
        {
            type: 'rule_association_table',
            name: 'memberuser_user',
            widget: 'user.rule.memberuser_user',
            priority: IPA.hbac.remove_method_priority
        },
        {
            type: 'rule_association_table',
            name: 'memberuser_group',
            widget: 'user.rule.memberuser_group',
            priority: IPA.hbac.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            factory: IPA.collapsible_section,
            name: 'user',
            label: IPA.messages.objects.hbacrule.user,
            widgets: [
                {
                    factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'usercategory',
                    options: [
                        { value: 'all',
                        label: IPA.messages.objects.hbacrule.anyone },
                        { value: '',
                        label: IPA.messages.objects.hbacrule.specified_users }
                    ],
                    tables: [
                        { name: 'memberuser_user' },
                        { name: 'memberuser_group' }
                    ],
                    widgets: [
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-memberuser_user',
                            name: 'memberuser_user',
                            add_method: 'add_user',
                            remove_method: 'remove_user',
                            add_title: IPA.messages.association.add.member,
                            remove_title: IPA.messages.association.remove.member
                        },
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-memberuser_group',
                            name: 'memberuser_group',
                            add_method: 'add_user',
                            remove_method: 'remove_user',
                            add_title: IPA.messages.association.add.member,
                            remove_title: IPA.messages.association.remove.member
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
            type: 'radio',
            name: 'hostcategory',
            widget: 'host.rule.hostcategory'
        },
        {
            type: 'rule_association_table',
            name: 'memberhost_host',
            widget: 'host.rule.memberhost_host',
            priority: IPA.hbac.remove_method_priority
        },
        {
            type: 'rule_association_table',
            name: 'memberhost_hostgroup',
            widget: 'host.rule.memberhost_hostgroup',
            priority: IPA.hbac.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            factory: IPA.collapsible_section,
            name: 'host',
            label: IPA.messages.objects.hbacrule.host,
            widgets: [
                {
                    factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'hostcategory',
                    options: [
                        {
                            'value': 'all',
                            'label': IPA.messages.objects.hbacrule.any_host
                        },
                        {
                            'value': '',
                            'label': IPA.messages.objects.hbacrule.specified_hosts
                        }
                    ],
                    tables: [
                        { 'name': 'memberhost_host' },
                        { 'name': 'memberhost_hostgroup' }
                    ],
                    widgets: [
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-memberuser_user',
                            name: 'memberhost_host',
                            add_method: 'add_host',
                            remove_method: 'remove_host',
                            add_title: IPA.messages.association.add.member,
                            remove_title: IPA.messages.association.remove.member
                        },
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-memberuser_group',
                            name: 'memberhost_hostgroup',
                            add_method: 'add_host',
                            remove_method: 'remove_host',
                            add_title: IPA.messages.association.add.member,
                            remove_title: IPA.messages.association.remove.member
                        }
                    ]
                }
            ]
        }
    );

    //
    // Service
    //

    spec.fields.push(
        {
            type: 'radio',
            name: 'servicecategory',
            widget: 'service.rule.servicecategory'
        },
        {
            type: 'rule_association_table',
            name: 'memberservice_hbacsvc',
            widget: 'service.rule.memberservice_hbacsvc',
            priority: IPA.hbac.remove_method_priority
        },
        {
            type: 'rule_association_table',
            name: 'memberservice_hbacsvcgroup',
            widget: 'service.rule.memberservice_hbacsvcgroup',
            priority: IPA.hbac.remove_method_priority
        }
    );

    spec.widgets.push(
    {
            factory: IPA.collapsible_section,
            name: 'service',
            label: IPA.messages.objects.hbacrule.service,
            widgets: [
                {
                    factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'servicecategory',
                    options: [
                        { 'value': 'all', 'label': IPA.messages.objects.hbacrule.any_service },
                        { 'value': '', 'label': IPA.messages.objects.hbacrule.specified_services }
                    ],
                    tables: [
                        { 'name': 'memberservice_hbacsvc' },
                        { 'name': 'memberservice_hbacsvcgroup' }
                    ],
                    widgets: [
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-memberuser_user',
                            name: 'memberservice_hbacsvc',
                            add_method: 'add_service',
                            remove_method: 'remove_service',
                            add_title: IPA.messages.association.add.member,
                            remove_title: IPA.messages.association.remove.member
                        },
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-memberuser_group',
                            name: 'memberservice_hbacsvcgroup',
                            add_method: 'add_service',
                            remove_method: 'remove_service',
                            add_title: IPA.messages.association.add.member,
                            remove_title: IPA.messages.association.remove.member
                        }
                    ]
                }
            ]
        }
    );

    //
    // Source host
    //

    spec.fields.push(
        {
            type: 'radio',
            name: 'sourcehostcategory',
            widget: 'sourcehost.rule.sourcehostcategory'
        },
        {
            type: 'rule_association_table',
            name: 'sourcehost_host',
            widget: 'sourcehost.rule.sourcehost_host',
            priority: IPA.hbac.remove_method_priority
        },
        {
            type: 'rule_association_table',
            name: 'sourcehost_hostgroup',
            widget: 'sourcehost.rule.sourcehost_hostgroup',
            priority: IPA.hbac.remove_method_priority
        }
    );

    spec.widgets.push(
    {
            factory: IPA.collapsible_section,
            name: 'sourcehost',
            label: IPA.messages.objects.hbacrule.sourcehost,
            widgets: [
                {
                    factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'sourcehostcategory',
                    options: [
                        { 'value': 'all', 'label': IPA.messages.objects.hbacrule.any_host },
                        { 'value': '', 'label': IPA.messages.objects.hbacrule.specified_hosts }
                    ],
                    tables: [
                        { 'name': 'sourcehost_host' },
                        { 'name': 'sourcehost_hostgroup' }
                    ],
                    widgets: [
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-memberuser_user',
                            name: 'sourcehost_host',
                            add_method: 'add_sourcehost',
                            remove_method: 'remove_sourcehost',
                            add_title: IPA.messages.association.add.sourcehost,
                            remove_title: IPA.messages.association.remove.sourcehost
                        },
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-memberuser_group',
                            name: 'sourcehost_hostgroup',
                            add_method: 'add_sourcehost',
                            remove_method: 'remove_sourcehost',
                            add_title: IPA.messages.association.add.sourcehost,
                            remove_title: IPA.messages.association.remove.sourcehost
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

IPA.register('hbacrule', IPA.hbac.rule_entity);
IPA.register('hbacsvc', IPA.hbac.service_entity);
IPA.register('hbacsvcgroup', IPA.hbac.service_group_entity);
