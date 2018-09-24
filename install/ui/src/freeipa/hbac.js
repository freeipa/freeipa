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

define([
        './ipa',
        './jquery',
        './phases',
        './reg',
        './rpc',
        './association',
        './details',
        './entity',
        './rule',
        './search'
        ],
            function(IPA, $, phases, reg, rpc) {

var exp = IPA.hbac = {
    //priority of commands in details facet
    remove_method_priority: IPA.config.default_priority - 1
};

var make_rule_spec = function() {
var spec =  {
    name: 'hbacrule',
    facets: [
        {
            $type: 'search',
            row_enabled_attribute: 'ipaenabledflag',
            columns: [
                'cn',
                {
                    name: 'ipaenabledflag',
                    label: '@i18n:status.label',
                    formatter: 'boolean_status'
                },
                'description'
            ],
            actions: [
                'batch_disable',
                'batch_enable'
            ],
            control_buttons: [
                {
                    name: 'disable',
                    label: '@i18n:buttons.disable',
                    icon: 'fa-minus'
                },
                {
                    name: 'enable',
                    label: '@i18n:buttons.enable',
                    icon: 'fa-check'
                }
            ]
        },
        {
            $type: 'details',
            $factory: IPA.hbacrule_details_facet,
            command_mode: 'info',
            actions: [
                'select',
                'enable',
                'disable',
                'delete'
            ],
            header_actions: ['enable', 'disable', 'delete'],
            state: {
                evaluators: [
                    {
                        $factory: IPA.enable_state_evaluator,
                        field: 'ipaenabledflag'
                    }
                ],
                summary_conditions: [
                    IPA.enabled_summary_cond,
                    IPA.disabled_summary_cond
                ]
            }
        }
    ],
    adder_dialog: {
        title: '@i18n:objects.hbacrule.add',
        fields: [ 'cn' ]
    },
    deleter_dialog: {
        title: '@i18n:objects.hbacrule.remove'
    }
};

    add_hbacrule_details_facet_widgets(spec.facets[1]);
    return spec;
};

var make_service_spec = function() {
return {
    name: 'hbacsvc',
    facets: [
        {
            $type: 'search',
            columns: [
                'cn',
                'description'
            ]
        },
        {
            $type: 'details',
            sections: [
                {
                    name: 'general',
                    label: '@i18n:details.general',
                    fields: [
                        'cn',
                        {
                            $type: 'textarea',
                            name: 'description'
                        }
                    ]
                }
            ]
        },
        {
            $type: 'association',
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
            ],
            add_title: '@i18n:objects.hbacsvc.add_hbacsvcgroups',
            remove_title: '@i18n:objects.hbacsvc.remove_from_hbacsvcgroups'
        }
    ],
    standard_association_facets: true,
    adder_dialog: {
        title: '@i18n:objects.hbacsvc.add',
        fields: [
            'cn',
            {
                $type: 'textarea',
                name: 'description'
            }
        ]
    },
    deleter_dialog: {
        title: '@i18n:objects.hbacsvc.remove'
    }
};};

var make_service_group_spec = function() {
return {
    name: 'hbacsvcgroup',
    facets: [
        {
            $type: 'search',
            columns: [
                'cn',
                'description'
            ]
        },
        {
            $type: 'details',
            sections: [
                {
                    name: 'general',
                    label: '@i18n:details.general',
                    fields: [
                        'cn',
                        {
                            $type: 'textarea',
                            name: 'description'
                        }
                    ]
                }
            ]
        },
        {
            $type: 'association',
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
            ],
            add_title: '@i18n:objects.hbacsvcgroup.add_hbacsvcs',
            remove_title: '@i18n:objects.hbacsvcgroup.remove_hbacsvcs'
        }
    ],
    standard_association_facets: true,
    adder_dialog: {
        title: '@i18n:objects.hbacsvcgroup.add',
        fields: [
            'cn',
            {
                $type: 'textarea',
                name: 'description'
            }
        ]
    },
    deleter_dialog: {
        title: '@i18n:objects.hbacsvcgroup.remove'
    }
};};

/**
 * @ignore
 * @param {Object} facet spec
 */
var add_hbacrule_details_facet_widgets = function (spec) {

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
            $type: 'textarea',
            name: 'description',
            widget: 'general.description'
        }
    ];

    spec.widgets = [
        {
            $type: 'details_section',
            name: 'general',
            label: '@i18n:details.general',
            widgets: [
                {
                    name: 'cn'
                },
                {
                    $type: 'textarea',
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
            $type: 'radio',
            name: 'usercategory',
            widget: 'user.rule.usercategory'
        },
        {
            $type: 'rule_association_table',
            name: 'memberuser_user',
            widget: 'user.rule.memberuser_user',
            priority: IPA.hbac.remove_method_priority
        },
        {
            $type: 'rule_association_table',
            name: 'memberuser_group',
            widget: 'user.rule.memberuser_group',
            priority: IPA.hbac.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            $factory: IPA.section,
            name: 'user',
            label: '@i18n:objects.hbacrule.user',
            widgets: [
                {
                    $factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'usercategory',
                    options: [
                        { value: 'all',
                        label: '@i18n:objects.hbacrule.anyone' },
                        { value: '',
                        label: '@i18n:objects.hbacrule.specified_users' }
                    ],
                    tables: [
                        { name: 'memberuser_user' },
                        { name: 'memberuser_group' }
                    ],
                    widgets: [
                        {
                            $type: 'rule_association_table',
                            id: 'hbacrule-memberuser_user',
                            name: 'memberuser_user',
                            add_method: 'add_user',
                            remove_method: 'remove_user',
                            add_title: '@i18n:association.add.member',
                            remove_title: '@i18n:objects.hbacrule.remove_users'
                        },
                        {
                            $type: 'rule_association_table',
                            id: 'hbacrule-memberuser_group',
                            name: 'memberuser_group',
                            add_method: 'add_user',
                            remove_method: 'remove_user',
                            add_title: '@i18n:association.add.member',
                            remove_title: '@i18n:objects.hbacrule.remove_groups'
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
            priority: IPA.hbac.remove_method_priority
        },
        {
            $type: 'rule_association_table',
            name: 'memberhost_hostgroup',
            widget: 'host.rule.memberhost_hostgroup',
            priority: IPA.hbac.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            $factory: IPA.section,
            name: 'host',
            label: '@i18n:objects.hbacrule.host',
            widgets: [
                {
                    $factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'hostcategory',
                    options: [
                        {
                            'value': 'all',
                            'label': '@i18n:objects.hbacrule.any_host'
                        },
                        {
                            'value': '',
                            'label': '@i18n:objects.hbacrule.specified_hosts'
                        }
                    ],
                    tables: [
                        { 'name': 'memberhost_host' },
                        { 'name': 'memberhost_hostgroup' }
                    ],
                    widgets: [
                        {
                            $type: 'rule_association_table',
                            id: 'hbacrule-memberuser_user',
                            name: 'memberhost_host',
                            add_method: 'add_host',
                            remove_method: 'remove_host',
                            add_title: '@i18n:association.add.member',
                            remove_title: '@i18n:objects.hbacrule.remove_hosts'
                        },
                        {
                            $type: 'rule_association_table',
                            id: 'hbacrule-memberuser_group',
                            name: 'memberhost_hostgroup',
                            add_method: 'add_host',
                            remove_method: 'remove_host',
                            add_title: '@i18n:association.add.member',
                            remove_title: '@i18n:objects.hbacrule.remove_hostgroups'
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
            $type: 'radio',
            name: 'servicecategory',
            widget: 'service.rule.servicecategory'
        },
        {
            $type: 'rule_association_table',
            name: 'memberservice_hbacsvc',
            widget: 'service.rule.memberservice_hbacsvc',
            priority: IPA.hbac.remove_method_priority
        },
        {
            $type: 'rule_association_table',
            name: 'memberservice_hbacsvcgroup',
            widget: 'service.rule.memberservice_hbacsvcgroup',
            priority: IPA.hbac.remove_method_priority
        }
    );

    spec.widgets.push(
    {
            $factory: IPA.section,
            name: 'service',
            label: '@i18n:objects.hbacrule.service',
            widgets: [
                {
                    $factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'servicecategory',
                    options: [
                        { 'value': 'all', 'label': '@i18n:objects.hbacrule.any_service' },
                        { 'value': '', 'label': '@i18n:objects.hbacrule.specified_services' }
                    ],
                    tables: [
                        { 'name': 'memberservice_hbacsvc' },
                        { 'name': 'memberservice_hbacsvcgroup' }
                    ],
                    widgets: [
                        {
                            $type: 'rule_association_table',
                            id: 'hbacrule-memberuser_user',
                            name: 'memberservice_hbacsvc',
                            add_method: 'add_service',
                            remove_method: 'remove_service',
                            add_title: '@i18n:association.add.member',
                            remove_title: '@i18n:objects.hbacrule.remove_services'
                        },
                        {
                            $type: 'rule_association_table',
                            id: 'hbacrule-memberuser_group',
                            name: 'memberservice_hbacsvcgroup',
                            add_method: 'add_service',
                            remove_method: 'remove_service',
                            add_title: '@i18n:association.add.member',
                            remove_title: '@i18n:objects.hbacrule.remove_servicegroups'
                        }
                    ]
                }
            ]
        }
    );
};

IPA.hbacrule_details_facet = function(spec) {

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

exp.rule_spec = make_rule_spec();
exp.svc_spec = make_service_spec();
exp.svcgroup_spec = make_service_group_spec();
exp.register = function() {
    var e = reg.entity;
    e.register({type: 'hbacrule', spec: exp.rule_spec});
    e.register({type: 'hbacsvc', spec: exp.svc_spec});
    e.register({type: 'hbacsvcgroup', spec: exp.svcgroup_spec});
};
phases.on('registration', exp.register);

return exp;
});
