//
// Copyright (C) 2015  FreeIPA Contributors see COPYING for license
//

define([
    '../ipa',
    '../jquery',
    '../phases',
    '../reg',
    '../certificate',
    '../rule'
],
function(IPA, $, phases, reg, cert) {
/**
 * caacl module
 * @class plugins.caacl
 * @singleton
 */
var caacl = IPA.caacl = {
    remove_method_priority: IPA.config.default_priority - 1
};

var make_caacl_spec = function() {
var spec = {
    name: 'caacl',
    facets: [
        {
            $type: 'search',
            disable_facet_tabs: false,
            tabs_in_sidebar: true,
            tab_label: '@mo:caacl.label',
            facet_groups: [cert.facet_group],
            facet_group: 'certificates',
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
            $factory: IPA.sudorule_details_facet,
            disable_facet_tabs: true,
            command_mode: 'info',
            actions: [
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
        title: '@i18n:objects.caacl.add',
        fields: [
            'cn',
            {
                $type: 'checkboxes',
                name: 'ipacacategory',
                options: [
                    {
                        label: '@i18n:objects.caacl.all',
                        value: 'all'
                    }
                ],
                tooltip: '@i18n:objects.caacl.no_ca_msg'
            },
            {
                $type: 'textarea',
                name: 'description'
            }
        ]
    },
    deleter_dialog: {
        title: '@i18n:objects.caacl.remove'
    }
};

    add_caacl_details_facet_widgets(spec.facets[1]);
    return spec;
};

/**
 * @ignore
 * @param {Object} facet spec
 */
var add_caacl_details_facet_widgets = function (spec) {

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
    // Cert Profiles
    //

    spec.fields.push(
        {
            $type: 'radio',
            name: 'ipacertprofilecategory',
            widget: 'certprofile.rule.ipacertprofilecategory'
        },
        {
            $type: 'rule_association_table',
            name: 'ipamembercertprofile_certprofile',
            widget: 'certprofile.rule.ipamembercertprofile_certprofile',
            priority: IPA.caacl.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            $factory: IPA.section,
            name: 'certprofile',
            label: '@i18n:objects.caacl.profile',
            widgets: [
                {
                    $factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'ipacertprofilecategory',
                    options: [
                        { value: 'all',
                        label: '@i18n:objects.caacl.any_profile' },
                        { value: '',
                        label: '@i18n:objects.caacl.specified_profiles' }
                    ],
                    tables: [
                        { name: 'ipamembercertprofile_certprofile' }
                    ],
                    widgets: [
                        {
                            $type: 'rule_association_table',
                            id: 'caacl-ipamembercertprofile_certprofile',
                            name: 'ipamembercertprofile_certprofile',
                            add_method: 'add_profile',
                            remove_method: 'remove_profile',
                            add_title: '@i18n:objects.caacl.add_profiles',
                            remove_title: '@i18n:objects.caacl.remove_profiles'
                        }
                    ]
                }
            ]
        }
    );

    //
    // Who
    //

    spec.fields.push(
        // users
        {
            $type: 'radio',
            name: 'usercategory',
            widget: 'who.user.usercategory'
        },
        {
            $type: 'rule_association_table',
            name: 'memberuser_user',
            widget: 'who.user.memberuser_user',
            priority: IPA.caacl.remove_method_priority
        },
        {
            $type: 'rule_association_table',
            name: 'memberuser_group',
            widget: 'who.user.memberuser_group',
            priority: IPA.caacl.remove_method_priority
        },

        // hosts
        {
            $type: 'radio',
            name: 'hostcategory',
            widget: 'who.host.hostcategory'
        },
        {
            $type: 'rule_association_table',
            name: 'memberhost_host',
            widget: 'who.host.memberhost_host',
            priority: IPA.caacl.remove_method_priority
        },
        {
            $type: 'rule_association_table',
            name: 'memberhost_hostgroup',
            widget: 'who.host.memberhost_hostgroup',
            priority: IPA.caacl.remove_method_priority
        },

        // services
        {
            $type: 'radio',
            name: 'servicecategory',
            widget: 'who.service.servicecategory'
        },
        {
            $type: 'rule_association_table',
            name: 'memberservice_service',
            widget: 'who.service.memberservice_service',
            priority: IPA.caacl.remove_method_priority
        },
        // ca
        {
            $type: 'radio',
            name: 'ipacacategory',
            widget: 'who.ipaca.ipacacategory'
        },
        {
            $type: 'rule_association_table',
            name: 'ipamemberca_ca',
            widget: 'who.ipaca.ipamemberca_ca',
            priority: IPA.caacl.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            $factory: IPA.section,
            name: 'who',
            label: '@i18n:objects.caacl.who',
            widgets: [
                {
                    $factory: IPA.rule_details_widget,
                    name: 'user',
                    radio_name: 'usercategory',
                    options: [
                        { value: 'all',
                        label: '@i18n:objects.caacl.anyone' },
                        { value: '',
                        label: '@i18n:objects.caacl.specified_users' }
                    ],
                    tables: [
                        { name: 'memberuser_user' },
                        { name: 'memberuser_group' }
                    ],
                    widgets: [
                        {
                            $type: 'rule_association_table',
                            id: 'caacl-memberuser_user',
                            name: 'memberuser_user',
                            add_method: 'add_user',
                            remove_method: 'remove_user',
                            add_title: '@i18n:objects.caacl.add_users',
                            remove_title: '@i18n:objects.caacl.remove_users'
                        },
                        {
                            $type: 'rule_association_table',
                            id: 'caacl-memberuser_group',
                            name: 'memberuser_group',
                            add_method: 'add_user',
                            remove_method: 'remove_user',
                            add_title: '@i18n:objects.caacl.add_groups',
                            remove_title: '@i18n:objects.caacl.remove_groups'
                        }
                    ]
                },
                {
                    $factory: IPA.rule_details_widget,
                    name: 'host',
                    radio_name: 'hostcategory',
                    options: [
                        {
                            'value': 'all',
                            'label': '@i18n:objects.caacl.any_host'
                        },
                        {
                            'value': '',
                            'label': '@i18n:objects.caacl.specified_hosts'
                        }
                    ],
                    tables: [
                        { 'name': 'memberhost_host' },
                        { 'name': 'memberhost_hostgroup' }
                    ],
                    widgets: [
                        {
                            $type: 'rule_association_table',
                            id: 'caacl-memberuser_user',
                            name: 'memberhost_host',
                            add_method: 'add_host',
                            remove_method: 'remove_host',
                            add_title: '@i18n:objects.caacl.add_hosts',
                            remove_title: '@i18n:objects.caacl.remove_hosts'
                        },
                        {
                            $type: 'rule_association_table',
                            id: 'caacl-memberuser_group',
                            name: 'memberhost_hostgroup',
                            add_method: 'add_host',
                            remove_method: 'remove_host',
                            add_title: '@i18n:objects.caacl.add_hostgroups',
                            remove_title: '@i18n:objects.caacl.remove_hostgroups'
                        }
                    ]
                },
                {
                    $factory: IPA.rule_details_widget,
                    name: 'service',
                    radio_name: 'servicecategory',
                    options: [
                        { 'value': 'all', 'label': '@i18n:objects.caacl.any_service' },
                        { 'value': '', 'label': '@i18n:objects.caacl.specified_services' }
                    ],
                    tables: [
                        { 'name': 'memberservice_service' }
                    ],
                    widgets: [
                        {
                            $type: 'rule_association_table',
                            id: 'caacl-memberservice_service',
                            name: 'memberservice_service',
                            add_method: 'add_service',
                            remove_method: 'remove_service',
                            add_title: '@i18n:objects.caacl.add_services',
                            remove_title: '@i18n:objects.caacl.remove_services'
                        }
                    ]
                },
                {
                    $factory: IPA.rule_details_widget,
                    name: 'ipaca',
                    radio_name: 'ipacacategory',
                    note: '@i18n:objects.caacl.no_ca_msg',
                    options: [
                        { 'value': 'all', 'label': '@i18n:objects.caacl.any_ca' },
                        { 'value': '', 'label': '@i18n:objects.caacl.specified_cas' }
                    ],
                    tables: [
                        { 'name': 'ipamemberca_ca' }
                    ],
                    widgets: [
                        {
                            $type: 'rule_association_table',
                            id: 'caacl-ipamemberca_ca',
                            name: 'ipamemberca_ca',
                            add_method: 'add_ca',
                            remove_method: 'remove_ca',
                            add_title: '@i18n:objects.caacl.add_ca',
                            remove_title: '@i18n:objects.caacl.remove_ca'
                        }
                    ]
                }
            ]
        }
    );
};

/**
 * CAACL entity specification object
 * @member plugins.caacl
 */
caacl.caacl_spec = make_caacl_spec();


/**
 * Register entity
 * @member plugins.caacl
 */
caacl.register = function() {
    var e = reg.entity;
    e.register({type: 'caacl', spec: caacl.caacl_spec});
};

phases.on('registration', caacl.register);

return caacl;
});
