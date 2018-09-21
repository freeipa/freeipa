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

define([
        './ipa',
        './jquery',
        './phases',
        './reg',
        './association',
        './entity',
        './details',
        './rule',
        './search'
        ],
            function(IPA, $, phases, reg) {

var exp = IPA.selinux = {
    remove_method_priority: IPA.config.default_priority - 1
};

var make_spec = function() {
var spec = {
    name: 'selinuxusermap',
    facets: [
        {
            $type: 'search',
            row_enabled_attribute: 'ipaenabledflag',
            columns: [
                'cn',
                'ipaselinuxuser',
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
            $factory: IPA.selinux_details_facet,
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
        title: '@i18n:objects.selinuxusermap.add',
        fields: [
            'cn',
            'ipaselinuxuser'
        ]
    },
    deleter_dialog: {
        title: '@i18n:objects.selinuxusermap.remove'
    }
};

    add_selinux_details_facet_widgets(spec.facets[1]);
    return spec;
};


/**
 * @ignore
 * @param {Object} facet spec
 */
var add_selinux_details_facet_widgets = function (spec) {

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
        },
        {
            name: 'ipaselinuxuser',
            widget: 'general.ipaselinuxuser'
        },
        {
            $type: 'entity_select',
            name: 'seealso',
            widget: 'general.seealso'
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
                },
                {
                    name: 'ipaselinuxuser',
                    widget: 'general.ipaselinuxuser'
                },
                {
                    $type: 'entity_select',
                    name: 'seealso',
                    other_entity: 'hbacrule',
                    other_field: 'cn'
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
            priority: IPA.selinux.remove_method_priority
        },
        {
            $type: 'rule_association_table',
            name: 'memberuser_group',
            widget: 'user.rule.memberuser_group',
            priority: IPA.selinux.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            $factory: IPA.section,
            name: 'user',
            label: '@i18n:objects.selinuxusermap.user',
            widgets: [
                {
                    $factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'usercategory',
                    options: [
                        { value: 'all',
                        label: '@i18n:objects.selinuxusermap.anyone' },
                        { value: '',
                        label: '@i18n:objects.selinuxusermap.specified_users' }
                    ],
                    tables: [
                        { name: 'memberuser_user' },
                        { name: 'memberuser_group' }
                    ],
                    widgets: [
                        {
                            $type: 'rule_association_table',
                            id: 'selinuxusermap-memberuser_user',
                            name: 'memberuser_user',
                            add_method: 'add_user',
                            remove_method: 'remove_user',
                            add_title: '@i18n:association.add.member',
                            remove_title: '@i18n:objects.selinuxusermap.remove_users'
                        },
                        {
                            $type: 'rule_association_table',
                            id: 'selinuxusermap-memberuser_group',
                            name: 'memberuser_group',
                            add_method: 'add_user',
                            remove_method: 'remove_user',
                            add_title: '@i18n:association.add.member',
                            remove_title: '@i18n:objects.selinuxusermap.remove_groups'
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
            priority: IPA.selinux.remove_method_priority
        },
        {
            $type: 'rule_association_table',
            name: 'memberhost_hostgroup',
            widget: 'host.rule.memberhost_hostgroup',
            priority: IPA.selinux.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            $factory: IPA.section,
            name: 'host',
            label: '@i18n:objects.selinuxusermap.host',
            widgets: [
                {
                    $factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'hostcategory',
                    options: [
                        {
                            'value': 'all',
                            label: '@i18n:objects.selinuxusermap.any_host'
                        },
                        {
                            'value': '',
                            label: '@i18n:objects.selinuxusermap.specified_hosts'
                        }
                    ],
                    tables: [
                        { 'name': 'memberhost_host' },
                        { 'name': 'memberhost_hostgroup' }
                    ],
                    widgets: [
                        {
                            $type: 'rule_association_table',
                            id: 'selinuxusermap-memberuser_user',
                            name: 'memberhost_host',
                            add_method: 'add_host',
                            remove_method: 'remove_host',
                            add_title: '@i18n:association.add.member',
                            remove_title: '@i18n:objects.selinuxusermap.remove_hosts'
                        },
                        {
                            $type: 'rule_association_table',
                            id: 'selinuxusermap-memberuser_group',
                            name: 'memberhost_hostgroup',
                            add_method: 'add_host',
                            remove_method: 'remove_host',
                            add_title: '@i18n:association.add.member',
                            remove_title: '@i18n:objects.selinuxusermap.remove_hostgroups'
                        }
                    ]
                }
            ]
        }
    );
};

IPA.selinux_details_facet = function(spec) {

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

exp.entity_spec = make_spec();
exp.register = function() {
    var e = reg.entity;
    e.register({type: 'selinuxusermap', spec: exp.entity_spec});
};
phases.on('registration', exp.register);

return exp;
});
