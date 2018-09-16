/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
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
        './menu',
        './phases',
        './reg',
        './details',
        './search',
        './association',
        './entity'],
            function(IPA, $, menu, phases, reg) {

var exp = IPA.trust = {};

var make_trust_spec = function() {
return {
    name: 'trust',
    enable_test: function() {
        return IPA.trust_enabled;
    },
    policies: [
        IPA.search_facet_update_policy,
        IPA.details_facet_update_policy,
        {
            $factory: IPA.adder_facet_update_policy,
            source_facet: 'search',
            dest_entity: 'idrange',
            dest_facet: 'search'
        }
    ],
    facet_groups: [ 'settings', 'trustdomain' ],
    facets: [
        {
            $type: 'search',
            columns: [
                'cn'
            ]
        },
        {
            $type: 'nested_search',
            $pre_ops: [
                // trustdomain-add is hidden, remove add button
                { $del: [[ 'control_buttons', [{ name: 'add'}] ]] }
            ],
            nested_entity: 'trustdomain',
            facet_group: 'trustdomain',
            name: 'domains',
            label: '@mo:trustdomain.label',
            tab_label: '@mo:trustdomain.label',
            search_all_entries: true,
            deleter_dialog: {
                title: '@i18n:objects.trust.remove_domains',
                $factory: IPA.search_deleter_dialog,
            },
            actions: [
                {
                    $type: 'batch_disable'
                },
                {
                    $type: 'batch_enable'
                },
                {
                    $type: 'object',
                    name: 'fetch',
                    label: '@i18n:objects.trust.fetch_domains',
                    method: 'fetch_domains'
                }
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
                },
                {
                    name: 'fetch',
                    label: '@i18n:objects.trust.fetch_domains',
                    icon: 'fa-download'
                }
            ],
            columns: [
                {
                    name: 'cn',
                    link: false
                },
                {
                    name: 'domain_enabled',
                    label: '@i18n:status.label',
                    formatter: 'boolean_status'
                },
                'ipantflatname',
                'ipanttrusteddomainsid'
            ]
        },
        {
            $type: 'details',
            sections: [
                {
                    name: 'details',
                    label: '@i18n:objects.trust.details',
                    fields: [
                        'cn',
                        {
                            name: 'ipantflatname',
                            label: '@i18n:objects.trust.ipantflatname',
                            read_only: true
                        },
                        {
                            name: 'ipanttrusteddomainsid',
                            label: '@i18n:objects.trust.ipanttrusteddomainsid',
                            read_only: true
                        },
                        {
                            name: 'trustdirection',
                            label: '@i18n:objects.trust.trustdirection'
                        },
                        {
                            name: 'trusttype',
                            label: '@i18n:objects.trust.trusttype'
                        }
                    ]
                },
                {
                    name: 'suffixes',
                    label: '@i18n:objects.trust.ipantadditionalsuffixes',
                    fields: [
                        {
                            $type: 'multivalued',
                            name: 'ipantadditionalsuffixes'
                        }
                    ]
                },
                {
                    name: 'blacklists',
                    label: '@i18n:objects.trust.blacklists',
                    fields: [
                        {
                            $type: 'multivalued',
                            name: 'ipantsidblacklistincoming'
                        },
                        {
                            $type: 'multivalued',
                            name: 'ipantsidblacklistoutgoing'
                        }
// trust status not supported by show command at the moment
//                         {
//                             name: 'truststatus',
//                             label: '@i18n:objects.trust.truststatus'
//                         }
                    ]
                }
            ]
        }
    ],
    adder_dialog: {
        $factory: IPA.trust.adder_dialog,
        fields: [
            {
                name: 'cn',
                label: '@i18n:objects.trust.domain',
                widget: 'realm.realm_server'
            },
            {
                $type: 'checkbox',
                name: 'bidirectional',
                metadata: '@mc-opt:trust_add:bidirectional',
                widget: 'realm.bidirectional'
            },
            {
                $type: 'checkbox',
                name: 'external',
                metadata: '@mc-opt:trust_add:external',
                widget: 'realm.external'
            },
            {
                name: 'realm_admin',
                label: '@i18n:objects.trust.account',
                widget: 'method.realm_admin'
            },
            {
                $type: 'password',
                name: 'realm_passwd',
                label: '@i18n:password.password',
                widget: 'method.realm_passwd'
            },
            {
                $type: 'password',
                name: 'trust_secret',
                label: '@i18n:password.password',
                widget: 'method.trust_secret'
            },
            {
                $type: 'password',
                name: 'trust_secret_verify',
                label: '@i18n:password.verify_password',
                widget: 'method.trust_secret_verify',
                flags: ['no_command'],
                validators: [{
                    $type: 'same_password',
                    other_field: 'trust_secret'
                }]
            },
            {
                $type: 'radio',
                name: 'range_type',
                metadata: '@mc-opt:trust_add:range_type',
                widget: 'range.range_type'
            },
            {
                name: 'base_id',
                label: '@i18n:objects.idrange.ipabaseid',
                metadata: '@mc-opt:trust_add:base_id',
                widget: 'range.base_id'
            },
            {
                name: 'range_size',
                label: '@i18n:objects.idrange.ipaidrangesize',
                metadata: '@mc-opt:trust_add:range_size',
                widget: 'range.range_size'
            }

        ],
        widgets: [
            {
                $type: 'details_section',
                name: 'realm',
                widgets: [
                    'realm_server',
                    {
                        $type: 'checkbox',
                        name: 'bidirectional',
                        tooltip: '@mc-opt:trust_add:bidirectional:doc'
                    },
                    {
                        $type: 'checkbox',
                        name: 'external',
                        tooltip: '@mc-opt:trust_add:external:doc'
                    }
                ]
            },
            {
                $type: 'multiple_choice_section',
                name: 'method',
                label: '@i18n:objects.trust.establish_using',
                choices: [
                    {
                        name: 'admin-account',
                        label: '@i18n:objects.trust.admin_account',
                        fields: ['realm_admin', 'realm_passwd'],
                        required: ['realm_admin', 'realm_passwd'],
                        enabled: true
                    },
                    {
                        name: 'preshared_password',
                        label: '@i18n:objects.trust.preshared_password',
                        fields: ['trust_secret', 'trust_secret_verify'],
                        required: ['trust_secret', 'trust_secret_verify']
                    }
                ],
                widgets: [
                    {
                        name: 'realm_admin'
                    },
                    {
                        $type: 'password',
                        name: 'realm_passwd'
                    },
                    {
                        $type: 'password',
                        name: 'trust_secret'
                    },
                    {
                        $type: 'password',
                        name: 'trust_secret_verify'
                    }
                ]
            },
            {
                $type: 'details_section',
                name: 'range',
                widgets: [
                    {
                        $type: 'radio',
                        name: 'range_type',
                        layout: 'vertical',
                        default_value: '',
                        options: [
                            {
                                value: '',
                                label: '@i18n:objects.idrange.type_detect'
                            },
                            {
                                value: 'ipa-ad-trust',
                                label: '@i18n:objects.idrange.type_ad'
                            },
                            {
                                value: 'ipa-ad-trust-posix',
                                label: '@i18n:objects.idrange.type_ad_posix'
                            }
                        ]
                    },
                    'base_id',
                    'range_size'
                ]
            }
        ],
        policies: [
            {
                $factory: IPA.multiple_choice_section_policy,
                widget: 'method'
            }
        ]
    },
    deleter_dialog: {
        title: '@i18n:objects.trust.remove',
    },
};};

IPA.trust.adder_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.entity_adder_dialog(spec);

    that.get_success_message = function(data) {
        return that.entity_adder_dialog_get_success_message(data) + '. ' + data.result.result.truststatus[0];
    };

    that.notify_success = function(data) {
        IPA.notify_success(that.get_success_message(data), 5000);
    };

    return that;
};


var make_trustdomain_spec = function() {
return {
    name: 'trustdomain',
    containing_entity: 'trust'
};};

var make_trustconfig_spec = function() {
return {
    name: 'trustconfig',
    defines_key: false,
    enable_test: function() {
        return IPA.trust_enabled;
    },
    facets: [
        {
            $type: 'details',
            $factory: IPA.trust.config_details_facet,
            trust_type:  'ad',
            sections: [
                {
                    name: 'details',
                    label: '@i18n:objects.trustconfig.options',
                    fields: [
                        'cn',
                        'ipantsecurityidentifier',
                        'ipantflatname',
                        'ipantdomainguid',
                        {
                            $type: 'trust_fallbackgroup_select',
                            name: 'ipantfallbackprimarygroup',
                            other_entity: 'group',
                            other_field: 'cn',
                            empty_option: false,
                            filter_options: {
                                posix: true
                            }
                        },
                        {
                            $type: 'multivalued',
                            name: 'ad_trust_agent_server',
                            read_only: true
                        },
                        {
                            $type: 'multivalued',
                            name: 'ad_trust_controller_server',
                            read_only: true
                        }
                    ]
                }
            ]
        }
    ]
};};

IPA.trust.config_details_facet = function(spec) {

    spec = spec || {};

    var that = IPA.details_facet(spec);

    that.trust_type = spec.trust_type;

    that.get_refresh_command_name = function() {
        return that.entity.name+that.trust_type+'_show';
    };

    that.create_refresh_command = function() {

        var command = that.details_facet_create_refresh_command();
        command.set_option('trust_type', that.trust_type);

        return command;
    };

    that.create_update_command = function() {

        var command = that.details_facet_create_update_command();
        command.set_option('trust_type', that.trust_type);

        return command;
    };

    return that;
};

IPA.trust.fallbackgroup_select_widget = function(spec) {
    var that = IPA.entity_select_widget(spec);

    that.set_options = function(options) {
        // always add 'Default SMB Group', it can't be obtained by group-find.
        options.unshift('Default SMB Group');
        that.entity_select_set_options(options);
    };

    return that;
};

exp.remove_menu_item = function() {
    if (!IPA.trust_enabled) {
        menu.remove_item('ipaserver/trusts');
    }
};

exp.trust_spec = make_trust_spec();
exp.trustdomain_spec = make_trustdomain_spec();
exp.trustconfig_spec = make_trustconfig_spec();


IPA.trust.register = function() {
    var e = reg.entity;
    var w = reg.widget;
    var f = reg.field;

    e.register({type: 'trust', spec: exp.trust_spec});
    e.register({type: 'trustdomain', spec: exp.trustdomain_spec});
    e.register({type: 'trustconfig', spec: exp.trustconfig_spec});

    w.register('trust_fallbackgroup_select', IPA.trust.fallbackgroup_select_widget);
    f.register('trust_fallbackgroup_select', IPA.field);
};

phases.on('registration', IPA.trust.register);
phases.on('profile', exp.remove_menu_item, 20);

return exp;
});
