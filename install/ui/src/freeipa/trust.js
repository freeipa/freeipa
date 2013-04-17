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

define(['./ipa', './jquery', './details', './search', './association',
       './entity'], function(IPA, $) {

IPA.trust = {};

IPA.trust.entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {

        if (!IPA.trust_enabled) {
            throw {
                expected: true
            };
        }

        that.entity_init();

        that.builder.search_facet({
            columns: [
                'cn'
            ]
        }).
        details_facet({
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
        }).
        adder_dialog({
            $factory: IPA.trust.adder_dialog,
            fields: [
                {
                    name: 'cn',
                    label: '@i18n:objects.trust.domain',
                    widget: 'realm.realm_server'
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
                }
            ],
            widgets: [
                {
                    $type: 'details_table_section_nc',
                    name: 'realm',
                    widgets: [
                        'realm_server'
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
                }
            ],
            policies: [
                {
                    $factory: IPA.multiple_choice_section_policy,
                    widget: 'method'
                }
            ]
        });
    };

    return that;
};

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

IPA.trust.config_entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {

        if (!IPA.trust_enabled) {
            throw {
                expected: true
            };
        }

        that.entity_init();

        that.builder.details_facet({
            factory: IPA.trust.config_details_facet,
            trust_type:  'ad',
            sections: [
                {
                    name: 'details',
                    label: IPA.messages.objects.trustconfig.options,
                    fields: [
                        'cn',
                        'ipantsecurityidentifier',
                        'ipantflatname',
                        'ipantdomainguid',
                        {
                            type: 'trust_fallbackgroup_select',
                            name: 'ipantfallbackprimarygroup',
                            other_entity: 'group',
                            other_field: 'cn',
                            empty_option: false,
                            filter_options: {
                                posix: true
                            }
                        }
                    ]
                }
            ]
        });
    };

    return that;
};

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

IPA.widget_factories['trust_fallbackgroup_select'] = IPA.trust.fallbackgroup_select_widget;
IPA.field_factories['trust_fallbackgroup_select'] = IPA.field_factories['entity_select'];

IPA.register('trust', IPA.trust.entity);
IPA.register('trustconfig', IPA.trust.config_entity);

return {};
});