/*jsl:import ipa.js */

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

/* REQUIRES: ipa.js, details.js, search.js, add.js, facet.js, entity.js */

IPA.trust = {};

IPA.trust.entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
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
                    label: IPA.messages.objects.trust.details,
                    fields: [
                        'cn',
                        {
                            name: 'ipantflatname',
                            label: IPA.messages.objects.trust.ipantflatname,
                            read_only: true
                        },
                        {
                            name: 'ipanttrusteddomainsid',
                            label: IPA.messages.objects.trust.ipanttrusteddomainsid,
                            read_only: true
                        },
                        {
                            name: 'trustdirection',
                            label: IPA.messages.objects.trust.trustdirection
                        },
                        {
                            name: 'trusttype',
                            label: IPA.messages.objects.trust.trusttype
                        }
// trust status not supported by show command at the moment
//                         {
//                             name: 'truststatus',
//                             label: IPA.messages.objects.trust.truststatus
//                         }
                    ]
                }
            ]
        }).
        adder_dialog({
            factory: IPA.trust.adder_dialog,
            fields: [
                {
                    name: 'cn',
                    label: IPA.messages.objects.trust.domain,
                    widget: 'realm.realm_server'
                },
                {
                    name: 'realm_admin',
                    label: IPA.messages.objects.trust.account,
                    widget: 'method.realm_admin'
                },
                {
                    type: 'password',
                    name: 'realm_passwd',
                    label: IPA.messages.password.password,
                    widget: 'method.realm_passwd'
                },
                {
                    type: 'password',
                    name: 'trust_secret',
                    label: IPA.messages.password.password,
                    widget: 'method.trust_secret'
                },
                {
                    type: 'password',
                    name: 'trust_secret_verify',
                    label: IPA.messages.password.verify_password,
                    widget: 'method.trust_secret_verify',
                    flags: ['no_command'],
                    validators: [IPA.same_password_validator({
                        other_field: 'trust_secret'
                    })]
                }
            ],
            widgets: [
                {
                    type: 'details_table_section_nc',
                    name: 'realm',
                    widgets: [
                        'realm_server'
                    ]
                },
                {
                    type: 'multiple_choice_section',
                    name: 'method',
                    label: IPA.messages.objects.trust.establish_using,
                    choices: [
                        {
                            name: 'admin-account',
                            label: IPA.messages.objects.trust.admin_account,
                            fields: ['realm_admin', 'realm_passwd'],
                            required: ['realm_admin', 'realm_passwd'],
                            enabled: true
                        },
                        {
                            name: 'preshared_password',
                            label: IPA.messages.objects.trust.preshared_password,
                            fields: ['trust_secret', 'trust_secret_verify'],
                            required: ['trust_secret', 'trust_secret_verify']
                        }
                    ],
                    widgets: [
                        {
                            name: 'realm_admin'
                        },
                        {
                            type: 'password',
                            name: 'realm_passwd'
                        },
                        {
                            type: 'password',
                            name: 'trust_secret'
                        },
                        {
                            type: 'password',
                            name: 'trust_secret_verify'
                        }
                    ]
                }
            ],
            policies: [
                IPA.multiple_choice_section_policy({
                    widget: 'method'
                })
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

IPA.register('trust', IPA.trust.entity);
