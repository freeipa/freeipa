/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2013 Red Hat
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
        './facet',
        './search',
        './entity'],
            function(IPA, $, menu, phases, reg, mod_details, mod_facet) {

/**
 * OTP tokens module
 * @class
 * @singleton
 */
var otptoken = IPA.otptoken = {};

var make_spec = function() {
return {
    name: 'otptoken',
    enable_test: function() {
        return true;
    },
    facets: [
        {
            $type: 'search',
            $pre_ops: [
                // redefining 'add' and 'remove' actions to be shown in
                // self service
                {
                    $replace: [ [ 'actions', [
                        [
                            'add',
                            {
                                $type:'add',
                                name: 'add',
                                hide_cond: []
                            }
                        ],
                        [
                            'batch_remove',
                            {
                                $type: 'batch_remove',
                                name: 'remove',
                                hide_cond: []
                            }
                        ]
                    ] ] ]
                }
            ],
            actions: [
                {
                    $type: 'batch_items',
                    name: 'enable',
                    method: 'mod',
                    options: { ipatokendisabled: false },
                    needs_confirm: true,
                    enable_cond: ['item-selected'],
                    success_msg: '@i18n:search.enabled',
                    confirm_msg: '@i18n:search.enable_confirm'
                },
                {
                    $type: 'batch_items',
                    name: 'disable',
                    method: 'mod',
                    options: { ipatokendisabled: true },
                    needs_confirm: true,
                    enable_cond: ['item-selected'],
                    success_msg: '@i18n:search.disabled',
                    confirm_msg: '@i18n:search.disable_confirm'
                },
                'delete'
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
            ],
            columns: [
                'ipatokenuniqueid',
                'ipatokenowner',
                {
                    name: 'ipatokendisabled',
                    label: '@i18n:status.label',
                    formatter: {
                        $type: 'boolean_status',
                        invert_value: true,
                        empty_value: false
                    }
                },
                'description'
            ]
        },
        {
            $type: 'details',
            actions: [
                'select',
                {
                    $type: 'object',
                    name: 'otp_enable',
                    label: '@i18n:objects.otptoken.enable',
                    method: 'mod',
                    options: { ipatokendisabled: false },
                    enable_cond: ['disabled'],
                    hide_cond: ['self-service']
                },
                {
                    $type: 'object',
                    name: 'otp_disable',
                    label: '@i18n:objects.otptoken.disable',
                    method: 'mod',
                    options: { ipatokendisabled: true },
                    enable_cond: ['enabled'],
                    hide_cond: ['self-service']
                },
                'delete'
            ],
            header_actions: ['select_action', 'otp_enable', 'otp_disable', 'delete'],
            state: {
                evaluators: [
                    {
                        $factory: mod_details.enable_state_evaluator,
                        field: 'ipatokendisabled',
                        parser: {
                            $factory: IPA.boolean_formatter,
                            invert_value: true,
                            empty_value: false
                        }
                    },
                    mod_facet.self_service_state_evaluator
                ],
                summary_conditions: [
                    mod_details.enabled_summary_cond,
                    mod_details.disabled_summary_cond
                ]
            },
            sections: [
                {
                    name: 'details',
                    label: '@i18n:objects.otptoken.details',
                    fields: [
                        'ipatokenuniqueid',
                        {
                            $type: 'textarea',
                            name: 'description'
                        },
                        {
                            $type: 'entity_select',
                            name: 'ipatokenowner',
                            other_entity: 'user',
                            other_field: 'uid'
                        },
                        'ipatokennotbefore',
                        'ipatokennotafter',
                        'ipatokenvendor',
                        'ipatokenmodel',
                        'ipatokenserial',
                        'ipatokenotpalgorithm',
                        'ipatokenotpdigits',
                        'ipatokentotpclockoffset',
                        'ipatokentotptimestep',
                        'ipatokenhotpcounter'
                    ]
                }
            ]
        }
    ],

    adder_dialog: {
        $factory: otptoken.adder_dialog,
        $pre_ops: [
            otptoken.adder_dialog_preop
        ],
        fields: [
            {
                $type: 'radio',
                name: 'type',
                default_value: 'totp',
                options: [
                    { label: 'TOTP', value: 'totp' },
                    { label: 'HOTP', value: 'hotp' }
                ]
            },
            {
                name: 'ipatokenuniqueid',
                required: false
            },
            'description',
            {// only when not self-service
                $type: 'entity_select',
                name: 'ipatokenowner',
                other_entity: 'user',
                other_field: 'uid'
            },
            'ipatokennotbefore',
            'ipatokennotafter',
            'ipatokenvendor',
            'ipatokenmodel',
            'ipatokenserial',
            'ipatokenotpkey',
            {
                $type: 'radio',
                name: 'ipatokenotpalgorithm',
                default_value: 'sha1',
                options: [
                    'sha1', 'sha256', 'sha384', 'sha512'
                ]
            },
            {
                $type: 'radio',
                name: 'ipatokenotpdigits',
                default_value: '6',
                options: ['6', '8']
            },
             'ipatokentotptimestep'
        ],
        selfservice_fields: [
            {
                $type: 'radio',
                name: 'type',
                default_value: 'totp',
                options: [
                    { label: 'TOTP', value: 'totp' },
                    { label: 'HOTP', value: 'hotp' }
                ]
            },
            {
                name: 'ipatokenuniqueid',
                required: false
            },
            'description'
        ]
    }
};};

/**
 * OTP adder dialog pre-op.
 *
 * Switches fields to different set when in self-service.
 */
otptoken.adder_dialog_preop = function(spec) {

    spec.self_service = IPA.is_selfservice;

    if (IPA.is_selfservice) {
        spec.fields = spec.selfservice_fields;
    }

    return spec;
};

/**
 * OTP adder dialog
 *
 * - otp-add requires 'type' to be set. At the moment IPA supports only 'totp'
 * @class
 * @extends IPA.entity_adder_dialog
 */
otptoken.adder_dialog = function(spec) {

    var that = IPA.entity_adder_dialog(spec);

    /**
     * Dialog sends different command options when in self-service mode.
     */
    that.self_service = !!spec.self_service;

    /** @inheritDoc */
    that.create_add_command = function(record) {

        var command = that.entity_adder_dialog_create_add_command(record);
        if (that.self_service) {
            command.set_option('ipatokenowner', IPA.whoami.uid[0]);
        }
        return command;
    };

    return that;
};

/**
 * Entity specification object
 * @member otptoken
 */
otptoken.spec = make_spec();

/**
 * Register entity
 * @member otptoken
 */
otptoken.register = function() {
    var e = reg.entity;
    e.register({type: 'otptoken', spec: otptoken.spec});
};

phases.on('registration', otptoken.register);

return otptoken;
});
