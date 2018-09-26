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
        'dojo/on',
        './ipa',
        './jquery',
        './menu',
        './phases',
        './reg',
        './details',
        './facet',
        './qrcode',
        './text',
        './search',
        './entity'],
            function(on, IPA, $, menu, phases, reg, mod_details, mod_facet, QRCode, text) {
/**
 * OTP tokens module
 * @class
 * @singleton
 */
var otptoken = IPA.otptoken = {
    app_link: 'https://fedorahosted.org/freeotp/',
    app_link_text: '@i18n:objects.otptoken.app_link'
};

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
                    enabled: false,
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
                    enabled: false,
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
                    needs_confirm: true,
                    confirm_msg: '@i18n:actions.enable_confirm',
                    options: { ipatokendisabled: false },
                    enable_cond: ['disabled'],
                    hide_cond: ['self-service']
                },
                {
                    $type: 'object',
                    name: 'otp_disable',
                    label: '@i18n:objects.otptoken.disable',
                    method: 'mod',
                    needs_confirm: true,
                    confirm_msg: '@i18n:actions.disable_confirm',
                    options: { ipatokendisabled: true },
                    enable_cond: ['enabled'],
                    hide_cond: ['self-service']
                },
                'delete'
            ],
            header_actions: ['otp_enable', 'otp_disable', 'delete'],
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
                        'type',
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
                        {
                            $type: 'datetime',
                            name: 'ipatokennotbefore'
                        },
                        {
                            $type: 'datetime',
                            name: 'ipatokennotafter'
                        },
                        'ipatokenvendor',
                        'ipatokenmodel',
                        'ipatokenserial',
                        'ipatokenotpalgorithm',
                        'ipatokenotpdigits',
                        {
                            name: 'ipatokentotpclockoffset',
                            measurement_unit: 'seconds',
                            hidden_if_empty: true
                        },
                        {
                            name: 'ipatokentotptimestep',
                            measurement_unit: 'seconds',
                            hidden_if_empty: true
                        },
                        {
                            name: 'ipatokenhotpcounter',
                            hidden_if_empty: true
                        }
                    ]
                }
            ]
        },
        {
            $type: 'association',
            name: 'managedby_user',
            add_method: 'add_managedby',
            remove_method: 'remove_managedby',
            remove_title: '@i18n:objects.otptoken.remove_users_managing'
        }
    ],

    adder_dialog: {
        $factory: otptoken.adder_dialog,
        $pre_ops: [
            otptoken.adder_dialog_preop
        ],
        $post_ops: [
            otptoken.adder_dialog_qrcode_post_op
        ],
        policies: [
            { $factory: otptoken.adder_policy }
        ],
        fields: [
            {
                $type: 'radio',
                name: 'type',
                default_value: 'totp',
                options: [
                    { label: '@i18n:objects.otptoken.type_totp', value: 'totp' },
                    { label: '@i18n:objects.otptoken.type_hotp', value: 'hotp' }
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
            {
                $type: 'datetime',
                name: 'ipatokennotbefore'
            },
            {
                $type: 'datetime',
                name: 'ipatokennotafter'
            },
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
            {
                name: 'ipatokentotptimestep',
                measurement_unit: 'seconds'
            }
        ],
        selfservice_fields: [
            {
                $type: 'radio',
                name: 'type',
                default_value: 'totp',
                options: [
                    { label: '@i18n:objects.otptoken.type_totp', value: 'totp' },
                    { label: '@i18n:objects.otptoken.type_hotp', value: 'hotp' }
                ]
            },
            'description'
        ]
    },
    deleter_dialog: {
        title: '@i18n:objects.otptoken.remove'
    }
};};

otptoken.adder_policy = function(spec) {
    var that = IPA.facet_policy(spec);
    that.init = function() {
        var type_f = that.container.fields.get_field('type');
        on(type_f, 'value-change', that.on_type_change);
    };
    that.on_type_change = function(args) {
        var step_f = that.container.fields.get_field('ipatokentotptimestep');
        if (!step_f) return;
        var step_w = step_f.widget;
        var is_totp = args.value[0] === 'totp';
        step_f.set_enabled(is_totp);
        step_w.set_visible(is_totp);
    };
    return that;
};

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
            command.set_option('ipatokenowner', IPA.whoami.data.uid[0]);
        }
        return command;
    };

    return that;
};

/**
 * Displays text as QR code
 * @class
 * @extends IPA.widget
 */
otptoken.qr_widget = function(spec) {

    var that = IPA.widget(spec);

    /**
     * Text to be displayed as QR Code
     * @property {string}
     * @readonly
     */
    that.text = spec.text;

    /**
     * Show link with the text instead of QR code
     * @property {boolean}
     */
    that.show_link = !!spec.show_link;

    /** @inheritDoc */
    that.create = function(container) {

        that.widget_create(container);
        container.addClass('qrcode-widget');

        that.div_link_control = $('<a/>', {
            name: that.name,
            href: ''
        }).appendTo(that.container);

        that.qr_control = $('<div/>', {
            name: that.name
        }).appendTo(that.div_link_control);

        that.uri_control = $('<div/>', {
            name: 'uri-control',
            'class': 'otp-uri',
            style: 'display: none;'
        }).appendTo(container);

        that.link_container = $('<div/>', {
            style: 'padding: 5px 0;'
        }).appendTo(container);

        that.show_uri_link = $('<a/>', {
            name: 'show-uri',
            href: '#',
            text: text.get('@i18n:objects.otptoken.show_uri'),
            click: function(e) {
                e.preventDefault();
                that.update_display_mode(!that.show_link);
            }
        }).appendTo(that.link_container);

        that.qrcode = new QRCode(that.qr_control[0], {
            text: "",
            width: 450,
            height: 450,
            colorDark : "#000000",
            colorLight : "#ffffff",
            correctLevel : QRCode.CorrectLevel.M
        });

        that.update(that.text);
        that.update_display_mode(that.show_link);
    };

    /**
     * Update displayed information with supplied values.
     * @param {String|Array|null} values
     */
    that.update = function(values) {

        var val;
        if (typeof values === 'string') {
            val = values;
        } else if (values.length) {
            val = values[0];
        } else {
            val = '';
        }
        that.text = val;
        that.qrcode.makeCode(that.text);
        that.uri_control.text(that.text);
        that.div_link_control.prop('href', that.text);
        that.emit('value-change', { source: that, value: val });
    };

    /**
     * Switches between QR code and link
     * @protected
     * @param {boolean} show_link
     */
    that.update_display_mode = function(show_link) {

        that.show_link = !!show_link;

         if (that.show_link) {
             that.show_uri_link.text(text.get('@i18n:objects.otptoken.show_qr'));
             that.qr_control.hide();
             that.uri_control.show();
         } else {
             that.show_uri_link.text(text.get('@i18n:objects.otptoken.show_uri'));
             that.qr_control.show();
             that.uri_control.hide();
         }
    };

    /**
     * @inheritDoc
     */
    that.clear = function() {
        that.qrcode.clear();
        that.link_control.text('');
    };

    return that;
};

/**
 * Displays text as QR code in a dialog
 * @class
 * @extends IPA.message_dialog
 */
otptoken.qr_dialog = function(spec) {

    var that = IPA.message_dialog(spec);

    /**
     * Uses IPA.dialog UI
     */
    that.create_content = that.dialog_create_content;

    return that;
};

/**
 * OTP adder dialog post-op which enables showing of QR code after token is
 * successfully added by displaying QR dialog.
 * @member otptoken
 */
otptoken.adder_dialog_qrcode_post_op = function(object) {

    object.added.attach(function(data) {

        var uri = data.result.result.uri;
        var qr_dialog = otptoken.qr_dialog({
            name: 'qr_dialog',
            title: '@i18n:objects.otptoken.config_title',
            widgets: [
                {
                    $type: 'qrcode',
                    name: 'qr',
                    css_class: 'col-sm-12',
                    text: uri
                }
            ]
        });

        qr_dialog.open();
        qr_dialog.show_message(text.get('@i18n:objects.otptoken.config_instructions'));
        if (otptoken.app_link && otptoken.app_link_text) {
            var app_text = text.get(otptoken.app_link_text);
            app_text = app_text.replace('${link}', otptoken.app_link);
            qr_dialog.show_message(app_text);
        }
    });


    return object;
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
    var w = reg.widget;

    e.register({type: 'otptoken', spec: otptoken.spec});
    w.register('qrcode', otptoken.qr_widget);
};

phases.on('registration', otptoken.register);

return otptoken;
});
