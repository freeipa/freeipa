/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *    Endi Sukma Dewata <edewata@redhat.com>
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
        './builder',
        './ipa',
        './jquery',
        './phases',
        './reg',
        './rpc',
        './text',
        './dialogs/password',
        './details',
        './search',
        './association',
        './entity',
        './certificate'],
    function(builder, IPA, $, phases, reg, rpc, text, password_dialog) {

/**
 * User module
 * @class user
 * @alternateClassName IPA.user
 * @singleton
 */
var exp = IPA.user = {
    search_facet_group: {
        name: 'search',
        label: '@i18n:objects.stageuser.user_categories',
        facets: {
            search_normal: 'user_search',
            search: 'stageuser_search',
            search_preserved: 'user_search_preserved'
        }
    }
};

var make_spec = function() {
return {
    name: 'user',
    facets: [
        {
            $type: 'search',
            label: '@i18n:objects.user.activeuser_label',
            tab_label: '@i18n:objects.user.activeuser_label',
            disable_facet_tabs: false,
            tabs_in_sidebar: true,
            facet_groups: [exp.search_facet_group],
            row_disabled_attribute: 'nsaccountlock',
            columns: [
                'uid',
                'givenname',
                'sn',
                {
                    name: 'nsaccountlock',
                    label: '@i18n:status.label',
                    formatter: {
                        $type: 'boolean_status',
                        invert_value: true
                    }
                },
                'uidnumber',
                'mail',
                'telephonenumber',
                'title'
            ],
            actions: [
                'select',
                {
                    $type: 'automember_rebuild',
                    name: 'automember_rebuild',
                    label: '@i18n:actions.automember_rebuild'
                },
                {
                    $type: 'batch_disable',
                    hide_cond: ['self-service']
                },
                {
                    $type: 'batch_enable',
                    hide_cond: ['self-service']
                }
            ],
            header_actions: ['automember_rebuild'],
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
            $factory: IPA.user.details_facet,
            sections: [
                {
                    name: 'identity',
                    label: '@i18n:details.identity',
                    fields: [
                        'title',
                        'givenname',
                        'sn',
                        'cn',
                        'displayname',
                        'initials',
                        'gecos',
                        {
                            name: 'userclass',
                            flags: ['w_if_no_aci']
                        }
                    ]
                },
                {
                    name: 'account',
                    fields: [
                        'uid',
                        {
                            $factory: IPA.user.password_widget,
                            name: 'has_password',
                            metadata: '@mo-param:user:userpassword'
                        },
                        {
                            $type: 'datetime',
                            name: 'krbpasswordexpiration',
                            label: '@i18n:objects.user.krbpasswordexpiration',
                            read_only: true
                        },
                        'uidnumber',
                        'gidnumber',
                        'krbprincipalname',
                        {
                            $type: 'datetime',
                            name: 'krbprincipalexpiration'
                        },
                        'loginshell',
                        'homedirectory',
                        {
                            $type: 'sshkeys',
                            name: 'ipasshpubkey',
                            label: '@i18n:objects.sshkeystore.keys'
                        },
                        {
                            $type: 'checkboxes',
                            name: 'ipauserauthtype',
                            flags: ['w_if_no_aci'],
                            options: [
                                { label: '@i18n:authtype.type_password', value: 'password' },
                                { label: '@i18n:authtype.type_radius', value: 'radius' },
                                { label: '@i18n:authtype.type_otp', value: 'otp' }
                            ],
                            tooltip: '@i18n:authtype.user_tooltip'
                        },
                        {
                            $type: 'entity_select',
                            name: 'ipatokenradiusconfiglink',
                            flags: ['w_if_no_aci'],
                            other_entity: 'radiusproxy',
                            other_field: 'cn'
                        },
                        {
                            name: 'ipatokenradiususername',
                            flags: ['w_if_no_aci']
                        }
                    ]
                },
                {
                    name: 'pwpolicy',
                    label: '@i18n:objects.pwpolicy.identity',
                    field_adapter: { result_index: 1 },
                    fields: [
                        {
                            name: 'krbmaxpwdlife',
                            label: '@mo-param:pwpolicy:krbmaxpwdlife:label',
                            read_only: true
                        },
                        {
                            name: 'krbminpwdlife',
                            label: '@mo-param:pwpolicy:krbminpwdlife:label',
                            read_only: true
                        },
                        {
                            name: 'krbpwdhistorylength',
                            label: '@mo-param:pwpolicy:krbpwdhistorylength:label',
                            read_only: true,
                            measurement_unit: 'number_of_passwords'
                        },
                        {
                            name: 'krbpwdmindiffchars',
                            label: '@mo-param:pwpolicy:krbpwdmindiffchars:label',
                            read_only: true
                        },
                        {
                            name: 'krbpwdminlength',
                            label: '@mo-param:pwpolicy:krbpwdminlength:label',
                            read_only: true
                        },
                        {
                            name: 'krbpwdmaxfailure',
                            label: '@mo-param:pwpolicy:krbpwdmaxfailure:label',
                            read_only: true
                        },
                        {
                            name: 'krbpwdfailurecountinterval',
                            label: '@mo-param:pwpolicy:krbpwdfailurecountinterval:label',
                            read_only: true,
                            measurement_unit: 'seconds'
                        },
                        {
                            name: 'krbpwdlockoutduration',
                            label: '@mo-param:pwpolicy:krbpwdlockoutduration:label',
                            read_only: true,
                            measurement_unit: 'seconds'
                        }
                    ]
                },
                {
                    name: 'krbtpolicy',
                    label: '@i18n:objects.krbtpolicy.identity',
                    field_adapter: { result_index: 2 },
                    fields: [
                        {
                            name: 'krbmaxrenewableage',
                            label: '@mo-param:krbtpolicy:krbmaxrenewableage:label',
                            read_only: true,
                            measurement_unit: 'seconds'
                        },
                        {
                            name: 'krbmaxticketlife',
                            label: '@mo-param:krbtpolicy:krbmaxticketlife:label',
                            read_only: true,
                            measurement_unit: 'seconds'
                        }
                    ]
                },
                {
                    name: 'contact',
                    fields: [
                        { $type: 'multivalued', name: 'mail' },
                        { $type: 'multivalued', name: 'telephonenumber' },
                        { $type: 'multivalued', name: 'pager' },
                        { $type: 'multivalued', name: 'mobile' },
                        { $type: 'multivalued', name: 'facsimiletelephonenumber' }
                    ]
                },
                {
                    name: 'mailing',
                    fields: ['street', 'l', 'st', 'postalcode']
                },
                {
                    name: 'employee',
                    fields: [
                        'ou',
                        {
                            $type: 'entity_select',
                            name: 'manager',
                            other_entity: 'user',
                            other_field: 'uid'
                        },
                        { $type: 'multivalued', name: 'departmentnumber' },
                        'employeenumber',
                        'employeetype',
                        'preferredlanguage'
                    ]
                },
                {
                    name: 'misc',
                    fields: [
                        { $type: 'multivalued', name: 'carlicense' }
                    ]
                }
            ],
            actions: [
                'add_otptoken',
                'enable',
                'disable',
                'delete',
                'reset_password',
                {
                    $factory: IPA.object_action,
                    name: 'unlock',
                    method: 'unlock',
                    label: '@i18n:objects.user.unlock',
                    needs_confirm: true,
                    confirm_msg: '@i18n:objects.user.unlock_confirm'
                },
                {
                    $type: 'automember_rebuild',
                    name: 'automember_rebuild',
                    label: '@i18n:actions.automember_rebuild'
                }
            ],
            header_actions: ['reset_password', 'enable', 'disable', 'delete', 'unlock', 'add_otptoken', 'automember_rebuild'],
            state: {
                evaluators: [
                    {
                        $factory: IPA.enable_state_evaluator,
                        field: 'nsaccountlock',
                        adapter: { $type: 'batch', result_index: 0 },
                        invert_value: true
                    },
                    {
                        $factory: IPA.acl_state_evaluator,
                        name: 'reset_password_acl_evaluator',
                        adapter: { $type: 'batch', result_index: 0 },
                        attribute: 'userpassword'
                    },
                    IPA.user.self_service_other_user_evaluator
                ],
                summary_conditions: [
                    IPA.enabled_summary_cond,
                    IPA.disabled_summary_cond
                ]
            }
        },
        {
            $type: 'association',
            $pre_ops: [ IPA.user.association_facet_ss_pre_op ],
            name: 'memberof_group',
            associator: IPA.serial_associator
        },
        {
            $type: 'association',
            $pre_ops: [ IPA.user.association_facet_ss_pre_op ],
            name: 'memberof_netgroup',
            associator: IPA.serial_associator
        },
        {
            $type: 'association',
            $pre_ops: [ IPA.user.association_facet_ss_pre_op ],
            name: 'memberof_role',
            associator: IPA.serial_associator
        },
        {
            $type: 'association',
            $pre_ops: [ IPA.user.association_facet_ss_pre_op ],
            name: 'memberof_hbacrule',
            associator: IPA.serial_associator,
            add_method: 'add_user',
            remove_method: 'remove_user'
        },
        {
            $type: 'association',
            $pre_ops: [ IPA.user.association_facet_ss_pre_op ],
            name: 'memberof_sudorule',
            associator: IPA.serial_associator,
            add_method: 'add_user',
            remove_method: 'remove_user'
        }
    ],
    standard_association_facets: {
        $pre_ops: [ IPA.user.association_facet_ss_pre_op ]
    },
    adder_dialog: {
        $factory: IPA.user.adder_dialog,
        sections: [
            {
                fields: [
                    {
                        name: 'uid',
                        required: false
                    },
                    'givenname',
                    'sn',
                    'userclass'
                ]
            },
            {
                fields: [
                    {
                        name: 'userpassword',
                        label: '@i18n:password.new_password',
                        $type: 'password'
                    },
                    {
                        name: 'userpassword2',
                        label: '@i18n:password.verify_password',
                        $type: 'password'
                    }
                ]
            }
        ]
    }
};};

IPA.user.details_facet = function(spec) {

    spec = spec || {};

    var that = IPA.details_facet(spec);

    that.create_refresh_command = function() {

        var pkey = that.get_pkey();

        var batch = rpc.batch_command({
            name: 'user_details_refresh'
        });

        var user_command = that.details_facet_create_refresh_command();
        batch.add_command(user_command);

        var pwpolicy_command = rpc.command({
            entity: 'pwpolicy',
            method: 'show',
            retry: false,
            options: {
                user: pkey,
                all: true,
                rights: true
            }
        });

        pwpolicy_command.on_success = function(data, text_status, xhr) {
            that.widgets.get_widget('pwpolicy').set_visible(true);
        };

        pwpolicy_command.on_error = function(xhr, text_status, error_thrown) {
            that.widgets.get_widget('pwpolicy').set_visible(false);
        };

        batch.add_command(pwpolicy_command);

        var krbtpolicy_command = rpc.command({
            entity: 'krbtpolicy',
            method: 'show',
            args: [ pkey ],
            retry: false,
            options: {
                all: true,
                rights: true
            }
        });

        krbtpolicy_command.on_success = function(data, text_status, xhr) {
            that.widgets.get_widget('krbtpolicy').set_visible(true);
        };

        krbtpolicy_command.on_error = function(xhr, text_status, error_thrown) {
            that.widgets.get_widget('krbtpolicy').set_visible(false);
        };

        batch.add_command(krbtpolicy_command);

        return batch;
    };

    return that;
};

/**
 * @member user
 * Makes user association facets read-only in self service
 */
IPA.user.association_facet_ss_pre_op = function(spec, context) {

    var self_service = IPA.is_selfservice;

    spec.read_only = self_service;
    spec.link = self_service ? false : undefined;

    return spec;
};


IPA.user.adder_dialog = function(spec) {

    var that = IPA.entity_adder_dialog(spec);

    that.validate = function() {
        var valid = that.dialog_validate();

        var field1 = that.fields.get_field('userpassword');
        var field2 = that.fields.get_field('userpassword2');

        var password1 = field1.save()[0];
        var password2 = field2.save()[0];

        if (password1 !== password2) {
            field2.set_valid({ valid: false, message: text.get('@i18n:password.password_must_match') });
            valid = false;
        }

        return valid;
    };

    that.save = function(record) {
        that.dialog_save(record);
        delete record.userpassword2;
    };

    return that;
};

IPA.user.password_widget = function(spec) {

    spec = spec || {};
    spec.read_only = true;

    var that = IPA.input_widget(spec);
    that.set_value = spec.set_value || '******';
    that.unset_value = spec.unset_value || '';

    that.create = function(container) {

        that.widget_create(container);

        that.display_control = $('<label/>', {
            name: that.name
        }).appendTo(container);
    };

    that.update = function(values) {

        if (values && values[0]) {
            that.display_control.text(that.set_value);
        } else {
            that.display_control.text(that.unset_value);
        }
        that.on_value_changed(values);
    };

    that.clear = function() {
        that.display_control.text('');
    };

    return that;
};

IPA.user.password_dialog_pre_op0 = function(spec) {

    spec.password_name = spec.password_name || 'password';
    return spec;
};

IPA.user.password_dialog_pre_op = function(spec) {

    spec.sections[0].fields.splice(0, 0, {
        name: 'current_password',
        label: '@i18n:password.current_password',
        $type: 'password',
        required: true
    }, {
         name: 'otp',
        label: '@i18n:password.otp',
        $type: 'password'
    });

    spec.method = spec.method || 'passwd';

    return spec;
};

IPA.user.password_dialog = function(spec) {

    var that = password_dialog.dialog(spec);

    that.is_self_service = function() {
        var self_service = that.args[0] === IPA.whoami.uid[0];
        return self_service;
    };

    that.open = function() {
        that.dialog_open();

        var self_service = that.is_self_service();
        var current_pw_f = that.fields.get_field('current_password');
        var current_pw_w = that.widgets.get_widget('general.current_password');
        var otp_f = that.fields.get_field('otp');
        var otp_w = that.widgets.get_widget('general.otp');

        current_pw_f.set_required(self_service);
        current_pw_f.set_enabled(self_service);
        current_pw_w.set_visible(self_service);
        otp_f.set_enabled(self_service);
        otp_w.set_visible(self_service);

        that.focus_first_element();
    };

    return that;
};

IPA.user.reset_password_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'reset_password';
    spec.label = spec.label || '@i18n:password.reset_password';
    spec.enable_cond = spec.enable_cond || ['userpassword_w'];

    var that = IPA.action(spec);

    that.execute_action = function(facet) {

        var dialog = builder.build('dialog', {
            $type: 'user_password',
            args: [facet.get_pkey()]
        });

        dialog.succeeded.attach(function() {
            facet.refresh();
            if (dialog.is_self_service()) {
                var command = IPA.get_whoami_command();
                command.execute();
            }
        });

        dialog.open();
    };

    return that;
};


IPA.user.add_otptoken_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'add_otptoken';
    spec.label = spec.label || '@i18n:objects.otptoken.add_token';
    spec.disable_cond = spec.disable_cond || ['self-service-other'];

    var that = IPA.action(spec);

    that.execute_action = function(facet) {

        var otp_e = reg.entity.get('otptoken');
        var dialog = otp_e.get_dialog('add');
        dialog.open();
        if (!IPA.is_selfservice) {
            var owner = facet.get_pkey();
            dialog.get_field('ipatokenowner').set_value([owner]);
        }
    };

    return that;
};

IPA.user.self_service_other_user_evaluator = function(spec) {

    spec = spec || {};
    spec.event = spec.event || 'post_load';

    var that = IPA.state_evaluator(spec);
    that.name = spec.name || 'self_service_other_user_evaluator';
    that.param = spec.param || 'uid';
    that.adapter = builder.build('adapter', spec.adapter || 'adapter', { context: that });

    /**
     * Evaluates if user is in self-service and viewing himself
     */
    that.on_event = function(data) {

        var old_state = that.state;
        that.state = [];

        var value = that.adapter.load(data);
        if (IPA.is_selfservice && IPA.whoami.uid[0] !== value[0]) {
            that.state.push('self-service-other');
        }

        that.notify_on_change(old_state);
    };

    return that;
};

exp.entity_spec = make_spec();
exp.register = function() {
    var e = reg.entity;
    var a = reg.action;
    var d = reg.dialog;
    e.register({type: 'user', spec: exp.entity_spec});
    a.register('reset_password', IPA.user.reset_password_action);
    a.register('add_otptoken', IPA.user.add_otptoken_action);
    d.copy('password', 'user_password', {
        factory: IPA.user.password_dialog,
        pre_ops: [IPA.user.password_dialog_pre_op]
    });
    d.register_pre_op('user_password', IPA.user.password_dialog_pre_op0, true);
};
phases.on('registration', exp.register);

return exp;
});
