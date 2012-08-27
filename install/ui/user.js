/*jsl:import ipa.js */

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

/* REQUIRES: ipa.js, details.js, search.js, add.js, facet.js, entity.js */

IPA.user = {};

IPA.user.entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        var self_service = IPA.nav.name === 'self-service';
        var link = self_service ? false : undefined;

        that.builder.search_facet({
            row_disabled_attribute: 'nsaccountlock',
            columns: [
                'uid',
                'givenname',
                'sn',
                {
                    name: 'nsaccountlock',
                    label: IPA.messages.status.label,
                    formatter: IPA.boolean_status_formatter({
                        invert_value: true
                    })
                },
                'uidnumber',
                'mail',
                'telephonenumber',
                'title'
            ],
            actions: [
                {
                    factory: IPA.batch_disable_action,
                    hide_cond: ['self-service']
                },
                {
                    factory: IPA.batch_enable_action,
                    hide_cond: ['self-service']
                }
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
            factory: IPA.user.details_facet,
            sections: [
                {
                    name: 'identity',
                    label: IPA.messages.details.identity,
                    fields: [
                        'title',
                        'givenname',
                        'sn',
                        'cn',
                        'displayname',
                        'initials'
                    ]
                },
                {
                    name: 'account',
                    action_panel: {
                        factory: IPA.action_panel,
                        name: 'account_actions',
                        actions: ['reset_password']
                    },
                    fields: [
                        'uid',
                        {
                            factory: IPA.user_password_widget,
                            name: 'has_password',
                            metadata: IPA.get_entity_param('user', 'userpassword')
                        },
                        {
                            name: 'krbpasswordexpiration',
                            label: IPA.messages.objects.user.krbpasswordexpiration,
                            read_only: true,
                            formatter: IPA.utc_date_formatter()
                        },
                        'uidnumber',
                        'gidnumber',
                        'loginshell',
                        'homedirectory',
                        {
                            type: 'sshkeys',
                            name: 'ipasshpubkey',
                            label: IPA.messages.objects.sshkeystore.keys
                        }
                    ]
                },
                {
                    name: 'pwpolicy',
                    label: IPA.messages.objects.pwpolicy.identity,
                    fields: [
                        {
                            name: 'krbmaxpwdlife',
                            label: IPA.get_entity_param('pwpolicy', 'krbmaxpwdlife').label,
                            read_only: true
                        },
                        {
                            name: 'krbminpwdlife',
                            label: IPA.get_entity_param('pwpolicy', 'krbminpwdlife').label,
                            read_only: true
                        },
                        {
                            name: 'krbpwdhistorylength',
                            label: IPA.get_entity_param('pwpolicy', 'krbpwdhistorylength').label,
                            read_only: true,
                            measurement_unit: 'number_of_passwords'
                        },
                        {
                            name: 'krbpwdmindiffchars',
                            label: IPA.get_entity_param('pwpolicy', 'krbpwdmindiffchars').label,
                            read_only: true
                        },
                        {
                            name: 'krbpwdminlength',
                            label: IPA.get_entity_param('pwpolicy', 'krbpwdminlength').label,
                            read_only: true
                        },
                        {
                            name: 'krbpwdmaxfailure',
                            label: IPA.get_entity_param('pwpolicy', 'krbpwdmaxfailure').label,
                            read_only: true
                        },
                        {
                            name: 'krbpwdfailurecountinterval',
                            label: IPA.get_entity_param('pwpolicy', 'krbpwdfailurecountinterval').label,
                            read_only: true,
                            measurement_unit: 'seconds'
                        },
                        {
                            name: 'krbpwdlockoutduration',
                            label: IPA.get_entity_param('pwpolicy', 'krbpwdlockoutduration').label,
                            read_only: true,
                            measurement_unit: 'seconds'
                        }
                    ]
                },
                {
                    name: 'krbtpolicy',
                    label: IPA.messages.objects.krbtpolicy.identity,
                    fields: [
                        {
                            name: 'krbmaxrenewableage',
                            label: IPA.get_entity_param('krbtpolicy', 'krbmaxrenewableage').label,
                            read_only: true,
                            measurement_unit: 'seconds'
                        },
                        {
                            name: 'krbmaxticketlife',
                            label: IPA.get_entity_param('krbtpolicy', 'krbmaxticketlife').label,
                            read_only: true,
                            measurement_unit: 'seconds'
                        }
                    ]
                },
                {
                    name: 'contact',
                    fields: [
                        { type: 'multivalued', name: 'mail' },
                        { type: 'multivalued', name: 'telephonenumber' },
                        { type: 'multivalued', name: 'pager' },
                        { type: 'multivalued', name: 'mobile' },
                        { type: 'multivalued', name: 'facsimiletelephonenumber' }
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
                            type: 'entity_select',
                            name: 'manager',
                            other_entity: 'user',
                            other_field: 'uid'
                        }
                    ]
                },
                {
                    name: 'misc',
                    fields: [ 'carlicense' ]
                }
            ],
            actions: [
                IPA.select_action,
                IPA.enable_action,
                IPA.disable_action,
                IPA.delete_action,
                IPA.user.reset_password_action
            ],
            header_actions: ['select_action', 'enable', 'disable', 'delete'],
            state: {
                evaluators: [
                    {
                        factory: IPA.enable_state_evaluator,
                        field: 'nsaccountlock',
                        invert_value: true
                    },
                    IPA.user.reset_password_acl_evaluator
                ],
                summary_conditions: [
                    IPA.enabled_summary_cond(),
                    IPA.disabled_summary_cond()
                ]
            }
        }).
        association_facet({
            name: 'memberof_group',
            associator: IPA.serial_associator,
            link: link,
            read_only: self_service
        }).
        association_facet({
            name: 'memberof_netgroup',
            associator: IPA.serial_associator,
            link: link,
            read_only: self_service
        }).
        association_facet({
            name: 'memberof_role',
            associator: IPA.serial_associator,
            link: link,
            read_only: self_service
        }).
        association_facet({
            name: 'memberof_hbacrule',
            associator: IPA.serial_associator,
            add_method: 'add_user',
            remove_method: 'remove_user',
            link: link,
            read_only: self_service
        }).
        association_facet({
            name: 'memberof_sudorule',
            associator: IPA.serial_associator,
            add_method: 'add_user',
            remove_method: 'remove_user',
            link: link,
            read_only: self_service
        }).
        standard_association_facets({
            link: link
        }).
        adder_dialog({
            factory: IPA.user_adder_dialog,
            sections: [
                {
                    fields: [
                        {
                            name: 'uid',
                            required: false
                        },
                        'givenname',
                        'sn'
                    ]
                },
                {
                    fields: [
                        {
                            name: 'userpassword',
                            label: IPA.messages.password.new_password,
                            type: 'password'
                        },
                        {
                            name: 'userpassword2',
                            label: IPA.messages.password.verify_password,
                            type: 'password'
                        }
                    ]
                }
            ]
        });
    };

    return that;
};

IPA.user.details_facet = function(spec) {

    spec = spec || {};

    var that = IPA.details_facet(spec);

    that.refresh_on_success = function(data, text_status, xhr) {
        // do not load data from batch

        that.show_content();
    };

    that.create_refresh_command = function() {

        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');

        var batch = IPA.batch_command({
            name: 'user_details_refresh'
        });

        var user_command = that.details_facet_create_refresh_command();

        user_command.on_success = function(data, text_status, xhr) {
            // create data that mimics user-show output
            var user_data = {};
            user_data.result = data;
            that.load(user_data);
        };

        batch.add_command(user_command);

        var pwpolicy_command = IPA.command({
            entity: 'pwpolicy',
            method: 'show',
            options: {
                user: pkey,
                all: true,
                rights: true
            }
        });

        pwpolicy_command.on_success = function(data, text_status, xhr) {
            // TODO: Use nested fields: that.fields.get_field('pwpolicy').get_fields();
            var fields = that.fields.get_fields();
            for (var i=0; i<fields.length; i++) {
                var field = fields[i];

                // load result into pwpolicy fields
                if (field.widget_name.match(/^pwpolicy\./)) {
                    field.load(data.result);
                }
            }
        };

        batch.add_command(pwpolicy_command);

        var krbtpolicy_command = IPA.command({
            entity: 'krbtpolicy',
            method: 'show',
            args: [ pkey ],
            options: {
                all: true,
                rights: true
            }
        });

        krbtpolicy_command.on_success = function(data, text_status, xhr) {
            // TODO: Use nested fields: that.fields.get_field('krbtpolicy').get_fields();
            var fields = that.fields.get_fields();
            for (var i=0; i<fields.length; i++) {
                var field = fields[i];

                // load result into krbtpolicy fields
                if (field.widget_name.match(/^krbtpolicy\./)) {
                    field.load(data.result);
                }
            }
        };

        batch.add_command(krbtpolicy_command);

        return batch;
    };

    return that;
};

IPA.user_adder_dialog = function(spec) {

    var that = IPA.entity_adder_dialog(spec);

    that.validate = function() {
        var valid = that.dialog_validate();

        var field1 = that.fields.get_field('userpassword');
        var field2 = that.fields.get_field('userpassword2');

        var password1 = field1.save()[0];
        var password2 = field2.save()[0];

        if (password1 !== password2) {
            field2.show_error(IPA.messages.password.password_must_match);
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

IPA.user_password_widget = function(spec) {

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
    };

    that.clear = function() {
        that.display_control.text('');
    };

    return that;
};

IPA.user_password_dialog = function(spec) {

    spec = spec || {};

    spec.width = spec.width || 400;
    spec.title = spec.title || IPA.messages.password.reset_password;
    spec.sections = spec.sections || [];

    spec.sections.push(
        {
            name: 'input',
            fields: [
                {
                    name: 'current_password',
                    label: IPA.messages.password.current_password,
                    type: 'password',
                    required: true
                },
                {
                    name: 'password1',
                    label: IPA.messages.password.new_password,
                    type: 'password',
                    required: true
                },
                {
                    name: 'password2',
                    label: IPA.messages.password.verify_password,
                    type: 'password',
                    required: true
                }
            ]
        });

    var that = IPA.dialog(spec);
    that.success_handler = spec.on_success;
    that.error_handler = spec.on_error;
    that.self_service = spec.self_service; //option to force self-service

    that.get_pkey = function() {
        var pkey;
        if (that.self_service) {
            pkey = IPA.whoami.uid[0];
        } else {
            pkey = IPA.nav.get_state('user-pkey');
        }
        return pkey;
    };

    that.is_self_service = function() {
        var pkey = that.get_pkey();
        var self_service = pkey === IPA.whoami.uid[0];
        return self_service;
    };

    that.open = function() {

        var self_service = that.is_self_service();
        var section = that.widgets.get_widget('input');

        that.dialog_open();
        section.set_row_visible('current_password', self_service);
    };

    that.create_buttons = function() {

        that.create_button({
            name: 'reset_password',
            label: IPA.messages.password.reset_password,
            click: that.on_reset_click
        });

        that.create_button({
            name: 'cancel',
            label: IPA.messages.buttons.cancel,
            click: function() {
                that.close();
            }
        });
    };

    that.on_reset_click = function() {

        var pkey = that.get_pkey();
        var self_service = that.is_self_service();

        var record = {};
        that.save(record);

        var current_password;

        if (self_service) {
            current_password = record.current_password[0];
            if (!current_password) {
                alert(IPA.messages.password.current_password_required);
                return;
            }
        }

        var new_password = record.password1[0];
        var repeat_password = record.password2[0];

        if (IPA.is_empty(new_password)) {
            alert(IPA.messages.password.new_password_required);
            return;
        }

        if (new_password != repeat_password) {
            alert(IPA.messages.password.password_must_match);
            return;
        }

        that.set_password(
            pkey,
            current_password,
            new_password,
            that.on_reset_success,
            that.on_reset_error);
    };

    that.set_password = function(pkey, current_password, password, on_success, on_error) {

        var command = IPA.command({
            method: 'passwd',
            args: [ pkey ],
            options: {
                current_password: current_password,
                password: password
            },
            on_success: on_success,
            on_error: on_error
        });

        command.execute();
    };

    that.on_reset_success = function(data, text_status, xhr) {

        if (that.success_handler) {
            that.success_handler.call(this, data, text_status, xhr);
        } else {
            IPA.notify_success(IPA.messages.password.password_change_complete);
            that.close();

            // refresh password expiration field
            var facet = IPA.current_entity.get_facet();
            facet.refresh();

            if (that.is_self_service()) {
                var command = IPA.get_whoami_command();
                command.execute();
            }
        }
    };

    that.on_reset_error = function(xhr, text_status, error_thrown) {

        if (that.error_handler) {
            that.error_handler.call(this, xhr, text_status, error_thrown);
        } else {
            that.close();
        }
    };

    that.create_buttons();

    return that;
};

IPA.user.reset_password_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'reset_password';
    spec.label = spec.label || IPA.messages.password.reset_password;
    spec.enable_cond = spec.enable_cond || ['userpassword_w'];

    var that = IPA.action(spec);

    that.execute_action = function(facet) {

        var dialog = IPA.user_password_dialog({
            entity: facet.entity
        });

        dialog.open();
    };

    return that;
};

IPA.user.reset_password_acl_evaluator = function(spec) {

    spec.name = spec.name || 'reset_password_acl_evaluator';
    spec.attribute = spec.attribute || 'userpassword';

    var that = IPA.acl_state_evaluator(spec);
    return that;
};

IPA.register('user', IPA.user.entity);