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
        'dojo/_base/lang',
        '../builder',
        '../ipa',
        '../phases',
        '../reg',
        '../rpc',
        '../text',
        '../dialog'],
            function(lang, builder, IPA, phases, reg, rpc, text) {

var dialogs = {}; // dummy object
/**
 * Password dialog module
 * @class
 * @singleton
 */
dialogs.password = {};
var DP = dialogs.password;

/**
 * Dialog's pre_ops
 */
dialogs.password.default_fields_pre_op =  function(spec) {

    var name = spec.password_name || 'password1';
    var label = spec.password_label || '@i18n:password.new_password';
    var verify_label = spec.verify_label ||'@i18n:password.verify_password';

    spec.title = spec.title || '@i18n:password.reset_password';
    spec.width = spec.width || 400;
    spec.sections = spec.sections || [
        {
            name: 'general',
            fields: [
                {
                    name: name,
                    label: label,
                    $type: 'password',
                    required: true
                },
                {
                    name: 'password2',
                    label: verify_label,
                    $type: 'password',
                    required: true,
                    flags: ['no_command'],
                    validators: [{
                        $type: 'same_password',
                        other_field: name
                    }]
                }
            ]
        }
    ];
    return spec;
};

/**
 * Dialog's post_ops
 */
dialogs.password.default_post_op = function(dialog, spec) {
    dialog.init();
    return dialog;
};

/**
 * Password dialog
 * @class
 * @extends IPA.dialog
 * @mixins IPA.confirm_mixin
 */
dialogs.password.dialog = function(spec) {

    var that = IPA.dialog(spec);

    IPA.confirm_mixin().apply(that);

    /**
     * Method for setting password
     * @property {string}
     */
    that.method = spec.method || 'mod';

    /**
     * Command args
     * @property {string[]}
     */
    that.args = spec.args || [];

    /**
     * Command additional options
     * @property {Object}
     */
    that.options = spec.options || {};

    /**
     * Success message
     * @property {string}
     */
    that.success_message = spec.success_message || '@i18n:password.password_change_complete';

    /**
     * Set button label
     * @property {string}
     */
    that.confirm_button_label = spec.confirm_button_label || '@i18n:password.reset_password';

    /**
     * Failed event
     * @event
     */
    that.failed = IPA.observer();

    /**
     * Succeeded event
     * @event
     */
    that.succeeded = IPA.observer();

    /**
     * Execute password change
     */
    that.execute = function() {

        var command = that.create_command();
        command.execute();
    };

    /**
     * Confirm handler
     * @protected
     */
    that.on_confirm = function() {

        if (!that.validate()) return;
        that.execute();
        that.close();
    };

    /**
     * Create buttons
     * @protected
     */
    that.create_buttons = function() {

        that.create_button({
            name: 'confirm',
            label: that.confirm_button_label,
            click: function() {
                that.on_confirm();
            }
        });

        that.create_button({
            name: 'cancel',
            label: '@i18n:buttons.cancel',
            click: function() {
                that.close();
            }
        });
    };

    /**
     * Make options for command
     * @protected
     */
    that.make_otions = function() {

        var options = {};
        lang.mixin(options, that.options);

        var fields = that.fields.get_fields();
        for (var j=0; j<fields.length; j++) {
            var field = fields[j];
            var values = field.save();
            if (!values || values.length === 0 || !field.enabled) continue;
            if (field.flags.indexOf('no_command') > -1) continue;

            if (values.length === 1) {
                options[field.param] = values[0];
            } else {
                options[field.param] = values;
            }
        }
        return options;
    };

    /**
     * Create command
     * @protected
     */
    that.create_command = function() {

        var options = that.make_otions();
        var entity = null;
        if (that.entity) entity = that.entity.name;
        var command = rpc.command({
            entity: entity,
            method: that.method,
            args: that.args,
            options: options,
            on_success: function(data) {
                that.on_success();
            },
            on_error: function() {
                that.on_error();
            }
        });
        return command;
    };

    /**
     * Get success message
     * @protected
     */
    that.get_success_message = function() {
        return text.get(that.success_message);
    };

    /**
     * Success handler
     * @protected
     * @param {Object} data
     */
    that.on_success = function(data) {
        that.succeeded.notify([data], that);
        IPA.notify_success(that.get_success_message());
    };

    /**
     * Error handler
     * @protected
     */
    that.on_error = function(xhr, status, error) {
        that.failed.notify([xhr, status, error], that);
    };

    /**
     * Init function
     *
     * - should be called right after instance creation
     */
    that.init = function() {
        that.create_buttons();
    };

    return that;
};

/**
 * Action to open a password dialog
 * @class
 * @extends facet.action
 */
dialogs.password.action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'password';
    spec.label = spec.label || '@i18n:password.reset_password';

    var that = IPA.action(spec);

    /**
     * Dialog spec
     * @property {Object}
     */
    that.dialog = spec.dialog || {};

    /**
     * Refresh facet after successful password reset
     * @property {boolean} refresh=true
     */
    that.refresh = spec.refresh !== undefined ? spec.refresh : true;

    /**
     * @inheritDoc
     */
    that.execute_action = function(facet) {

        var ds = lang.clone(that.dialog);
        ds.entity = ds.entity || facet.entity;
        if (!ds.$type && !ds.$factory && !ds.$ctor) {
            ds.$type = 'password';
        }
        var dialog = builder.build('dialog', ds);
        dialog.args = facet.get_pkeys();
        dialog.succeeded.attach(function() {
            if (that.refresh) facet.refresh();
        });
        dialog.open();
    };
    return that;
};

/**
 * Register dialog
 * @member dialogs.password
 */
dialogs.password.register = function() {

    var d = reg.dialog;
    var a = reg.action;

    d.register({
        type: 'password',
        factory: DP.dialog,
        pre_ops: [DP.default_fields_pre_op],
        post_ops: [DP.default_post_op]
    });

    a.register('password', DP.action);
};

phases.on('registration', DP.register);

return DP;
});