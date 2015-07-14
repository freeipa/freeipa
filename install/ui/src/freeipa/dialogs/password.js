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
            function(lang, builder, IPA, phases, reg, rpc, text, dialogs) {

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
    spec.success_message = spec.success_message || '@i18n:password.password_change_complete';
    spec.confirm_button_label = spec.confirm_button_label || '@i18n:password.reset_password';
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
        factory: dialogs.command_dialog,
        pre_ops: [DP.default_fields_pre_op],
        post_ops: [dialogs.command_dialog_post_op]
    });

    a.register('password', DP.action);
};

phases.on('registration', DP.register);

return DP;
});