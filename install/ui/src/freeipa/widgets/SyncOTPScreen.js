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

define(['dojo/_base/declare',
        'dojo/Deferred',
        'dojo/dom-construct',
        'dojo/dom-style',
        'dojo/query',
        'dojo/topic',
        'dojo/on',
        '../ipa',
        '../auth',
        '../config',
        '../reg',
        '../FieldBinder',
        '../text',
        '../util',
        './LoginScreenBase'
       ],
       function(declare, Deferred, construct, dom_style, query, topic, on,
                IPA, auth, config, reg, FieldBinder, text, util,
                LoginScreenBase) {


    /**
     * Widget with OTP sync form.
     *
     * @class widgets.SyncOTPScreen
     */
    var SyncOTPScreen = declare([LoginScreenBase], {

        sync_fail: "Token synchronization failed",

        invalid_credentials: "The username, password or token codes are not correct",

        sync_success: "Token was synchronized",

        allow_cancel: true,

        user: null,

        //nodes:
        cancel_btn_node: null,
        sync_btn_node: null,

        render_buttons: function(container) {
            this.cancel_btn_node = IPA.button({
                name: 'cancel',
                label: text.get('@i18n:buttons.cancel', "Cancel"),
                'class': 'btn-default btn-lg',
                click: this.on_cancel.bind(this)
            })[0];
            if (this.allow_cancel) {
                construct.place(this.cancel_btn_node, container);
            }
            this.sync_btn_node = IPA.button({
                label: text.get('@i18n:login.sync_otp_token', "Sync OTP Token"),
                'class': 'btn-primary btn-lg',
                click: this.on_confirm.bind(this)
            })[0];
            construct.place(this.sync_btn_node, container);
        },

        refresh: function() {
            this.reset();
            this.get_widget('validation').remove('sync');
            if (this.user) {
                this.get_field('user').set_value([this.user]);
                this.get_widget('password').focus_input();
            } else {
                this.get_widget('user').focus_input();
            }
            if (this.buttons_node) {
                this.buttons_node.innerHTML = "";
                if (this.allow_cancel) {
                    construct.place(this.cancel_btn_node, this.buttons_node);
                }
                construct.create('span', { innerHTML: ' '}, this.buttons_node);
                construct.place(this.sync_btn_node, this.buttons_node);
            }
        },

        on_cancel: function() {
            this.emit('sync-cancel', { source: this });
        },

        on_confirm: function() {
            this.sync();
        },

        sync: function() {

            var val_summary = this.get_widget('validation');
            val_summary.remove('sync');

            if (!this.validate()) return;

            var user = this.get_field('user').get_value()[0];
            var password_f = this.get_field('password');
            var password = password_f.get_value()[0];
            var otp1 = this.get_field('first_code').get_value()[0];
            var otp2 = this.get_field('second_code').get_value()[0];
            var token = this.get_field('token').get_value()[0];

            var p = this.sync_core(user, password, otp1, otp2, token);
            p.then( function(result) {
                var msg = this.sync_fail;
                var evt = 'sync-fail';
                var type = 'error';
                this.refresh();
                if (result === 'ok') {
                    evt = 'sync-success';
                    msg = this.sync_success;
                    val_summary.add_success('sync', msg);
                } else if (result === 'invalid-credentials') {
                    msg = this.invalid_credentials;
                    val_summary.add_error('sync', msg);
                } else {
                    val_summary.add_error('sync', msg);
                }
                this.emit(evt, { source: this, message: msg, status: result });
            }.bind(this));
        },

        sync_core: function(user, password, otp1, otp2, token) {

            var d = new Deferred();
            var data = {
                user: user,
                password: password,
                first_code: otp1,
                second_code: otp2
            };
            if (token) data.token = token;

            var handler = function(data, text_status, xhr) {
                var result = xhr.getResponseHeader("X-IPA-TokenSync-Result");
                result = result || 'error';
                topic.publish('rpc-end');
                d.resolve(result);
            };

            var request = {
                url: config.token_sync_url,
                data: data,
                contentType: 'application/x-www-form-urlencoded',
                processData: true,
                dataType: 'html',
                type: 'POST',
                success: handler,
                error: handler
            };

            topic.publish('rpc-start');
            $.ajax(request);
            return d.promise;
        },

        setUser: function(value) {
            this.user = value;
            this.get_field('user').set_value([value]);
        },

        constructor: function(spec) {
            spec = spec || {};

            this.aside = "<p>" + this.otp_info_msg + "</p>";

            this.sync_fail = text.get(spec.sync_fail || '@i18n:password.otp_sync_fail',
                this.sync_fail);

            this.sync_success = text.get(spec.sync_success || '@i18n:password.otp_sync_success',
                this.sync_success);

            this.invalid_credentials = text.get(spec.invalid_credentials || '@i18n:password.otp_sync_invalid',
                this.invalid_credentials);

            this.field_specs = SyncOTPScreen.field_specs;
        }
    });

    SyncOTPScreen.field_specs = [
        {
            $type: 'text',
            name: 'user',
            label: text.get('@i18n:login.username', "Username"),
            show_errors: false,
            undo: false,
            required: true
        },
        {
            $type: 'password',
            name: 'password',
            label: text.get('@i18n:login.password', "Password"),
            show_errors: false,
            undo: false,
            required: true
        },
        {
            $type: 'password',
            name: 'first_code',
            label: text.get('@i18n:password.first_otp', "First OTP"),
            show_errors: false,
            undo: false,
            required: true
        },
        {
            $type: 'password',
            name: 'second_code',
            label: text.get('@i18n:password.second_otp', "Second OTP"),
            show_errors: false,
            undo: false,
            required: true
        },
        {
            $type: 'text',
            name: 'token',
            label: text.get('@i18n:password.token_id', "Token ID"),
            show_errors: false,
            undo: false
        }
    ];

    return SyncOTPScreen;
});
