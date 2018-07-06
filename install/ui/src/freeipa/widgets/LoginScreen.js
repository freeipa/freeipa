/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2013-2016 Red Hat
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
        'dojo/on',
        'dojo/topic',
        '../ipa',
        '../auth',
        '../config',
        '../reg',
        '../FieldBinder',
        '../text',
        '../util',
        './LoginScreenBase'
       ],
       function(declare, Deferred, construct, dom_style, query, on, topic,
                IPA, auth, config, reg, FieldBinder, text, util,
                LoginScreenBase) {


    /**
     * Widget with login form.
     *
     * Supported operations:
     *
     * - login with password, kerberos
     * - password change
     *
     * @class widgets.LoginScreen
     */
    var LoginScreen = declare([LoginScreenBase], {

        expired_msg: "Your session has expired. Please re-login.",

        form_auth_msg: "<i class=\"fa fa-info-circle\"></i> To log in with " +
            "<strong>username and password</strong>, enter them in the " +
            "corresponding fields, then click Login.",

        kerberos_msg: "<i class=\"fa fa-info-circle\"></i> To log in with " +
            "<strong>Kerberos</strong>, please make sure you" +
            " have valid tickets (obtainable via kinit) and <a href=" +
            "'http://${host}/ipa/config/ssbrowser.html'>configured</a>" +
            " the browser correctly, then click Login. ",
        cert_msg: "<i class=\"fa fa-info-circle\"></i> To log in with " +
            "<strong>certificate</strong>, please make sure you have valid " +
            "personal certificate. ",

        form_auth_failed: "Login failed due to an unknown reason",

        krb_auth_failed: "Authentication with Kerberos failed",

        cert_auth_failed: "Authentication with personal certificate failed",

        password_expired: "Your password has expired. Please enter a new " +
            "password.",

        password_change_complete: "Password change complete",

        krbprincipal_expired: "Kerberos Principal you entered is expired",

        invalid_password: "The password or username you entered is incorrect",

        user_locked: "The user account you entered is locked",

        //nodes:
        login_btn_node: null,
        reset_btn_node: null,
        cert_btn_node: null,

        /**
         * View this form is in.
         *
         * Possible views: ['login', 'reset', 'reset_and_login']
         * @property {string}
         */
        view: 'login',

        render_buttons: function(container) {

            this.cert_btn_node = IPA.button({
                name: 'cert_auth',
                title: text.get('@i18n:login.login_certificate_desc',
                    'Log in using personal certificate'),
                label: text.get('@i18n:login.login_certificate',
                    'Log In Using Certificate'),
                button_class: 'btn btn-link',
                click: this.login_with_cert.bind(this)
            })[0];
            construct.place(this.cert_btn_node, container);
            construct.place(document.createTextNode(" "), container);

            this.sync_btn_node = IPA.button({
                name: 'sync',
                label: text.get('@i18n:login.sync_otp_token', "Sync OTP Token"),
                button_class: 'btn btn-link',
                click: this.on_sync.bind(this)
            })[0];
            construct.place(this.sync_btn_node, container);
            construct.place(document.createTextNode(" "), container);

            this.login_btn_node = IPA.button({
                name: 'login',
                label: text.get('@i18n:login.login', "Log in"),
                'class': 'btn-primary btn-lg',
                click: this.on_confirm.bind(this)
            })[0];
            construct.place(this.login_btn_node, container);
            construct.place(document.createTextNode(" "), container);

            this.cancel_btn_node = IPA.button({
                name: 'cancel',
                label: text.get('@i18n:buttons.cancel', "Cancel"),
                'class': 'btn-default',
                click: this.on_cancel.bind(this)
            })[0];
            construct.place(this.cancel_btn_node, container);
            construct.place(document.createTextNode(" "), container);

            this.reset_btn_node = IPA.button({
                name: 'reset',
                label: text.get('@i18n:buttons.reset_password',
                                "Reset Password"),
                'class': 'btn-primary btn-lg',
                click: this.on_confirm.bind(this)
            })[0];
            construct.place(this.reset_btn_node, container);
            construct.place(document.createTextNode(" "), container);

            this.reset_and_login_btn_node = IPA.button({
                name: 'reset_and_login',
                label: text.get('@i18n:buttons.reset_password_and_login',
                                "Reset Password and Log in"),
                'class': 'btn-primary btn-lg',
                click: this.on_confirm.bind(this)
            })[0];
            construct.place(this.reset_and_login_btn_node, container);
        },

        set_visible_buttons: function(buttons) {
            if (!this.buttons_node) return;
            query('button', this.buttons_node).forEach(function(el) {
                if (buttons.indexOf(el.name) > -1) {
                    dom_style.set(el, 'display', '');
                } else {
                    dom_style.set(el, 'display', 'none');
                }
            });
        },

        post_create_fields: function() {
            if (this.view === 'login') {
                var u_f = this.get_field('username');
                var p_f = this.get_field('password');
                var otp_f = this.get_field('otp');

                u_f.on('value-change', this.on_form_change.bind(this));
                p_f.on('value-change', this.on_form_change.bind(this));
                otp_f.on('value-change', this.on_otp_change.bind(this));
                this.on_form_change();
            }
        },

        on_form_change: function(event) {

            var u_f = this.get_field('username');
            var p_f = this.get_field('password');
            var required = !util.is_empty(u_f.get_value()) ||
                    !util.is_empty(p_f.get_value()) || !this.kerberos_enabled();
            u_f.set_required(required);
            p_f.set_required(required);
        },

        on_otp_change: function(event) {
            if (this.view === 'login' || this.view === 'reset') return;
            if (!event.value[0]) {
                this.set_visible_buttons(['cancel', 'reset_and_login']);
            } else {
                this.set_visible_buttons(['cancel', 'reset']);
            }
        },

        on_sync: function() {
            var user = this.get_field('username').get_value()[0];
            this.get_widget('validation').remove_all('error');
            this.emit('require-otp-sync', { source: this, user: user });
        },

        on_confirm: function() {
            if (this.view === 'login') {
                this.login();
            } else if (this.view === 'reset_and_login') {
                this.reset_and_login();
            } else if (this.view === 'reset') {
                this.reset();
            }
        },

        on_cancel: function() {
            this.set('view', 'login');
        },

        login: function() {

            var val_summary = this.get_widget('validation');
            val_summary.remove('login');

            if (!this.validate()) return;

            var login = this.get_field('username').get_value()[0];
            if (util.is_empty(login) && this.kerberos_enabled()) {
                this.login_with_kerberos();
            } else {
                this.login_with_password();
            }
        },

        login_with_kerberos: function() {

            IPA.get_credentials().then(function(status) {
                if (status === 200) {
                    this.emit('logged_in');
                } else {
                    var val_summary = this.get_widget('validation');
                    val_summary.add_error('login', this.krb_auth_failed);
                }
            }.bind(this));
        },

        login_with_password: function() {

            if(!this.password_enabled()) return;

            var val_summary = this.get_widget('validation');
            var login = this.get_field('username').get_value()[0];
            var password_f = this.get_field('password');
            var password = password_f.get_value()[0];

            IPA.login_password(login, password).then(
                function(result) {

                if (result === 'success') {
                    this.emit('logged_in');
                    password_f.set_value('');
                } else if (result === 'password-expired') {
                    this.set('view', 'reset_and_login');
                    val_summary.add_info('login', this.password_expired);
                } else if (result === 'krbprincipal-expired') {
                    password_f.set_value('');
                    val_summary.add_error('login', this.krbprincipal_expired);
                } else if (result === 'invalid-password') {
                    password_f.set_value('');
                    val_summary.add_error('login', this.invalid_password);
                } else if (result === 'user-locked') {
                    password_f.set_value('');
                    val_summary.add_error('login', this.user_locked);
                } else {
                    password_f.set_value('');
                    val_summary.add_error('login', this.form_auth_failed);
                }
            }.bind(this));
        },

        login_with_cert: function() {

            this.lookup_credentials().then(function(status) {
                if (status === 200) {
                    this.emit('logged_in');
                } else {
                    var val_summary = this.get_widget('validation');
                    val_summary.add_error('login', this.cert_auth_failed);
                }
            }.bind(this));
        },

        reset_password: function() {

            var psw_f = this.get_field('password');
            var psw_f2 = this.get_field('current_password');
            var otp_f = this.get_field('otp');
            var new_f = this.get_field('new_password');
            var ver_f = this.get_field('verify_password');
            var username_f = this.get_field('username');

            var psw = psw_f2.get_value()[0] || psw_f.get_value()[0];
            var otp = otp_f.get_value()[0];

            var result = IPA.reset_password(
                username_f.get_value()[0],
                psw,
                new_f.get_value()[0],
                otp);

            if (result.status === 'ok') {
                psw_f.set_value('');
                psw_f2.set_value('');
            } else {
                otp_f.set_value('');
                new_f.set_value('');
                ver_f.set_value('');
            }
            return result;
        },

        reset_and_login: function() {

            if (!this.validate()) return;
            var val_summary = this.get_widget('validation');
            val_summary.remove('login');
            var psw_f = this.get_field('password');
            var new_f = this.get_field('new_password');
            var otp_f = this.get_field('otp');
            var otp = otp_f.get_value()[0];

            var result = this.reset_password();
            if (result.status === 'ok') {
                /* do not login if otp is used because it will fail
                 * (reuse of OTP)
                */
                if (!otp) {
                    psw_f.set_value(new_f.get_value());
                    this.login();
                }
                val_summary.add_success('login', this.password_change_complete);
                this.set('view', 'login');
            } else {
                val_summary.add_error('login', result.message);
            }
        },

        reset: function() {

            if (!this.validate()) return;
            var val_summary = this.get_widget('validation');
            val_summary.remove('login');
            var otp_f = this.get_field('otp');
            var new_f = this.get_field('new_password');
            var ver_f = this.get_field('verify_password');

            var result = this.reset_password();
            if (result.status === 'ok') {
                otp_f.set_value('');
                new_f.set_value('');
                ver_f.set_value('');
                val_summary.add_success('login', this.password_change_complete);
                this.redirect();
            } else {
                val_summary.add_error('login', result.message);
            }
        },

        lookup_credentials: function() {

            var status;
            var d = new Deferred();

            function error_handler(xhr, text_status, error_thrown) {
                d.resolve(xhr.status);
                topic.publish('rpc-end');
            }

            function success_handler(data, text_status, xhr) {
                auth.current.set_authenticated(true, 'kerberos');
                d.resolve(xhr.status);
                topic.publish('rpc-end');
            }

            var login = this.get_field('username').get_value()[0];

            var request = {
                url: config.x509_login_url,
                cache: false,
                type: "GET",
                data: $.param({
                    'username': login
                }),
                success: success_handler,
                error: error_handler
            };
            topic.publish('rpc-start');
            $.ajax(request);

            return d.promise;
        },

        refresh: function() {
            if (this.view === 'reset') {
                this.show_reset_view();
            } else if (this.view === 'reset_and_login') {
                    this.show_reset_and_login_view();
            } else {
                this.show_login_view();
            }
        },

        show_login_view: function() {
            this.set_login_aside_text();
            if (auth.current.expired) {
                var val_summary = this.get_widget('validation');
                val_summary.add_info('expired', this.expired_msg);
            }
            this.set_visible_buttons(['cert_auth', 'sync', 'login']);
            if (this.password_enabled()) {
                this.use_fields(['username', 'password']);
                var username_f = this.get_field('username');
                if (username_f.get_value()[0]) {
                    this.get_widget('password').focus_input();
                } else {
                    this.get_widget('username').focus_input();
                }
            } else {
                this.use_fields([]);
                this.login_btn_node.focus();
            }
        },

        show_reset_view: function() {

            this.set_reset_aside_text();
            this.set_visible_buttons(['reset']);
            this.use_fields(['username', 'current_password', 'otp',
                             'new_password', 'verify_password']);

            var val_summary = this.get_widget('validation');
            this.fields.get('username').set_required(true);
            this.fields.get('current_password').set_required(true);

            this.get_widget('username').focus_input();
        },

        show_reset_and_login_view: function() {

            this.set_reset_aside_text();
            this.set_visible_buttons(['cancel', 'reset_and_login']);
            this.use_fields(['username_r', 'current_password', 'otp',
                             'new_password', 'verify_password']);

            var val_summary = this.get_widget('validation');

            var u_f = this.fields.get('username');
            var u_r_f = this.fields.get('username_r');
            u_r_f.set_value(u_f.get_value());
            this.get_widget('current_password').focus_input();
        },

        set_login_aside_text: function() {
            var aside = "";
            if (this.password_enabled()) {
                aside += "<p>"+this.form_auth_msg+"<p/>";
            }
            if (this.kerberos_enabled()) {
                aside += "<p>"+this.kerberos_msg+"<p/>";
            }
            if (this.certificate_enabled()) {
                aside += "<p>"+this.cert_msg+"<p/>";
            }

            this.set('aside', aside);
        },

        set_reset_aside_text: function() {
            this.set('aside', "<p>"+this.otp_info_msg+"<p/>");
        },

        constructor: function(spec) {
            spec = spec || {};

            this.expired_msg = text.get(
                spec.expired_msg || '@i18n:ajax.401.message',
                this.expired_msg
            );

            this.form_auth_msg = text.get(
                spec.form_auth_msg || '@i18n:login.form_auth',
                this.form_auth_msg
            );

            this.kerberos_msg = text.get(
                spec.kerberos_msg || '@i18n:login.krb_auth_msg',
                this.kerberos_msg
            );

            this.cert_msg = text.get(
                spec.cert_msg || '@i18n:login.cert_msg',
                this.cert_msg
            );

            this.redirect_msg = text.get(
                spec.redirect_msg || '@i18n:login.redirect_msg',
                this.redirect_msg
            );

            this.continue_msg = text.get(
                spec.continue_msg || '@i18n:login.continue_msg',
                this.continue_msg
            );

            this.kerberos_msg = this.kerberos_msg.replace(
                '${host}', window.location.hostname
            );

            this.password_change_complete = text.get(
                spec.password_change_complete ||
                    '@i18n:password.password_change_complete',
                this.password_change_complete
            );

            this.form_auth_failed = text.get(
                spec.form_auth_failed || '@i18n:login.form_auth_failed',
                this.form_auth_failed
            );

            this.krb_auth_failed = text.get(
                spec.krb_auth_failed || '@i18n:login.krb_auth_failed',
                this.krb_auth_failed
            );

            this.cert_auth_failed = text.get(
                spec.cert_auth_failed || '@i18n:login.cert_auth_failed',
                this.cert_auth_failed
            );

            this.password_expired = text.get(
                spec.password_expired || '@i18n:password.password_expired',
                this.password_expired
            );

            this.krbprincipal_expired = text.get(
                spec.krbprincipal_expired ||
                    '@i18n:login.krbprincipal_expired',
                this.krbprincipal_expired
            );

            this.invalid_password = text.get(
                spec.invalid_password || '@i18n:password.invalid_password',
                this.invalid_password
            );

            this.user_locked = text.get(
                spec.user_locked || '@i18n:login.user_locked',
                this.user_locked
            );

            this.field_specs = LoginScreen.field_specs;
        }
    });

    LoginScreen.field_specs = [
        {
            $type: 'text',
            name: 'username',
            label: text.get('@i18n:login.username', "Username"),
            placeholder: text.get('@i18n:login.username', "Username"),
            show_errors: false,
            undo: false
        },
        {
            $type: 'password',
            name: 'password',
            label: text.get('@i18n:login.password', "Password"),
            placeholder: text.get(
                '@i18n:login.password_and_otp',
                'Password or Password+One-Time-Password'
            ),
            show_errors: false,
            undo: false
        },
        {
            name: 'username_r',
            read_only: true,
            label: text.get('@i18n:login.username', "Username"),
            show_errors: false,
            undo: false
        },
        {
            name: 'current_password',
            $type: 'password',
            label: text.get(
                '@i18n:password.current_password',
                "Current Password"
            ),
            placeholder: text.get(
                '@i18n:password.current_password',
                "Current Password"
            ),
            show_errors: false,
            undo: false
        },
        {
            name: 'otp',
            $type: 'password',
            label: text.get('@i18n:password.otp', "OTP"),
            placeholder: text.get(
                '@i18n:password.otp_long',
                'One-Time-Password'
            ),
            show_errors: false,
            undo: false
        },
        {
            name: 'new_password',
            $type: 'password',
            required: true,
            label: text.get(
                '@i18n:password.new_password',
                "New Password"
            ),
            placeholder: text.get(
                '@i18n:password.new_password',
                "New Password"
            ),
            show_errors: false,
            undo: false
        },
        {
            name: 'verify_password',
            $type: 'password',
            required: true,
            label: text.get(
                '@i18n:password.verify_password',
                "Verify Password"
            ),
            placeholder: text.get(
                '@i18n:password.new_password',
                "New Password"
            ),
            validators: [{
                $type: 'same_password',
                other_field: 'new_password'
            }],
            show_errors: false,
            undo: false
        }
    ];

    return LoginScreen;
});
