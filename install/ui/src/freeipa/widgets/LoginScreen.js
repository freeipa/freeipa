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
        'dojo/_base/lang',
        'dojo/dom-construct',
        'dojo/dom-style',
        'dojo/query',
        'dojo/on',
        'dojo/Evented',
        'dojo/Stateful',
        '../ipa',
        '../auth',
        '../reg',
        '../FieldBinder',
        '../FormMixin',
        '../text',
        '../util',
        './ContainerMixin'
       ],
       function(declare, lang,  construct, dom_style, query, on,
                Evented, Stateful, IPA, auth, reg, FieldBinder, FormMixin, text,
                util, ContainerMixin) {

    var ConfirmMixin = declare(null, IPA.confirm_mixin().mixin);

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
    var LoginScreen = declare([Stateful, Evented, FormMixin, ContainerMixin, ConfirmMixin], {

        id: '',

        'class': 'login-pf',

        logo_src: 'images/login-screen-logo.png',

        product_name_src: 'images/product-name.png',

        product_name: '',

        expired_msg: "Your session has expired. Please re-login.",

        form_auth_msg: "To login with username and password, enter them in the fields below, then click Login.",

        kerberos_msg: " To login with Kerberos, please make sure you" +
                    " have valid tickets (obtainable via kinit) and " +
                    "<a href='http://${host}/ipa/config/unauthorized.html'>configured</a>" +
                    " the browser correctly, then click Login. ",

        form_auth_failed: "The password or username you entered is incorrect. ",

        krb_auth_failed: "Authentication with Kerberos failed",

        password_expired: "Your password has expired. Please enter a new password.",

        password_change_complete: "Password change complete",

        denied: "Sorry you are not allowed to access this service.",

        caps_warning_msg: "Warning: CAPS LOCK key is on",

        /**
         * Details builder
         * @property {IPA.details_builder}
         * @protected
         */
        details_builder: null,

        /**
         * Aside text
         * @property {string}
         */
        aside: "",

        //nodes:
        dom_node: null,
        container_node: null,
        content_node: null,
        aside_node: null,
        login_btn_node: null,
        reset_btn_node: null,
        buttons_node: null,

        /**
         * View this form is in.
         *
         * Possible views: ['login', 'reset']
         * @property {string}
         */
        view: 'login',

        /**
         * Indicates that CAPS LOCK warning is on. Null indicates that we don't
         * know the state.
         * @property {boolean|null}
         */
        caps_warning: null,


        _asideSetter: function(text) {
            this.aside = text;
            if (this.aside_node) {
                this.aside_node.innerHTML = this.aside;
            }
        },

        _viewSetter: function(view) {
            this.view = view;
            this.refresh();
        },

        render: function() {

            this.dom_node = construct.create('div', {
                id: this.id,
                'class': this['class']
            });

            if (this.container_node) {
                construct.place(this.dom_node, this.container_node);
            }

            this.render_content();
            this.register_listeners();

            return this.dom_node;
        },

        render_content: function() {

            var login_body = construct.create('div', {
                'class': 'login-pf-body'
            }, this.dom_node);

            construct.empty(login_body);

            this.render_badge(login_body);

            var cnt = construct.create('div', {
                'class': 'container'
            }, login_body);

            var row = construct.create('div', {
                'class': 'row'
            }, cnt);


            this.render_brand(row);
            this.render_form(row);
            this.render_aside(row);
        },

        render_badge: function(container) {

            var cnt = construct.create('span', {
                'id': 'badge'
            }, container);
            construct.create('img', {
                src: this.logo_src,
                alt: this.product_name
            }, cnt);
        },

        render_brand: function(container) {
            var c1 = construct.create('div', {
                'class': 'col-sm-12'
            }, container);
            var c2 = construct.create('div', {
                'id': 'brand'
            }, c1);
            construct.create('img', {
                src: this.product_name_src,
                height: '80px'
            }, c2);
        },

        render_form: function(container) {

            var form_cont = construct.create('div', {
                'class': 'col-sm-7 col-md-6 col-lg-5 login'
            }, container);

            var layout = IPA.fluid_layout({
                label_cls: 'col-sm-3 col-md-3 control-label',
                widget_cls: 'col-sm-9 col-md-9 controls'
            });
            var form = layout.create(this.get_widgets());
            construct.place(form[0], form_cont);
            this.register_caps_check();

            var btn_row = construct.create('div', {
                'class': 'row'
            }, form_cont);

            this.buttons_node = construct.create('div', {
                'class': 'col-sm-12 col-md-offset-3 col-md-9 submit'
            }, btn_row);

            this.login_btn_node = IPA.button({
                label: text.get('@i18n:login.login', "Login"),
                'class': 'btn-primary btn-lg',
                click: lang.hitch(this, this.on_confirm)
            })[0];
            construct.place(this.login_btn_node, this.buttons_node);

            this.reset_btn_node = IPA.button({
                label: text.get('@i18n:buttons.reset_password_and_login', "Reset Password and Login"),
                'class': 'btn-primary btn-lg',
                click: lang.hitch(this, this.on_confirm)
            })[0];
        },

        render_aside: function(container) {

            this.aside_node = construct.create('div', {
                'class': 'col-sm-5 col-md-6 col-lg-7 details',
                innerHTML: this.aside
            }, container);
        },

        create_fields: function() {

            var validation_summary = {
                $type: 'validation_summary',
                name: 'validation',
                visible: false
            };

            var val_w = this.add_widget(validation_summary);
            var fields = LoginScreen.field_specs;
            for (var i=0, l=fields.length; i<l; i++) {
                var f = this.add_field(fields[i]);
                var w = this.add_widget(fields[i]);
                new FieldBinder(f, w).bind(true);
                this.bind_validation(val_w, f);
            }

            var u_f = this.get_field('username');
            var p_f = this.get_field('password');

            u_f.on('value-change', lang.hitch(this, this.on_form_change));
            p_f.on('value-change', lang.hitch(this, this.on_form_change));
            this.on_form_change();
        },

        on_form_change: function(event) {

            var u_f = this.get_field('username');
            var p_f = this.get_field('password');
            var required = !util.is_empty(u_f.get_value()) ||
                    !util.is_empty(p_f.get_value()) || !this.kerberos_enabled();
            u_f.set_required(required);
            p_f.set_required(required);
        },

        register_caps_check: function() {

            // this is not a nice solution. It breaks widget encapsulation over
            // input field, but we need to listen to keydown events which are
            // not exposed
            var nodes = query("input[type=text],input[type=password]", this.dom_node);
            nodes.on('keypress', lang.hitch(this, this.check_caps_lock));
            nodes.on('keydown', lang.hitch(this, this.check_caps_lock_press));
        },

        /**
         * Check if Caps Lock key is on.
         *
         * Works fine only with keypress events. Doesn't work with keydown or
         * up since keyCode is always uppercase there.
         * @param {Event} e  Key press event
         * @protected
         */
        check_caps_lock: function(e) {

            var s = String.fromCharCode(e.keyCode || e.which);

            if ((s.toUpperCase() === s && s.toLowerCase() !== s && !e.shiftKey)||
              (s.toUpperCase() !== s && s.toLowerCase() === s && e.shiftKey)) {
                this.displey_caps_warning(true);
            } else if ((s.toLowerCase() === s && s.toUpperCase() !== s && !e.shiftKey)||
              (s.toLowerCase() !== s && s.toUpperCase() === s && e.shiftKey)) {
                this.displey_caps_warning(false);
            }
            // in other cases it's most likely non alpha numeric character
        },

        /**
         * Check if Caps Lock was press
         * If current caps lock state is known, i.e. by `check_caps_lock` method,
         * toogle it.
         * @param {Event} e Key down or key up event
         * @protected
         */
        check_caps_lock_press: function(e) {

            if (this.caps_warning !== null && e.keyCode == 20) {
                this.displey_caps_warning(!this.caps_warning);
            }
        },

        /**
         * Show or hide CAPS lock warning
         * @param {boolean} display
         * @protected
         */
        displey_caps_warning: function(display) {

            this.caps_warning = display;
            var val_summary = this.get_widget('validation');
            if (display) {
                val_summary.add_warning('caps', this.caps_warning_msg);
            } else {
                val_summary.remove('caps');
            }
        },

        bind_validation: function(summary, field) {

            on(field, 'valid-change', function(e) {
                if (e.valid) {
                    summary.remove(field.name);
                } else {
                    summary.add_error(field.name, field.label + ': ' + e.result.message);
                }
            });
        },

        on_confirm: function() {
            if (this.view == 'login') {
                this.login();
            } else {
                this.login_and_reset();
            }
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

            IPA.get_credentials().then(lang.hitch(this, function(status) {
                if (status === 200) {
                    this.emit('logged_in');
                } else {
                    var val_summary = this.get_widget('validation');
                    val_summary.add_error('login', this.krb_auth_failed);
                }
            }));
        },

        login_with_password: function() {

            if(!this.password_enabled()) return;

            var val_summary = this.get_widget('validation');
            var login = this.get_field('username').get_value()[0];
            var password_f = this.get_field('password');
            var password = password_f.get_value()[0];

            IPA.login_password(login, password).then(
                lang.hitch(this, function(result) {

                if (result === 'success') {
                    this.emit('logged_in');
                    password_f.set_value('');
                } else if (result === 'password-expired') {
                    this.set('view', 'reset');
                    val_summary.add_info('login', this.password_expired);
                } else {
                    val_summary.add_error('login', this.form_auth_failed);
                    password_f.set_value('');
                }
            }));
        },

        login_and_reset: function() {

            var val_summary = this.get_widget('validation');
            val_summary.remove('login');

            if (!this.validate()) return;

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
                val_summary.add_success('login', this.password_change_complete);
                psw_f.set_value('');
                psw_f2.set_value('');
                // do not login if otp is used because it will fail (reuse of OTP)
                if (!otp) {
                    psw_f.set_value(new_f.get_value());
                    this.login();
                }
                this.set('view', 'login');
            } else {
                val_summary.add_error('login', result.message);
            }

            otp_f.set_value('');
            new_f.set_value('');
            ver_f.set_value('');
        },

        refresh: function() {
            if (this.buttons_node) {
                this.buttons_node.innerHTML = "";
            }
            if (this.view === 'reset') {
                this.show_reset_view();
            } else {
                this.show_login_view();
            }
        },

        show_login_view: function() {
            this.set_login_aside_text();
            if (this.buttons_node) {
                construct.place(this.login_btn_node, this.buttons_node);
            }
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
            if (this.buttons_node) {
                construct.place(this.reset_btn_node, this.buttons_node);
            }
            this.use_fields(['username_r', 'current_password', 'otp', 'new_password', 'verify_password']);

            var val_summary = this.get_widget('validation');

            var u_f = this.fields.get('username');
            var u_r_f = this.fields.get('username_r');
            u_r_f.set_value(u_f.get_value());
            this.get_widget('current_password').focus_input();
        },

        use_fields: function(names) {

            var fields = this.get_fields();
            for (var i=0, l=fields.length; i<l; i++) {
                var f = fields[i];
                var w = this.get_widget(f.name);
                var enable = names.indexOf(f.name) >-1;
                f.set_enabled(enable);
                w.set_visible(enable);
            }
        },

        set_login_aside_text: function() {
            var aside = "";
            if (auth.current.expired) {
                aside += "<p>"+this.expired_msg;+"<p/>";
            }
            if (this.password_enabled()) {
                aside += "<p>"+this.form_auth_msg;+"<p/>";
            }
            if (this.kerberos_enabled()) {
                aside += "<p>"+this.kerberos_msg;+"<p/>";
            }
            this.set('aside', aside);
        },

        set_reset_aside_text: function() {
            this.set('aside', '');
        },

        kerberos_enabled: function() {
            return auth.current.auth_methods.indexOf('kerberos') > -1;
        },

        password_enabled: function() {
            return auth.current.auth_methods.indexOf('password') > -1;
        },

        postscript: function(args) {
            this.create_fields();
        },

        constructor: function(spec) {
            spec = spec || {};
            declare.safeMixin(this, spec);

            this.expired_msg = text.get(spec.expired_msg || '@i18n:ajax.401.message',
                this.expired_msg);

            this.form_auth_msg = text.get(spec.form_auth_msg || '@i18n:login.form_auth',
                this.form_auth_msg);

            this.kerberos_msg = text.get(spec.kerberos_msg || '@i18n:login.krb_auth_msg',
                this.kerberos_msg);

            this.kerberos_msg = this.kerberos_msg.replace('${host}', window.location.hostname);

            this.password_change_complete = text.get(spec.password_change_complete ||
                '@i18n:password.password_change_complete', this.password_change_complete);

            this.krb_auth_failed = text.get(spec.krb_auth_failed, this.krb_auth_failed);
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
            placeholder: text.get('@i18n:login.password_and_otp', 'Password or Password+One-Time-Password'),
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
            label: text.get('@i18n:login.current_password', "Current Password"),
            placeholder: text.get('@i18n:login.current_password', "Current Password"),
            show_errors: false,
            undo: false
        },
        {
            name: 'otp',
            $type: 'password',
            label: text.get('@i18n:password.otp', "OTP"),
            placeholder: text.get('@i18n:password.otp_long', 'One-Time-Password'),
            show_errors: false,
            undo: false
        },
        {
            name: 'new_password',
            $type: 'password',
            required: true,
            label: text.get('@i18n:password.new_password)', "New Password"),
            placeholder: text.get('@i18n:password.new_password)', "New Password"),
            show_errors: false,
            undo: false
        },
        {
            name: 'verify_password',
            $type: 'password',
            required: true,
            label: text.get('@i18n:password.verify_password', "Verify Password"),
            placeholder: text.get('@i18n:password.new_password)', "New Password"),
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