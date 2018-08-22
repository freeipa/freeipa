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
       function(declare, construct, dom_style, query, on,
                Evented, Stateful, IPA, auth, reg, FieldBinder, FormMixin, text,
                util, ContainerMixin) {

    var ConfirmMixin = declare(null, IPA.confirm_mixin().mixin);

    /**
     * Base widget for PatternFly Login Page
     *
     * @class widgets.LoginScreenBase
     */
    var LoginScreenBase = declare([Stateful, Evented, FormMixin, ContainerMixin, ConfirmMixin], {

        id: '',

        'class': 'login-pf',

        logo_src: 'images/login-screen-logo.png',

        product_name_src: 'images/product-name.png',

        product_name: '',

        caps_warning_msg: "Warning: CAPS LOCK key is on",

        otp_info_msg: "<i class=\"fa fa-info-circle\"></i> <strong>One-Time-Password(OTP):</strong> \
        Generate new OTP code for each OTP field.",

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
        buttons_node: null,

        /**
         * Indicates that CAPS LOCK warning is on. Null indicates that we don't
         * know the state.
         * @property {boolean|null}
         */
        caps_warning: null,

        /**
         * Field specifications
         * @property {Array}
         */
        field_specs: null,


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
                'class': 'col-sm-7 col-md-7 col-lg-6 login'
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

            this.render_buttons(this.buttons_node);
        },

        render_buttons: function(container) {
        },

        render_aside: function(container) {

            this.aside_node = construct.create('div', {
                'class': 'col-sm-5 col-md-5 col-lg-6 details',
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
            var fields = this.field_specs;
            for (var i=0, l=fields.length; i<l; i++) {
                var f = this.add_field(fields[i]);
                var w = this.add_widget(fields[i]);
                new FieldBinder(f, w).bind(true);
                this.bind_validation(val_w, f);
            }

            this.post_create_fields();
        },

        post_create_fields: function() {
        },

        register_caps_check: function() {

            // this is not a nice solution. It breaks widget encapsulation over
            // input field, but we need to listen to keydown events which are
            // not exposed
            var nodes = query("input[type=text],input[type=password]", this.dom_node);
            nodes.on('keypress', this.check_caps_lock.bind(this));
            nodes.on('keydown', this.check_caps_lock_press.bind(this));
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
                this.display_caps_warning(true);
            } else if ((s.toLowerCase() === s && s.toUpperCase() !== s && !e.shiftKey)||
              (s.toLowerCase() !== s && s.toUpperCase() === s && e.shiftKey)) {
                this.display_caps_warning(false);
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
                this.display_caps_warning(!this.caps_warning);
            }
        },

        /**
         * Show or hide CAPS lock warning
         * @param {boolean} display
         * @protected
         */
        display_caps_warning: function(display) {

            var val_summary = this.get_widget('validation');
            if (display) {
                if (!this.caps_warning) {
                    val_summary.add_warning('caps', this.caps_warning_msg);
                }
            } else {
                if (this.caps_warning) {
                    val_summary.remove('caps');
                }
            }
            this.caps_warning = display;
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

        refresh: function() {
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

        kerberos_enabled: function() {
            return auth.current.auth_methods.indexOf('kerberos') > -1;
        },

        password_enabled: function() {
            return auth.current.auth_methods.indexOf('password') > -1;
        },

        certificate_enabled: function() {
            return auth.current.auth_methods.indexOf('certificate') > -1;
        },


        postscript: function(args) {
            this.create_fields();
        },

        constructor: function(spec) {
            spec = spec || {};
            declare.safeMixin(this, spec);

            this.otp_info_msg = text.get(spec.otp_info_msg || '@i18n:password.otp_info',
                this.otp_info_msg);
        }
    });
    return LoginScreenBase;
});
