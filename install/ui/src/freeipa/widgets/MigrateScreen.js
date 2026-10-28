//
// Copyright (C) 2018  FreeIPA Contributors see COPYING for license
//

define(['dojo/_base/declare',
    'dojo/dom-construct',
    'dojo/topic',
    '../ipa',
    '../config',
    '../text',
    '../util',
    './LoginScreenBase'
    ],
    function(declare, construct, topic, IPA, config, text, util,
        LoginScreenBase) {

        /**
         * Widget with password migration form.
         *
         * Supported operations:
         *
         * - password migration
         *
         * @class widgets.MigrateScreen
         */
        var MigrateScreen = declare([LoginScreenBase], {

            migration_error_msg: "There was a problem with your request."+
            "Please, try again later.",

            migration_failure_msg: "Password migration was not successful",

            migration_info_msg: "<h1>Password Migration</h1><p>"+
            "If you have been sent here by your administrator, your personal "+
            "information is being migrated to a new identity management "+
            "solution (IPA).</p><p>Please, enter your credentials in the form"+
            " to complete the process. Upon successful login your kerberos "+
            "account will be activated.</p>",

            migration_invalid_password: "The password or username you entered"+
            " is incorrect",

            migration_success: "Password migration was successful",

            //nodes:
            migrate_btn_node: null,

            render_buttons: function(container) {
                this.migrate_btn_node = IPA.button({
                    label: text.get('@i18n:buttons.migrate', "Migrate"),
                    'class': 'btn-primary btn-lg',
                    click: this.on_confirm.bind(this)
                })[0];
                construct.place(this.migrate_btn_node, container);
            },

            on_confirm: function() {
                this.migrate();
            },

            migrate: function() {
                var val_summary = this.get_widget('validation');
                val_summary.remove('migrate');

                if (!this.validate()) return;

                var username = this.get_field('username');
                var psw = this.get_field('password');
                var result = this.migrate_core(
                    username.get_value()[0],
                    psw.get_value()[0]);

                psw.set_value('');
                if (result.status === 'ok') {
                    val_summary.add_success('migrate', this.migration_success);
                    window.setTimeout(this.redirect, 3000);
                } else {
                    val_summary.add_error('migrate', result.message);
                }
            },

            redirect: function() {
                window.location = config.url;
            },

            migrate_core: function(username, password) {

                //possible results: 'ok', 'invalid-password', 'migration-error'

                var status = 'invalid';
                var result = {
                    status: status,
                    message: this.migration_failure_msg
                };

                function success_handler(data, text_status, xhr) {
                    topic.publish('rpc-end');
                    result.status = xhr.getResponseHeader(
                        "X-IPA-Migrate-Result") || status;

                    if (result.status === 'migration-error') {
                        result.message = this.migration_error_msg;
                    } else if (result.status === 'invalid-password') {
                        result.message = this.migration_invalid_password;
                    }
                    return result;
                }

                function error_handler(xhr, text_status, error_thrown) {
                    topic.publish('rpc-end');
                    return result;
                }

                var data = {
                    username: username,
                    password: password
                };

                var request = {
                    url: config.migration_url,
                    data: data,
                    contentType: 'application/x-www-form-urlencoded',
                    processData: true,
                    dataType: 'html',
                    async: false,
                    type: 'POST',
                    success: success_handler.bind(this),
                    error: error_handler.bind(this)
                };

                topic.publish('rpc-start');
                $.ajax(request);

                return result;
            },

            refresh: function() {
                this.set('aside', this.migration_info_msg);
                var val_summary = this.get_widget('validation');

                var u_f = this.fields.get('username');
                this.get_widget('username').focus_input();
            },

            constructor: function(spec) {
                spec = spec || {};

                this.migration_error_msg = text.get(
                    spec.migration_error_msg ||
                        '@i18n:migration.migration_error_msg',
                        this.migration_error_msg);

                this.migration_failure_msg = text.get(
                    spec.migration_failure_msg ||
                        '@i18n:migration.migration_failure_msg',
                        this.migration_failure_msg);

                this.migration_info_msg = text.get(
                    spec.migration_info_msg ||
                        '@i18n:migration.migration_info_msg',
                        this.migration_info_msg);

                this.migration_invalid_password = text.get(
                    spec.migration_invalid_password ||
                        '@i18n:migration.migration_invalid_password',
                        this.migration_invalid_password);

                this.migration_success = text.get(
                    spec.migration_success ||
                        '@i18n:migration.migration_success',
                        this.migration_success);

                this.field_specs = MigrateScreen.field_specs;
            }
        });

        MigrateScreen.field_specs = [
            {
                $type: 'text',
                name: 'username',
                label: text.get('@i18n:login.username', "Username"),
                placeholder: text.get('@i18n:login.username', "Username"),
                required: true,
                show_errors: false,
                undo: false
            },
            {
                $type: 'password',
                name: 'password',
                label: text.get('@i18n:login.password', "Password"),
                placeholder: text.get('@i18n:login.password', 'Password'),
                required: true,
                show_errors: false,
                undo: false
            }
        ];

        return MigrateScreen;
    });
