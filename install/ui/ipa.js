/*jsl:import jquery.ordered-map.js */
/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *    Endi Dewata <edewata@redhat.com>
 *    John Dennis <jdennis@redhat.com>
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


/* REQUIRES: jquery.ordered-map.js */
/*global $:true, location:true */

var IPA = function() {

    var that = {
        jsonrpc_id: 0
    };

    // live server path
    that.url = '/ipa/ui/';

    that.ajax_options = {
        type: 'POST',
        contentType: 'application/json',
        dataType: 'json',
        async: true,
        processData: false
    };

    that.metadata = {};
    that.messages = {};
    that.whoami = {};

    that.entities = $.ordered_map();
    that.entity_factories = {};
    that.field_factories = {};
    that.widget_factories = {};

    that.network_call_count = 0;

    that.ui = {};

    /* initialize the IPA JSON-RPC helper */
    that.init = function(params) {

        // if current path matches live server path, use live data
        if (that.url && window.location.pathname.substring(0, that.url.length) === that.url) {
            that.json_url = params.url || '/ipa/session/json';
            that.login_url = params.url || '/ipa/session/login_kerberos';

        } else { // otherwise use fixtures
            that.json_path = params.url || "test/data";
            // that.login_url is not needed for fixtures
        }

        $.ajaxSetup(that.ajax_options);

        var batch = IPA.batch_command({
            name: 'ipa_init',
            retry: false,
            on_success: function() {
                that.init_metadata({
                    on_success: params.on_success,
                    on_error: params.on_error
                });
            },
            on_error: function(xhr, text_status, error_thrown) {

                // On IE the request is missing after authentication,
                // so the request needs to be resent.
                if (error_thrown.code === 909) {
                    batch.execute();

                } else {
                    var ajax = this;

                    var dialog = IPA.error_dialog({
                        xhr: xhr,
                        text_status: text_status,
                        error_thrown: error_thrown,
                        command: batch
                    });

                    dialog.on_cancel = function() {
                        dialog.close();
                        if (params.on_error) {
                            params.on_error.call(ajax, xhr, text_status, error_thrown);
                        }
                    };

                    dialog.open();
                }
            }
        });

        batch.add_command(IPA.command({
            method: 'i18n_messages',
            on_success: function(data, text_status, xhr) {
                that.messages = data.messages;
            }
        }));

        batch.add_command(IPA.command({
            entity: 'config',
            method: 'show',
            on_success: function(data, text_status, xhr) {
                that.server_config = data.result;
            }
        }));

        batch.add_command(that.get_whoami_command(true));

        batch.add_command(IPA.command({
            method: 'env',
            on_success: function(data, text_status, xhr) {
                that.env = data.result;
                that.version = that.env.version;
            }
        }));

        batch.add_command(IPA.command({
            entity: 'dns',
            method: 'is_enabled',
            on_success: function(data, text_status, xhr) {
                that.dns_enabled = data.result;
            }
        }));



        batch.execute();
    };

    that.get_whoami_command = function(batch) {
        return IPA.command({
            entity: 'user',
            method: 'find',
            options: {
                whoami: true,
                all: true
            },
            on_success: function(data, text_status, xhr) {
                that.whoami = batch ? data.result[0] : data.result.result[0];
                that.principal = that.whoami.krbprincipalname[0];
            }
        });
    };

    that.init_metadata = function(params) {

        var objects = IPA.command({
            name: 'ipa_init_objects',
            method: 'json_metadata',
            options: {
                object: 'all'
            },
            on_success: function(data, text_status, xhr) {
                that.metadata.objects = data.result.objects;
            }
        });

        var commands = IPA.command({
            name: 'ipa_init_commands',
            method: 'json_metadata',
            options: {
                command: 'all'
            },
            on_success: function(data, text_status, xhr) {
                that.metadata.commands = data.result.commands;
            }
        });

        var metadata_command = IPA.concurrent_command({
            commands: [
                objects,
                commands
            ],
            on_success: function(data, text_status, xhr) {
                IPA.ui.initialized = true;
                if (params.on_success) {
                    params.on_success.call(this, data, text_status, xhr);
                }
            },
            on_error: params.on_error
        });

        metadata_command.execute();
    };

    that.register = function(name, factory) {
        that.remove_entity(name);
        that.entity_factories[name] = factory;
    };

    that.create_entity = function(name) {
        var factory = that.entity_factories[name];
        if (!factory) return null;

        try {
            var builder = IPA.entity_builder();

            builder.entity({
                factory: factory,
                name: name
            });

            var entity = builder.build();
            entity.init();

            return entity;

        } catch (e) {
            if (e.expected) {
                /*expected exceptions thrown by builder just mean that
                  entities are not to be registered. */
                return null;
            }

            if (e.message) {
                alert(e.message);
            } else {
                alert(e);
            }

            return null;
        }
    };

    that.get_entities = function() {
        return that.entities.values;
    };

    that.get_entity = function(name) {
        if (typeof name === 'object') return name;
        var entity = that.entities.get(name);
        if (!entity) {
            entity = that.create_entity(name);
            if (entity) that.add_entity(entity);
        }
        return entity;
    };

    that.add_entity = function(entity) {
        that.entities.put(entity.name, entity);
    };

    that.remove_entity = function(name) {
        that.entities.remove(name);
    };

    that.display_activity_icon = function() {
        that.network_call_count++;
        $('.network-activity-indicator').css('visibility', 'visible');
    };

    that.hide_activity_icon = function() {
        that.network_call_count--;

        if (0 === that.network_call_count) {
            $('.network-activity-indicator').css('visibility', 'hidden');
        }
    };

    that.get_message = function(id, default_message) {
        var messages = IPA.messages;
        var keys = id.split(/\./);

        for (var i=0; messages && i<keys.length; i++) {
            var key = keys[i];
            var value = messages[key];

            // undefined key => not found
            if (!value) return default_message;

            // if value is string
            if (typeof value === 'string') {

                // and it's the last key => found
                if (i === keys.length-1) return value;

                // otherwise value should have been a container => not found
                return default_message;
            }

            // value is container => check next key
            messages = value;
        }

        // no more keys/messages => not found
        return default_message;
    };

    return that;
}();

IPA.get_credentials = function() {
    var status;

    function error_handler(xhr, text_status, error_thrown) {
        status = xhr.status;
        IPA.ui.logged_kerberos = false;
    }

    function success_handler(data, text_status, xhr) {
        status = xhr.status;
        IPA.ui.logged_kerberos = true;
    }

    var request = {
        url: IPA.login_url,
        cache: false,
        async: false,
        type: "GET",
        success: success_handler,
        error: error_handler
    };

    $.ajax(request);

    return status;
};

IPA.logout = function() {

    function show_error(message) {
        var dialog = IPA.message_dialog({
            name: 'logout_error',
            message: message,
            title: IPA.messages.login.logout_error
        });
        dialog.open();
    }

    function redirect () {
        window.location = 'logout.html';
    }

    function success_handler(data, text_status, xhr) {
        if (data && data.error) {
            show_error(data.error.message);
        } else {
            redirect();
        }
    }

    function error_handler(xhr, text_status, error_thrown) {
        if (xhr.status === 401) {
            redirect();
        } else {
            show_error(text_status);
        }
    }

    var command = {
        method: 'session_logout',
        params: [[], {}]
    };

    var request = {
        url: IPA.json_url || IPA.json_path + '/session_logout.json',
        data: JSON.stringify(command),
        success: success_handler,
        error: error_handler
    };

    $.ajax(request);
};

IPA.login_password = function(username, password) {

    var result = 'invalid';

    function success_handler(data, text_status, xhr) {
        result = 'success';
        IPA.ui.logged_password = true;
    }

    function error_handler(xhr, text_status, error_thrown) {

        if (xhr.status === 401) {
            var reason = xhr.getResponseHeader("X-IPA-Rejection-Reason");

            //change result from invalid only if we have a header which we
            //understand
            if (reason === 'password-expired') {
                result = 'expired';
            }
        }

        IPA.ui.logged_password = false;
    }

    var data = {
        user: username,
        password: password
    };

    var request = {
        url: '/ipa/session/login_password',
        data: data,
        contentType: 'application/x-www-form-urlencoded',
        processData: true,
        dataType: 'html',
        async: false,
        type: 'POST',
        success: success_handler,
        error: error_handler
    };

    IPA.display_activity_icon();
    $.ajax(request);
    IPA.hide_activity_icon();

    return result;
};

IPA.reset_password = function(username, old_password, new_password) {

    //possible results: 'ok', 'invalid-password', 'policy-error'

    var status, result, reason, invalid, failure, data, request;

    status = 'invalid';
    result = {
        status: status,
        message: IPA.get_message('password.reset_failure',
                "Password reset was not successful.")
    };

    function success_handler(data, text_status, xhr) {

        result.status = xhr.getResponseHeader("X-IPA-Pwchange-Result") || status;

        if (result.status === 'policy-error') {
            result.message = xhr.getResponseHeader("X-IPA-Pwchange-Policy-Error");
        } else if (result.status === 'invalid-password') {
            result.message = IPA.get_message('password.invalid_password',
                          "The password or username you entered is incorrect.");
        }

        return result;
    }

    function error_handler(xhr, text_status, error_thrown) {
        return result;
    }

    data = {
        user: username,
        old_password: old_password,
        new_password: new_password
    };

    request = {
        url: '/ipa/session/change_password',
        data: data,
        contentType: 'application/x-www-form-urlencoded',
        processData: true,
        dataType: 'html',
        async: false,
        type: 'POST',
        success: success_handler,
        error: error_handler
    };

    IPA.display_activity_icon();
    $.ajax(request);
    IPA.hide_activity_icon();

    return result;
};

IPA.update_password_expiration = function() {

    var now, expires, notify_days, diff, message, container;

    expires = IPA.whoami.krbpasswordexpiration;
    expires = expires ? IPA.parse_utc_date(expires[0]) : null;

    notify_days = IPA.server_config.ipapwdexpadvnotify;
    notify_days = notify_days ? notify_days[0] : 0;

    now = new Date();

    container = $('.header-passwordexpires');
    container.empty();

    if (expires) {

        diff = expires.getTime() - now.getTime();
        diff = Math.floor(diff / 86400000);

        if (diff <= notify_days) {
            message = IPA.messages.password.expires_in;
            message = message.replace('${days}', diff);
            container.append(message + ' ');
            $('<a/>', {
                href: '#reset-password',
                click: function() {
                    IPA.password_selfservice();
                    return false;
                },
                text: IPA.messages.password.reset_password_sentence,
                title: IPA.messages.password.reset_password
            }).appendTo(container);
        }
    }
};

IPA.password_selfservice = function() {
    var reset_dialog = IPA.user_password_dialog({
        self_service: true,
        on_success: function() {
            var command = IPA.get_whoami_command();
            var orig_on_success = command.on_success;
            command.on_success = function(data, text_status, xhr) {
                orig_on_success.call(this, data, text_status, xhr);
                IPA.update_password_expiration();
            };
            command.execute();

            alert(IPA.messages.password.password_change_complete);
            reset_dialog.close();
        }
    });
    reset_dialog.open();
};

IPA.parse_utc_date = function(value) {

    if (!value) return null;

    // verify length
    if (value.length  != 'YYYYmmddHHMMSSZ'.length) {
        return null;
    }

    // We only handle GMT
    if (value.charAt(value.length -1) !== 'Z') {
        return null;
    }

    var date = new Date();

    date.setUTCFullYear(
        value.substring(0, 4),    // YYYY
        value.substring(4, 6)-1,  // mm (0-11)
        value.substring(6, 8));   // dd (1-31)

    date.setUTCHours(
        value.substring(8, 10),   // HH (0-23)
        value.substring(10, 12),  // MM (0-59)
        value.substring(12, 14)); // SS (0-59)

    return date;
};

/**
 * Call an IPA command over JSON-RPC.
 *
 * Arguments:
 *   name - command name (optional)
 *   entity - command entity (optional)
 *   method - command method
 *   args - list of arguments, e.g. [username]
 *   options - dict of options, e.g. {givenname: 'Pavel'}
 *   on_success - callback function if command succeeds
 *   on_error - callback function if command fails
 */
IPA.command = function(spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;

    that.entity = spec.entity;
    that.method = spec.method;

    that.args = $.merge([], spec.args || []);
    that.options = $.extend({}, spec.options || {});

    that.on_success = spec.on_success;
    that.on_error = spec.on_error;

    that.retry = typeof spec.retry == 'undefined' ? true : spec.retry;

    that.error_message = spec.error_message || IPA.get_message('dialogs.batch_error_message', 'Some operations failed.');
    that.error_messages = $.ordered_map({
        911: 'Missing HTTP referer. <br/> You have to configure your browser to send HTTP referer header.'
    });

    that.get_command = function() {
        return (that.entity ? that.entity+'_' : '') + that.method;
    };

    that.add_arg = function(arg) {
        that.args.push(arg);
    };

    that.add_args = function(args) {
        $.merge(that.args, args);
    };

    that.set_option = function(name, value) {
        that.options[name] = value;
    };

    that.set_options = function(options) {
        $.extend(that.options, options);
    };

    that.add_option = function(name, value) {
        var values = that.options[name];
        if (!values) {
            values = [];
            that.options[name] = values;
        }
        values.push(value);
    };

    that.get_option = function(name) {
        return that.options[name];
    };

    that.remove_option = function(name) {
        delete that.options[name];
    };

    that.execute = function() {

        function dialog_open(xhr, text_status, error_thrown) {

            var ajax = this;

            var dialog = IPA.error_dialog({
                xhr: xhr,
                text_status: text_status,
                error_thrown: error_thrown,
                command: that
            });

            dialog.on_cancel = function() {
                dialog.close();
                if (that.on_error) {
                    that.on_error.call(ajax, xhr, text_status, error_thrown);
                }
            };

            dialog.open();
        }

        function auth_dialog_open(xhr, text_status, error_thrown) {

            var ajax = this;

            var dialog = IPA.unauthorized_dialog({
                xhr: xhr,
                text_status: text_status,
                error_thrown: error_thrown,
                close_on_escape: false,
                command: that
            });

            dialog.open();
        }

        /*
         * Special error handler used the first time this command is
         * submitted. It checks to see if the session credentials need
         * to be acquired and if so sends a request to a special url
         * to establish the sesion credentials. If acquiring the
         * session credentials is successful it simply resubmits the
         * exact same command after setting the error handler back to
         * the normal error handler. If aquiring the session
         * credentials fails the normal error handler is invoked to
         * process the error returned from the attempt to aquire the
         * session credentials.
         */
        function error_handler_login(xhr, text_status, error_thrown) {
            if (xhr.status === 401) {
                var login_status = IPA.get_credentials();

                if (login_status === 200) {
                    that.request.error = error_handler;
                    $.ajax(that.request);
                    return;
                }
            }
            // error_handler() calls IPA.hide_activity_icon()
            error_handler.call(this, xhr, text_status, error_thrown);
        }

        /*
         * Normal error handler, handles all errors.
         * error_handler_login() is initially used to trap the
         * special case need to aquire session credentials, this is
         * not a true error, rather it's an indication an extra step
         * needs to be taken before normal processing can continue.
         */
        function error_handler(xhr, text_status, error_thrown) {

            IPA.hide_activity_icon();

            if (xhr.status === 401) {
                auth_dialog_open(xhr, text_status, error_thrown);
                return;
            } else if (!error_thrown) {
                error_thrown = {
                    name: xhr.responseText || IPA.get_message('errors.unknown_error', 'Unknown Error'),
                    message: xhr.statusText || IPA.get_message('errors.unknown_error', 'Unknown Error')
                };

            } else if (typeof error_thrown == 'string') {
                error_thrown = {
                    name: error_thrown,
                    message: error_thrown
                };
            }

            // custom messages for set of codes
            var error_msg = that.error_messages.get(error_thrown.code);
            if (error_msg) {
                error_msg = error_msg.replace('${message}', error_thrown.message);
                error_thrown.message = error_msg;
            }

            // global specical cases error handlers section

            // With trusts, user from trusted domain can use his ticket but he
            // doesn't have rights for LDAP modify. It will throw internal errror.
            // We should offer form base login.
            if (xhr.status === 500 && IPA.ui.logged_kerberos && !IPA.ui.initialized) {
                auth_dialog_open(xhr, text_status, error_thrown);
                return;
            }

            if (that.retry) {
                dialog_open.call(this, xhr, text_status, error_thrown);

            } else if (that.on_error) {
                //custom error handling, maintaining AJAX call's context
                that.on_error.call(this, xhr, text_status, error_thrown);
            }
        }

        function success_handler(data, text_status, xhr) {

            if (!data) {
                // error_handler() calls IPA.hide_activity_icon()
                error_handler.call(this, xhr, text_status, /* error_thrown */ {
                    name: IPA.get_message('errors.http_error', 'HTTP Error')+' '+xhr.status,
                    url: this.url,
                    message: data ? xhr.statusText : IPA.get_message('errors.no_response', 'No response')
                });

            } else if (IPA.version && data.version && IPA.version !== data.version) {
                window.location.reload();

            } else if (IPA.principal && data.principal && IPA.principal !== data.principal) {
                window.location.reload();

            } else if (data.error) {
                // error_handler() calls IPA.hide_activity_icon()
                error_handler.call(this, xhr, text_status,  /* error_thrown */ {
                    name: IPA.get_message('errors.ipa_error', 'IPA Error')+' '+data.error.code,
                    code: data.error.code,
                    message: data.error.message,
                    data: data
                });

            } else {
                IPA.hide_activity_icon();

                var ajax = this;
                var failed = that.get_failed(that, data.result, text_status, xhr);
                if (!failed.is_empty()) {
                    var dialog = IPA.error_dialog({
                        xhr: xhr,
                        text_status: text_status,
                        error_thrown: {
                            name: IPA.get_message('dialogs.batch_error_title', 'Operations Error'),
                            message: that.error_message
                        },
                        command: that,
                        errors: failed.errors,
                        visible_buttons: ['ok']
                    });

                    dialog.on_ok = function() {
                        dialog.close();
                        if (that.on_success) that.on_success.call(ajax, data, text_status, xhr);
                    };

                    dialog.open();

                } else {
                    //custom success handling, maintaining AJAX call's context
                    if (that.on_success) that.on_success.call(this, data, text_status, xhr);
                }
            }
        }

        that.data = {
            method: that.get_command(),
            params: [that.args, that.options]
        };

        that.request = {
            url: IPA.json_url || IPA.json_path + '/' + (that.name || that.data.method) + '.json',
            data: JSON.stringify(that.data),
            success: success_handler,
            error: error_handler_login
        };

        IPA.display_activity_icon();
        $.ajax(that.request);
    };

    that.get_failed = function(command, result, text_status, xhr) {
        var errors = IPA.error_list();
        if(result && result.failed) {
            for(var association in result.failed) {
                for(var member_name in result.failed[association]) {
                    var member = result.failed[association][member_name];
                    for(var i = 0; i < member.length; i++) {
                        if(member[i].length > 1) {
                            var name = IPA.get_message('errors.ipa_error', 'IPA Error');
                            var message = member[i][1];
                            if(member[i][0])
                                message = member[i][0] + ': ' + message;
                            errors.add(command, name, message, text_status);
                        }
                    }
                }
            }
        }
        return errors;
    };

    that.check_option = function(option_name) {

        var metadata = IPA.get_command_option(that.get_command(), option_name);
        return metadata !== null;
    };

    that.to_json = function() {
        var json = {};

        json.method = that.get_command();

        json.params = [];
        json.params[0] = that.args || [];
        json.params[1] = that.options || {};

        return json;
    };

    that.to_string = function() {
        var string = that.get_command().replace(/_/g, '-');

        for (var i=0; i<that.args.length; i++) {
            string += ' '+that.args[i];
        }

        for (var name in that.options) {
            string += ' --'+name+'=\''+that.options[name]+'\'';
        }

        return string;
    };

    return that;
};

IPA.batch_command = function (spec) {

    spec = spec || {};

    spec.method = 'batch';

    var that = IPA.command(spec);

    that.commands = [];
    that.errors = IPA.error_list();
    that.show_error = typeof spec.show_error == 'undefined' ?
            true : spec.show_error;

    that.add_command = function(command) {
        that.commands.push(command);
        that.add_arg(command.to_json());
    };

    that.add_commands = function(commands) {
        for (var i=0; i<commands.length; i++) {
            that.add_command(commands[i]);
        }
    };

    that.execute = function() {
        that.errors.clear();

        var command = IPA.command({
            name: that.name,
            entity: that.entity,
            method: that.method,
            args: that.args,
            options: that.options,
            retry: that.retry
        });

        command.on_success = that.batch_command_on_success;
        command.on_error = that.batch_command_on_error;

        command.execute();
    };

    that.batch_command_on_success = function(data, text_status, xhr) {

        for (var i=0; i<that.commands.length; i++) {
            var command = that.commands[i];
            var result = data.result.results[i];

            var name = '';
            var message = '';

            if (!result) {
                name = IPA.get_message('errors.internal_error', 'Internal Error')+' '+xhr.status;
                message = result ? xhr.statusText : IPA.get_message('errors.internal_error', 'Internal Error');

                that.errors.add(command, name, message, text_status);

                if (command.on_error) command.on_error.call(
                    this,
                    xhr,
                    text_status,
                    {
                        name: name,
                        message: message
                    }
                );

            } else if (result.error) {
                var code = result.error.code || result.error_code;
                name = IPA.get_message('errors.ipa_error', 'IPA Error')+(code ? ' '+code : '');
                message = result.error.message || result.error;

                if (command.retry) that.errors.add(command, name, message, text_status);

                if (command.on_error) command.on_error.call(
                    this,
                    xhr,
                    text_status,
                    {
                        name: name,
                        code: code,
                        message: message,
                        data: result
                    }
                );

            } else {
                var failed = that.get_failed(command, result, text_status, xhr);
                that.errors.add_range(failed);

                if (command.on_success) command.on_success.call(this, result, text_status, xhr);
            }
        }

        //check for partial errors and show error dialog
        if (that.show_error && that.errors.errors.length > 0) {
            var ajax = this;
            var dialog = IPA.error_dialog({
                xhr: xhr,
                text_status: text_status,
                error_thrown: {
                    name: IPA.get_message('dialogs.batch_error_title', 'Operations Error'),
                    message: that.error_message
                },
                command: that,
                errors: that.errors.errors,
                visible_buttons: [ 'ok' ]
            });

            dialog.on_ok = function() {
                dialog.close();
                if (that.on_success) that.on_success.call(ajax, data, text_status, xhr);
            };

            dialog.open();

        } else {
            if (that.on_success) that.on_success.call(this, data, text_status, xhr);
        }
    };

    that.batch_command_on_error = function(xhr, text_status, error_thrown) {
        // TODO: undefined behavior
        if (that.on_error) {
            that.on_error.call(this, xhr, text_status, error_thrown);
        }
    };

    return that;
};


IPA.concurrent_command = function(spec) {

    spec = spec || {};
    var that = {};

    that.commands = [];
    that.on_success = spec.on_success;
    that.on_error = spec.on_error;

    that.add_commands = function(commands) {

        if(commands && commands.length) {
            for(var i=0; i < commands.length; i++) {
                that.commands.push({
                    command: commands[i]
                });
            }
        }
    };

    that.execute = function() {

        var command_info, command, i;

        //prepare for execute
        for(i=0; i < that.commands.length; i++) {
            command_info = that.commands[i];
            command = command_info.command;
            if(!command) {
                var dialog = IPA.message_dialog({
                    name: 'internal_error',
                    title: IPA.get_message('errors.error', 'Error'),
                    message: IPA.get_message('errors.internal_error', 'Internal error.')
                });
                break;
            }
            command_info.completed = false;
            command_info.success = false;
            command_info.on_success = command_info.on_success || command.on_success;
            command_info.on_error = command_info.on_error || command.on_error;
            command.on_success = function(command_info) {
                return function(data, text_status, xhr) {
                    that.success_handler.call(this, command_info, data, text_status, xhr);
                };
            }(command_info);
            command.on_error = function(command_info) {
                return function(xhr, text_status, error_thrown) {
                    that.error_handler.call(this, command_info, xhr, text_status, error_thrown);
                };
            }(command_info);
        }

        //execute
        for(i=0; i < that.commands.length; i++) {
            command = that.commands[i].command;
            command.execute();
        }
    };

    that.error_handler = function(command_info, xhr, text_status, error_thrown) {

        command_info.completed = true;
        command_info.success = false;
        command_info.xhr = xhr;
        command_info.text_status = text_status;
        command_info.error_thrown = error_thrown;
        command_info.context = this;
        that.command_completed();
    };

    that.success_handler = function(command_info, data, text_status, xhr) {

        command_info.completed = true;
        command_info.success = true;
        command_info.data = data;
        command_info.text_status = text_status;
        command_info.xhr = xhr;
        command_info.context = this;
        that.command_completed();
    };

    that.command_completed = function() {

        var all_completed = true;
        var all_success = true;

        for(var i=0; i < that.commands.length; i++) {
            var command_info = that.commands[i];
            all_completed = all_completed &&  command_info.completed;
            all_success = all_success && command_info.success;
        }

        if(all_completed) {
            if(all_success) {
                that.on_success_all();
            } else {
                that.on_error_all();
            }
        }
    };

    that.on_success_all = function() {

        for(var i=0; i < that.commands.length; i++) {
            var command_info = that.commands[i];
            if(command_info.on_success) {
                command_info.on_success.call(
                                command_info.context,
                                command_info.data,
                                command_info.text_status,
                                command_info.xhr);
            }
        }

        if(that.on_success) {
            that.on_success();
        }
    };

    that.on_error_all = function() {

        if(that.on_error) {
            that.on_error();

        } else {
            var dialog = IPA.message_dialog({
                name: 'operation_error',
                title: IPA.get_message('dialogs.batch_error_title', 'Operations Error'),
                message: IPA.get_message('dialogs.batch_error_message', 'Some operations failed.')
            });

            dialog.open();
        }
    };

    that.add_commands(spec.commands);

    return that;
};

IPA.builder = function(spec) {

    spec = spec || {};

    var that = {};

    that.factory = spec.factory || IPA.default_factory;

    that.build = function(spec) {

        var factory = spec.factory || that.factory;

        //when spec is a factory function
        if (!spec.factory && typeof spec === 'function') {
            factory = spec;
            spec = {};
        }

        var obj = factory(spec);
        return obj;
    };

    that.build_objects = function(specs) {

        var objects = [];

        for (var i=0; i<specs.length; i++) {
            var spec = specs[i];
            var obj = that.build(spec);
            objects.push(obj);
        }

        return objects;
    };

    return that;
};

IPA.build = function(spec, builder_fac) {

    if (!spec) return null;

    if (!builder_fac) builder_fac = IPA.builder;

    var builder = builder_fac();
    var product;

    if ($.isArray(spec)) {
        product = builder.build_objects(spec);
    } else {
        product = builder.build(spec);
    }

    return product;
};

IPA.build_default = function(spec, def_spec) {

    var builder, factory, default_object;

    if (!spec && !def_spec) return null;

    if (typeof def_spec === 'function') { //factory function
        factory = def_spec;
    } else if (typeof def_spec === 'object') {
        default_object = def_spec;
    }

    builder = IPA.builder({
        factory: factory
    });

    var product;
    spec = spec || default_object || {};

    if ($.isArray(spec)) {
        product = builder.build_objects(spec);
    } else {
        product = builder.build(spec);
    }

    return product;
};

IPA.default_factory = function(spec) {

    spec = spec || {};

    var that = {};

    $.extend(that, spec);

    return that;
};

/* helper function used to retrieve information about an attribute */
IPA.get_entity_param = function(entity_name, name) {

    var metadata = IPA.metadata.objects[entity_name];
    if (!metadata) {
        return null;
    }

    var params = metadata.takes_params;
    if (!params) {
        return null;
    }

    for (var i=0; i<params.length; i++) {
        if (params[i].name === name) {
            return params[i];
        }
    }

    return null;
};

IPA.get_command_arg = function(command_name, arg_name) {

    var metadata = IPA.metadata.commands[command_name];
    if (!metadata) {
        return null;
    }

    var args = metadata.takes_args;
    if (!args) {
        return null;
    }

    for (var i=0; i<args.length; i++) {
        if (args[i].name === arg_name) {
            return args[i];
        }
    }

    return null;
};

IPA.get_command_option = function(command_name, option_name) {

    var metadata = IPA.metadata.commands[command_name];
    if (!metadata) {
        return null;
    }

    var options = metadata.takes_options;
    if (!options) {
        return null;
    }

    for (var i=0; i<options.length; i++) {
        if (options[i].name === option_name) {
            return options[i];
        }
    }

    return null;
};

/* helper function used to retrieve attr name with members of type `member` */
IPA.get_member_attribute = function(obj_name, member) {

    var obj = IPA.metadata.objects[obj_name];
    if (!obj) {
        return null;
    }

    var attribute_members = obj.attribute_members;
    for (var a in attribute_members) {
        var objs = attribute_members[a];
        for (var i = 0; i < objs.length; i += 1) {
            if (objs[i] === member){
                return a;
            }
        }
    }

    return null;
};

IPA.create_network_spinner = function(){
    var span = $('<span/>', {
        'class': 'network-activity-indicator'
    });
    $('<img/>', {
        src: 'images/spinner-small.gif'
    }).appendTo(span);
    return span;
};

IPA.dirty_dialog = function(spec) {

    spec = spec || {};
    spec.title = spec.title || IPA.messages.dialogs.dirty_title;
    spec.width = spec.width || '25em';

    var that = IPA.dialog(spec);
    that.facet = spec.facet;
    that.message = spec.message || IPA.messages.dialogs.dirty_message;

    that.create = function() {
        that.container.append(that.message);
    };

    that.create_button({
        name: 'update',
        label: IPA.messages.buttons.update,
        click: function() {
            that.facet.update(function() {
                that.close();
                that.callback();
            });
        }
    });

    that.create_button({
        name: 'reset',
        label: IPA.messages.buttons.reset,
        click: function() {
            that.facet.reset();
            that.close();
            that.callback();
        }
    });

    that.create_button({
        name: 'cancel',
        label: IPA.messages.buttons.cancel,
        click: function() {
            that.close();
        }
    });

    that.callback = function() {
    };

    return that;
};

IPA.error_dialog = function(spec) {

    var that = IPA.dialog(spec);

    var init = function() {
        spec = spec || {};

        that.id = spec.id || 'error_dialog';
        that.xhr = spec.xhr || {};
        that.text_status = spec.text_status || '';
        that.error_thrown = spec.error_thrown || {};
        that.command = spec.command;
        that.title = spec.error_thrown.name;
        that.errors = spec.errors;
        that.visible_buttons = spec.visible_buttons || ['retry', 'cancel'];
    };

    that.beautify_message = function(container, message) {
        var lines = message.split(/\n/g);
        var line_span;
        for(var i=0; i<lines.length; i++) {
            // multi-lined text may contain TAB character as first char of the line
            // to hint at marking the whole line differently
            if (lines[i].charAt(0) == '\t') {
                line_span = $('<p />', {
                    'class': 'error-message-hinted',
                    text: lines[i].substr(1)
                }).appendTo(container);
            } else {
                line_span = $('<p />', {
                    text: lines[i]
                }).appendTo(container);
            }
        }
    };

    that.create = function() {
        if (that.error_thrown.url) {
            $('<p/>', {
                text: IPA.get_message('errors.url', 'URL')+': '+that.error_thrown.url
            }).appendTo(that.container);
        }

        var error_message = $('<div />', {});
        that.beautify_message(error_message, that.error_thrown.message);
        error_message.appendTo(that.container);

        if(that.errors && that.errors.length > 0) {
            //render errors
            var errors_title_div = $('<div />', {
                'class': 'errors_title'
            }).appendTo(that.container);

            var show_details = $('<a />', {
                href: '#',
                title: IPA.messages.dialogs.show_details,
                text: IPA.messages.dialogs.show_details
            }).appendTo(errors_title_div);

            var hide_details = $('<a />', {
                href: '#',
                title: IPA.messages.dialogs.hide_details,
                text: IPA.messages.dialogs.hide_details,
                style : 'display: none'
            }).appendTo(errors_title_div);

            var errors_container = $('<ul />', {
                'class' : 'error-container',
                style : 'display: none'
            }).appendTo(that.container);

            for(var i=0; i < that.errors.length; i++) {
                var error = that.errors[i];
                if(error.message) {
                    var error_div = $('<li />', {});
                    that.beautify_message(error_div, error.message);
                    error_div.appendTo(errors_container);
                }
            }

            show_details.click(function() {
                errors_container.show();
                show_details.hide();
                hide_details.show();
                return false;
            });

            hide_details.click(function() {
                errors_container.hide();
                hide_details.hide();
                show_details.show();
                return false;
            });
        }
    };

    that.create_buttons = function() {
        /**
        * When a user initially opens the Web UI without a Kerberos
        * ticket, the messages including the button labels have not
        * been loaded yet, so the button labels need default values.
        */

        var visible = that.visible_buttons.indexOf('retry') > -1;
        var label = IPA.get_message('buttons.retry', 'Retry');
        that.create_button({
            name: 'retry',
            label: label,
            visible: visible,
            click: function() {
                that.on_retry();
            }
        });

        visible = that.visible_buttons.indexOf('ok') > -1;
        label = IPA.get_message('buttons.ok', 'OK');
        that.create_button({
            name: 'ok',
            label: label,
            visible: visible,
            click: function() {
                that.on_ok();
            }
        });

        visible = that.visible_buttons.indexOf('cancel') > -1;
        label = IPA.get_message('buttons.cancel', 'Cancel');
        that.create_button({
            name: 'cancel',
            label: label,
            visible: visible,
            click: function() {
                that.on_cancel();
            }
        });
    };

    that.on_retry = function() {
        that.close();
        that.command.execute();
    };

    that.on_ok = function() {
        that.close();
    };

    that.on_cancel = function() {
        that.close();
    };

    init();
    that.create_buttons();

    return that;
};

IPA.error_list = function() {
    var that = {};

    that.clear = function() {
        that.errors = [];
    };

    that.add = function(command, name, message, status) {
        that.errors.push({
            command: command,
            name: name,
            message: message,
            status: status
        });
    };

    that.add_range = function(error_list) {
        that.errors = that.errors.concat(error_list.errors);
    };

    that.is_empty = function () {
        return that.errors.length === 0;
    };

    that.clear();
    return that;
};

IPA.create_4304_error_handler = function(adder_dialog) {

    var set_pkey = function(result) {

        var pkey_name = adder_dialog.entity.metadata.primary_key;
        var args = adder_dialog.command.args;
        var pkey = args[args.length-1];
        result[pkey_name] = pkey;
    };

    return function (xhr, text_status, error_thrown) {

        var ajax = this;
        var command = adder_dialog.command;
        var data = error_thrown.data;
        var dialog = null;

        if (data && data.error && data.error.code === 4304) {
            dialog = IPA.message_dialog({
                name: 'error_4304_info',
                message: data.error.message,
                title: adder_dialog.title,
                on_ok: function() {
                    data.result = { result: {} };
                    set_pkey(data.result.result);
                    command.on_success.call(ajax, data, text_status, xhr);
                }
            });
        } else {
            dialog = IPA.error_dialog({
                xhr: xhr,
                text_status: text_status,
                error_thrown: error_thrown,
                command: command
            });
        }

        dialog.open(adder_dialog.container);
    };
};

IPA.unauthorized_dialog = function(spec) {

    spec = spec || {};

    spec.sections = [
        {
            name: 'login',
            label: 'Login',
            fields: [
                {
                    name: 'username',
                    label: IPA.get_message('login.username', "Username")
                },
                {
                    name: 'password',
                    type: 'password',
                    label: IPA.get_message('login.password', "Password")
                }
            ]
        },
        {
            name: 'reset',
            label: 'Reset',
            fields: [
                {
                    name: 'username_r',
                    read_only: true,
                    label: IPA.get_message('login.username', "Username")
                },
                {
                    name: 'new_password',
                    type: 'password',
                    required: true,
                    label: IPA.get_message('password.new_password)', "New Password")
                },
                {
                    name: 'verify_password',
                    type: 'password',
                    required: true,
                    label: IPA.get_message('password.verify_password', "Verify Password")
                }
            ]
        }
    ];

    spec.visible_buttons = spec.visible_buttons || ['retry'];
    spec.name = spec.name || 'unauthorized_dialog';
    spec.id = spec.id || spec.name;

    var that = IPA.error_dialog(spec);

    that.title = spec.title || IPA.get_message('login.login', "Login");

    that.message = spec.message || IPA.get_message('ajax.401.message',
                    "Your session has expired. Please re-login.");

    that.form_auth_msg = spec.form_auth_msg || IPA.get_message('login.form_auth',
                    "To login with username and password, enter them in the fields below then click Login.");

    that.krb_auth_msg = spec.krb_auth_msg || IPA.get_message('login.krb_auth_msg',
                    " To login with Kerberos, please make sure you" +
                    " have valid tickets (obtainable via kinit) and " +
                    "<a href='http://${host}/ipa/config/unauthorized.html'>configured</a>" +
                    " the browser correctly, then click Login. ");

    that.krb_auth_msg = that.krb_auth_msg.replace('${host}', window.location.hostname);

    that.form_auth_failed = "<p><strong>Please re-enter your username or password</strong></p>" +
                "<p>The password or username you entered is incorrect. " +
                "Please try again (make sure your caps lock is off).</p>" +
                "<p>If the problem persists, contact your administrator.</p>";

    that.password_expired = "Your password has expired. Please enter a new password.";

    that.create = function() {

        that.session_expired_form();
        that.create_reset_form();
    };

    that.session_expired_form = function() {
        that.session_form = $('<div\>', {
            keyup: that.on_login_keyup
        }).appendTo(that.container);

        that.login_error_box = $('<div/>', {
            'class': 'error-box',
            style: 'display:none',
            html: that.form_auth_failed
        }).appendTo(that.session_form);

        $('<p/>', {
            html: that.message
        }).appendTo(that.session_form);

        $('<p/>', {
            html: that.krb_auth_msg
        }).appendTo(that.session_form);

        $('<p/>', {
            html: that.form_auth_msg
        }).appendTo(that.session_form);

        $('<div>', {
            'class': 'auth-dialog'
        }).appendTo(that.session_form);


        var section = that.widgets.get_widget('login');
        var div = $('<div/>', {
            name: 'login',
            'class': 'dialog-section'
        }).appendTo(that.session_form);
        section.create(div);

        that.username_widget = that.widgets.get_widget('login.username');
        that.password_widget = that.widgets.get_widget('login.password');

        that.username_widget.value_changed.attach(that.on_username_change);
    };

    that.create_reset_form = function() {

        that.reset_form = $('<div\>', {
            keyup: that.on_reset_keyup,
            style: 'display:none'
        }).appendTo(that.container);

        that.reset_error_box =  $('<div/>', {
            'class': 'error-box'
        }).appendTo(that.reset_form);

        $('<p/>', {
            html: that.password_expired
        }).appendTo(that.reset_form);

        var section = that.widgets.get_widget('reset');
        var div = $('<div/>', {
            name: 'reset',
            'class': 'dialog-section'
        }).appendTo(that.reset_form);
        section.create(div);

        that.username_r_widget = that.widgets.get_widget('reset.username_r');
        that.new_password_widget = that.widgets.get_widget('reset.new_password');
        that.verify_password_widget = that.widgets.get_widget('reset.verify_password');
    };

    that.create_buttons = function() {

        that.buttons.empty();

        var visible = that.visible_buttons.indexOf('login') > -1;
        var label = IPA.get_message('login.login', "Login");
        that.create_button({
            name: 'login',
            label: label,
            visible: visible,
            click: function() {
                that.on_login();
            }
        });

        visible = that.visible_buttons.indexOf('reset') > -1;
        label = IPA.get_message('buttons.reset_password_and_login', "Reset Password and Login");
        that.create_button({
            name: 'reset',
            label: label,
            visible: visible,
            click: function() {
                that.on_reset();
            }
        });

        visible = that.visible_buttons.indexOf('cancel') > -1;
        label = IPA.get_message('buttons.cancel', "Cancel");
        that.create_button({
            name: 'cancel',
            label: label,
            visible: visible,
            click: function() {
                that.on_cancel();
            }
        });
    };

    that.open = function() {
        that.dialog_open();
        that.show_session_form();
    };

    that.on_username_change = function() {

        var password_field = that.fields.get_field('password');
        var user_specified = !IPA.is_empty(that.username_widget.save());
        password_field.set_required(user_specified);
        if (!user_specified) that.password_widget.clear();
    };

    that.enable_fields = function(field_names) {

        var field, fields, i, enable;
        fields = that.fields.get_fields();
        for (i=0; i<fields.length; i++) {
            field = fields[i];
            enable = field_names.indexOf(field.name) > -1;
            field.set_enabled(enable);
        }
    };

    that.show_session_form = function() {

        that.enable_fields(['username', 'password']);
        that.session_form.css('display', 'block');
        that.reset_form.css('display', 'none');
        that.display_buttons(['login']);
        that.username_widget.focus_input();
    };

    that.show_reset_form = function() {

        that.enable_fields(['new_password', 'verify_password']);
        that.session_form.css('display', 'none');
        that.reset_form.css('display', 'block');
        that.display_buttons(['reset', 'cancel']);

        var username = that.username_widget.save();
        that.username_r_widget.update(username);
        that.new_password_widget.focus_input();
    };

    that.on_login_keyup = function(event) {

        if (that.switching) {
            that.switching = false;
            return;
        }

        if (event.keyCode === 13) { // enter
            that.on_login();
            event.preventDefault();
        }
    };

    that.on_cancel = function() {

        that.username_widget.clear();
        that.password_widget.clear();
        that.username_r_widget.clear();
        that.new_password_widget.clear();
        that.verify_password_widget.clear();

        that.show_session_form();
    };

    that.on_login = function() {

        var username = that.username_widget.save();
        var password = that.password_widget.save();

        //if user doesn't specify username and password try kerberos auth
        if (IPA.is_empty(username) && IPA.is_empty(password)) {
            that.on_retry();
            return;
        }

        if (!that.validate()) return;

        IPA.display_activity_icon();

        var result = IPA.login_password(username[0], password[0]);

        IPA.hide_activity_icon();

        if (result === 'success') {
            that.on_login_success();
        } else if (result === 'expired') {
            that.reset_error_box.css('display', 'none');
            that.show_reset_form();
        } else {
            that.login_error_box.html(that.form_auth_failed);
            that.login_error_box.css('display', 'block');
        }
    };

    that.on_login_success = function() {
        that.login_error_box.css('display', 'none');

        that.username_widget.clear();
        that.password_widget.clear();

        that.on_retry();
    };

    that.on_reset_keyup = function(event) {

        if (that.switching) {
            that.switching = false;
            return;
        }

        if (event.keyCode === 13) { // enter
            that.on_reset();
            event.preventDefault();
        } else if (event.keyCode === 27) { // escape
            that.on_cancel();
            event.preventDefault();
        }
    };

    that.on_reset = function() {
        if (!that.validate()) return;

        var username = that.username_widget.save();
        var password = that.password_widget.save();
        var new_password = that.new_password_widget.save();
        var verify_password = that.verify_password_widget.save();

        if (new_password[0] !== verify_password[0]) {
            var message = IPA.get_message('password.password_must_match',
                            "Passwords must match");
            that.reset_error_box.html(message);
            that.reset_error_box.css('display', 'block');
            return;
        } else {
            that.reset_error_box.css('display', 'none');
        }

        IPA.display_activity_icon();

        var result = IPA.reset_password(username[0],
                                        password[0],
                                        new_password[0]);

        IPA.hide_activity_icon();

        if (result.status === 'ok') {
            that.on_reset_success();
        } else {
            that.reset_error_box.html(result.message);
            that.reset_error_box.css('display', 'block');
        }
    };

    that.on_reset_success = function() {

        that.login_error_box.css('display', 'none');
        that.reset_error_box.css('display', 'none');

        that.password_widget.update(that.new_password_widget.save());

        that.new_password_widget.clear();
        that.verify_password_widget.clear();

        that.show_session_form();

        //re-login
        that.on_login();
    };

    that.create_buttons();

    return that;
};

IPA.limit_text = function(value, max_length) {

    if (!value) return '';

    var limited_text = value;

    if (value.length && value.length > max_length) {
        limited_text = value.substring(0, max_length - 3)+'...';
    }

    return limited_text;
};

IPA.create_options = function(values) {

    var options = [];

    for (var i=0; i<values.length; i++) {
        var val = values[i];
        var option = val;

        if (typeof val === 'string') {
            option = {
                value: val,
                label: val
            };
        }

        options.push(option);
    }

    return options;
};

IPA.is_empty = function(value) {

    var empty = false;

    if (!value) empty = true;

    if (value instanceof Array) {
        empty = empty || value.length === 0 ||
                (value.length === 1) && (value[0] === '');
    }

    if (value === '') empty = true;

    return empty;
};

IPA.defined = function(value, check_empty_str) {
    return value !== null && value !== undefined &&
        ((check_empty_str && value !== '') || !check_empty_str);
};

IPA.array_diff = function(a, b) {

    if (a === b || (!a && !b)) return false;

    if (!a || !b) return true;

    if (a.length !== b.length) return true;

    for (var i=0; i<a.length; i++) {
        if (a[i] !== b[i]) return true;
    }

    return false;
};

IPA.confirm = function(msg) {
    return window.confirm(msg);
};

IPA.notify_success = function(message, timeout) {

    if (!message) return; // don't show undefined, null and such

    function destroy_timeout() {
        if (IPA.notify_success.timeout) window.clearTimeout(IPA.notify_success.timeout);
    }

    var notification_area = $('.notification-area');

    if (notification_area.length === 0) {
        notification_area =  $('<div/>', {
            'class': 'notification-area ui-corner-all ui-state-highlight',
            click: function() {
                destroy_timeout();
                notification_area.fadeOut(100);
            }
        });

        notification_area.appendTo('#container');
    }

    notification_area.text(message);

    destroy_timeout();
    notification_area.fadeIn(IPA.config.message_fadein_time);

    IPA.notify_success.timeout = window.setTimeout(function() {
        notification_area.fadeOut(IPA.config.message_fadeout_time);
    }, timeout || IPA.config.message_timeout);
};

IPA.config = {
    default_priority: 500,
    message_timeout: 3000, // [ms]
    message_fadeout_time: 800, // [ms]
    message_fadein_time: 400 // [ms]
};
