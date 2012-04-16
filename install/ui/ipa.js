/*jsl:import jquery.ordered-map.js */
/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *    Endi Dewata <edewata@redhat.com>
 *    John Dennis <jdennis@redhat.com>
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
            entity: 'user',
            method: 'find',
            options: {
                whoami: true,
                all: true
            },
            on_success: function(data, text_status, xhr) {
                that.whoami = data.result[0];
                that.principal = that.whoami.krbprincipalname[0];
            }
        }));

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
            on_success: params.on_success,
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
    }

    function success_handler(data, text_status, xhr) {
        status = xhr.status;
    }

    var request = {
        url: IPA.login_url,
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
                name = IPA.get_message('errors.ipa_error', 'IPA Error')+(result.error.code ? ' '+result.error.code : '');
                message = result.error.message || result.error;

                that.errors.add(command, name, message, text_status);

                if (command.on_error) command.on_error.call(
                    this,
                    xhr,
                    text_status,
                    {
                        name: name,
                        code: result.error.code,
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
                title: IPA.get_message('dialogs.batch_error_title', 'Operations Error'),
                message: IPA.get_message('dialogs.batch_error_message', 'Some operations failed.')
            });

            dialog.open();
        }
    };

    that.add_commands(spec.commands);

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

        that.id = 'error_dialog';
        that.xhr = spec.xhr || {};
        that.text_status = spec.text_status || '';
        that.error_thrown = spec.error_thrown || {};
        that.command = spec.command;
        that.title = spec.error_thrown.name;
        that.errors = spec.errors;
        that.visible_buttons = spec.visible_buttons || ['retry', 'cancel'];
    };

    that.create = function() {
        if (that.error_thrown.url) {
            $('<p/>', {
                text: IPA.get_message('errors.url', 'URL')+': '+that.error_thrown.url
            }).appendTo(that.container);
        }

        $('<p/>', {
            html: that.error_thrown.message
        }).appendTo(that.container);

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
                    var error_div = $('<li />', {
                        text: error.message
                    }).appendTo(errors_container);
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
            fields: [
                {
                    name: 'username',
                    required: true,
                    label: IPA.get_message('login.username', "Username")
                },
                {
                    name: 'password',
                    type: 'password',
                    required: true,
                    label: IPA.get_message('login.password', "Password")
                }
            ]
        }
    ];

    spec.visible_buttons = spec.visible_buttons || ['retry'];

    var that = IPA.error_dialog(spec);

    that.title = spec.title || IPA.get_message('ajax.401.title',
                    'Kerberos ticket no longer valid.');

    that.message = spec.message || IPA.get_message('ajax.401.message',
                    "Your kerberos ticket is no longer valid. "+
                    "Please run kinit and then click 'Retry'. "+
                    "If this is your first time running the IPA Web UI "+
                    "<a href='/ipa/config/unauthorized.html'>"+
                    "follow these directions</a> to configure your browser.");

    that.form_auth_failed = "<p><strong>Please re-enter your username or password</strong></p>" +
                "<p>The password or username you entered is incorrect. " +
                "Please try again (make sure your caps lock is off).</p>" +
                "<p>If the problem persists, contact your administrator.</p>";

    that.password_expired = "<p><strong>Password expired</strong></p>" +
                "<p>Please run kinit to reset the password and then try to login again.</p>" +
                "<p>If the problem persists, contact your administrator.</p>";

    that.create = function() {

        that.krb_message_contatiner = $('<div\>').appendTo(that.container);

        $('<p/>', {
            html: that.message
        }).appendTo(that.krb_message_contatiner);

        var text = IPA.get_message('login.use', "Or you can use ");
        var fb_title = $('<p/>', {
            text: text
        }).appendTo(that.krb_message_contatiner);

        text = IPA.get_message('login.form_auth', "form-based authentication");
        that.form_auth_link = $('<a/>', {
            text: text,
            href: '#',
            click: function() {
                that.show_form();
                return false;
            },
            keydown: function(event) {
                if (event.keyCode === 13) { //enter
                    that.show_form();
                    return false;
                }
            }
        }).appendTo(fb_title);

        fb_title.append('.');

        that.create_form();
    };

    that.create_form = function() {

        that.form = $('<div>', {
            'class': 'auth-dialog',
            style: 'display: none;',
            keyup: that.on_form_keyup
        }).appendTo(that.container);

        var text = IPA.get_message('login.login', "Login");
        $('<h3/>', {
            text: text
        }).appendTo(that.form);

        that.error_box = $('<div/>', {
            'class': 'error-box',
            style: 'display:none',
            html: that.form_auth_failed
        }).appendTo(that.form);


        var widgets = that.widgets.get_widgets();
        for (var i=0; i<widgets.length; i++) {
            var widget = widgets[i];

            var div = $('<div/>', {
                name: widget.name,
                'class': 'dialog-section'
            }).appendTo(that.form);

            widget.create(div);
        }
    };

    that.create_login_buttons = function() {

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

        visible = that.visible_buttons.indexOf('back') > -1;
        label = IPA.get_message('buttons.back', "Back");
        that.create_button({
            name: 'back',
            label: label,
            visible: visible,
            click: function() {
                that.on_back();
            }
        });
    };

    that.open = function() {
        that.dialog_open();
        that.form_auth_link.focus();
    };

    that.on_form_keyup = function(event) {

        if (that.switching) {
            that.switching = false;
            return;
        }

        if (event.keyCode === 13) { // enter
            that.on_login();
            event.preventDefault();
        } else if (event.keyCode === 27) { // escape
            that.on_back();
            event.preventDefault();
        }
    };

    that.show_form = function() {

        that.switching = true;

        that.krb_message_contatiner.css('display', 'none');
        that.form.css('display', 'block');
        that.display_buttons(['login', 'back']);

        var user_field = that.fields.get_field('username');
        user_field.widget.focus_input();
    };

    that.on_back = function() {

        that.krb_message_contatiner.css('display', 'block');
        that.form.css('display', 'none');
        that.display_buttons(['retry']);
        that.form_auth_link.focus();
    };

    that.on_login = function() {

        if (!that.validate()) return;

        var record = {};
        that.save(record);

        IPA.display_activity_icon();

        var result = IPA.login_password(record.username[0], record.password[0]);

        IPA.hide_activity_icon();

        if (result === 'success') {
            that.on_login_success();
        } else if (result === 'expired') {
            that.error_box.html(that.password_expired);
            that.error_box.css('display', 'block');
        }else {
            that.error_box.html(that.form_auth_failed);
            that.error_box.css('display', 'block');
        }
    };

    that.on_login_success = function() {
        that.error_box.css('display', 'none');
        that.on_retry();
    };

    that.create_login_buttons();

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

IPA.array_diff = function(a, b) {

    if (a === b || (!a && !b)) return false;

    if (!a || !b) return true;

    if (a.length !== b.length) return true;

    for (var i=0; i<a.length; i++) {
        if (a[i] !== b[i]) return true;
    }

    return false;
};

IPA.config = {
    default_priority: 500
};
