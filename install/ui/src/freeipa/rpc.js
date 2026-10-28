/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *    Endi Dewata <edewata@redhat.com>
 *    John Dennis <jdennis@redhat.com>
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2014 Red Hat
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
    'dojo/Deferred',
    'dojo/on',
    'dojo/topic',
    './auth',
    './ipa',
    './text',
    './util',
    'exports'
   ],
   function(lang, Deferred, on, topic, auth, IPA, text, util, rpc /*exports*/) {

/**
 * Call an IPA command over JSON-RPC.
 *
 * @class rpc.command
 *
 * @param {Object} spec - construct specification
 * @param {string} spec.name - command name (optional)
 * @param {string} spec.entity - command entity(name) (optional)
 * @param {string}  spec.method - command method
 * @param {string[]}  spec.args - list of arguments, e.g. ['username']
 * @param {Object} spec.options - dict of options, e.g. {givenname: 'Petr'}
 * @param {Function} spec.on_success - callback function if command succeeds
 * @param {Function} spec.on_error - callback function if command fails
 *
 */
rpc.command = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    /** @property {string} name Name */
    that.name = spec.name;

    /** @property {entity.entity} entity Entity */
    that.entity = spec.entity;

    /** @property {string} method Method */
    that.method = spec.method;

    /** @property {string[]} args Command Arguments */
    that.args = $.merge([], spec.args || []);

    /** @property {Object} options Option map */
    that.options = $.extend({}, spec.options || {});

    /**
     * @property {Array} suppress_warnings array of message codes which
     * are suppressed
     */
    that.suppress_warnings = spec.suppress_warnings || [];

    /**
     * Success handler
     * @property {Function}
     * @param {Object} data
     * @param {string} text_status
     * @param {XMLHttpRequest} xhr
     */
    that.on_success = spec.on_success;

    /**
     * Error handler
     * @property {Function}
     * @param {XMLHttpRequest} xhr
     * @param {string} text_status
     * @param {{name:string,message:string}} error_thrown
     */
    that.on_error = spec.on_error;

    /**
     * Allow retrying of execution if previous ended as error
     *
     * Manifested by error dialog. Set it to `false` for custom error dialogs or
     * error handling without any dialog.
     * @property {Boolean} retry=true
     */
    that.retry = typeof spec.retry == 'undefined' ? true : spec.retry;

    /**
     * Allow turning off the activity icon.
     *
     * @property {Boolean} notify_globally=true
     */
    that.notify_globally = spec.notify_globally === undefined ? true :
        spec.notify_globally;

    /**
     * Allow set function which will be called when the activity of the command
     * starts. Works only when 'activity_icon' property is set to false
     *
     * @property {Function}
     */
    that.start_handler = spec.start_handler || null;

    /**
     * Allow set function which will be called when the activity of the command
     * ends. Works only when 'activity_icon' property is set to false
     *
     * @property {Function}
     */
    that.end_handler = spec.end_handler || null;

    /** @property {string} error_message Default error message */
    that.error_message = text.get(spec.error_message || '@i18n:dialogs.batch_error_message', 'Some operations failed.');

    /** @property {ordered_map.<number,string>} error_messages Error messages map */
    that.error_messages = $.ordered_map({
        911: 'Missing HTTP referer. You have to configure your browser to send HTTP referer header.',
        404: 'Cannot connect to the server, please check API accesibility (certificate, API, proxy, etc.)'
    });

    /**
     * Get command name
     *
     * - it's `entity.name + '_' + method`
     * - or `method`
     * @return {string}
     */
    that.get_command = function() {
        return (that.entity ? that.entity+'_' : '') + that.method;
    };

    /**
     * Add argument
     * @param {string} arg
     */
    that.add_arg = function(arg) {
        that.args.push(arg);
    };

    /**
     * Add arguments
     * @param {string[]} args
     */
    that.add_args = function(args) {
        $.merge(that.args, args);
    };

    /**
     * Set option
     * @param {string} name
     * @param {Mixed} value
     */
    that.set_option = function(name, value) {
        that.options[name] = value;
    };

    /**
     * Extends options map with another options map
     *
     * @param {{opt1:Mixed, opt2:Mixed}} options
     */
    that.set_options = function(options) {
        $.extend(that.options, options);
    };

    /**
     * Add value to an option
     *
     * - creates a new option if it does not exist yet
     * - for option overriding use `set_option` method
     * @param {string} name
     * @param {Mixed} value
     */
    that.add_option = function(name, value) {
        var values = that.options[name];
        if (!values) {
            values = [];
            that.options[name] = values;
        }
        values.push(value);
    };

    /**
     * Get option value
     * @return {Mixed}
     */
    that.get_option = function(name) {
        return that.options[name];
    };

    /**
     * Remove option from option map
     */
    that.remove_option = function(name) {
        delete that.options[name];
    };

    /**
     * Check result for warnings and process them
     * @param  {Object} result
     */
    that.process_warnings = function(result) {

        var msgs = result.messages;
        if (!result.messages) return;

        for (var i=0,l=msgs.length; i<l; i++) {
            var msg = lang.clone(msgs[i]);
            if (that.suppress_warnings.indexOf(msg.code) > -1) continue;
            // escape and reformat message
            msg.message = util.beautify_message(msg.message);
            IPA.notify(msg.message, msg.type);
        }
    };

    that.handle_notify_execution_end = function() {
        if (that.notify_globally) {
            topic.publish('rpc-end');
        }
        else {
            that.emit('end');
        }
    };

    /**
     * Execute the command.
     *
     * Set `on_success` and/or `on_error` handlers to be informed about result.
     */
    that.execute = function() {

        var deferred = new Deferred();

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

        function error_handler_auth(xhr, text_status, error_thrown) {

            auth.current.set_authenticated(false, '');
            auth.current.authenticate().then(function() {
                that.execute();
            });
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

            var self = this;
            function proceed() {
                // error_handler() publishes 'rpc-end'
                error_handler.call(self, xhr, text_status, error_thrown);
            }

            if (xhr.status === 401) {

                IPA.get_credentials().then(function(login_status) {
                    if (login_status === 200) {
                        that.request.error = error_handler;
                        $.ajax(that.request);
                        return;
                    }
                    proceed();
                });
            } else {
                proceed();
            }
        }

        /*
         * Normal error handler, handles all errors.
         * error_handler_login() is initially used to trap the
         * special case need to aquire session credentials, this is
         * not a true error, rather it's an indication an extra step
         * needs to be taken before normal processing can continue.
         */
        function error_handler(xhr, text_status, error_thrown) {

            that.handle_notify_execution_end();

            if (xhr.status === 401) {
                error_handler_auth(xhr, text_status, error_thrown);
                return;
            } else if (xhr.status === 404) {
                error_thrown = {
                    code: xhr.status,
                    name: xhr.responseText || text.get('@i18n:errors.http_error',
                                                    'HTTP Error')+' '+xhr.status
                };
            } else if (!error_thrown) {
                error_thrown = {
                    name: xhr.responseText || text.get('@i18n:errors.unknown_error', 'Unknown Error'),
                    message: xhr.statusText || text.get('@i18n:errors.unknown_error', 'Unknown Error')
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

            // global special cases error handlers section

            // With trusts, user from trusted domain can use his ticket but he
            // doesn't have rights for LDAP modify. It will throw internal error.
            // We should offer form base login.
            if (xhr.status === 500 && auth.current.authenticated_by === 'kerberos' &&
                !IPA.ui.initialized) {
                error_handler_auth(xhr, text_status, error_thrown);
                return;
            }

            if (that.retry) {
                dialog_open.call(this, xhr, text_status, error_thrown);

            } else if (that.on_error) {
                //custom error handling, maintaining AJAX call's context
                that.on_error.call(this, xhr, text_status, error_thrown);
            }

            deferred.reject({
                command: that,
                context: this,
                xhr: xhr,
                text_status: text_status,
                error_thrown: error_thrown
            });
        }

        function success_handler(data, text_status, xhr) {

            if (!data) {
                // error_handler() publishes 'rpc-end'
                error_handler.call(this, xhr, text_status, /* error_thrown */ {
                    name: text.get('@i18n:errors.http_error', 'HTTP Error')+' '+xhr.status,
                    url: this.url,
                    message: xhr ? xhr.statusText :
                            text.get('@i18n:errors.no_response', 'No response')
                });

            } else if (IPA.version && data.version && IPA.version !== data.version) {
                window.location.reload();

            } else if (IPA.principal && data.principal &&
                IPA.principal.toLowerCase() !== data.principal.toLowerCase()) {
                window.location.reload();

            } else if (data.error) {
                // error_handler() publishes 'rpc-end'
                error_handler.call(this, xhr, text_status,  /* error_thrown */ {
                    name: text.get('@i18n:errors.ipa_error', 'IPA Error') + ' ' +
                          data.error.code + ': ' + data.error.name,
                    code: data.error.code,
                    message: data.error.message,
                    data: data
                });

            } else {
                that.handle_notify_execution_end();

                var ajax = this;
                var failed = that.get_failed(that, data.result, text_status, xhr);
                if (!failed.is_empty()) {
                    var dialog = IPA.error_dialog({
                        xhr: xhr,
                        text_status: text_status,
                        error_thrown: {
                            name: text.get('@i18n:dialogs.batch_error_title', 'Operations Error'),
                            message: that.error_message
                        },
                        command: that,
                        errors: failed.errors,
                        visible_buttons: ['ok']
                    });

                    dialog.on_ok = function() {
                        dialog.close();
                        that.emit('success', {
                            that: ajax,
                            data: data,
                            text_status: text_status,
                            xhr: xhr
                        });
                    };

                    dialog.open();

                } else {
                    //custom success handling, maintaining AJAX call's context
                    that.emit('success', {
                        that: this,
                        data: data,
                        text_status: text_status,
                        xhr: xhr
                    });
                }
                that.process_warnings(data.result);
                deferred.resolve({
                    command: that,
                    context: this,
                    data: data,
                    text_status: text_status,
                    xhr: xhr
                });
            }
        }

        that.options.version = window.ipa_loader.api_version;

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

        if (that.notify_globally) {
            topic.publish('rpc-start');
        }
        else {
            that.emit('start');
        }

        $.ajax(that.request);
        return deferred.promise;
    };

    /**
     * Parse successful command result and get all errors.
     * @protected
     * @param {rpc.command} command
     * @param {Object} result
     * @param {string} text_status
     * @param {XMLHttpRequest} xhr
     * @return {rpc.error_list}
     */
    that.get_failed = function(command, result, text_status, xhr) {
        var errors = rpc.error_list();
        if(result && result.failed) {
            for(var association in result.failed) {
                for(var member_name in result.failed[association]) {
                    var member = result.failed[association][member_name];
                    for(var i = 0; i < member.length; i++) {
                        if(member[i].length > 1) {
                            var name = text.get('@i18n:errors.ipa_error', 'IPA Error');
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

    /**
     * Check if command accepts option
     * @param {string} option_name
     * @return {Boolean}
     */
    that.check_option = function(option_name) {

        var metadata = IPA.get_command_option(that.get_command(), option_name);
        return metadata !== null;
    };

    /**
     * Encodes command into JSON-RPC command object
     * @return {Object}
     */
    that.to_json = function() {
        var json = {};

        json.method = that.get_command();

        json.params = [];
        json.params[0] = that.args || [];
        json.params[1] = that.options || {};

        return json;
    };

    /**
     * Encodes command into CLI command string
     * @return {string}
     */
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

    that.register_handlers = function() {
        on(that, 'start', function() {
            if (that.start_handler) that.start_handler();
        });

        on(that, 'end', function() {
            if (that.end_handler) that.end_handler();
        });

        on(that, 'success', function(e) {
            if (that.on_success) that.on_success(e.data, e.text_status, e.xhr);
        });

        on(that, 'error', function(xhr, text_status, error_thrown) {
            if (that.on_error) that.on_error(xhr, text_status, error_thrown);
        });
    };

    that.register_handlers();

    return that;
};

/**
 * Call multiple IPA commands in a batch over JSON-RPC.
 *
 * @class rpc.batch_command
 * @extends rpc.command
 *
 * @param {Object} spec
 * @param {rpc.command[]} spec.commands - IPA commands to be executed
 * @param {Function} spec.on_success - callback function if command succeeds
 * @param {Function} spec.on_error - callback function if command fails
 */
rpc.batch_command = function(spec) {

    spec = spec || {};

    spec.method = 'batch';

    var that = rpc.command(spec);

    /** @property {rpc.command[]} commands Commands */
    that.commands = [];
    /** @property {rpc.error_list} errors Errors  */
    that.errors = rpc.error_list();

    /**
     * Show error if some command fail
     * @property {Boolean} show_error=true
     */
    that.show_error = typeof spec.show_error == 'undefined' ?
            true : spec.show_error;

    /**
     * Add command
     * @param {rpc.command} command
     */
    that.add_command = function(command) {
        that.commands.push(command);
        that.add_arg(command.to_json());
    };

    /**
     * Add commands
     * @param {rpc.command[]} commands
     */
    that.add_commands = function(commands) {
        for (var i=0; i<commands.length; i++) {
            that.add_command(commands[i]);
        }
    };

    /**
     * @inheritDoc
     */
    that.execute = function() {
        that.errors.clear();

        that.options.version = window.ipa_loader.api_version;

        var command = rpc.command({
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

    /**
     * Internal XHR success handler
     *
     * Parses data and looks for errors. `on_success` or `on_error` is then
     * called.
     * @protected
     * @param {Object} data
     * @param {string} text_status
     * @param {XMLHttpRequest} xhr
     */
    that.batch_command_on_success = function(data, text_status, xhr) {

        for (var i=0; i<that.commands.length; i++) {
            var command = that.commands[i];
            var result = data.result.results[i];

            var name = '';
            var message = '';

            if (!result) {
                name = text.get('@i18n:errors.internal_error', 'Internal Error')+' '+xhr.status;
                message = xhr ? xhr.statusText :
                    text.get('@i18n:errors.internal_error', 'Internal Error');

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
                name = text.get('@i18n:errors.ipa_error', 'IPA Error')+(code ? ' '+code : '');
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

                command.emit('success', {
                    data: result,
                    text_status: text_status,
                    xhr: xhr
                });
            }
        }

        if (that.show_error && that.errors.errors.length > 0) {
            var ajax = this;
            var dialog = IPA.error_dialog({
                xhr: xhr,
                text_status: text_status,
                error_thrown: {
                    name: text.get('@i18n:dialogs.batch_error_title', 'Operations Error'),
                    message: that.error_message
                },
                command: that,
                errors: that.errors.errors,
                visible_buttons: [ 'ok' ]
            });

            dialog.on_ok = function() {
                dialog.close();
                that.emit('success', {
                    that: ajax,
                    data: data,
                    text_status: text_status,
                    xhr: xhr
                });
            };

            dialog.open();

        } else {
            that.emit('success', {
                data: data,
                text_status: text_status,
                xhr: xhr
            });
        }
    };

    /**
     * Internal XHR error handler
     * @protected
     * @param {XMLHttpRequest} xhr
     * @param {string} text_status
     * @param {{name:string,message:string}} error_thrown
     */
    that.batch_command_on_error = function(xhr, text_status, error_thrown) {
        // TODO: undefined behavior
        if (that.on_error) {
            that.on_error.call(this, xhr, text_status, error_thrown);
        }
    };

    return that;
};

/**
 * Call multiple IPA commands over JSON-RPC separately and wait for every
 * command's response.
 *
 * - concurrent command fails if any command fails
 * - result is reported when each command finishes
 *
 * @class rpc.concurrent_command
 *
 * @param {Object} spec - construct specification
 * @param {Array.<rpc.command>} spec.commands - IPA commands to execute
 * @param {Function} spec.on_success - callback function if each command succeed
 * @param {Function} spec.on_error - callback function one command fails
 *
 */
rpc.concurrent_command = function(spec) {

    spec = spec || {};
    var that = IPA.object();

    /** @property {rpc.command[]} commands Commands */
    that.commands = [];

    /**
     * Success handler
     * @property {Function}
     */
    that.on_success = spec.on_success;

    /**
     * Error handler
     * @property {Function}
     */
    that.on_error = spec.on_error;

    /**
     * Add commands
     * @param {rpc.command[]} commands
     */
    that.add_commands = function(commands) {

        if(commands && commands.length) {
            for(var i=0; i < commands.length; i++) {
                that.commands.push({
                    command: commands[i]
                });
            }
        }
    };

    /**
     * Execute the commands one by one.
     */
    that.execute = function() {

        var command_info, command, i;

        //prepare for execute
        for(i=0; i < that.commands.length; i++) {
            command_info = that.commands[i];
            command = command_info.command;
            if(!command) {
                var dialog = IPA.message_dialog({
                    name: 'internal_error',
                    title: text.get('@i18n:errors.error', 'Error'),
                    message: text.get('@i18n:errors.internal_error', 'Internal error.')
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

    /**
     * Internal error handler
     * @protected
     */
    that.error_handler = function(command_info, xhr, text_status, error_thrown) {

        command_info.completed = true;
        command_info.success = false;
        command_info.xhr = xhr;
        command_info.text_status = text_status;
        command_info.error_thrown = error_thrown;
        command_info.context = this;
        that.command_completed();
    };

    /**
     * Internal success handler
     * @protected
     */
    that.success_handler = function(command_info, data, text_status, xhr) {

        command_info.completed = true;
        command_info.success = true;
        command_info.data = data;
        command_info.text_status = text_status;
        command_info.xhr = xhr;
        command_info.context = this;
        that.command_completed();
    };

    /**
     * Check if all commands finished.
     * If so, report it.
     * @protected
     */
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

    /**
     * Call each command's success handler and `on_success`.
     * @protected
     */
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

    /**
     * Call each command's error handler and `on_success`.
     * @protected
     */
    that.on_error_all = function() {

        if(that.on_error) {
            that.on_error();

        } else {
            var dialog = IPA.message_dialog({
                name: 'operation_error',
                title: text.get('@i18n:dialogs.batch_error_title', 'Operations Error'),
                message: text.get('@i18n:dialogs.batch_error_message', 'Some operations failed.')
            });

            dialog.open();
        }
    };

    that.add_commands(spec.commands);

    return that;
};

/**
 * Error list
 *
 * Collection for RPC command errors.
 *
 * @class rpc.error_list
 * @private
 */
rpc.error_list = function() {
    var that = IPA.object();

    /** Clear errors */
    that.clear = function() {
        that.errors = [];
    };

    /** Add error */
    that.add = function(command, name, message, status) {
        that.errors.push({
            command: command,
            name: name,
            message: message,
            status: status
        });
    };

    /** Add errors */
    that.add_range = function(error_list) {
        that.errors = that.errors.concat(error_list.errors);
    };

    /**
     * Check if there are no errors
     * @return {Boolean}
     */
    that.is_empty = function () {
        return that.errors.length === 0;
    };

    that.clear();
    return that;
};

/**
 * Error handler for rpc.command which handles error #4304 as success.
 *
 * 4304 is raised when part of an operation succeeds and the part that failed
 * isn't critical.
 * @member IPA
 * @param {IPA.entity_adder_dialog} adder_dialog
 */
rpc.create_4304_error_handler = function(adder_dialog) {

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
            adder_dialog.close();
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

        dialog.open();
    };
};

/**
 * Property names to identify objects and values to extract in
 * `rpc.extract_objects(array)` method.
 * @type {Array}
 */
rpc.extract_types = ['__base64__', '__datetime__', '__dns_name__'];

/**
 * Extract values from specially encoded objects
 *
 * '''
 * // from
 * [{"__datetime__": "20140625103152Z"}]
 * // to
 * ["20140625103152Z"]
 * '''
 *
 * - in-place operations, modifies input array
 * - object properties to extract are defined in `rpc.extract_types`
 * - other types are left intact
 *
 * @param  {Array} values
 * @return {Array}
 */
rpc.extract_objects = function(values) {

    if (!values) return values;

    var et = rpc.extract_types;
    for (var i=0, l=values.length; i<l; i++) {
        var val = values[i];
        if (typeof val === 'object') {
            for (var j=0, m=et.length; j<m; j++) {
                if (val[et[j]] !== undefined) {
                    values[i] = val[et[j]];
                    break;
                }
            }
        }
    }
    return values;
};

/**
 * Server side error/warning codes
 *
 * Add new errors from ipalib.messages only if necessary.
 */
rpc.errors = {
    search_result_truncated: 13017
};

return rpc;
});
