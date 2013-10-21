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

define(['./jquery',
        './json2',
        './_base/i18n',
        './metadata',
        './builder',
        './reg',
        './text'],
       function($, JSON, i18n, metadata_provider, builder, reg, text) {

/**
 * @class
 * @singleton
 *
 * Defined in ipa module. Other modules extend it.
 *
 * There is a long-term goal to reduce the number of items in this namespace
 * and move them to separate modules.
 *
 */
var IPA = function() {

    var that = {
        jsonrpc_id: 0
    };

    // live server path
    that.url = '/ipa/ui/';

    /**
     * jQuery AJAX options used by RPC commands
     * @property
     */
    that.ajax_options = {
        type: 'POST',
        contentType: 'application/json',
        dataType: 'json',
        async: true,
        processData: false
    };

    /**
     * i18n messages
     * @deprecated
     * @property {Object}
     */
    that.messages = {};

    /**
     * User information
     *
     * - output of ipa user-find --whoami
     */
    that.whoami = {};

    /**
     * Map of entities
     * @deprecated
     * @property {ordered_map}
     */
    that.entities = $.ordered_map();

    /**
     * Map of entity factories
     * @deprecated
     */
    that.entity_factories = {};

    /**
     * Number of currently active command calls - controls  visibility of network indicator
     */
    that.network_call_count = 0;

    /**
     * UI state
     * @property {boolean} initialized - Intialization completed:
     *                                      - metadata
     *                                      - user information
     *                                      - server configuration
     * @property {boolean} logged_kerberos - User authenticated by
     *                                       Kerberos negotiation
     * @property {boolean} logged_password - User authenticated by password
     */
    that.ui = {};

    /**
     * Load initialization data and initialize UI
     * @param {Object} params
     * @param {string} params.url - URL of JSON RPC interface
     * @param {Function} params.on_success - success callback
     * @param {Function} params.on_error - error callback
     */
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
                that.messages = data.texts;
                i18n.source = that.messages;
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

        batch.add_command(IPA.command({
            entity: 'trustconfig',
            method: 'show',
            retry: false,
            on_success: function(data, text_status, xhr) {
                that.trust_enabled = true;
            },
            on_error: function(xhr, text_status, error_thrown) {
                that.trust_enabled = false;
            }
        }));

        batch.execute();
    };

    /**
     * Prepares `user-find --whoami` command
     * @protected
     * @param {boolean} batch - Specifies if it will be used as single command or
     *                          in a batch.
     */
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

    /**
     * Executes RPC commands to load metadata
     * @protected
     * @param {Object} params
     * @param {Function} params.on_success
     * @param {Function} params.on_error
     */
    that.init_metadata = function(params) {

        var objects = IPA.command({
            name: 'ipa_init_objects',
            method: 'json_metadata',
            options: {
                object: 'all'
            },
            on_success: function(data, text_status, xhr) {
                metadata_provider.source.objects = data.result.objects;
            }
        });

        var commands = IPA.command({
            name: 'ipa_init_commands',
            method: 'json_metadata',
            options: {
                command: 'all'
            },
            on_success: function(data, text_status, xhr) {
                metadata_provider.source.commands = data.result.commands;
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

    /**
     * Register entity factory in global registry
     * @deprecated
     * @param {string} name - Entity name
     * @param {Function} factory - Entity factory
     */
    that.register = function(name, factory) {
        reg.entity.remove(name);
        reg.entity.register({
            type: name,
            factory: factory,
            spec: { name: name }
        });
    };

    /**
     * Return entity instance with given name from global entity registry
     * @deprecated
     * @param {string} name - entity name
     */
    that.get_entity = function(name) {
        return reg.entity.get(name);
    };

    /**
     * Display network activity indicator
     */
    that.display_activity_icon = function() {
        that.network_call_count++;
        $('.network-activity-indicator').css('visibility', 'visible');
    };

    /**
     * Hide network activity indicator
     *
     * - based on network_call_count
     */
    that.hide_activity_icon = function() {
        that.network_call_count--;

        if (0 === that.network_call_count) {
            $('.network-activity-indicator').css('visibility', 'hidden');
        }
    };

    that.obj_cls = function() {};
    that.obj_cls.prototype.__fw_obj = true;

    return that;
}();

/**
 * Framework objects created by factories should use this
 * instead of empty object when creating base objects. As an alternative
 * they can just set __fw_obj property.
 *
 * __fw_obj property serves for telling the framework that it's instantiated
 * object and not an object specification (spec).
 *
 * @class
 */
IPA.object = function(s) {
    return new IPA.obj_cls();
};

/**
 * Make request on Kerberos authentication url to initialize Kerberos negotiation.
 *
 * Set result to IPA.ui.logged_kerberos.
 *
 * @member IPA
 */
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

/**
 * Logout
 *
 * - terminate the session.
 * - redirect to logout landing page on success
 *
 * @member IPA
 */
IPA.logout = function() {

    function show_error(message) {
        var dialog = IPA.message_dialog({
            name: 'logout_error',
            message: message,
            title: '@i18n:login.logout_error'
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

/**
 * Login by username and password
 *
 * @member IPA
 * @param {string} username
 * @param {string} password
 * @return {string} Logout status - {password-expired, denied, invalid, success}
 */
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
            if (reason === 'password-expired' || reason === 'denied') {
                result = reason;
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

/**
 * Reset user's password
 *
 * @member IPA
 * @param {string} username
 * @param {string} old_password
 * @param {string} new_password
 * @return {Object} result
 * @return {string} result.status
 * @return {string} result.message
 */
IPA.reset_password = function(username, old_password, new_password) {

    //possible results: 'ok', 'invalid-password', 'policy-error'

    var status, result, reason, invalid, failure, data, request;

    status = 'invalid';
    result = {
        status: status,
        message: text.get('@i18n:password.reset_failure',
                "Password reset was not successful.")
    };

    function success_handler(data, text_status, xhr) {

        result.status = xhr.getResponseHeader("X-IPA-Pwchange-Result") || status;

        if (result.status === 'policy-error') {
            result.message = xhr.getResponseHeader("X-IPA-Pwchange-Policy-Error");
        } else if (result.status === 'invalid-password') {
            result.message = text.get('@i18n:password.invalid_password',
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

/**
 * Check if password is about to expired (based on
 * IPA.server_config.ipapwdexpadvnotify). If so, display a notification
 * message with a link to reset password dialog.
 *
 * @member IPA
 */
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
            message = text.get('@i18n:password.expires_in');
            message = message.replace('${days}', diff);
            container.append(message);
        }
    }
};

/**
 * Show password dialog for self-service change of password.
 *
 * @member IPA
 */
IPA.password_selfservice = function() {
    var reset_dialog = IPA.user_password_dialog({
        pkey: IPA.whoami.uid[0],
        on_success: function() {
            var command = IPA.get_whoami_command();
            var orig_on_success = command.on_success;
            command.on_success = function(data, text_status, xhr) {
                orig_on_success.call(this, data, text_status, xhr);
                IPA.update_password_expiration();
            };
            command.execute();

            IPA.notify_success(text.get('@i18n:password.password_change_complete'));
            reset_dialog.close();
        }
    });
    reset_dialog.open();
};

/**
 * Parse value as UTC date
 * @member IPA
 * @return Data
 */
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
 * @class IPA.command
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
IPA.command = function(spec) {

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

    /** @property {string} error_message Default error message */
    that.error_message = text.get(spec.error_message || '@i18n:dialogs.batch_error_message', 'Some operations failed.');

    /** @property {ordered_map.<number,string>} error_messages Error messages map */
    that.error_messages = $.ordered_map({
        911: 'Missing HTTP referer. <br/> You have to configure your browser to send HTTP referer header.'
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
     * Execute the command.
     *
     * Set `on_success` and/or `on_error` handlers to be informed about result.
     */
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
                    name: text.get('@i18n:errors.http_error', 'HTTP Error')+' '+xhr.status,
                    url: this.url,
                    message: data ? xhr.statusText : text.get('@i18n:errors.no_response', 'No response')
                });

            } else if (IPA.version && data.version && IPA.version !== data.version) {
                window.location.reload();

            } else if (IPA.principal && data.principal && IPA.principal !== data.principal) {
                window.location.reload();

            } else if (data.error) {
                // error_handler() calls IPA.hide_activity_icon()
                error_handler.call(this, xhr, text_status,  /* error_thrown */ {
                    name: text.get('@i18n:errors.ipa_error', 'IPA Error') + ' ' +
                          data.error.code + ': ' + data.error.name,
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
                            name: text.get('@i18n:dialogs.batch_error_title', 'Operations Error'),
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

    /**
     * Parse successful command result and get all errors.
     * @protected
     * @param {IPA.command} command
     * @param {Object} result
     * @param {string} text_status
     * @param {XMLHttpRequest} xhr
     * @return {IPA.error_list}
     */
    that.get_failed = function(command, result, text_status, xhr) {
        var errors = IPA.error_list();
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

    return that;
};

/**
 * Call multiple IPA commands in a batch over JSON-RPC.
 *
 * @class IPA.batch_command
 * @extends IPA.command
 *
 * @param {Object} spec
 * @param {Array.<IPA.command>} spec.commands - IPA commands to be executed
 * @param {Function} spec.on_success - callback function if command succeeds
 * @param {Function} spec.on_error - callback function if command fails
 */
IPA.batch_command = function(spec) {

    spec = spec || {};

    spec.method = 'batch';

    var that = IPA.command(spec);

    /** @property {IPA.command[]} commands Commands */
    that.commands = [];
    /** @property {IPA.error_list} errors Errors  */
    that.errors = IPA.error_list();

    /**
     * Show error if some command fail
     * @property {Boolean} show_error=true
     */
    that.show_error = typeof spec.show_error == 'undefined' ?
            true : spec.show_error;

    /**
     * Add command
     * @param {IPA.command} command
     */
    that.add_command = function(command) {
        that.commands.push(command);
        that.add_arg(command.to_json());
    };

    /**
     * Add commands
     * @param {IPA.command[]} commands
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
                message = result ? xhr.statusText : text.get('@i18n:errors.internal_error', 'Internal Error');

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
                    name: text.get('@i18n:dialogs.batch_error_title', 'Operations Error'),
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
 * @class IPA.concurrent_command
 *
 * @param {Object} spec - construct specification
 * @param {Array.<IPA.command>} spec.commands - IPA commands to execute
 * @param {Function} spec.on_success - callback function if each command succeed
 * @param {Function} spec.on_error - callback function one command fails
 *
 */
IPA.concurrent_command = function(spec) {

    spec = spec || {};
    var that = IPA.object();

    /** @property {IPA.command[]} commands Commands */
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
     * @param {IPA.command[]} commands
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
 * Build object with {@link builder}.
 * @member IPA
 * @param {Object} spec - contruction spec
 * @param {Object} context
 * @param {Object} overrides
 */
IPA.build = function(spec, context, overrides) {

    return builder.build(null, spec, context, overrides);
};

/**
 * Create a object defined by spec with IPA.object as parent.
 * @member IPA
 * @param {Object} spec
 * @return {Object} new object with all properties as spec
 */
IPA.default_factory = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    $.extend(that, spec);

    return that;
};

/**
 * Helper function used to retrieve information about an object attribute from metadata
 * @member IPA
 * @param {string} entity_name
 * @param {string} name - attribute name
 */
IPA.get_entity_param = function(entity_name, name) {

    return metadata_provider.get(['@mo-param', entity_name, name].join(':'));
};

/**
 * Helper function used to retrieve information about an command argument from metadata
 * @member IPA
 * @param {string} command_name
 * @param {string} arg_name - argument name
 */
IPA.get_command_arg = function(command_name, arg_name) {

    return metadata_provider.get(['@mc-arg', command_name, arg_name].join(':'));
};


/**
 * Helper function used to retrieve information about an command option from metadata
 * @member IPA
 * @param {string} command_name
 * @param {string} option_name - argument name
 */
IPA.get_command_option = function(command_name, option_name) {

    return metadata_provider.get(['@mc-opt', command_name, option_name].join(':'));
};

/**
 * Helper function used to retrieve information about an attribute member
 * @member IPA
 * @param {string} obj_name - object(entity) name
 * @param {string} member - attribute member
 */
IPA.get_member_attribute = function(obj_name, member) {

    var obj = metadata_provider.get('@mo:'+obj_name);
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

/**
 * Create HTML representation of network spinner.
 * @member IPA
 * @return {HTMLElement} Network spinner node
 */
IPA.create_network_spinner = function(){
    var span = $('<span/>', {
        'class': 'network-activity-indicator'
    });
    $('<img/>', {
        src: 'images/spinner-small.gif'
    }).appendTo(span);
    return span;
};

/**
 * Dirty dialog
 *
 * Should be used as an indication of unsaved changes on page when leaving the
 * page. Offers user to safe/reset the changes or cancel the action.
 *
 * @class
 * @extends IPA.dialog
 * @param {Object} spec
 * @param {IPA.facet} spec.facet - Dirty facet
 * @param {string} [spec.message] - Displayed message
 */
IPA.dirty_dialog = function(spec) {

    spec = spec || {};
    spec.title = spec.title || '@i18n:dialogs.dirty_title';
    spec.width = spec.width || '25em';

    var that = IPA.dialog(spec);

    /** @property {facet.facet} facet Facet*/
    that.facet = spec.facet;

    /** @property {string} message Dirty message*/
    that.message = text.get(spec.message || '@i18n:dialogs.dirty_message');

    /** @inheritDoc */
    that.create_content = function() {
        that.container.append(that.message);
    };

    that.create_button({
        name: 'update',
        label: '@i18n:buttons.update',
        click: function() {
            that.facet.update(function() {
                that.close();
                that.callback();
            });
        }
    });

    that.create_button({
        name: 'reset',
        label: '@i18n:buttons.reset',
        click: function() {
            that.facet.reset();
            that.close();
            that.callback();
        }
    });

    that.create_button({
        name: 'cancel',
        label: '@i18n:buttons.cancel',
        click: function() {
            that.close();
        }
    });

    /**
     * Function which is called when user click on 'update' or 'delete' button
     */
    that.callback = function() {
    };

    return that;
};

/**
 * Error dialog
 *
 * Serves for notifying an error in RPC command.
 *
 * @class
 * @extends IPA.dialog
 * @mixins IPA.confirm_mixin
 * @param {Object} spec
 */
IPA.error_dialog = function(spec) {

    spec = spec || {};

    spec.id = spec.id || 'error_dialog';
    spec.name = 'error_dialog';
    spec.title = spec.error_thrown.name;

    var that = IPA.dialog(spec);

    IPA.confirm_mixin().apply(that);

    /** @property {XMLHttpRequest} xhr Command's xhr */
    that.xhr = spec.xhr || {};
    /** @property {string} text_status Command's text status */
    that.text_status = spec.text_status || '';
    /** @property {{name:string,message:string}} error_thrown Command's error */
    that.error_thrown = spec.error_thrown || {};
    /** @property {IPA.command} command Command */
    that.command = spec.command;
    /** @property {IPA.error_list} errors Errors */
    that.errors = spec.errors;
    /** @property {string[]} visible_buttons=['retry', 'cancel'] Visible button names */
    that.visible_buttons = spec.visible_buttons || ['retry', 'cancel'];

    /**
     * Beautify error message
     *
     * Multi-lined text may contain TAB character as first char of the line
     * to hint at marking the whole line differently.
     * @param {jQuery} container Container to add the beautified message.
     * @param {string} message
     */
    that.beautify_message = function(container, message) {
        var lines = message.split(/\n/g);
        var line_span;
        for(var i=0; i<lines.length; i++) {

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

    /** @inheritDoc */
    that.create_content = function() {
        if (that.error_thrown.url) {
            $('<p/>', {
                text: text.get('@i18n:errors.url', 'URL')+': '+that.error_thrown.url
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
                title: text.get('@i18n:dialogs.show_details'),
                text: text.get('@i18n:dialogs.show_details')
            }).appendTo(errors_title_div);

            var hide_details = $('<a />', {
                href: '#',
                title: text.get('@i18n:dialogs.hide_details'),
                text: text.get('@i18n:dialogs.hide_details'),
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

    /**
     * Create dialog buttons
     * @protected
     */
    that.create_buttons = function() {

        // When a user initially opens the Web UI without a Kerberos
        // ticket, the messages including the button labels have not
        // been loaded yet, so the button labels need default values.

        var visible = that.visible_buttons.indexOf('retry') > -1;
        var label = text.get('@i18n:buttons.retry', 'Retry');
        that.create_button({
            name: 'retry',
            label: label,
            visible: visible,
            click: function() {
                that.on_retry();
            }
        });

        visible = that.visible_buttons.indexOf('ok') > -1;
        label = text.get('@i18n:buttons.ok', 'OK');
        that.create_button({
            name: 'ok',
            label: label,
            visible: visible,
            click: function() {
                that.on_ok();
            }
        });

        visible = that.visible_buttons.indexOf('cancel') > -1;
        label = text.get('@i18n:buttons.cancel', 'Cancel');
        that.create_button({
            name: 'cancel',
            label: label,
            visible: visible,
            click: function() {
                that.on_cancel();
            }
        });
    };

    /**
     * Retry handler
     * @protected
     */
    that.on_retry = function() {
        that.close();
        that.command.execute();
    };

    /**
     * OK button handler
     * @protected
     */
    that.on_ok = function() {
        that.close();
    };

    /**
     * Cancel button and negative confirmation handler
     * @protected
     */
    that.on_cancel = function() {
        that.close();
    };

    /**
     * Positive confirmation handler
     * @protected
     */
    that.on_confirm = function() {
        if (that.visible_buttons.indexOf('retry') > -1) that.on_retry();
        else that.on_ok();
    };

    that.create_buttons();

    return that;
};

/**
 * Error list
 *
 * Collection for RPC command errors.
 *
 * @class IPA.error_list
 * @private
 */
IPA.error_list = function() {
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
 * Error handler for IPA.command which handles error #4304 as success.
 *
 * 4304 is raised when part of an operation succeeds and the part that failed
 * isn't critical.
 * @member IPA
 * @param {IPA.entity_adder_dialog} adder_dialog
 */
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

        dialog.open();
    };
};

/**
 * Unauthorized dialog
 *
 * Notifies that user's session is expired. It supports forms-based authentication
 * and password reset when password is expired.
 *
 * @class IPA.unauthorized_dialog
 * @extends IPA.error_dialog
 * @param {Object} spec
 */
IPA.unauthorized_dialog = function(spec) {

    spec = spec || {};

    spec.sections = [
        {
            name: 'login',
            label: 'Login',
            fields: [
                {
                    name: 'username',
                    label: text.get('@i18n:login.username', "Username")
                },
                {
                    name: 'password',
                    $type: 'password',
                    label: text.get('@i18n:login.password', "Password")
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
                    label: text.get('@i18n:login.username', "Username")
                },
                {
                    name: 'new_password',
                    $type: 'password',
                    required: true,
                    label: text.get('@i18n:password.new_password)', "New Password")
                },
                {
                    name: 'verify_password',
                    $type: 'password',
                    required: true,
                    label: text.get('@i18n:password.verify_password', "Verify Password"),
                    validators: [{
                        $type: 'same_password',
                        other_field: 'new_password'
                    }]
                }
            ]
        }
    ];

    spec.visible_buttons = spec.visible_buttons || ['retry'];
    spec.name = spec.name || 'unauthorized_dialog';
    spec.id = spec.id || spec.name;

    var that = IPA.error_dialog(spec);

    /** @inheritDoc */
    that.title = spec.title || text.get('@i18n:login.login', "Login");

    /** @property {string} message Session expired message   */
    that.message = text.get(spec.message || '@i18n:ajax.401.message',
                    "Your session has expired. Please re-login.");

    /** @property {string} form_auth_msg Forms authentication message */
    that.form_auth_msg = text.get(spec.form_auth_msg || '@i18n:login.form_auth',
                    "To login with username and password, enter them in the fields below then click Login.");

    /** @property {string} krb_auth_msg Kerberos authentication message */
    that.krb_auth_msg = text.get(spec.krb_auth_msg || '@i18n:login.krb_auth_msg',
                    " To login with Kerberos, please make sure you" +
                    " have valid tickets (obtainable via kinit) and " +
                    "<a href='http://${host}/ipa/config/unauthorized.html'>configured</a>" +
                    " the browser correctly, then click Login. ");

    that.krb_auth_msg = that.krb_auth_msg.replace('${host}', window.location.hostname);

    /** @property {string} form_auth_failed Forms authentication failure message */
    that.form_auth_failed = "<p><strong>Please re-enter your username or password</strong></p>" +
                "<p>The password or username you entered is incorrect. " +
                "Please try again (make sure your caps lock is off).</p>" +
                "<p>If the problem persists, contact your administrator.</p>";

    /** @property {string} password_expired Password expired message */
    that.password_expired = "Your password has expired. Please enter a new password.";

    /** @property {string} denied Login denied message */
    that.denied = "Sorry you are not allowed to access this service.";

    /** @inheritDoc */
    that.create_content = function() {

        that.session_expired_form();
        that.create_reset_form();
    };

    /**
     * Create session expired form
     * @protected
     */
    that.session_expired_form = function() {
        that.session_form = $('<div\>').appendTo(that.container);

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

    /**
     * Create password reset form
     * @protected
     */
    that.create_reset_form = function() {

        that.reset_form = $('<div\>', {
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

    /**
     * Create dialog buttons
     * @protected
     */
    that.create_buttons = function() {

        that.buttons.empty();

        var visible = that.visible_buttons.indexOf('login') > -1;
        var label = text.get('@i18n:login.login', "Login");
        that.create_button({
            name: 'login',
            label: label,
            visible: visible,
            click: function() {
                that.on_login();
            }
        });

        visible = that.visible_buttons.indexOf('reset') > -1;
        label = text.get('@i18n:buttons.reset_password_and_login', "Reset Password and Login");
        that.create_button({
            name: 'reset',
            label: label,
            visible: visible,
            click: function() {
                that.on_reset();
            }
        });

        visible = that.visible_buttons.indexOf('cancel') > -1;
        label = text.get('@i18n:buttons.cancel', "Cancel");
        that.create_button({
            name: 'cancel',
            label: label,
            visible: visible,
            click: function() {
                that.on_cancel();
            }
        });
    };

    /** @inheritDoc */
    that.open = function() {
        that.dialog_open();
        that.show_session_form();
        that.check_error_reason();
    };

    /**
     * Check if response contains IPA specific rejection reason.
     * @protected
     */
    that.check_error_reason = function() {
        if (this.xhr) {
            var reason = this.xhr.getResponseHeader("X-IPA-Rejection-Reason");
            if (reason) {
                that.show_login_error_message(reason);
            }
        }
    };

    /**
     * User name field value change handler
     * @protected
     */
    that.on_username_change = function() {

        var password_field = that.fields.get_field('password');
        var user_specified = !IPA.is_empty(that.username_widget.save());
        password_field.set_required(user_specified);
        if (!user_specified) that.password_widget.clear();
    };

    /**
     * Enable fields with given name
     * @protected
     * @param {string[]} field_names
     */
    that.enable_fields = function(field_names) {

        var field, fields, i, enable;
        fields = that.fields.get_fields();
        for (i=0; i<fields.length; i++) {
            field = fields[i];
            enable = field_names.indexOf(field.name) > -1;
            field.set_enabled(enable);
        }
    };

    /**
     * Shows session expired form. Hides other.
     * @protected
     */
    that.show_session_form = function() {

        that.current_view = 'session';
        that.enable_fields(['username', 'password']);
        that.session_form.css('display', 'block');
        that.reset_form.css('display', 'none');
        that.display_buttons(['login']);
        that.username_widget.focus_input();
    };

    /**
     * Shows password reset form. Hides other.
     * @protected
     */
    that.show_reset_form = function() {

        that.current_view = 'reset';
        that.enable_fields(['new_password', 'verify_password']);
        that.session_form.css('display', 'none');
        that.reset_form.css('display', 'block');
        that.display_buttons(['reset', 'cancel']);

        var username = that.username_widget.save();
        that.username_r_widget.update(username);
        that.new_password_widget.focus_input();
    };

    /**
     * Show login error message - based on reason
     * @protected
     * @param {"invalid"|"denied"|string} reason
     */
    that.show_login_error_message = function(reason) {
        var errors = {
            'invalid': that.form_auth_failed,
            'denied': that.denied
        };

        var message = errors[reason];

        if (message) {
            that.login_error_box.html(message);
            that.login_error_box.css('display', 'block');
        }
    };

    /**
     * Cancel handler
     * @protected
     */
    that.on_cancel = function() {

        that.username_widget.clear();
        that.password_widget.clear();
        that.username_r_widget.clear();
        that.new_password_widget.clear();
        that.verify_password_widget.clear();

        that.show_session_form();
    };

    /**
     * Initiates login procedure
     * @protected
     */
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
        } else if (result === 'password-expired') {
            that.reset_error_box.css('display', 'none');
            that.show_reset_form();
        } else {
            that.show_login_error_message(result);
        }
    };

    /**
     * Login success handler
     * @protected
     */
    that.on_login_success = function() {
        that.login_error_box.css('display', 'none');

        that.username_widget.clear();
        that.password_widget.clear();

        that.on_retry();
    };

    /**
     * Initiates password reset procedure
     * @protected
     */
    that.on_reset = function() {
        if (!that.validate()) return;

        var username = that.username_widget.save();
        var password = that.password_widget.save();
        var new_password = that.new_password_widget.save();
        var verify_password = that.verify_password_widget.save();

        that.reset_error_box.css('display', 'none');

        var result = IPA.reset_password(username[0],
                                        password[0],
                                        new_password[0]);

        if (result.status === 'ok') {
            that.on_reset_success();
        } else {
            that.reset_error_box.html(result.message);
            that.reset_error_box.css('display', 'block');
        }
    };

    /**
     * Password reset success handler
     * @protected
     */
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

    /**
     * Key up handler for proper keyboard usage.
     * @protected
     */
    that.on_key_up = function(event) {

        if (that.switching) {
            that.switching = false;
            return;
        }

        if (that.current_view === 'session') {
            if (event.keyCode === $.ui.keyCode.ENTER && !this.test_ignore(event)) {
                that.on_login();
                event.preventDefault();
            }
        } else {
            if (event.keyCode === $.ui.keyCode.ENTER && !this.test_ignore(event)) {
                that.on_reset();
                event.preventDefault();
            } else if (event.keyCode === $.ui.ESCAPE) {
                that.on_cancel();
                event.preventDefault();
            }
        }
    };

    that.create_buttons();

    return that;
};

/**
 * Shorten text to desired number of characters.
 *
 * If shortened, '...' is appended to the shortened text.
 * @member IPA
 * @param {string} value - text to shorten
 * @param {number} max_length - maximum number of characters
 * @return {string} shortened text
 */
IPA.limit_text = function(value, max_length) {

    if (!value) return '';

    var limited_text = value;

    if (value.length && value.length > max_length) {
        limited_text = value.substring(0, max_length - 3)+'...';
    }

    return limited_text;
};


/**
 * Convert strings to options.
 * @member IPA
 * @param {string[]} values - options as strings
 * @return {Array.<{value,label}>} options
 */
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

/**
 * Check if value is not defined.
 *
 * True when:
 *
 * - value is undefined or null or ''
 * - value is empty Array
 * - value is Array with an empty string ('')
 * - value is empty Object- {}
 * @member IPA
 * @param value - value to check
 * @return {boolean}
 */
IPA.is_empty = function(value) {

    var empty = false;

    if (!value) empty = true;

    if (value instanceof Array) {
        empty = empty || value.length === 0 ||
                (value.length === 1) && (value[0] === '');
    } else if (typeof value === 'object') {
        var has_p = false;
        for (var p in value) {
            if (value.hasOwnProperty(p)) {
                has_p = true;
                break;
            }
        }
        empty = !has_p;
    } else  if (value === '') empty = true;

    return empty;
};

/**
 * Check if value is not null or undefined.
 * @member IPA
 * @param value
 * @param {boolean} check_empty_str - additional check for empty string
 */
IPA.defined = function(value, check_empty_str) {
    return value !== null && value !== undefined &&
        ((check_empty_str && value !== '') || !check_empty_str);
};


/**
 * Check if arrays differ.
 *
 * False when:
 *
 * - length and items or arrays equals (===)
 * - undefined state of both is the same
 * @member IPA
 * @param a
 * @param b
 */
IPA.array_diff = function(a, b) {

    if (a === b || (!a && !b)) return false;

    if (!a || !b) return true;

    if (a.length !== b.length) return true;

    for (var i=0; i<a.length; i++) {
        if (a[i] !== b[i]) return true;
    }

    return false;
};

/**
 * Shows confirm dialog with message
 * @member IPA
 * @param {string} msg - message
 * @return {boolean} confirmed state
 */
IPA.confirm = function(msg) {
    return window.confirm(msg);
};

/**
 * Display positive notification message
 * @member IPA
 * @param {string} message
 * @param {number} [timeout=IPA.config.message_timeout] - duration for the
 *                 message to be displayed [ms]
 */
IPA.notify_success = function(message, timeout) {

    if (!message) return; // don't show undefined, null and such

    message = text.get(message);

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

/**
 * Get number of succeeded commands in RPC command
 * @member IPA
 * @param {Object} data - RPC command data
 * @return {number}
 */
IPA.get_succeeded = function(data) {
    var succeeded = data.result.completed;

    if (typeof succeeded !== 'number') {
        succeeded = 0;
        for (var i = 0; i< data.result.results.length; i++) {
            if (data.result.results[i].completed === 1) {
                succeeded++;
            }
        }
    }

    return succeeded;
};

/**
 * Global configuration
 * @member IPA
 * @property {number} default_priority - command default priority. Used in
 *                                        'update info' concept
 * @property {number} message_timeout - timeout for notification messages
 * @property {number} message_fadeout_time
 * @property {number} message_fadein_time
 */
IPA.config = {
    default_priority: 500,
    message_timeout: 3000, // [ms]
    message_fadeout_time: 800, // [ms]
    message_fadein_time: 400 // [ms]
};

return IPA;
});
