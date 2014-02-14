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

define([
        'dojo/keys',
        'dojo/topic',
        './jquery',
        './json2',
        './_base/i18n',
        './datetime',
        './metadata',
        './builder',
        './reg',
        './rpc',
        './text',
        'exports'
    ], function(keys, topic, $, JSON, i18n, datetime, metadata_provider,
        builder, reg, rpc, text, exports) {

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
var IPA = function () {

    var that = exports;

    that.jsonrpc_id = 0;

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

        var batch = rpc.batch_command({
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

        batch.add_command(rpc.command({
            method: 'i18n_messages',
            on_success: function(data, text_status, xhr) {
                that.messages = data.texts;
                i18n.source = that.messages;
            }
        }));

        batch.add_command(rpc.command({
            entity: 'config',
            method: 'show',
            on_success: function(data, text_status, xhr) {
                that.server_config = data.result;
            }
        }));

        batch.add_command(that.get_whoami_command(true));

        batch.add_command(rpc.command({
            method: 'env',
            on_success: function(data, text_status, xhr) {
                that.env = data.result;
                that.version = that.env.version;
            }
        }));

        batch.add_command(rpc.command({
            entity: 'dns',
            method: 'is_enabled',
            on_success: function(data, text_status, xhr) {
                that.dns_enabled = data.result;
            }
        }));

        batch.add_command(rpc.command({
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
        return rpc.command({
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

        var objects = rpc.command({
            name: 'ipa_init_objects',
            method: 'json_metadata',
            options: {
                object: 'all'
            },
            on_success: function(data, text_status, xhr) {
                metadata_provider.source.objects = data.result.objects;
            }
        });

        var commands = rpc.command({
            name: 'ipa_init_commands',
            method: 'json_metadata',
            options: {
                command: 'all'
            },
            on_success: function(data, text_status, xhr) {
                metadata_provider.source.commands = data.result.commands;
            }
        });

        var metadata_command = rpc.concurrent_command({
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
        if (that.network_call_count === 1) {
            topic.publish('network-activity-start');
        }
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
            topic.publish('network-activity-end');
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
    expires = expires ? datetime.parse(expires[0]) : null;

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
    /** @property {rpc.command} command Command */
    that.command = spec.command;
    /** @property {rpc.error_list} errors Errors */
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
                hide_details.focus();
                return false;
            });

            hide_details.click(function() {
                errors_container.hide();
                hide_details.hide();
                show_details.show();
                show_details.focus();
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
            show_header: false,
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
            show_header: false,
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
        that.enable_fields(['username_r', 'new_password', 'verify_password']);
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
            if (event.keyCode === keys.ENTER && !this.test_ignore(event)) {
                that.on_login();
                event.preventDefault();
            }
        } else {
            if (event.keyCode === keys.ENTER && !this.test_ignore(event)) {
                that.on_reset();
                event.preventDefault();
            } else if (event.keyCode === keys.ESCAPE) {
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
    IPA.notify(message, 'success', timeout);
};

/**
 * Display positive message
 * @member IPA
 * @param {string} message
 * @param {string} type
 *                      message type ('success', 'warning', 'info', 'error')
 *                      Default: 'warning'
 * @param {number} [timeout=IPA.config.message_timeout] - duration for the
 *                 message to be displayed [ms]
 */
IPA.notify = function(message, type, timeout) {

    if (!message) return; // don't show undefined, null and such

    message = text.get(message);

    function destroy_timeout() {
        if (IPA.notify_success.timeout) window.clearTimeout(IPA.notify_success.timeout);
    }

    var notification_area = $('.notification-area');
    var message_el = $('.notification-area div');

    if (notification_area.length === 0) {
        notification_area =  $('<div/>', {
            'class': 'notification-area',
            click: function() {
                destroy_timeout();
                notification_area.fadeOut(100);
            }
        });
        message_el = $('<div/>', {
            'class': 'alert'
        }).appendTo(notification_area);

        notification_area.appendTo('#container');
    }

    if (IPA.notify_success.current_cls) {
        message_el.removeClass(IPA.notify_success.current_cls);
        IPA.notify_success.current_cls = null;
    }

    if (type && type !== 'warning') {
        var type_cls = 'alert-'+type;
        message_el.addClass(type_cls);
        IPA.notify_success.current_cls = type_cls;
    }

    message_el.text(message);

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
