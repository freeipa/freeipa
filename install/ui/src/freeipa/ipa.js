/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *    Endi Dewata <edewata@redhat.com>
 *    John Dennis <jdennis@redhat.com>
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2010-2016 Red Hat
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
        'dojo/_base/declare',
        'dojo/Deferred',
        'dojo/Evented',
        'dojo/keys',
        'dojo/topic',
        './jquery',
        './json2',
        './_base/i18n',
        './auth',
        './config',
        './datetime',
        './metadata',
        './builder',
        './reg',
        './rpc',
        './text',
        './util',
        'exports'
    ], function(declare, Deferred, Evented, keys, topic, $, JSON, i18n, auth,
        config, datetime, metadata_provider, builder, reg, rpc, text,
        util, exports) {

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
    that.url = config.url;

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
     * User information
     *
     * - output of ipa whoami in that.whoami.metadata and then object_show method
     * in that.whoami.data
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
            that.json_url = params.url || config.json_url;

        } else { // otherwise use fixtures
            that.json_path = params.url || "test/data";
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
            entity: 'config',
            method: 'show',
            on_success: function(data, text_status, xhr) {
                that.server_config = data.result;
            }
        }));

        batch.add_command(that.get_whoami_command());

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

        batch.add_command(rpc.command({
            entity: 'domainlevel',
            method: 'get',
            retry: false,
            on_success: function(data, text_status, xhr) {
                that.domain_level = data.result;
            },
            on_error: function(xhr, text_status, error_thrown) {
                that.domain_level = 0;
            }
        }));

        batch.add_command(rpc.command({
            entity: 'ca',
            method: 'is_enabled',
            on_success: function(data, text_status, xhr) {
                that.ca_enabled = data.result;
            }
        }));

        batch.add_command(rpc.command({
            entity: 'vaultconfig',
            method: 'show',
            retry: false,
            on_success: function(data, text_status, xhr) {
                that.vault_enabled = true;
            },
            on_error: function(xhr, text_status, error_thrown) {
                that.vault_enabled = false;
            }
        }));

        batch.execute();
    };

    /**
     * Prepares `user-find --whoami` command
     * @protected
     */
    that.get_whoami_command = function() {
        return rpc.command({
            method: 'whoami',
            on_success: function(data, text_status, xhr) {
                that.whoami.metadata = data.result || data;
                var wa_data = that.whoami.metadata;
                // This AJAX request has no synchronization point,
                // so we set async = false to make sure that init_metadata
                // doesn't start before we get whoami response.
                $.ajaxSetup({async: false});
                rpc.command({
                    method: wa_data.details || wa_data.command,
                    args: wa_data.arguments,
                    options: function() {
                        var options = wa_data.options || [];
                        $.extend(options, {all: true});
                        return options;
                    }(),
                    on_success: function(data, text_status, xhr) {
                        that.whoami.data = data.result.result;
                        var entity = that.whoami.metadata.object;

                        if (entity === 'user') {
                            var cn = that.whoami.data.krbcanonicalname;
                            if (cn) that.principal = cn[0];
                            if (!that.principal) {
                                that.principal = that.whoami.data.krbprincipalname[0];
                            }
                        } else if (entity === 'idoverrideuser') {
                            that.principal = that.whoami.data.ipaoriginaluid[0];
                        }
                    }
                }).execute();
                // Restore AJAX options
                $.ajaxSetup(that.ajax_options);
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
        var loading = text.get('@i18n:login.loading_md');

        topic.publish('set-activity', loading);

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

    that.obj_cls = declare([Evented]);

    return that;
}();

/**
 * Framework objects created by factories should use this
 * instead of empty object when creating base objects.
 *
 * @class
 */
IPA.object = function(s) {
    return new IPA.obj_cls();
};

/**
 * Make request on Kerberos authentication url to initialize Kerberos negotiation.
 *
 * Set result to auth module.
 *
 * @member IPA
 */
IPA.get_credentials = function() {
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

    var request = {
        url: config.krb_login_url,
        cache: false,
        type: "GET",
        success: success_handler,
        error: error_handler
    };

    topic.publish('rpc-start');

    $.ajax(request);

    return d.promise;
};

/**
 * Logout
 *
 * - terminate the session.
 * - reloads UI
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

    function reload () {
        window.sessionStorage.setItem('logout', true);
        var l = window.location;
        l.assign(l.href.split('#')[0]);
    }

    function success_handler(data, text_status, xhr) {
        topic.publish('rpc-end');

        if (data && data.error) {
            show_error(data.error.message);
        } else {
            reload();
        }
    }

    function error_handler(xhr, text_status, error_thrown) {
        topic.publish('rpc-end');

        if (xhr.status === 401) {
            reload();
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
    topic.publish('rpc-start');

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
    var d = new Deferred();

    function success_handler(data, text_status, xhr) {
        topic.publish('rpc-end');

        result = 'success';
        auth.current.set_authenticated(true, 'password');
        d.resolve(result);
    }

    function error_handler(xhr, text_status, error_thrown) {

        topic.publish('rpc-end');

        if (xhr.status === 401) {
            var reason = xhr.getResponseHeader("X-IPA-Rejection-Reason");

            //change result from invalid only if we have a header which we
            //understand
            if (reason === 'password-expired' ||
                reason === 'denied' ||
                reason === 'krbprincipal-expired' ||
                reason === 'invalid-password' ||
                reason === 'user-locked') {
                result = reason;
            }
        }
        d.resolve(result);
    }

    var data = {
        user: username,
        password: password
    };

    var request = {
        url: config.forms_login_url,
        data: data,
        contentType: 'application/x-www-form-urlencoded',
        processData: true,
        dataType: 'html',
        type: 'POST',
        success: success_handler,
        error: error_handler
    };

    topic.publish('rpc-start');

    $.ajax(request);

    return d.promise;
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
IPA.reset_password = function(username, old_password, new_password, otp) {

    //possible results: 'ok', 'invalid-password', 'policy-error'

    var status, result, reason, invalid, failure, data, request;

    status = 'invalid';
    result = {
        status: status,
        message: text.get('@i18n:password.reset_failure',
                "Password reset was not successful.")
    };

    function success_handler(data, text_status, xhr) {

        topic.publish('rpc-end');

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
        topic.publish('rpc-end');
        return result;
    }

    data = {
        user: username,
        old_password: old_password,
        new_password: new_password
    };

    if (otp) {
        data.otp = otp;
    }

    request = {
        url: config.reset_psw_url,
        data: data,
        contentType: 'application/x-www-form-urlencoded',
        processData: true,
        dataType: 'html',
        async: false,
        type: 'POST',
        success: success_handler,
        error: error_handler
    };

    topic.publish('rpc-start');
    $.ajax(request);

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

    var now, expires, notify_days, diff, message, container, notify;

    expires = rpc.extract_objects(IPA.whoami.data.krbpasswordexpiration);
    expires = expires ? datetime.parse(expires[0]) : null;

    notify_days = IPA.server_config.ipapwdexpadvnotify;
    notify_days = notify_days ? notify_days[0] : 0;
    notify = false;
    now = new Date();

    container = $('.header-passwordexpires');
    container.empty();

    if (expires) {

        diff = expires.getTime() - now.getTime();
        diff = Math.floor(diff / 86400000);

        if (diff <= notify_days) {
            notify = true;
            message = text.get('@i18n:password.expires_in');
            message = message.replace('${days}', diff);
            container.append(message);
        }
    }
    container.toggle(notify);
};

/**
 * Show password dialog for self-service change of password.
 *
 * @member IPA
 */
IPA.password_selfservice = function() {
    var reset_dialog = builder.build('dialog', {
        $type: 'user_password',
        args: [IPA.whoami.data.uid[0]]
    });
    reset_dialog.succeeded.attach(function() {
        var command = IPA.get_whoami_command();
        var orig_on_success = command.on_success;
        command.on_success = function(data, text_status, xhr) {
            orig_on_success.call(this, data.result, text_status, xhr);
            IPA.update_password_expiration();
        };
        command.execute();
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
        name: 'save',
        label: '@i18n:buttons.save',
        click: function() {
            that.facet.update(function() {
                that.close();
                that.callback();
            });
        }
    });

    that.create_button({
        name: 'revert',
        label: '@i18n:buttons.revert',
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
    that.xhr = spec.xhr || null;
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

    /** @inheritDoc */
    that.create_content = function() {
        if (that.error_thrown.url) {
            $('<p/>', {
                text: text.get('@i18n:errors.url', 'URL')+': '+that.error_thrown.url
            }).appendTo(that.container);
        }

        var error_message = $('<div />', {});
        error_message.append(util.beautify_message(that.error_thrown.message));
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
                    error_div.append(util.beautify_message(error.message));
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

    if (typeof message === 'string') {
        message = text.get(message);
        message = document.createTextNode(message);
    }

    var notification_area = $('#notification .notification-area');
    if (notification_area.length === 0) {
        notification_area =  $('<div/>', {
            'class': 'notification-area'
        });
        notification_area.appendTo('#notification');
    }
    var alert = IPA.alert_helper.create_alert('msg', message, type);
    var el = IPA.alert_helper.render_alert(alert, true);
    notification_area.append(el);
    el.alert();

    if (!timeout) {
        // compute timeout, based on text length

        // get text length without whitespace chars (misleading with
        // multiple inner HTML elements)
        var l = el.text().replace(/\s+/g, ' ').length;
        var ratio = IPA.config.message_timeout_length;
        if (l < ratio) timeout = IPA.config.message_timeout;
        else {
            timeout = l/ratio*IPA.config.message_timeout;
        }
    }

    window.setTimeout(function() {
        el.alert('close');
    }, timeout);
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
 * @property {number} message_timeout_length - longer messages will be displayed
 *                                             longer
 */
IPA.config = {
    default_priority: 500,
    message_timeout: 5000, // [ms]
    message_timeout_length: 50 // [chars]
};

return IPA;
});
