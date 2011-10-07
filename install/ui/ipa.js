/*jsl:import jquery.ordered-map.js */
/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *    Endi Dewata <edewata@redhat.com>
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

var IPA = ( function () {

    var that = {
        jsonrpc_id: 0
    };

    that.use_static_files = false;
    that.json_url = '/ipa/json';
    if (that.use_static_files){
        that.json_url = 'test/data';
    }

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

    that.network_call_count = 0;

    /* initialize the IPA JSON-RPC helper
     * arguments:
     *   url - JSON-RPC URL to use (optional) */
    that.init = function (url, use_static_files, on_success, on_error) {
        if (url) {
            that.json_url = url;
        }

        if (use_static_files) {
            that.use_static_files = use_static_files;
        }

        $.ajaxSetup(that.ajax_options);

        var methods = IPA.command({
            name: 'ipa_init_methods',
            method: 'json_metadata',
            options: {
                methodname: 'all'
            },
            on_success: function(data, text_status, xhr) {
                if(!that.metadata) that.metadata = {};
                that.metadata.methods = data.result.methods;
            }
        });

        var objects = IPA.command({
            name: 'ipa_init_objects',
            method: 'json_metadata',
            options: {
                objname: 'all'
            },
            on_success: function(data, text_status, xhr) {
                if(!that.metadata) that.metadata = {};
                that.metadata.objects = data.result.objects;
            }
        });

        var metadata_command = IPA.concurrent_command({
            commands: [
                methods,
                objects
            ],
            on_success: on_success
        });

        var batch = IPA.batch_command({
            name: 'ipa_init',
            retry: false,
            on_success: function() {
                metadata_command.execute();
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
                        if (on_error) {
                            on_error.call(ajax, xhr, text_status, error_thrown);
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
            }
        }));

        batch.add_command(IPA.command({
            method: 'env',
            on_success: function(data, text_status, xhr) {
                that.env = data.result;
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
            entity: 'hbacrule',
            method: 'find',
            options:{"accessruletype":"deny"},
            on_success: function(data, text_status, xhr) {
                that.hbac_deny_rules = data;
            }
        }));

        batch.execute();
    };

    that.get_entities = function() {
        return that.entities.values;
    };



    that.get_entity = function(name) {
        var entity = that.entities.get(name);
        if (!entity){
            var factory = that.entity_factories[name];
            if (!factory){
                return null;
            }
            try {
                entity = factory();
                that.add_entity(entity);
            } catch (e) {
                if (e.expected){
                    /*expected exceptions thrown by builder just mean that
                      entities are not to be registered. */
                    return null;
                }
                if (e.message){
                    alert(e.message);
                }else{
                    alert(e);
                }
                return null;
            }
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
}());

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

        function error_handler(xhr, text_status, error_thrown) {

            IPA.hide_activity_icon();

            if (xhr.status === 401) {
                error_thrown = {}; // error_thrown is string
                error_thrown.name = IPA.get_message('ajax.401.title',
                    'Kerberos ticket no longer valid.');
                error_thrown.message = IPA.get_message('ajax.401.message',
                    "Your kerberos ticket is no longer valid. "+
                    "Please run kinit and then click 'Retry'. "+
                    "If this is your first time running the IPA Web UI "+
                    "<a href='/ipa/config/unauthorized.html'>"+
                    "follow these directions</a> to configure your browser.");

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

        var url = IPA.json_url;

        var command = that.get_command();

        if (IPA.use_static_files) {
            url += '/' + (that.name ? that.name : command) + '.json';
        }

        var data = {
            method: command,
            params: [that.args, that.options]
        };

        var request = {
            url: url,
            data: JSON.stringify(data),
            success: success_handler,
            error: error_handler
        };

        IPA.display_activity_icon();
        $.ajax(request);
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

        IPA.command({
            name: that.name,
            entity: that.entity,
            method: that.method,
            args: that.args,
            options: that.options,
            retry: that.retry,
            on_success: function(data, text_status, xhr) {

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
                if(that.show_error && that.errors.errors.length > 0) {
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
                        visible_buttons: ['ok']
                    });

                    dialog.on_ok = function() {
                        dialog.close();
                        if (that.on_success) that.on_success.call(ajax, data, text_status, xhr);
                    };

                    dialog.open();

                } else {
                    if (that.on_success) that.on_success.call(this, data, text_status, xhr);
                }
            },
            on_error: function(xhr, text_status, error_thrown) {
                // TODO: undefined behavior
                if (that.on_error) {
                    that.on_error.call(this, xhr, text_status, error_thrown);
                }
            }
        }).execute();
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
            all_completed &= command_info.completed;
            all_success &= command_info.success;
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

IPA.get_method_arg = function(method_name, name) {

    var metadata = IPA.metadata.methods[method_name];
    if (!metadata) {
        return null;
    }

    var args = metadata.takes_args;
    if (!args) {
        return null;
    }

    for (var i=0; i<args.length; i++) {
        if (args[i].name === name) {
            return args[i];
        }
    }

    return null;
};

IPA.get_method_option = function(method_name, name) {

    var metadata = IPA.metadata.methods[method_name];
    if (!metadata) {
        return null;
    }

    var options = metadata.takes_options;
    if (!options) {
        return null;
    }

    for (var i=0; i<options.length; i++) {
        if (options[i].name === name) {
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
    return $('<span />',{
        'class':'network-activity-indicator',
        html: '<img src="spinner_small.gif" />'});
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
        var label;

        if(that.visible_buttons.indexOf('retry') > -1) {
            label = IPA.get_message('buttons.retry', 'Retry');
            that.create_button({
                name: 'retry',
                label: label,
                click: function() {
                    that.on_retry();
                }
            });
        }

        if(that.visible_buttons.indexOf('ok') > -1) {
            label = IPA.get_message('buttons.ok', 'OK');
            that.create_button({
                name: 'ok',
                label: label,
                click: function() {
                    that.on_ok();
                }
            });
        }

        if(that.visible_buttons.indexOf('cancel') > -1) {
            label = IPA.get_message('buttons.cancel', 'Cancel');
            that.create_button({
                name: 'cancel',
                label: label,
                click: function() {
                    that.on_cancel();
                }
            });
        }
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
