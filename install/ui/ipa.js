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

        var batch = IPA.batch_command({
            name: 'ipa_init',
            on_success: on_success,
            on_error: on_error
        });

        batch.add_command(IPA.command({
            method: 'json_metadata',
            on_success: function(data, text_status, xhr) {
                that.metadata = data;
            }
        }));

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

    that.get_command = function() {
        return (that.entity ? that.entity+'_' : '') + that.method;
    };

    that.add_arg = function(arg) {
        that.args.push(arg);
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

            IPA.error_dialog = $('<div/>', {
                id: 'error_dialog'
            });

            if (error_thrown.url) {
                $('<p/>', {
                    text: 'URL: '+error_thrown.url
                }).appendTo(IPA.error_dialog);
            }

            $('<p/>', {
                html: error_thrown.message
            }).appendTo(IPA.error_dialog);

            function close() {
                IPA.error_dialog.dialog('destroy');
                IPA.error_dialog.remove();
                IPA.error_dialog = null;
            }

            var buttons = {};

            /**
             * When a user initially opens the Web UI without a Kerberos
             * ticket, the messages including the button labels have not
             * been loaded yet, so the button labels need default values.
             */
            var label = IPA.messages.buttons ? IPA.messages.buttons.retry : 'Retry';
            buttons[label] = function() {
                close();
                that.execute();
            };

            label = IPA.messages.buttons ? IPA.messages.buttons.cancel : 'Cancel';
            buttons[label] = function() {
                close();
                if (that.on_error) {
                    that.on_error.call(this, xhr, text_status, error_thrown);
                }
            };

            IPA.error_dialog.dialog({
                modal: true,
                title: error_thrown.name,
                width: 400,
                buttons: buttons,
                close: function() {
                    close();
                }
            });
        }

        function error_handler(xhr, text_status, error_thrown) {

            IPA.hide_activity_icon();

            if (xhr.status === 401) {
                error_thrown = {}; // error_thrown is string
                error_thrown.name = 'Kerberos ticket no longer valid.';
                if (IPA.messages && IPA.messages.ajax) {
                    error_thrown.message = IPA.messages.ajax["401"];
                } else {
                    error_thrown.message =
                        "Your kerberos ticket is no longer valid. "+
                        "Please run kinit and then click 'Retry'. "+
                        "If this is your first time running the IPA Web UI "+
                        "<a href='/ipa/config/unauthorized.html'>"+
                        "follow these directions</a> to configure your browser.";
                }

            } else if (!error_thrown) {
                error_thrown = {
                    name: xhr.responseText || 'Unknown Error',
                    message: xhr.statusText || 'Unknown Error'
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
                that.on_error.call(this, xhr, text_status, error_thrown);
            }
        }

        function success_handler(data, text_status, xhr) {

            if (!data) {
                // error_handler() calls IPA.hide_activity_icon()
                error_handler.call(this, xhr, text_status, /* error_thrown */ {
                    name: 'HTTP Error '+xhr.status,
                    url: this.url,
                    message: data ? xhr.statusText : 'No response'
                });

            } else if (data.error) {
                // error_handler() calls IPA.hide_activity_icon()
                error_handler.call(this, xhr, text_status,  /* error_thrown */ {
                    name: 'IPA Error '+data.error.code,
                    message: data.error.message
                });

            } else if (that.on_success) {
                IPA.hide_activity_icon();
                that.on_success.call(this, data, text_status, xhr);
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

        IPA.command({
            name: that.name,
            entity: that.entity,
            method: that.method,
            args: that.args,
            options: that.options,
            on_success: function(data, text_status, xhr) {

                for (var i=0; i<that.commands.length; i++) {
                    var command = that.commands[i];
                    var result = data.result.results[i];

                    if (!result) {
                        if (command.on_error) command.on_error(
                            xhr, text_status,
                            {
                                name: 'Internal Error '+xhr.status,
                                message: result ? xhr.statusText : "Internal error"
                            }
                        );

                    } else if (result.error) {
                        if (command.on_error) command.on_error(
                            xhr,
                            text_status,
                            {
                                name: 'IPA Error '+result.error.code,
                                message: result.error.message
                            }
                        );

                    } else {
                        if (command.on_success) command.on_success(result, text_status, xhr);
                    }
                }
                if (that.on_success) that.on_success(data, text_status, xhr);
            },
            on_error: function(xhr, text_status, error_thrown) {
                // TODO: undefined behavior
                if (that.on_error) {
                    that.on_error(xhr, text_status, error_thrown);
                }
            }
        }).execute();
    };

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

    that.add_button(IPA.messages.buttons.update, function() {
        that.facet.update(function() {
            that.close();
            that.callback();
        });
    });

    that.add_button(IPA.messages.buttons.reset, function() {
        that.facet.reset();
        that.close();
        that.callback();
    });

    that.add_button(IPA.messages.buttons.cancel, function() {
        that.close();
    });

    that.callback = function() {
    };

    return that;
};
