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

    that.messages = {};
    that.metadata = {};
    that.whoami = {};

    that.entities = [];
    that.entity_factories = {};

    that.entities_by_name = {};

    that.error_dialog = $('<div/>', {
        id: 'error_dialog'
    });

    that.layout = $.bbq.getState('layout');
    that.layouts_dir = 'layouts';

    that.get_template = function(path) {
        var layout = that.layout || 'default';
        return that.layouts_dir+'/'+layout+'/'+path;
    };

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


        var startup_batch =
            [
                {"method":"json_metadata","params":[[],{}]},
                {"method":"i18n_messages","params":[[],{}]},
                {"method":"user_find","params":[[],{
                    "whoami":"true","all":"true"}]},
                {"method":"env","params":[[],{}]},
                {"method":"dns_is_enabled","params":[[],{}]}
            ];


        IPA.cmd('batch', startup_batch, {},
            function (data, text_status, xhr) {
                that.metadata = data.result.results[0].metadata;
                that.messages = data.result.results[1].messages;
                that.whoami  = data.result.results[2].result[0];
                that.env = data.result.results[3].result;
                that.dns_enabled = data.result.results[4].result;
                if (on_success) {
                    on_success(data, text_status, xhr);
                }
            },
            on_error,
            null,
            'ipa_init');
    };

    that.get_entities = function () {
        return that.entities;
    };

    that.get_entity = function (name) {
        return that.entities_by_name[name];
    };

    function add_entity(entity) {
        that.entities.push(entity);
        that.entities_by_name[entity.name] = entity;
    }

    that.start_entities = function(){
        var factory;
        var name ;
        for (name in that.entity_factories){
            factory = that.entity_factories[name];
            var entity = factory();
            add_entity(entity);
            entity.init();
        }
    };


    that.test_dirty = function(){
        if (IPA.current_entity){
            var facet_name =   IPA.current_facet(IPA.current_entity);
            var facet = IPA.current_entity.facets_by_name[facet_name];
            if (facet.is_dirty()){
                var message_box =  $("<div/>",{
                    html: IPA.messages.dirty
                }).
                    appendTo($("#navigation"));
                message_box.dialog({
                    title: 'Dirty',
                    modal:true,
                    width: '20em',
                    buttons: {
		        Ok: function() {
			    $( this ).dialog( "close" );
		        }
		    }
                });
                return false;
            }
        }
        return true;
    };

    that.show_page = function (entity_name, facet_name) {
        if (!IPA.test_dirty()){
            return false;
        }

        var state = {};
        state[entity_name + '-facet'] = facet_name;
        $.bbq.pushState(state);
        return true;
    };

    that.switch_and_show_page = function (this_entity,  facet_name, pkey) {
        if (!IPA.test_dirty()){
            return false;
        }

        if (!pkey){
            that.show_page(this_entity,  facet_name);
            return false;
        }
        var state = {};
        state[this_entity+'-pkey'] = pkey;
        state[this_entity + '-facet'] = facet_name;
        $.bbq.pushState(state);
        return true;
    };

    return that;
}());

IPA.command = function (spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.method = spec.method;

    that.args = $.merge([], spec.args || []);
    that.options = $.extend({}, spec.options || {});

    that.on_success = spec.on_success;
    that.on_error = spec.on_error;

    that.add_arg = function(arg) {
        that.args.push(arg);
    };

    that.set_option = function(name, value) {
        that.options[name] = value;
    };

    that.get_option = function(name) {
        return that.options[name];
    };

    that.execute = function() {
        IPA.cmd(
            that.method,
            that.args,
            that.options,
            that.on_success,
            that.on_error,
            null,
            that.name);
    };

    that.to_json = function() {
        var json = {};

        json.method = that.method;

        json.params = [];
        json.params[0] = that.args || [];
        json.params[1] = that.options || {};

        return json;
    };

    that.to_string = function() {
        var string = that.method.replace(/_/g, '-');

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
        IPA.cmd(
            that.method,
            that.args,
            that.options,
            function(data, text_status, xhr) {

                for (var i=0; i<that.commands.length; i++) {
                    var command = that.commands[i];
                    var result = data.result.results[i];

                    if (!result) {
                        if (command.on_error) command.on_error(
                            xhr, text_status,
                            {
                                title: 'Internal Error '+xhr.status,
                                message: result ? xhr.statusText : "Internal error"
                            }
                        );

                    } else if (result.error) {
                        if (command.on_error) command.on_error(
                            xhr,
                            text_status,
                            {
                                title: 'IPA Error '+result.error.code,
                                message: result.error.message
                            }
                        );

                    } else {
                        if (command.on_success) command.on_success(result, text_status, xhr);
                    }
                }
                if (that.on_success) that.on_success(data, text_status, xhr);
            },
            function(xhr, text_status, error_thrown) {
                // TODO: undefined behavior
                if (that.on_error) {
                    that.on_error(xhr, text_status, error_thrown);
                }
            },
            null,
            that.name);
    };

    return that;
};

/* call an IPA command over JSON-RPC
 * arguments:
 *   name - name of the command or method if objname is set
 *   args - list of positional arguments, e.g. [username]
 *   options - dict of options, e.g. {givenname: 'Pavel'}
 *   win_callback - function to call if the JSON request succeeds
 *   fail_callback - function to call if the JSON request fails
 *   objname - name of an IPA object (optional) */
IPA.cmd = function (name, args, options, win_callback, fail_callback, objname, command_name) {
    var default_json_url = '/ipa/json';

    var network_call_count = 0;
    function display_activity_icon(){
        network_call_count += 1;
        $('.network-activity-indicator').css('display','inline');
    }

    function hide_activity_icon(){
        network_call_count -= 1;

        if (0 === network_call_count){
            $('.network-activity-indicator').css('display','none');
        }
    }

    function dialog_open(xhr, text_status, error_thrown) {
        var that = this;

        IPA.error_dialog.dialog({
            modal: true,
            width: 400,
            buttons: {
                'Retry': function () {
                    IPA.error_dialog.dialog('close');
                    IPA.cmd(name, args, options, win_callback, fail_callback,
                            objname, command_name);
                },
                'Cancel': function () {
                    IPA.error_dialog.dialog('close');
                    if (fail_callback) {
                        fail_callback.call(that, xhr, text_status,
                                           error_thrown);
                    }
                }
            }
        });
    }

    function ajax_error_handler(xhr, text_status, error_thrown) {
        IPA.error_dialog.empty();
        IPA.error_dialog.attr('title', error_thrown.title);

        IPA.error_dialog.append('<p>'+error_thrown.message+'</p>');

        dialog_open.call(this, xhr, text_status, error_thrown);
    }

    function error_handler(xhr, text_status, error_thrown) {
        hide_activity_icon();
        if (!error_thrown) {
            error_thrown = {
                name: xhr.responseText || 'Unknown Error',
                message: xhr.statusText || 'Unknown Error'
            };
        }

        if (xhr.status === 401) {
            error_thrown.name = 'Kerberos ticket no longer valid.';
            if (IPA.messages && IPA.messages.ajax){
                error_thrown.message = IPA.messages.ajax["401"];
            } else {
                error_thrown.message =
                    "Your kerberos ticket no longer valid. "+
                    "Please run kinit and then click 'retry'. "+
                    "If this is your first time running the IPA Web UI "+
                    "<a href='/ipa/config/unauthorized.html'>"+
                    "follow these directions</a> to configure your browser.";
            }
        }

        error_thrown.title = 'AJAX Error: '+error_thrown.name;
        ajax_error_handler.call(this, xhr, text_status, error_thrown);
    }


    function http_error_handler(xhr, text_status, error_thrown) {
        IPA.error_dialog.empty();
        IPA.error_dialog.attr('title', error_thrown.title);

        IPA.error_dialog.append('<p>URL: '+this.url+'</p>');
        IPA.error_dialog.append('<p>'+error_thrown.message+'</p>');

        dialog_open.call(this, xhr, text_status, error_thrown);
    }

    //Think this should be removed
    function alt_error_handler(xhr, text_status, error_thrown) {
        hide_activity_icon();
        IPA.error_dialog.empty();
        IPA.error_dialog.attr('title', error_thrown.title);

        IPA.error_dialog.append('<p>'+error_thrown.message+'</p>');

        dialog_open.call(this, xhr, text_status, error_thrown);
    }


    function success_handler(data, text_status, xhr) {
        hide_activity_icon();
        if (!data) {
            var error_thrown = {
                title: 'HTTP Error '+xhr.status,
                message: data ? xhr.statusText : "No response"
            };
            http_error_handler.call(this, xhr, text_status, error_thrown);

        } else if (data.error) {
            error_handler.call(this, xhr, text_status,  /* error_thrown */ {
                title: 'IPA Error '+data.error.code,
                message: data.error.message
            });

        } else if (win_callback) {
            win_callback.call(this, data, text_status, xhr);
        }
    }

    IPA.jsonrpc_id += 1;
    var id = IPA.jsonrpc_id;

    var method_name = name;

    if (objname){
        method_name = objname + '_' + name;
    }

    var url = IPA.json_url;

    if (IPA.use_static_files){
        if (command_name) {
            url += '/' + command_name + '.json';
        } else {
            url += '/' + method_name + '.json';
        }
    }
    var data = {
        method: method_name,
        params: [args, options],
        id: id
    };

    var request = {
        url: url,
        data: JSON.stringify(data),
        success: success_handler,
        error: error_handler
    };
    display_activity_icon();
    $.ajax(request);

    return (id);
};


/* helper function used to retrieve information about an attribute */
IPA.get_param_info = function(obj_name, attr) {
    var obj = IPA.metadata[obj_name];
    if (!obj) {
        return null;
    }

    var takes_params = obj.takes_params;
    if (!takes_params) {
        return (null);

    }
    for (var i = 0; i < takes_params.length; i += 1) {
        if (takes_params[i].name === attr){
            return (takes_params[i]);
        }
    }

    return (null);
};

/* helper function used to retrieve attr name with members of type `member` */
IPA.get_member_attribute = function (obj_name, member) {
    var obj = IPA.metadata[obj_name];
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
