/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 only
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/


/*global $:true, location:true */

/*Forward defined due to circular dependency with IPA.*/
var ipa_cmd;
var IPA = ( function () {

    var that = {
        jsonrpc_id: 0
    };

    that.json_url = null;
    that.use_static_files = false;

    that.ajax_options = {
        type: 'POST',
        contentType: 'application/json',
        dataType: 'json',
        async: true,
        processData: false
    };

    that.messages = {};
    that.metadata = {};

    that.entities = [];
    that.entities_by_name = {};

    that.error_dialog = $('<div/>', {
        id: 'error_dialog'
    });

    that.layout = $.bbq.getState('layout');
    that.layouts_dir = 'layouts';

    that.get_template = function(path) {
        if (!that.layout) return path;
        return that.layouts_dir+'/'+that.layout+'/'+path;
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

        ipa_cmd('json_metadata', [], {},
            function (data, text_status, xhr) {
                that.metadata = data.result.metadata;
                that.messages = data.result.messages;
                if (on_success) {
                    on_success(data, text_status, xhr);
                }
            },
            on_error
        );
    };

    that.get_entities = function () {
        return that.entities;
    };

    that.get_entity = function (name) {
        return that.entities_by_name[name];
    };

    that.add_entity = function (entity) {
        that.entities.push(entity);
        that.entities_by_name[entity.name] = entity;
    };

    that.show_page = function (entity_name, facet_name, other_entity) {

        var state = {};
        state[entity_name + '-facet'] = facet_name;
        state[entity_name + '-enroll'] = other_entity ? other_entity : '';
        $.bbq.pushState(state);
    };

    return that;
}());

function ipa_command(spec) {

    spec = spec || {};

    var that = {};
    that.method = spec.method;

    that.params = spec.params || [];
    that.params[0] = spec.args || [];
    that.params[1] = spec.options || {};

    that.add_arg = function(arg) {
        that.params[0].push(arg);
    };

    that.get_args = function() {
        return that.params[0];
    };

    that.set_option = function(name, value) {
        that.params[1][name] = value;
    };

    that.get_option = function(name) {
        return that.params[1][name];
    };

    that.get_options = function() {
        return that.params[1];
    };

    that.execute = function(on_success, on_error) {
        ipa_cmd(
            that.method,
            that.get_args(),
            that.get_options(),
            on_success,
            on_error
        );
    };

    that.to_string = function() {
        var string = that.method.replace(/_/g, '-');

        var args = that.get_args();
        for (var i=0; i<args.length; i++) {
            string += ' '+args[i];
        }

        var options = that.get_options();
        for (var name in options) {
            string += ' --'+name+'=\''+options[name]+'\'';
        }

        return string;
    };

    return that;
}

function ipa_batch_command(spec) {

    spec = spec || {};

    spec.method = 'batch';

    var that = ipa_command(spec);

    that.add_command = function(command) {
        that.add_arg(command);
    };

    return that;
}

/* call an IPA command over JSON-RPC
 * arguments:
 *   name - name of the command or method if objname is set
 *   args - list of positional arguments, e.g. [username]
 *   options - dict of options, e.g. {givenname: 'Pavel'}
 *   win_callback - function to call if the JSON request succeeds
 *   fail_callback - function to call if the JSON request fails
 *   objname - name of an IPA object (optional) */
function ipa_cmd(name, args, options, win_callback, fail_callback, objname)
{
    var default_json_url = '/ipa/json';

    function dialog_open(xhr, text_status, error_thrown) {
        var that = this;

        IPA.error_dialog.dialog({
            modal: true,
            width: 400,
            buttons: {
                'Retry': function () {
                    IPA.error_dialog.dialog('close');
                    ipa_cmd(name, args, options, win_callback, fail_callback, objname);
                },
                'Cancel': function () {
                    IPA.error_dialog.dialog('close');
                    fail_callback.call(that, xhr, text_status, error_thrown);
                }
            }
        });
    }

    function ajax_error_handler(xhr, text_status, error_thrown) {
        IPA.error_dialog.empty();
        IPA.error_dialog.attr('title', error_thrown.title);

        IPA.error_dialog.append('<p>URL: '+this.url+'</p>');
        IPA.error_dialog.append('<p>'+error_thrown.message+'</p>');

        dialog_open.call(this, xhr, text_status, error_thrown);
    }

    function error_handler(xhr, text_status, error_thrown) {
        if (!error_thrown){
            error_thrown = {name:'unknown'}
        }

        if (xhr.status === 401){
            error_thrown.name  = 'Kerberos ticket no longer valid.';
            if (IPA.messages && IPA.messages.ajax){
                error_thrown.message =  IPA.messages.ajax["401"];
            }else{
                error_thrown.message =
                    "Your kerberos ticket no longer valid."+
                    "Please run KInit and then click 'retry'"+
                    "If this is your first time running the IPA Web UI"+
                    "<a href='/ipa/errors/ssbrowser.html'> "+
                    "Follow these directions</a> to configure your browser."
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

    function ipa_error_handler(xhr, text_status, error_thrown) {
        IPA.error_dialog.empty();
        IPA.error_dialog.attr('title', error_thrown.title);

        IPA.error_dialog.append('<p>'+error_thrown.message+'</p>');

        dialog_open.call(this, xhr, text_status, error_thrown);
    }


    function success_handler(data, text_status, xhr) {
        if (!data) {
            var error_thrown = {
                title: 'HTTP Error '+xhr.status,
                message: data ? xhr.statusText : "No response"
            };
            http_error_handler.call(this, xhr, text_status, error_thrown);

        } else if (data.error) {
            ipa_error_handler.call(this, xhr, text_status,  /* error_thrown */ {
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

    if (!url){
        url = default_json_url;
    }

    if (IPA.use_static_files){
        url += '/' + method_name + '.json';
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

    $.ajax(request);

    return (id);
}


/* helper function used to retrieve information about an attribute */
function ipa_get_param_info(obj_name, attr)
{
    var ipa_obj = IPA.metadata[obj_name];
    if (!ipa_obj) {
        return null;
    }

    var takes_params = ipa_obj.takes_params;
    if (!takes_params) {
        return (null);

    }
    for (var i = 0; i < takes_params.length; i += 1) {
        if (takes_params[i].name === attr){
            return (takes_params[i]);
        }
    }

    return (null);
}

/* helper function used to retrieve attr name with members of type `member` */
function ipa_get_member_attribute(obj_name, member)
{
    var ipa_obj = IPA.metadata[obj_name];
    if (!ipa_obj) {
        return null;
    }
    var attribute_members = ipa_obj.attribute_members;
    for (var a in attribute_members) {
        var objs = attribute_members[a];
        for (var i = 0; i < objs.length; i += 1) {
            if (objs[i] === member){
                return a;
            }
        }
    }
    return null;
}
