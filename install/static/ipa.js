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

/* IPA JSON-RPC helper */

var IPA_DEFAULT_JSON_URL = '/ipa/json';

var ipa_json_url;
var ipa_use_static_files;
var ipa_record_limit=100;

var ipa_ajax_options = {
    type: 'POST',
    contentType: 'application/json',
    dataType: 'json',
    async: true,
    processData: false
};

/* JSON-RPC ID counter */
var ipa_jsonrpc_id = 0;

/* IPA objects data in JSON format */
var ipa_messages = {};
var ipa_objs = {};

var ipa_dialog = $('<div/>', {id: 'ipa_dialog'});

/* initialize the IPA JSON-RPC helper
 * arguments:
 *   url - JSON-RPC URL to use (optional) */
function ipa_init(url, use_static_files, on_win, on_error)
{
    if (url)
        ipa_json_url = url;

    if (use_static_files)
        ipa_use_static_files = use_static_files;

    $.ajaxSetup(ipa_ajax_options);

    ipa_cmd('json_metadata', [], {},
        function(data, text_status, xhr) {
            ipa_objs = data.result.metadata;
            ipa_messages = data.result.messages;
            if (on_win) on_win(data, text_status, xhr);
        },
        on_error
    );
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
    function ipa_success_handler(data, text_status, xhr) {
        if (!data) {
            var error_thrown = {
                name: 'HTTP Error '+xhr.status,
                message: data ? xhr.statusText : "No response"
            };
            ipa_error_handler.call(this, xhr, text_status, error_thrown);

        } else if (data.error) {
            var error_thrown = {
                name: 'IPA Error '+data.error.code,
                message: data.error.message
            };
            ipa_error_handler.call(this, xhr, text_status, error_thrown);

        } else if (win_callback) {
            win_callback.call(this, data, text_status, xhr);
        }
    }

    function ipa_error_handler(xhr, text_status, error_thrown) {
        ipa_dialog.empty();
        ipa_dialog.attr('title', 'Error: '+error_thrown.name);

        ipa_dialog.append('<p>URL: '+this.url+'</p>');
        if (error_thrown.message) {
            ipa_dialog.append('<p>'+error_thrown.message+'</p>');
        }

        var that = this;

        ipa_dialog.dialog({
            modal: true,
            width: 400,
            buttons: {
                'Retry': function() {
                    ipa_dialog.dialog('close');
                    ipa_cmd(name, args, options, win_callback, fail_callback, objname);
                },
                'Cancel': function() {
                    ipa_dialog.dialog('close');
                    fail_callback.call(that, xhr, text_status, error_thrown);
                }
            }
        });
    }

    var id = ipa_jsonrpc_id++;

    var method_name = name;

    if (objname)
        method_name = objname + '_' + name;

    var url = ipa_json_url;

    if (!url)
        url = IPA_DEFAULT_JSON_URL;

    if (ipa_use_static_files)
        url += '/' + method_name + '.json';

    options.sizelimit=ipa_record_limit;
    var data = {
        method: method_name,
        params: [args, options],
        id: id
    };

    var request = {
        url: url,
        data: JSON.stringify(data),
        success: ipa_success_handler,
        error: ipa_error_handler
    };

    $.ajax(request);

    return (id);
}

/* parse query string into key:value dict
 * arguments:
 *   qs - query string (optional) */
function ipa_parse_qs(qs)
{
    var dict = {};

    if (!qs)
        qs = location.hash.substring(1);
    qs = qs.replace(/\+/g, ' ');

    var args = qs.split('&');
    for (var i = 0; i < args.length; ++i) {
        var parts = args[i].split('=', 2);
        var key = decodeURIComponent(parts[0]);
    if (parts.length == 2)
        dict[key] = decodeURIComponent(parts[1]);
    else
        dict[key] = key;
    }

    return (dict);
}

/* helper function used to retrieve information about an attribute */
function ipa_get_param_info(obj_name, attr)
{
    var ipa_obj = ipa_objs[obj_name];
    if (!ipa_obj) return null;

    var takes_params = ipa_obj.takes_params;
    if (!takes_params)
        return (null);

    for (var i = 0; i < takes_params.length; ++i) {
        if (takes_params[i]['name'] == attr)
            return (takes_params[i]);
    }

    return (null);
}

/* helper function used to retrieve attr name with members of type `member` */
function ipa_get_member_attribute(obj_name, member)
{
    var ipa_obj = ipa_objs[obj_name];
    if (!ipa_obj) return null;

    var attribute_members = ipa_obj.attribute_members
    for (var a in attribute_members) {
        var objs = attribute_members[a];
        for (var i = 0; i < objs.length; ++i) {
            if (objs[i] == member)
                return a;
        }
    }

    return null;
}
