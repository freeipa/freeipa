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



//the develop.js file that follows will set this to true.
//that file should only exist in the source file system
//and should not get deployed to the web server
var useSampleData = false;


//Maximum number of records to return on any query.
var sizelimit=100;

/* IPA JSON-RPC helper */

/* JSON-RPC ID counter */
var ipa_jsonrpc_id = 0;

/* IPA objects data in JSON format */
var ipa_objs = {};

/* initialize the IPA JSON-RPC helper
 * arguments:
 *   url - JSON-RPC URL to use (optional) */
function ipa_init(url)
{
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
    id = ipa_jsonrpc_id++;
    if (objname)
	name = objname + '_' + name;

    options.sizelimit	= sizelimit;

    var data = {
	method: name,
	params: [args, options],
	id: id,
    };

    var jsonUrl =  '/ipa/json';
    if (useSampleData){
	jsonUrl = sampleData;
    }
    $.ajax({
	    beforeSend: function(xhrObj){
		xhrObj.setRequestHeader("Content-Type","application/json");
		xhrObj.setRequestHeader("Accept","application/json");
	    },
	    type: "POST",
	    url: jsonUrl,
	    processData: false,
	    data: JSON.stringify(data),
	    dataType: "json",
	    success: win_callback,
	    error: fail_callback,
    });

    return (id);
}

/* parse query string into key:value dict
 * arguments:
 *   qs - query string (optional) */
function ipa_parse_qs(qs)
{
    var dict = {};

    if (!qs)
	qs = location.search.substring(1, location.search.length);
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
function ipa_get_param_info(attr)
{
    var takes_params = ipa_objs[_ipa_obj_name]['takes_params'];
    if (!takes_params)
	return (null);

    for (var i = 0; i < takes_params.length; ++i) {
	if (takes_params[i]['name'] == attr)
	    return (takes_params[i]);
    }

    return (null);
}

