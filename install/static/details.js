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

/* IPA Object Details - populating definiton lists from entry data */

/* REQUIRES: ipa.js */

var IPA_DETAILS_POPULATE = 1;
var IPA_DETAILS_UPDATE = 2;

/* name of IPA object, that we're populating the lists for */
var _ipa_obj_name = '';

/* initialize the IPA Object Details library */
function ipa_details_init(obj_name, url)
{
    _ipa_obj_name = obj_name;
}

var _ipa_load_on_win_callback = null;
var _ipa_load_on_fail_callback = null;

var ipa_details_cache = null;

function ipa_details_load(pkey, on_win, on_fail)
{
    if (!pkey)
	return;

    _ipa_load_on_win_callback = on_win;
    _ipa_load_on_fail_callback = on_fail;

    ipa_cmd(
	'show', [pkey], {all: true}, _ipa_load_on_win, _ipa_load_on_fail,
	_ipa_obj_name
    );
}

function _ipa_load_on_win(data, text_status, xhr)
{
    if (_ipa_load_on_win_callback)
	_ipa_load_on_win_callback(data, text_status, xhr);

    if (data['error'])
	return;

    var result = data.result.result;

    ipa_details_cache = $.extend(true, {}, result);
    ipa_details_display(result);
}

function _ipa_load_on_fail(xhr, text_status, error_thrown)
{
    if (_ipa_load_on_fail_callback)
	_ipa_load_on_fail_callback(xhr, text_status, error_thrown);
}

var _ipa_update_on_win_callback = null;
var _ipa_update_on_fail_callback = null;

function ipa_details_update(pkey, on_win, on_fail)
{
    if (!pkey)
	return;

    var modlist = {'all': true, 'setattr': [], 'addattr': []};
    var attrs_wo_option = {};

    $('.entryattrs input').each(function () {
	var jobj = $(this);

	var dt = jobj.parent().prevAll('dt').slice(0, 1);
	if (!dt)
	    return;

	var attr = dt.attr('title');
	if (!attr || attr.indexOf('call_') == 0)
	    return;

	var param_info = ipa_get_param_info(attr);
	if (param_info) {
	    modlist[attr] = jobj.val();
	    return;
	}

	if (!attrs_wo_option[attr])
	    attrs_wo_option[attr] = [];
	attrs_wo_option[attr].push(jobj.val());
    });

    $('.entryattrs dt').each(function () {
	var jobj = $(this);

	var attr = jobj.attr('title');
	if (!attr)
	    return;

	if (attr.indexOf('call_') == 0) {
	    var func = window[attr.substr(5)];
	    if (func)
	        func(jobj, modlist, IPA_DETAILS_UPDATE);
	    return;
	}

        var param_info = ipa_get_param_info(attr);
        if (param_info && param_info['primary_key'])
            return;

	var next = jobj.next('dd');
	if ((!next.length) || (!next.children('input').length))
	    attrs_wo_option[attr] = [''];
    });

    for (attr in attrs_wo_option) {
	var values = attrs_wo_option[attr];
	modlist['setattr'].push(attr + '=' + values[0]);
	for (var i = 1; i < values.length; ++i)
	    modlist['addattr'].push(attr + '=' + values[i]);
    }

    _ipa_update_on_win_callback = on_win;
    _ipa_update_on_fail_callback = on_fail;

    ipa_cmd(
	'mod', [pkey], modlist, _ipa_update_on_win, _ipa_update_on_fail,
	_ipa_obj_name
    );
}

function _ipa_update_on_win(data, text_status, xhr)
{
    if (_ipa_update_on_win_callback)
	_ipa_update_on_win_callback(data, text_status, xhr);

    if (data['error'])
	return;

    var result = data.result.result;
    ipa_details_cache = $.extend(true, {}, result);
    ipa_details_display(result);
}

function _ipa_update_on_fail(xhr, text_status, error_thrown)
{
    if (_ipa_update_on_fail_callback)
	_ipa_update_on_fail_callback(xhr, text_status, error_thrown);
}

function ipa_details_create(dls, container)
{
    if (!container)
        container = $('body');

    for (var i = 0; i < dls.length; ++i) {
	var d = dls[i];
	ipa_generate_dl(container.children('hr').last(), d[0], d[1], d[2]);
    }
}

var _ipa_h2_template = '<h2 onclick="_h2_on_click(this)">&#8722; I</h2>';
var _ipa_dl_template = '<dl id="I" class="entryattrs"></dl>';
var _ipa_dt_template = '<dt title="T">N:</dt>';

function ipa_generate_dl(jobj, id, name, dts)
{
    if (!dts)
	return;

    jobj.after(_ipa_h2_template.replace('I', name));
    jobj = jobj.next();
    jobj.after(_ipa_dl_template.replace('I', id));
    jobj = jobj.next();
    jobj.after('<hr />');

    for (var i = 0; i < dts.length; ++i) {
	var label = '';
	if (dts[i][0].indexOf('call_') != 0) {
	    var param_info = ipa_get_param_info(dts[i][0]);
	    if (param_info)
		label = param_info['label'];
	}
	if ((!label) && (dts[i].length > 1))
	    label = dts[i][1];
	jobj.append(
	    _ipa_dt_template.replace('T', dts[i][0]).replace('N', label)
	);
    }
}

/* HTML templates for ipa_details_display() */
var _ipa_a_add_template =
    '<a href="jslink" onclick="return (_ipa_add_on_click(this))" title="A">Add</a>';

/* populate definition lists with the class 'entryattrs' with entry attributes
 *
 * The list has to be specially crafted for this function to work properly:
 * <dt> tags should have the 'title' attribute set to an LDAP attribute name
 * OR to a javascript function name prefixed with 'call_', which will be given
 * the <dt> object and entry_attrs as arguments.
 * Example:
 *   <dl class="entryattrs">
 *     <dt title="givenname">First Name:</dt>
 *     <dt title="call_some_callback">Some Attribute:</dt>
 *   </dl>
 *
 * arguments:
 *   entry_attrs - 'result' field as returned by ipa *-show commnads
 *                 (basically an associative array with attr:value pairs) */
function ipa_details_display(entry_attrs)
{
    /* remove all <dd> tags i.e. all attribute values */
    $('.entryattrs dd').remove();

    /* go through all <dt> tags and pair them with newly created <dd>s */
    $('.entryattrs dt').each(function () {
	var jobj = $(this);

	var attr = jobj.attr('title');
	if (attr.indexOf('call_') == 0) {
	    /* title contains callback instead of attribute name */
	    var func = window[attr.substr(5)];
	    if (func)
		func(jobj, entry_attrs, IPA_DETAILS_POPULATE);
	    else
		jobj.after(_ipa_dd_first_template.replace('I', '-'));
	} else {
	    /* title contains attribute name - default behaviour */
	    var value = entry_attrs[attr];
	    if (value) {
		ipa_insert_first_dd(jobj, ipa_create_input(attr, value[0]));
		for (var i = 1; i < value.length; ++i) {
		    jobj = jobj.next();
		    ipa_insert_other_dd(jobj, ipa_create_input(attr, value[i]));
		}
	    } else {
		ipa_insert_first_dd(jobj, _ipa_a_add_template.replace('A', attr));
	    }
	}
    });
}

var _ipa_dd_first_template = '<dd class="first">I</dd>';

function ipa_insert_first_dd(jobj, content)
{
    jobj.after(_ipa_dd_first_template.replace('I', content));
}

var _ipa_dd_other_template = '<dd class="other">I</dd>';

function ipa_insert_other_dd(jobj, content)
{
    jobj.after(_ipa_dd_other_template.replace('I', content));
}


/* mapping of parameter types to handlers used to create inputs */
var _ipa_param_type_2_handler_map = {
    'Str': _ipa_create_text_input,
    'Int': _ipa_create_text_input,
    'Bool': _ipa_create_text_input,
};

/* create an HTML element for displaying/editing an attribute
 * arguments:
 *   attr - LDAP attribute name
 *   value - the attributes value */
function ipa_create_input(attr, value)
{
    var param_info = ipa_get_param_info(attr);
    if (!param_info) {
	/* no information about the param is available, default to text input */
	return (
	    _ipa_create_text_input(attr, value, null) +
	    _ipa_create_remove_link(attr, null)
	);
    }

    /* check if the param value can be modified */
    if (param_info['primary_key'] || ('no_update' in param_info['flags']))
	return (value.toString());

    /* call handler by param class */
    var handler = _ipa_param_type_2_handler_map[param_info['class']];
    if (handler) {
	return (
	    handler(attr, value, param_info) +
	    _ipa_create_remove_link(attr, param_info)
	);
    }

    /* no handler for this type? don't allow modification */
    return (value.toString());
}

/* HTML template for _ipa_create_remove_link() */
var _ipa_a_remove_template =
    '<a href="jslink" onclick="return (_ipa_remove_on_click(this))" title="A">Remove</a>';

/* creates a Remove link for deleting attribute values */
function _ipa_create_remove_link(attr, param_info)
{
    if (!param_info)
	return (_ipa_a_remove_template.replace('A', attr));

    /* check if the param is required or of the Password type
     * if it is, then we don't want people to be able to remove it */
    if ((param_info['required']) || (param_info['class'] == 'Password'))
	return ('');

    return (_ipa_a_remove_template.replace('A', attr));
}

/* HTML template for _ipa_create_text_input() */
var _ipa_input_text_template =
    '<input type="text" name="A" value="V" />';

/* creates a input box for editing a string attribute */
function _ipa_create_text_input(attr, value, param_info)
{
    return (
	_ipa_input_text_template.replace('A', attr).replace(
	    'V', value.toString()
	)
    );
}

function ipa_details_reset()
{
    if (ipa_details_cache)
	ipa_details_display(ipa_details_cache);
}

/* Event handlers */

function _ipa_add_on_click(obj)
{
    var jobj = $(obj);
    var par = jobj.parent();
    par.append(ipa_create_input(jobj.attr('title'), ''));
    jobj.next('input').focus();
    jobj.remove();
    return (false);
}

function _ipa_remove_on_click(obj)
{
    var jobj = $(obj);
    var attr = jobj.attr('title');
    var par = jobj.parent();

    var next = par.next('dd');
    if (next.length) {
	if (par.hasClass('first')) {
	    next.addClass('first');
	    next.removeClass('other');
	}
	par.remove();
    } else {
	par.empty();
	par.append(_ipa_a_add_template.replace('A', attr));
    }

    return (false);
}

function _h2_on_click(obj)
{
    var jobj = $(obj);
    var txt = jobj.text().replace(/^\s*/, '');
    if (txt.charCodeAt(0) == 8722) {
	obj.dl = jobj.next().detach();
	jobj.text('+' + txt.substr(1));
    } else {
	if (obj.dl)
	    obj.dl.insertAfter(obj);
	jobj.text(
	    String.fromCharCode(8722) + txt.substr(1)
	);
    }
}

