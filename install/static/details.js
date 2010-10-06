/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Adam Young <ayoung@redhat.com>
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

var ipa_details_cache = {};

function ipa_details_create(obj_name, dls, container)
{
    if (!container) {
        alert('ERROR: ipa_details_create: Missing container argument!');
        return;
    }

    container.attr('title', obj_name);
    container.addClass('details-container');

    var details = $('<div/>', {
        class: 'details'
    }).appendTo(container);

    details.append('<div class="details-buttons"></div>');
    var jobj = details.children().last();
    jobj.append('<a class="details-reset ui-state-default ui-corner-all input_link " href="jslink"><span class="ui-icon ui-icon-refresh" ></span> Reset</a>');
    jobj.append('<a class="details-update ui-state-default ui-corner-all input_link  " href="jslink"><span class="ui-icon ui-icon-check" ></span>Update</a>');

    details.append('<hr />');

    for (var i = 0; i < dls.length; ++i) {
        var d = dls[i];
        ipa_generate_dl(details.children().last(), d[0], d[1], d[2]);
    }

    details.append('<div class="details-back"></div>');
    var jobj = details.children().last();
    jobj.append('<a href="#details-viewtype">Back to Top</a>');
}


function ipa_generate_dl(jobj, id, name, dts)
{
    if (!dts)
        return;

    var parent = jobj.parent();
    var obj_name = parent.attr('title');

    parent.append($("<h2/>",{
        click: function(){_h2_on_click(this)},
        html:"&#8722; "+name
    }));

    var dl = $('<dl></dl>',{
        id:id,
        "class":"entryattrs"})

    for (var i = 0; i < dts.length; ++i) {
        var label = '';
        var param_info = ipa_get_param_info(obj_name, dts[i][0]);
        if (param_info)
            label = param_info['label'];
        if ((!label) && (dts[i].length > 1))
            label = dts[i][1];

        var title = dts[i][0];
        if (typeof dts[i][2] == 'function')
            title = 'call_' + dts[i][2].name;
        dl.append(
            $('<dt></dt>', {
                title: title,
                html: label + ':',
            })
        );
    }

    parent.append(dl);
    parent.append('<hr/>');
}

function ipa_details_load(jobj, pkey, on_win, on_fail)
{
    var obj_name = jobj.attr('id');

    function load_on_win(data, text_status, xhr) {
        if (on_win)
            on_win(data, text_status, xhr);
        if (data.error)
            return;

        var result = data.result.result;
        ipa_details_cache[obj_name] = $.extend(true, {}, result);
        ipa_details_display(obj_name, result);
    };

    function load_on_fail(xhr, text_status, error_thrown) {
        if (on_fail)
            on_fail(xhr, text_status, error_thrown);

        var details = $('.details', jobj).empty();
        details.append('<p>Error: '+error_thrown.name+'</p>');
        details.append('<p>URL: '+this.url+'</p>');
        details.append('<p>'+error_thrown.message+'</p>');
    };

    var params = [pkey];
    if (!pkey){
        params = [];
    }
    ipa_cmd(
        'show', params, {all: true}, load_on_win, load_on_fail, obj_name
    );
}
function ipa_details_update(obj_name, pkey, on_win, on_fail)
{
    function update_on_win(data, text_status, xhr) {
        if (on_win)
            on_win(data, text_status, xhr);
        if (data.error)
            return;

        var result = data.result.result;
        ipa_details_cache[obj_name] = $.extend(true, {}, result);
        ipa_details_display(obj_name, result);
    };

    function update_on_fail(xhr, text_status, error_thrown) {
        if (on_fail)
            on_fail(xhr, text_status, error_thrown);
    };

    if (!pkey)
        return;

    var selector = '.details-container[title=' + obj_name + ']';

    var modlist = {'all': true, 'setattr': [], 'addattr': []};
    var attrs_wo_option = {};

    $(selector + ' .entryattrs input').each(function () {
        var jobj = $(this);

        var dt = jobj.parent().prevAll('dt').slice(0, 1);
        if (!dt)
            return;

        var attr = dt.attr('title');
        if (!attr || attr.indexOf('call_') == 0)
            return;
        var value = jQuery.trim(jobj.val());

        var param_info = ipa_get_param_info(obj_name, attr);
        if (param_info) {
            modlist[attr] = value;
            return;
        }

        if (!attrs_wo_option[attr])
            attrs_wo_option[attr] = [];
        attrs_wo_option[attr].push(value);
    });

    $(selector + ' .entryattrs dt').each(function () {
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

        var param_info = ipa_get_param_info(obj_name, attr);
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

    ipa_cmd('mod', [pkey], modlist, update_on_win, update_on_fail, obj_name);
}

/* HTML templates for ipa_details_display() */
var _ipa_a_add_template =
    '<a href="jslink" onclick="return (_ipa_add_on_click(this))" title="A">Add</a>';
var _ipa_span_doc_template = '<span class="attrhint">Hint: D</span>';
var _ipa_span_hint_template = '<span class="attrhint">Hint: D</span>';

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
function ipa_details_display(obj_name, entry_attrs)
{
    var selector = '.details-container[title=' + obj_name + ']';

    /* remove all <dd> tags i.e. all attribute values */
    $(selector + ' .entryattrs dd').remove();

    /* go through all <dt> tags and pair them with newly created <dd>s */
    $(selector + ' .entryattrs dt').each(function () {
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
            var multivalue = false;
            var hint_span = null;

            var param_info = ipa_get_param_info(obj_name, attr);
            if (param_info) {
                if (param_info['multivalue'] || param_info['class'] == 'List')
                    multivalue = true;
                var hint = param_info['hint'];
                if (hint){
                    hint_span = $("<span />",{
                        "class":"attrhint",
                        html:"Hint: " + hint});
                }
            }

            var value = entry_attrs[attr];
            if (value) {
                ipa_insert_first_dd(
                    jobj, ipa_create_input(obj_name, attr, value[0],hint_span)
                );
                for (var i = 1; i < value.length; ++i) {
                    jobj = jobj.next();
                    ipa_insert_other_dd(
                      jobj, ipa_create_input(obj_name, attr, value[i],hint_span)
                    );
                }
                if (multivalue) {
                    ipa_insert_other_dd(
                        jobj.next(), _ipa_a_add_template.replace('A', attr)
                    );
                }
            } else {
                if (multivalue) {
                    ipa_insert_first_dd(
                        jobj, _ipa_a_add_template.replace('A', attr) /*.append( hint_span)*/
                    );
                } else {
                    ipa_insert_first_dd(
                        jobj, ipa_create_input(obj_name, attr, '')/*.append( hint_span)*/
                    );
                }
            }
        }
    });
}


function ipa_insert_first_dd(jobj, content)
{
    jobj.after( $('<dd class="first"></dd>').append(content))

}

function ipa_insert_other_dd(jobj, content)
{
    jobj.after($('<dd class="other"></dd>').append(content));
}


/* mapping of parameter types to handlers used to create inputs */
var _ipa_param_type_2_handler_map = {
    'Str': _ipa_create_text_input,
    'Int': _ipa_create_text_input,
    'Bool': _ipa_create_text_input,
    'List': _ipa_create_text_input
};

/* create an HTML element for displaying/editing an attribute
 * arguments:
 *   attr - LDAP attribute name
 *   value - the attributes value */
function ipa_create_input(obj_name, attr, value,hint)
{
    var input = $("<label>",{html:value.toString()});
    var param_info = ipa_get_param_info(obj_name, attr);
    if (!param_info) {
        /* no information about the param is available, default to text input */
        input = _ipa_create_text_input(attr, value, null);
        if (hint){
            input.after(hint);
        }
    }else if (param_info['primary_key'] ||
              ('no_update' in param_info['flags'])){
        /* check if the param value can be modified */
        /*  THis is currently a no-op, as we use this logic for the
            default case as well */
    }else{
        /* call handler by param class */
        var handler = _ipa_param_type_2_handler_map[param_info['class']];
        if (handler) {
            if (param_info['multivalue'] || param_info['class'] == 'List') {
                input = handler(attr, value, param_info) +
                    _ipa_create_remove_link(attr, param_info);
            }else{
                input =  (handler(attr, value, param_info));
                if (hint){
                    input.after(hint);
                }
            }
        }
    }
    return input;
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


/* creates a input box for editing a string attribute */
function _ipa_create_text_input(attr, value, param_info)
{
    return $("<input/>",{
        type:"text",
        name:attr,
        value:value.toString(),
        keypress: function(){
            var validation_info=param_info;
            var undo_link=this.nextElementSibling;
            undo_link.style.display ="inline";
            if(false){
                var error_link = undo_link.nextElementSibling;
                error_link.style.display ="block";
            }
        }
    }).after($("<a/>",{
        html:"undo",
        "class":"ui-state-highlight ui-corner-all",
        style:"display:none",
        click: function(){
            var key = this.previousElementSibling.name;
            var entity_divs = $(this).parents('.details-container');
            var entry_attrs = ipa_details_cache[entity_divs[0].id];
            var previous_value = entry_attrs[key] || "";
            this.previousElementSibling.value =  previous_value;
            this.style.display = "none";
        }
    })).after($("<span/>",{
        html:"Does not match pattern",
        "class":"ui-state-error ui-corner-all",
        style:"display:none",
    }));

}

function ipa_details_reset(obj_name)
{
    if (ipa_details_cache[obj_name]){
        ipa_details_display(obj_name, ipa_details_cache[obj_name]);
    }

}

/* Event handlers */

function _ipa_add_on_click(obj)
{
    var jobj = $(obj);
    var attr = jobj.attr('title');
    var par = jobj.parent();
    var obj_name = jobj.closest('.details-container').attr('title');

    par.prepend(ipa_create_input(obj_name, attr, ''));
    ipa_insert_other_dd(par, _ipa_a_add_template.replace('A', attr));
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
            var hint = par.children('span').detach();
            next.append(hint);
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

