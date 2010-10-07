/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *    Endi S. Dewata <edewata@redhat.com>
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

var ipa_details_cache = {};

function ipa_details_create(container, sections)
{
    if (!container) {
        alert('ERROR: ipa_details_create: Missing container argument!');
        return;
    }

    var obj_name = container.attr('id');
    container.attr('title', obj_name);
    container.addClass('details-container');

    var details = $('<div/>', {
        'class': 'details'
    }).appendTo(container);

    var buttons = $('<div/>', {
        'class': 'details-buttons'
    }).appendTo(details);

    buttons.append('<a class="details-reset ui-state-default ui-corner-all input_link " href="jslink"><span class="ui-icon ui-icon-refresh" ></span> Reset</a>');
    buttons.append('<a class="details-update ui-state-default ui-corner-all input_link  " href="jslink"><span class="ui-icon ui-icon-check" ></span>Update</a>');

    details.append('<hr />');

    for (var i = 0; i < sections.length; ++i) {
        var section = sections[i];
        ipa_details_section_setup(container, details, section);
    }

    details.append('<div class="details-back"></div>');
    var jobj = details.children().last();
    jobj.append('<a href="#details-viewtype">Back to Top</a>');
}


function ipa_details_section_setup(container, details, section)
{
    var id = section.name;
    var name = section.label;
    var fields = section.fields;

    if (!fields)
        return;

    details.append($("<h2/>",{
        click: function(){_h2_on_click(this)},
        html:"&#8722; "+name
    }));

    var dl = $('<dl></dl>',{
        id:id,
        "class":"entryattrs"
    }).appendTo(details);

    for (var i = 0; i < fields.length; ++i) {
        var field = fields[i];

        if (field.setup) {
            field.setup.call(field, container, dl, section);
            
        } else {
            ipa_details_field_setup.call(field, container, dl, section);
        }
    }

    details.append('<hr/>');
}

function ipa_details_field_setup(container, dl, section) {

    var obj_name = container.attr('title');
    
    var title = this.name;
    var label = '';
    var param_info = ipa_get_param_info(obj_name, this.name);
    if (param_info)
        label = param_info['label'];
    if (!label)
        label = this.label;

    $('<dt></dt>', {
        id: this.name,
        title: title,
        html: label + ':'
    }).appendTo(dl);
}

function ipa_details_load(container, pkey, on_win, on_fail)
{
    var obj_name = container.attr('id');

    function load_on_win(data, text_status, xhr) {
        if (on_win)
            on_win(data, text_status, xhr);
        if (data.error)
            return;

        var result = data.result.result;
        ipa_details_cache[obj_name] = $.extend(true, {}, result);
        ipa_details_display(container, result);
    }

    function load_on_fail(xhr, text_status, error_thrown) {
        if (on_fail)
            on_fail(xhr, text_status, error_thrown);

        var details = $('.details', container).empty();
        details.append('<p>Error: '+error_thrown.name+'</p>');
        details.append('<p>URL: '+this.url+'</p>');
        details.append('<p>'+error_thrown.message+'</p>');
    }

    var params = [pkey];
    if (!pkey){
        params = [];
    }
    ipa_cmd(
        'show', params, {all: true}, load_on_win, load_on_fail, obj_name
    );
}
function ipa_details_update(container, pkey, on_win, on_fail)
{
    var obj_name = container.attr('id');

    function update_on_win(data, text_status, xhr) {
        if (on_win)
            on_win(data, text_status, xhr);
        if (data.error)
            return;

        var result = data.result.result;
        ipa_details_cache[obj_name] = $.extend(true, {}, result);
        ipa_details_display(container, result);
    }

    function update_on_fail(xhr, text_status, error_thrown) {
        if (on_fail)
            on_fail(xhr, text_status, error_thrown);
    }

    if (!pkey)
        return;

    var values;
    var modlist = {'all': true, 'setattr': [], 'addattr': []};
    var attrs_wo_option = {};

    var sections = ipa_entity_get_details_sections(obj_name);
    for (var i=0; i<sections.length; i++) {
        var section = sections[i];
        var fields = section.fields;
        if (!fields) continue;

        for (var j=0; j<fields.length; j++) {
            var field = fields[j];

            if (field.save) {
                values = field.save.call(field, container);

            } else {
                values = ipa_details_field_save.call(field, container);
            }

            var param_info = ipa_get_param_info(obj_name, field.name);
            if (param_info) {
                if (param_info['primary_key']) continue;
                if (values.length) modlist[field.name] = values[0];

            } else {
                if (values.length) attrs_wo_option[field.name] = values;
            }
        }
    }

    for (attr in attrs_wo_option) {
        values = attrs_wo_option[attr];
        modlist['setattr'].push(attr + '=' + values[0]);
        for (var i = 1; i < values.length; ++i)
            modlist['addattr'].push(attr + '=' + values[i]);
    }

    ipa_cmd('mod', [pkey], modlist, update_on_win, update_on_fail, obj_name);
}

function ipa_details_field_save(container) {
    var field = this;
    var values = [];

    var dd = $('dd[title='+field.name+']', container);
    dd.each(function () {
        var input = $('input', dd);
        if (!input.length) return;

        var value = $.trim(input.val());
        if (!value) value = '';

        values.push(value);
    });

    return values;
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
function ipa_details_display(container, entry_attrs)
{
    var obj_name = container.attr('id');

    /* remove all <dd> tags i.e. all attribute values */
    $('dd', container).remove();

    /* go through all <dt> tags and pair them with newly created <dd>s */
    var sections = ipa_entity_get_details_sections(obj_name);
    for (var i=0; i<sections.length; i++) {
        var section = sections[i];
        var fields = section.fields;
        if (!fields) continue;

        for (var j=0; j<fields.length; j++) {
            var field = fields[j];
            var dt = $('dt[title='+field.name+']', container);
            if (!dt.length) continue;

            if (field.load) {
                field.load.call(field, dt, entry_attrs);

            } else {
                ipa_details_field_load.call(field, container, dt, entry_attrs);
            }
        }
    }
}

function ipa_details_field_load(container, dt, entry_attrs) {
    var obj_name = container.attr('id');

    var multivalue = false;
    var hint_span = null;
    var dd;

    var param_info = ipa_get_param_info(obj_name, this.name);
    if (param_info) {
        if (param_info['multivalue'] || param_info['class'] == 'List')
            multivalue = true;
        var hint = param_info['hint'];
        if (hint){
            hint_span = $('<span />',{
                'class': 'attrhint',
                'html': 'Hint: ' + hint});
        }
    }

    var value = entry_attrs[this.name];
    if (value) {
        dd = ipa_create_first_dd(
            this.name, ipa_create_input(obj_name, this.name, value[0],hint_span)
        );
        dt.after(dd);
        var last_dd = dd;
        for (var i = 1; i < value.length; ++i) {
            dd = ipa_create_other_dd(
              this.name, ipa_create_input(obj_name, this.name, value[i],hint_span)
            );
            last_dd.after(dd);
            last_dd = dd;
        }
        if (multivalue) {
            dd = ipa_create_other_dd(
                this.name, _ipa_a_add_template.replace('A', this.name)
            );
            last_dd.after(dd);
        }
    } else {
        if (multivalue) {
            dd = ipa_create_first_dd(
                this.name, _ipa_a_add_template.replace('A', this.name) /*.append(hint_span)*/
            );
            dt.after(dd);
        } else {
            dd = ipa_create_first_dd(
                this.name, ipa_create_input(obj_name, this.name, '') /*.append(hint_span)*/
            );
            dt.after(dd);
        }
    }
}

function ipa_create_first_dd(field_name, content)
{
    return $('<dd/>', {

        'class': 'first',
        'title': field_name
    }).append(content);
}

function ipa_create_other_dd(field_name, content)
{
    return $('<dd/>', {
        'class': 'other',
        'title': field_name
    }).append(content);
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
        style:"display:none"
    }));

}

function ipa_details_reset(container)
{
    var obj_name = container.attr('id');

    if (ipa_details_cache[obj_name]){
        ipa_details_display(container, ipa_details_cache[obj_name]);
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
    var dd = ipa_create_other_dd(field.name, _ipa_a_add_template.replace('A', attr));
    par.after(dd);
    jobj.next('input').focus();
    jobj.remove();

    return (false);
}

function _ipa_remove_on_click(obj)
{
    var jobj = $(obj);
    var attr = jobj.attr('title');
    var par = jobj.parent();

    var next = par.next('dd[title='+attr+']');
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

