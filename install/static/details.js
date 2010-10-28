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

function ipa_details_field(spec) {

    spec = spec || {};

    var that = {};
    that.name = spec.name;
    that.label = spec.label;

    that.setup = spec.setup || setup;
    that.load = spec.load || load;
    that.save = spec.save || save;

    function setup(container, dl, section) {

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

    function load(container, dt, entry_attrs) {

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

    function save(container) {
        var field = this;
        var values = [];

        var dd = $('dd[title='+field.name+']', container);
        dd.each(function () {
            var input = $('input', $(this));
            if (!input.length) return;

            if (input.is('.strikethrough')) return;

            var value = $.trim(input.val());
            if (!value) value = '';

            values.push(value);
        });

        return values;
    }

    return that;
}

function ipa_details_section(spec){

    spec = spec || {};

    var that = {};
    that.name = spec.name || '';
    that.label = spec.label || '';

    that.fields = [];
    that.fields_by_name = {};

    that.get_fields = function() {
        return that.fields;
    };

    that.get_field = function(name) {
        return that.fields_by_name[name];
    };

    that.add_field = function(field) {
        that.fields.push(field);
        that.fields_by_name[field.name] = field;
    };

    that.create_field = function(spec) {
        var field = ipa_details_field(spec);
        that.add_field(field);
        return field;
    };

    // Deprecated: Used for backward compatibility only.
    function input(spec){
        that.create_field(spec);
        return that;
    }

    that.input = input;

    return that;
}

// Deprecated: Used for backward compatibility only.
function ipa_stanza(spec) {
    return ipa_details_section(spec);
}

function ipa_details_facet(spec) {

    spec = spec || {};

    var that = ipa_facet(spec);

    that.init = spec.init;
    that.setup = spec.setup || setup;

    that.sections = [];
    that.sections_by_name = {};

    that.get_sections = function() {
        return that.sections;
    };

    that.get_section = function(name) {
        return that.sections_by_name[name];
    };

    that.add_section = function(section) {
        that.sections.push(section);
        that.sections_by_name[section.name] = section;
    };

    that.create_section = function(spec) {
        var section = ipa_stanza(spec);
        that.add_section(section);
        return section;
    };

    that.is_dirty = function() {
        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        return pkey != that.pkey;
    };

    function setup(container, unspecified) {

        that.pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

        that.setup_views(container);
        ipa_details_create(container, that.sections);

        container.find('.details-reset').click(function() {
            ipa_details_reset(container);
            return false;
        });

        container.find('.details-update').click(function() {
            var pkey_name = IPA.metadata[that.entity_name].primary_key;
            ipa_details_update(container, ipa_details_cache[that.entity_name][pkey_name][0]);
            return false;
        });

        if (that.pkey||unspecified){
            ipa_details_load(container, that.pkey, null, null);
        }
    }

    if (that.init) that.init();

    return that;
}

function ipa_make_button(which,text,details_class){

    var button_class= details_class +
        " ui-state-default ui-corner-all input_link ";
    return $('<a ></a>',{
        "class": button_class
        }).
        append('<span class="ui-icon ' + which +'" ></span> ').
        append(text);
}

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

    buttons.append(ipa_make_button('ui-icon-refresh','Reset','details-reset'));
    buttons.append(ipa_make_button('ui-icon-check','Update','details-update'));

    details.append('<hr />');

    for (var i = 0; i < sections.length; ++i) {
        var section = sections[i];
        ipa_details_section_setup(container, details, section);
    }

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

            field.setup(container, dl, section);
    }

    details.append('<hr/>');
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

    var facet = ipa_entity_get_details_facet(obj_name);
    var sections = facet.get_sections();
    for (var i=0; i<sections.length; i++) {
        var section = sections[i];
        var fields = section.fields;
        if (!fields) continue;

        for (var j=0; j<fields.length; j++) {
            var field = fields[j];

            values = field.save(container);

            var param_info = ipa_get_param_info(obj_name, field.name);
            if (param_info) {
                if (param_info['primary_key']) continue;
                if (values.length === 1) {
                    modlist[field.name] = values[0];
                }else if (values.length > 1){
                    modlist[field.name] = values;
                } else if (param_info['multivalue']){
                        modlist[field.name] = [];
                }
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
    var facet = ipa_entity_get_details_facet(obj_name);
    var sections = facet.get_sections();
    for (var i=0; i<sections.length; i++) {
        var section = sections[i];
        var fields = section.fields;
        if (!fields) continue;

        for (var j=0; j<fields.length; j++) {
            var field = fields[j];
            var dt = $('dt[title='+field.name+']', container);
            if (!dt.length) continue;
            field.load(container, dt, entry_attrs);
        }
    }
}



function ipa_create_first_dd(field_name, content){
    return $('<dd/>', {

        'class': 'first',
        'title': field_name
    }).append(content);
}

function ipa_create_other_dd(field_name, content){
    return $('<dd/>', {
        'class': 'other',
        'title': field_name
    }).append(content);
}

function ipa_insert_first_dd(jobj, content){
    ipa_insert_dd(jobj, content, "first");
}

function ipa_insert_dd(jobj, content, dd_class){
    jobj.after( $('<dd/>',{
        "class": dd_class
    }).append(content))
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
            input = handler(attr, value, param_info);
            if (param_info['multivalue'] || param_info['class'] == 'List') {
                input.append( _ipa_create_remove_link(attr, param_info));
            }
            if (hint){
                input.after(hint);
            }
        }
    }
    return input;
}


/* creates a Remove link for deleting attribute values */
function _ipa_create_remove_link(attr, param_info)
{
    if (!param_info)
        return (_ipa_a_remove_template.replace('A', attr));

    /* check if the param is required or of the Password type
     * if it is, then we don't want people to be able to remove it */
    if ((param_info['required']) || (param_info['class'] == 'Password'))
        return ('');

    return $('<a/>',{
        href:"jslink",
        click: function (){return (_ipa_remove_on_click(this))},
        title: attr,
        text: 'Remove'});

}


/* creates a input box for editing a string attribute */
function _ipa_create_text_input(attr, value, param_info)
{

    function calculate_dd_index(jobj){
        var index = 0;
        var dd = jobj.parents('dd').slice(0, 1)[0];
        dd = dd.previousElementSibling;

        while(dd.nodeName.toUpperCase() === 'DD'){
            dd = dd.previousElementSibling;
            index += 1;
            if (index > 100 )
                break;
        }
        return index;
    }

    function validate_input(text, param_info,error_link){
        if(param_info && param_info.pattern){
            var regex = new RegExp( param_info.pattern );
            if (!text.match(regex)) {
                error_link.style.display ="block";
                if ( param_info.pattern_errmsg){
                    error_link.innerHTML =  param_info.pattern_errmsg;
                }
            }else{
                error_link.style.display ="none";
            }
        }
    }

    var input = $("<Span />");
    input.append($("<input/>",{
        type:"text",
        name:attr,
        value:value.toString(),
        keyup: function(){
            var undo_link=this.nextElementSibling;
            undo_link.style.display ="inline";
            var error_link = undo_link.nextElementSibling;

            var text = $(this).val();
            validate_input(text, param_info,error_link);
        }

    }));
    input.append($("<a/>",{
        html:"undo",
        "class":"ui-state-highlight ui-corner-all",
        style:"display:none",
        click: function(){
            var key = this.previousElementSibling.name;
            var entity_divs = $(this).parents('.details-container');
            var entry_attrs = ipa_details_cache[entity_divs[0].id];

            index = calculate_dd_index($(this));

            var previous_value = entry_attrs[key] || "";
            if (index >= previous_value.length){
                previous_value = '';
            }else{
                previous_value= previous_value[index];
            }

            this.previousElementSibling.value =  previous_value;
            this.style.display = "none";
            var error_link = this.nextElementSibling;
            validate_input(previous_value, param_info,error_link);
        }
    }));
    input.append($("<span/>",{
        html:"Does not match pattern",
        "class":"ui-state-error ui-corner-all",
        style:"display:none"
    }));
    return input;
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

    var param_info = ipa_get_param_info(obj_name, '');
    var input = _ipa_create_text_input(attr, '', param_info);

    par.prepend(input);
    jobj.next('input').focus();
    jobj.remove();
    par.after( ipa_create_other_dd(attr,_ipa_a_add_template.replace('A', attr)));

    return (false);
}




function _ipa_remove_on_click(obj)
{
    var jobj = $(obj);
    var attr = jobj.attr('title');
    var par = jobj.parent();

    var input = par.find('input');

    if (input.is('.strikethrough')){
        input.removeClass('strikethrough');
        jobj.text("Remove");
    }else{
        input.addClass('strikethrough');
        jobj.text("Undo");
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

