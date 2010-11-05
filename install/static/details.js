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

IPA.is_field_writable = function(rights){
    if (!rights){
        alert('no right');
    }
    return rights.indexOf('w') > -1;
}

function ipa_details_field(spec) {

    spec = spec || {};

    spec.create = spec.create || create;
    spec.setup = spec.setup || setup;
    spec.load = spec.load || load;
    spec.save = spec.save || save;

    var that = ipa_widget(spec);

    function create(container) {
    }

    function setup(container) {

        var dl = $('dl', container);

        var title = that.name;
        var label = '';
        var param_info = ipa_get_param_info(that.entity_name, that.name);
        if (param_info)
            label = param_info['label'];
        if (!label)
            label = that.label;
        $('<dt></dt>', {
            id: that.name,
            title: title,
            html: label + ':'
        }).appendTo(dl);
    }

    function load(container, result) {

        var multivalue = false;
        var hint_span = null;
        var dd;

        var dt = $('dt[title='+that.name+']', container);
        if (!dt.length) return;

        var param_info = ipa_get_param_info(that.entity_name, that.name);
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

        var value = result[that.name];
        var rights = 'rsc';
        if (result.attributelevelrights){
            rights = result.attributelevelrights[this.name] || rights ;
        }
        if (value) {
            dd = ipa_create_first_dd(
                that.name,ipa_create_input(
                    that.entity_name, that.name, value[0],hint_span,rights)
            );
            dt.after(dd);
            var last_dd = dd;
            for (var i = 1; i < value.length; ++i) {
                dd = ipa_create_other_dd(
                    that.name, ipa_create_input(that.entity_name, that.name,
                                                value[i],hint_span,rights)
                );
                last_dd.after(dd);
                last_dd = dd;
            }
            if (multivalue && IPA.is_field_writable(rights) ) {
                dd = ipa_create_other_dd(
                    that.name, _ipa_a_add_template.replace('A', that.name)
                );
                last_dd.after(dd);
            }
        } else {
            if (multivalue  && IPA.is_field_writable(rights)) { 
                dd = ipa_create_first_dd(
                    that.name, _ipa_a_add_template.replace('A', that.name)
                );
                dt.after(dd);
            } else {
                dd = ipa_create_first_dd(
                    that.name, ipa_create_input(
                        that.entity_name, that.name,'',hint_span,rights)
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
    that.template = spec.template;
    that._entity_name = spec.entity_name;

    that.setup = spec.setup || ipa_details_section_setup;
    that.create = spec.create || ipa_details_section_create;
    that.load = spec.load || ipa_details_section_load;

    that.fields = [];
    that.fields_by_name = {};

    that.super = function(name) {
        var method = that[name];
        return function () {
            return method.apply(that, arguments);
        };
    };

    that.__defineGetter__("entity_name", function(){
        return that._entity_name;
    });

    that.__defineSetter__("entity_name", function(entity_name){
        that._entity_name = entity_name;

        for (var i=0; i<that.fields.length; i++) {
            that.fields[i].entity_name = entity_name;
        }
    });

    that.get_fields = function() {
        return that.fields;
    };

    that.get_field = function(name) {
        return that.fields_by_name[name];
    };

    that.add_field = function(field) {
        field.entity_name = that.entity_name;
        that.fields.push(field);
        that.fields_by_name[field.name] = field;
    };

    that.create_field = function(spec) {
        var field = ipa_details_field(spec);
        that.add_field(field);
        return field;
    };

    that.create_text = function(spec) {
        var field = ipa_text_widget(spec);
        that.add_field(field);
        return field;
    };

    that.create_radio = function(spec) {
        var field = ipa_radio_widget(spec);
        that.add_field(field);
        return field;
    };

    that.create_textarea = function(spec) {
        var field = ipa_textarea_widget(spec);
        that.add_field(field);
        return field;
    };

    that.create_button = function(spec) {
        var field = ipa_button_widget(spec);
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

    that.init = spec.init || init;
    that.is_dirty = spec.is_dirty || ipa_details_is_dirty;
    that.setup = spec.setup || ipa_details_setup;
    that.create = spec.create || ipa_details_create;

    that.sections = [];
    that.sections_by_name = {};

    that.__defineGetter__("entity_name", function(){
        return that._entity_name;
    });

    that.__defineSetter__("entity_name", function(entity_name){
        that._entity_name = entity_name;

        for (var i=0; i<that.sections.length; i++) {
            that.sections[i].entity_name = entity_name;
        }
    });

    that.get_sections = function() {
        return that.sections;
    };

    that.get_section = function(name) {
        return that.sections_by_name[name];
    };

    that.add_section = function(section) {
        section.entity_name = that.entity_name;
        that.sections.push(section);
        that.sections_by_name[section.name] = section;
    };

    that.create_section = function(spec) {
        var section = ipa_details_section(spec);
        that.add_section(section);
        return section;
    };

    function init() {
    }

    return that;
}

function ipa_button(spec) {

    spec = spec || {};

    var button = $('<a/>', {
        'id': spec.id,
        'html': spec.label,
        'class': 'ui-state-default ui-corner-all input_link'
    });

    if (spec.click) button.click(spec.click);
    if (spec.class) button.addClass(spec.class);
    if (spec.icon) button.append('<span class="ui-icon '+spec.icon+'" ></span> ');

    return button;
}

function ipa_details_is_dirty() {
    var pkey = $.bbq.getState(this.entity_name + '-pkey', true) || '';
    return pkey != this.pkey;
}

function ipa_details_setup(container, unspecified) {

    var facet = this;

    facet.setup_views(container);

    facet.pkey = $.bbq.getState(facet.entity_name + '-pkey', true) || '';
    if (!facet.pkey && !unspecified) return;

    function on_success(data, text_status, xhr) {
        var result = data.result.result;

        ipa_details_cache[facet.entity_name] = $.extend(true, {}, result);
        facet.create(container, result);
    }

    function on_failure(xhr, text_status, error_thrown) {
        var details = $('.details', container).empty();
        details.append('<p>Error: '+error_thrown.name+'</p>');
        details.append('<p>'+error_thrown.title+'</p>');
        details.append('<p>'+error_thrown.message+'</p>');
    }

    var params = [];
    if (facet.pkey) params.push(facet.pkey);

    ipa_cmd(
        'show', params, {all: true, rights: true}, on_success, on_failure, facet.entity_name
    );
}

function ipa_details_create(container, result)
{
    var facet = this;

    if (!container) {
        alert('ERROR: ipa_details_create: Missing container argument!');
        return;
    }

    var entity_name = container.attr('id');
    container.attr('title', entity_name);

    var details = $('<div/>', {
        'class': 'details'
    }).appendTo(container);

    var buttons = $('<div/>', {
        'class': 'details-buttons'
    }).appendTo(details);

    buttons.append(ipa_button({
        'label': 'Reset',
        'icon': 'ui-icon-refresh',
        'class': 'details-reset',
        'click': function() {
            ipa_details_reset(container);
            return false;
        }
    }));

    var pkey_name = IPA.metadata[facet.entity_name].primary_key;

    buttons.append(ipa_button({
        'label': 'Update',
        'icon': 'ui-icon-check',
        'class': 'details-update',
        'click': function() {
            ipa_details_update(container, ipa_details_cache[facet.entity_name][pkey_name][0]);
            return false;
        }
    }));

    details.append('<br/>');
    details.append('<hr/>');

    for (var i = 0; i < facet.sections.length; ++i) {
        var section = facet.sections[i];

        details.append($('<h2/>',{
            click: function(){_h2_on_click(this)},
            html:"&#8722; "+section.label
        }));

        var div = $('<div/>', {
            'id': facet.entity_name+'-'+facet.name+'-'+section.name,
            'class': 'details-section'
        }).appendTo(details);

        section.setup(div, result);

        details.append('<hr/>');
    }
}


function ipa_details_section_setup(container, result) {
    var section = this;
    var fields = section.get_fields();

    if (section.template) {
        var template = IPA.get_template(section.template);
        container.load(template, function(data, text_status, xhr) {
            for (var i = 0; i < fields.length; ++i) {
                var field = fields[i];
                field.create(container);
                field.setup(container);
                field.load(container, result);
            }
        });
        return;
    }

    section.create(container);

    for (var i = 0; i < fields.length; ++i) {
        var field = fields[i];
        field.create(container);
        field.setup(container);
        field.load(container, result);
    }
}

function ipa_details_section_create(container, result) {
    var section = this;

    var dl = $('<dl/>', {
        'id': section.name,
        'class': 'entryattrs'
    }).appendTo(container);
}

function ipa_details_section_load(container, result) {
    var section = this;
    var fields = section.get_fields();

    for (var j=0; j<fields.length; j++) {
        var field = fields[j];
        field.load(container, result);
    }
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
    var modlist = {'all': true, 'setattr': [], 'addattr': [], 'rights': true};
    var attrs_wo_option = {};

    var facet = ipa_entity_get_details_facet(obj_name);
    var sections = facet.get_sections();
    for (var i=0; i<sections.length; i++) {
        var section = sections[i];
        var fields = section.get_fields();

        var div = $('#'+facet.entity_name+'-'+facet.name+'-'+section.name, container);

        for (var j=0; j<fields.length; j++) {
            var field = fields[j];

            values = field.save(div);

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
 *   result - 'result' field as returned by ipa *-show commnads
 *                 (basically an associative array with attr:value pairs) */
function ipa_details_display(container, result)
{
    var entity_name = container.attr('id');

    /* remove all <dd> tags i.e. all attribute values */
    $('dd', container).remove();

    /* go through all <dt> tags and pair them with newly created <dd>s */
    var facet = ipa_entity_get_details_facet(entity_name);
    var sections = facet.get_sections();
    for (var i=0; i<sections.length; i++) {
        var section = sections[i];

        var div = $('#'+facet.entity_name+'-'+facet.name+'-'+section.name, container);

        section.load(div, result);
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
function ipa_create_input(entity_name, attr, value,hint,rights)
{
    var input = $("<label>",{html:value.toString()});
    var param_info = ipa_get_param_info(entity_name, attr);
    if (!param_info) {
        /* no information about the param is available, default to text input */
        input = _ipa_create_text_input(attr, value, null,rights);
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
            input = handler(attr, value, param_info,rights);
            if ((param_info['multivalue'] ||
                 param_info['class'] == 'List') &&
                IPA.is_field_writable(rights)){
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
function _ipa_create_text_input(attr, value, param_info, rights)
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

    var span = $("<Span />");
    var input = $("<input/>",{
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
    }).appendTo(span) ;

    if (!IPA.is_field_writable(rights)){
        input.attr('disabled', 'disabled');
    }

    span.append($("<a/>",{
        html:"undo",
        "class":"ui-state-highlight ui-corner-all",
        style:"display:none",
        click: function(){
            var key = this.previousElementSibling.name;
            var entity_divs = $(this).parents('.entity-container');
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
    span.append($("<span/>",{
        html:"Does not match pattern",
        "class":"ui-state-error ui-corner-all",
        style:"display:none"
    }));
    return span;
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
    var obj_name = jobj.closest('.entity-container').attr('title');

    var param_info = ipa_get_param_info(obj_name, '');
    //TODO rights need to be inherited
    //And used to control  presnece of the add link 
    var input = _ipa_create_text_input(attr, '', param_info, 'rswco');

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

