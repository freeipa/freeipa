/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *    Endi S. Dewata <edewata@redhat.com>
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

/* IPA Object Details - populating definiton lists from entry data */

/* REQUIRES: ipa.js */

IPA.expand_icon = 'ui-icon-minus';
IPA.collapse_icon = 'ui-icon-plus';

IPA.is_field_writable = function(rights){
    if (!rights){
        alert('no right');
    }
    return rights.indexOf('w') > -1;
};

IPA.details_field =  function (spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.load = spec.load || load;
    that.save = spec.save || save;

    function load(record) {
        that.record = record;
        that.values = record[that.name];
        that.reset();
    }

    that.update = function() {

        if (!that.record) return;

        /* remove all <dd> tags i.e. all attribute values */
        $('dd', that.container).remove();

        var multivalue = false;
        var hint_span = null;
        var dd;

        var param_info = IPA.get_param_info(that.entity_name, that.name);
        if (param_info) {
            if (param_info['multivalue'] || param_info['class'] == 'List')
                multivalue = true;
            var hint = param_info['doc'];
            if (hint){
                hint_span = $('<span />',{
                    'class': 'attrhint',
                    'html': 'Hint: ' + hint});
            }
        }

        var rights = 'rsc';

        if (that.record.attributelevelrights){
            rights = that.record.attributelevelrights[this.name] || rights ;
        }

        if (that.values) {
            /*
              Too much logic currently assumes an array.
              This is true everywhere but ACIs. */

            if (!(that.values instanceof Array)){
                that.values = [that.values];
            }

            dd = IPA.create_first_dd(that.name);
            dd.append(that.create_value(that.values[0], hint_span, rights, 0));
            dd.appendTo(that.container);

            for (var i = 1; i < that.values.length; ++i) {
                dd = IPA.create_other_dd(that.name);
                dd.append(that.create_value(that.values[i], hint_span, rights, i));
                dd.appendTo(that.container);
            }

            if (multivalue && IPA.is_field_writable(rights) ) {
                dd = IPA.create_other_dd(that.name);
                dd.append(IPA.details_field_create_add_link.call(that, that.name, rights, that.values.length));
                dd.appendTo(that.container);
            }

        } else {
            if (multivalue  && IPA.is_field_writable(rights)) {
                dd = IPA.create_first_dd(that.name);
                dd.append(IPA.details_field_create_add_link.call(that, that.name, rights, 0));
                dd.appendTo(that.container);

            } else {
                dd = IPA.create_first_dd(that.name);
                dd.append(that.create_value('', hint_span, rights, 0));
                dd.appendTo(that.container);
            }
        }
    };

    /* create an HTML element for displaying/editing an attribute
     * arguments:
     *   attr - LDAP attribute name
     *   value - the attributes value */
    that.create_value = function(value, hint, rights, index) {

        // if field is primary key or non-writable, return a label

        var label = $('<label/>', { html:value.toString() });

        if (!IPA.is_field_writable(rights)) return label;

        var param_info = IPA.get_param_info(that.entity_name, that.name);
        if (param_info) {
            if (param_info['primary_key']) return label;
            if ('no_update' in param_info['flags']) return label;
        }

        // otherwise, create input field

        var input = that.create_input(value, param_info, rights, index);
        if (param_info) {
            if (param_info['multivalue'] || param_info['class'] == 'List') {
                input.append(_ipa_create_remove_link(that.name, param_info));
            }
        }

        if (hint) input.after(hint);

        return input;
    };

    /* creates a input box for editing a string attribute */
    that.create_input = function(value, param_info, rights, index) {

        index = index || 0;

        function validate_input(text, param_info, error_link) {
            if (param_info && param_info.pattern) {
                var regex = new RegExp( param_info.pattern );
                if (!text.match(regex)) {
                    error_link.style.display = "block";
                    if (param_info.pattern_errmsg) {
                        error_link.innerHTML =  param_info.pattern_errmsg;
                    }
                } else {
                    error_link.style.display = "none";
                }
            }
        }

        var doc = that.name;
        if (param_info && param_info.doc) {
            doc = param_info.doc;
        }
        var span = $("<Span />");
        var input = $("<input/>", {
            type: "text",
            name: that.name,
            value: value.toString(),
            title: doc,
            keyup: function(){
                var undo_link = this.nextElementSibling;
                undo_link.style.display = "inline";
                var error_link = undo_link.nextElementSibling;

                var text = $(this).val();
                validate_input(text, param_info,error_link);
            }
        }).appendTo(span) ;

        if (!IPA.is_field_writable(rights)) {
            input.attr('disabled', 'disabled');
        }

        span.append($("<a/>", {
            html:"undo",
            "class":"ui-state-highlight ui-corner-all undo",
            style:"display:none",
            click: function(){
                var previous_value = that.values || '';
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
        span.append($("<span/>", {
            html:"Does not match pattern",
            "class":"ui-state-error ui-corner-all",
            style:"display:none"
        }));
        return span;
    };

    function save() {
        var values = [];

        $('dd', that.container).each(function () {

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

IPA.details_section = function (spec){

    spec = spec || {};

    var that = {};

    that.name = spec.name || '';
    that.label = spec.label || '';
    that.template = spec.template;
    that._entity_name = spec.entity_name;

    that.fields = [];
    that.fields_by_name = {};

    that.__defineGetter__("entity_name", function(){
        return that._entity_name;
    });

    that.__defineSetter__("entity_name", function(entity_name){
        that._entity_name = entity_name;

        for (var i=0; i<that.fields.length; i++) {
            that.fields[i].entity_name = entity_name;
        }
    });

    that.get_field = function(name) {
        return that.fields_by_name[name];
    };

    that.add_field = function(field) {
        field.entity_name = that.entity_name;
        that.fields.push(field);
        that.fields_by_name[field.name] = field;
        return field;
    };

    that.create_field = function(spec) {

        //TODO: replace IPA.details_field with class-specific implementation
        //Valid field classes: Str, IA5Str, Int, Bool and List
        var field = IPA.details_field(spec);
        that.add_field(field);
        return field;
    };

    that.create_text = function(spec) {
        var field = IPA.text_widget(spec);
        that.add_field(field);
        return field;
    };

    that.create_radio = function(spec) {
        var field = IPA.radio_widget(spec);
        that.add_field(field);
        return field;
    };

    that.create_textarea = function(spec) {
        var field = IPA.textarea_widget(spec);
        that.add_field(field);
        return field;
    };

    that.create_button = function(spec) {
        var field = IPA.button_widget(spec);
        that.add_field(field);
        return field;
    };

    that.init = function() {
        for (var i=0; i<that.fields.length; i++) {
            var field = that.fields[i];
            field.init();
        }
    };

    that.create = function(container) {

        if (that.template) return;

        var fields = that.fields;
        for (var i = 0; i < fields.length; ++i) {
            var field = fields[i];

            var span = $('<span/>', { 'name': field.name }).appendTo(container);
            field.create(span);
        }
    };

    that.setup = function(container) {

        that.container = container;

        if (that.template) return;

        var fields = that.fields;
        for (var i = 0; i < fields.length; ++i) {
            var field = fields[i];

            var span = $('span[name='+field.name+']', this.container).first();
            field.setup(span);
        }
    };

    that.load = function(record) {

        var fields = that.fields;

        if (that.template) {
            var template = IPA.get_template(that.template);
            this.container.load(
                template,
                function(data, text_status, xhr) {
                    for (var i = 0; i < fields.length; ++i) {
                        var field = fields[i];
                        var span = $('span[name='+field.name+']', this.container).first();
                        field.setup(span);
                        field.load(record);
                    }
                }
            );
            return;
        }

        for (var j=0; j<fields.length; j++) {
            var field = fields[j];
            var span = $('span[name='+field.name+']', this.container).first();
            field.load(record);
        }
    };

    that.reset = function() {
        for (var i=0; i<that.fields.length; i++) {
            var field = that.fields[i];
            var span = $('span[name='+field.name+']', this.container).first();
            field.reset();
        }
    };

    // methods that should be invoked by subclasses
    that.section_init = that.init;
    that.section_create = that.create;
    that.section_setup = that.setup;
    that.section_load = that.load;

    return that;
}

/**
 * This class creates a details section formatted as a list of
 * attributes names and values. The list is defined using <dl> tag.
 * The attribute name is defined inside a <dt> tag. The attribute
 * value is defined using a <dd> tag inside a <span> tag. If the
 * attribute has multiple values the content inside <span> will
 * be duplicated to display each value.
 *
 * Example:
 *   <dl class="entryattrs">
 *
 *     <dt title="givenname">First Name:</dt>
 *     <span name="givenname">
 *       <dd><input type="text" size="20"/></dd>
 *     </span>
 *
 *     <dt title="telephonenumber">Telephone Number:</dt>
 *     <span name="telephonenumber">
 *       <dd><input type="text" size="20"/></dd>
 *       <dd><input type="text" size="20"/></dd>
 *     </span>
 *
 *   </dl>
 */
IPA.details_list_section = function (spec){

    spec = spec || {};

    var that = IPA.details_section(spec);

    that.create = function(container) {

        // do not call section_create() here

        if (that.template) return;

        var dl = $('<dl/>', {
            'id': that.name,
            'class': 'entryattrs'
        }).appendTo(container);

        var fields = that.fields;
        for (var i = 0; i < fields.length; ++i) {
            var field = fields[i];

            var label = field.label;

            // no need to get i18n label from metadata
            // because it's already done by field.init()

            if (label !== '') {
                label += ':';
            }

            $('<dt/>', {
                html: label
            }).appendTo(dl);

            var span = $('<span/>', { 'name': field.name }).appendTo(dl);
            field.create(span);
        }
    };

    return that;
}

// shorthand notation used for declarative definitions of details pages
IPA.stanza =  function (spec) {

    spec = spec || {};

    var that = IPA.details_list_section(spec);

    // This is to allow declarative style programming for details
    that.input = function(spec) {
        that.create_field(spec);
        return that;
    };

    that.custom_input = function(input) {
        that.add_field(input);
        return that;
    };

    return that;
}

IPA.details_facet = function (spec) {

    spec = spec || {};

    var that = IPA.facet(spec);

    that.is_dirty = spec.is_dirty || is_dirty;
    that.create = spec.create || create;
    that.setup = spec.setup || setup;
    that.load = spec.load || load;
    that.update = spec.update || IPA.details_update;
    that.reset = spec.reset || reset;
    that.refresh = spec.refresh || IPA.details_refresh;

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

    that.get_section = function(name) {
        return that.sections_by_name[name];
    };

    that.add_section = function(section) {
        section.entity_name = that.entity_name;
        that.sections.push(section);
        that.sections_by_name[section.name] = section;
        return section;
    };

    that.create_section = function(spec) {
        var section = IPA.details_section(spec);
        that.add_section(section);
        return section;
    };

    that.init = function() {
        for (var i=0; i<that.sections.length; i++) {
            var section = that.sections[i];
            section.init();
        }
    };

    that.get_primary_key = function() {
        var pkey_name = IPA.metadata[that.entity_name].primary_key;
        if (that.record[pkey_name] instanceof Array){
            return that.record[pkey_name][0];
        }else{
            return that.record[pkey_name];
        }
    };

    that.get_section_header_prefix = function(visible) {
        if (visible) {
            return '<span class="ui-icon '+
                IPA.collapse_icon +
                ' section-expand" ></span>';
        } else {
            return '<span class="ui-icon '+
                IPA.expand_icon +
                ' section-expand" />';
        }
    };

    function create(container) {

        container.attr('title', that.entity_name);

        var details = $('<div/>', {
            'class': 'content'
        }).appendTo(container);

        var action_panel = that.get_action_panel();

        var ul = $('ul', action_panel);
        var buttons = $('.action-controls',action_panel);

        $('<input/>', {
            'type': 'text',
            'name': 'reset'
        }).appendTo(buttons);

        $('<input/>', {
            'type': 'text',
            'name': 'update'
        }).appendTo(buttons);

        details.append('<br/>');
        details.append('<hr/>');

        for (var i = 0; i < that.sections.length; ++i) {
            var section = that.sections[i];

            $('<h2/>', {
                name: section.name,
                title: section.label,
                html: that.get_section_header_prefix(true) + ' ' + section.label
            }).appendTo(details);

            var div = $('<div/>', {
                'id': that.entity_name+'-'+that.name+'-'+section.name,
                'class': 'details-section'
            }).appendTo(details);

            section.create(div);

            details.append('<hr/>');
        }
    }

    function setup(container) {

        that.facet_setup(container);

        var button = $('input[name=reset]', that.container);
        that.reset_button = IPA.action_button({
            'label': 'Reset',
            'icon': 'ui-icon-refresh',
            'class': 'details-reset',
            'click': function() {
                that.reset();
                return false;
            }
        });
        button.replaceWith(that.reset_button);

        button = $('input[name=update]', that.container);
        that.update_button = IPA.action_button({
            'label': 'Update',
            'icon': 'ui-icon-check',
            'class': 'details-update',
            'click': function() {
                that.update();
                return false;
            }
        });
        button.replaceWith(that.update_button);

        for (var i = 0; i < that.sections.length; ++i) {
            var section = that.sections[i];

            var header = $('h2[name='+section.name+']', that.container);

            var div = $('#'+that.entity_name+'-'+that.name+'-'+section.name,
                that.container);

            header.click(function(section, header, div) {
                return function() {
                    var visible = div.is(":visible");
                    header.html(that.get_section_header_prefix(!visible) + ' ' + section.label);
                    div.slideToggle();
                };
            }(section, header, div));

            section.setup(div);
        }
    }

    function is_dirty() {
        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        return pkey != that.pkey;
    }

    function load(record) {
        that.record = record;

        for (var i=0; i<that.sections.length; i++) {
            var section = that.sections[i];
            section.load(record);
        }
    }

    function reset() {
        for (var i=0; i<that.sections.length; i++) {
            var section = that.sections[i];
            section.reset();
        }
    }

    that.details_facet_init = that.init;
    that.details_facet_create = that.create;
    that.details_facet_load = that.load;

    return that;
}

IPA.action_button = function(spec) {
    var button = IPA.button(spec);
    button.removeClass("ui-state-default").addClass("action-button");
    return button;
};

IPA.button = function(spec) {

    spec = spec || {};

    var button = $('<a/>', {
        id: spec.id,
        html: spec.label,
        title: spec.title || spec.label,
        'class': 'ui-state-default ui-corner-all input_link'
    });

    if (spec.click) button.click(spec.click);
    if (spec['class']) button.addClass(spec['class']);
    if (spec.icon) button.append('<span class="ui-icon '+spec.icon+'" ></span> ');

    return button;
}

IPA.details_refresh =  function () {

    var that = this;

    that.pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

    function on_success(data, text_status, xhr) {
        that.load(data.result.result);
    }

    function on_failure(xhr, text_status, error_thrown) {
        var details = $('.details', that.container).empty();
        details.append('<p>Error: '+error_thrown.name+'</p>');
        details.append('<p>'+error_thrown.title+'</p>');
        details.append('<p>'+error_thrown.message+'</p>');
    }

    var params = [];
    if (that.pkey) params.push(that.pkey);

    IPA.cmd( 'show', params, {all: true, rights: true}, on_success, on_failure,
        that.entity_name );
}

IPA.details_update = function (on_win, on_fail)
{
    var that = this;
    var entity_name = that.entity_name;

    var pkey = that.get_primary_key();

    function update_on_win(data, text_status, xhr) {
        if (on_win)
            on_win(data, text_status, xhr);
        if (data.error)
            return;

        var result = data.result.result;
        that.load(result);
    }

    function update_on_fail(xhr, text_status, error_thrown) {
        if (on_fail)
            on_fail(xhr, text_status, error_thrown);
    }

    /*
      The check
      if (!pkey) {   return; }
      used to happen here, but it breaks krbtpolicy, which allows a null pkey
      and usually requires it.
    */

    var values;
    var modlist = {'all': true, 'setattr': [], 'addattr': [], 'rights': true};
    var attrs_wo_option = {};

    for (var i=0; i<that.sections.length; i++) {
        var section = that.sections[i];

        if (section.save){
            section.save(modlist);
            continue;
        }

        var div = $('#'+that.entity_name+'-'+that.name+'-'+section.name, that.container);

        for (var j=0; j<section.fields.length; j++) {
            var field = section.fields[j];

            var span = $('span[name='+field.name+']', div).first();
            values = field.save();
            if (!values) continue;

            var param_info = IPA.get_param_info(entity_name, field.name);
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
        for (var k = 1; k < values.length; ++k){
            modlist['addattr'].push(attr + '=' + values[k]);
        }
    }

    IPA.cmd('mod', [pkey], modlist, update_on_win, null, entity_name);
}


IPA.create_first_dd = function (field_name, content){
    var dd = $('<dd/>', {
        'class': 'first',
        'title': field_name
    });
    if (content) dd.append(content);
    return dd;
}

IPA.create_other_dd = function (field_name, content){
    return $('<dd/>', {
        'class': 'other',
        'title': field_name
    }).append(content);
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
        click: function (){return (_ipa_remove_on_click(this));},
        title: attr,
        text: 'Remove'});

}

IPA.details_field_create_add_link = function (title, rights, index) {

    var that = this;

    var link = $('<a/>', {
        'href': 'jslink',
        'title': title,
        'html': 'Add',
        'click': function () {

            var param_info = IPA.get_param_info(that.entity_name, '');
            var input = that.create_input('', param_info, rights, index);

            link.replaceWith(input);
            input.focus();

            var dd = IPA.create_other_dd(that.name);
            dd.append(IPA.details_field_create_add_link.call(that, that.name, rights, index+1));
            dd.appendTo(that.container);

            return false;
        }
    });

    return link;
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
