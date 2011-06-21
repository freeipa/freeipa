/*jsl:import ipa.js */
/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
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

/* REQUIRES: widget.js */

/**
 * This is a base class for dialog boxes.
 */
IPA.dialog = function(spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.title = spec.title;
    that.template = spec.template;
    that._entity_name = spec.entity_name;

    that.width = spec.width || '400px';
    that.height = spec.height;

    that.buttons = {};

    that.fields = $.ordered_map();
    that.sections = $.ordered_map();

    that.conditional_fields = [];

    that.enable_conditional_fields = function(){
        for (var i =0; i < that.conditional_fields.length; i+=1) {
            $('label[id='+
               that.conditional_fields[i] +'-label]',
              that.container).css('visibility','visible');
            $('input[name='+
               that.conditional_fields[i] +
              ']',that.container).css('visibility','visible');
        }
    };

    that.disable_conditional_fields = function(){
        for (var i =0; i < that.conditional_fields.length; i+=1) {
            $('label[id='+
               that.conditional_fields[i] +'-label]',
              that.container).css('visibility','hidden');

            $('input[name='+
              that.conditional_fields[i] +
              ']',that.container).css('visibility','hidden');
        }
    };

    that.__defineGetter__("entity_name", function(){
        return that._entity_name;
    });

    that.__defineSetter__("entity_name", function(entity_name){
        that._entity_name = entity_name;

        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            fields[i].entity_name = entity_name;
        }

        var sections = that.sections.values;
        for (var j=0; j<sections.length; j++) {
            sections[j].entity_name = entity_name;
        }
    });

    that.add_button = function(name, handler) {
        that.buttons[name] = handler;
    };

    that.get_field = function(name) {
        return that.fields.get(name);
    };

    that.add_field = function(field) {
        field.dialog = that;
        that.fields.put(field.name, field);
        if (field.conditional){
            that.conditional_fields.push(field.name);
        }

    };

    that.field = function(field) {
        that.add_field(field);
        return that;
    };

    that.is_valid = function() {
        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            if (!field.valid) return false;
        }
        return true;
    };

    that.text = function(name){
        that.field(IPA.text_widget({
            name: name,
            undo: false,
            entity_name : that.entity_name
        }));
        return that;
    };

    that.add_section = function(section) {
        that.sections.put(section.name, section);
        return that;
    };

    that.section = function(section) {
        that.add_section(section);
        return that;
    };

    that.create_section = function(spec) {
        var section = IPA.details_section(spec);
        that.add_section(section);
        return section;
    };

    that.init = function() {

        that.entity = IPA.get_entity(that.entity_name);

        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            field.entity_name = that.entity_name;
            field.init();
        }

        var sections = that.sections.values;
        for (var j=0; j<sections.length; j++) {
            var section = sections[j];
            section.entity_name = that.entity_name;
            section.init();
        }
    };

    /**
     * Create content layout
     */
    that.create = function() {

        var table = $('<table/>').appendTo(that.container);

        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            if (field.hidden) continue;

            var tr = $('<tr/>').appendTo(table);

            var td = $('<td/>', {
                style: 'vertical-align: top;',
                title: field.label
            }).appendTo(tr);
            td.append($('<label />',{id: field.name+'-label',
                                     text:field.label+': '}));

            td = $('<td/>', {
                style: 'vertical-align: top;'
            }).appendTo(tr);

            var span = $('<span/>', { 'name': field.name }).appendTo(td);
            field.create(span);
        }

        var sections = that.sections.values;
        for (var j=0; j<sections.length; j++) {
            var section = sections[j];

            var div = $('<div/>', {
                name: section.name,
                'class': 'details-section'
            }).appendTo(that.container);

            section.create(div);
        }
    };

    /**
     * Setup behavior
     */
    that.setup = function() {
        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];

            var span = $('span[name="'+field.name+'"]', that.container);
            field.setup(span);
        }

        var sections = that.sections.values;
        for (var j=0; j<sections.length; j++) {
            var section = sections[j];

            var div = $('div.details-section[name='+section.name+']',
                that.container);

            section.setup(div);
        }
    };

    /**
     * Open dialog
     */
    that.open = function(container) {

        that.container = $('<div/>');

        if (container) {
            container.append(that.container);
        }

        if (that.template) {
            var template = IPA.get_template(that.template);
            that.container.load(
                template,
                function(data, text_status, xhr) {
                    that.setup();
                    that.container.dialog({
                        'title': that.title,
                        'modal': true,
                        'width': that.width,
                        'height': that.height,
                        'buttons': that.buttons,
                        close: function(event, ui) {
                            that.close();
                        }
                    });
                }
            );

        } else {
            that.create();
            that.setup();

            that.container.dialog({
                'title': that.title,
                'modal': true,
                'width': that.width,
                'height': that.height,
                'buttons': that.buttons,
                close: function(event, ui) {
                    that.close();
                }
            });
        }
    };

    that.option = function(name, value) {
        that.container.dialog('option', name, value);
    };

    that.save = function(record) {
        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            var values = field.save();
            record[field.name] = values.join(',');
        }

        var sections = that.sections.values;
        for (var j=0; j<sections.length; j++) {
            var section = sections[j];

            if (section.save) {
                section.save(record);
            }
        }
    };

    that.close = function() {
        that.container.dialog('destroy');
        that.container.remove();
    };

    that.reset = function() {
        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            field.reset();
        }

        var sections = that.sections.values;
        for (var j=0; j<sections.length; j++) {
            sections[j].reset();
        }
    };

    that.dialog_init = that.init;
    that.dialog_create = that.create;
    that.dialog_setup = that.setup;
    that.dialog_open = that.open;

    var fields = spec.fields || [];
    for (var i=0; i<fields.length; i++) {
        var field_spec = fields[i];
        var field;

        if (field_spec instanceof Object) {
            var factory = field_spec.factory || IPA.text_widget;
            field = factory(field_spec);

            /* This is a bit of a hack, and is here to support ACI
               permissions. The target section is a group of several
               widgets together. It makes more sense to do them as a
               section than as a widget. However, since they can be mixed
               into the flow with the other widgets, the section needs to
               be defined here with the fields to get the order correct.*/
            if (field.section) {
                that.add_section(field);
            } else {
                that.add_field(field);
            }

        } else {
            field = IPA.text_widget({ name: field_spec, undo: false });
            that.add_field(field);
        }
    }

    return that;
};

/**
 * This dialog provides an interface for searching and selecting
 * values from the available results.
 */
IPA.adder_dialog = function (spec) {

    spec = spec || {};

    var that = IPA.dialog(spec);

    that.width = spec.width || '600px';

    that.columns = $.ordered_map();

    that.get_column = function(name) {
        return that.columns.get(name);
    };

    that.add_column = function(column) {
        that.columns.put(column.name, column);
    };

    that.set_columns = function(columns) {
        that.clear_columns();
        for (var i=0; i<columns.length; i++) {
            that.add_column(columns[i]);
        }
    };

    that.clear_columns = function() {
        that.columns.empty();
    };

    that.create_column = function(spec) {
        var column = IPA.column(spec);
        that.add_column(column);
        return column;
    };

    that.init = function() {
        that.available_table = IPA.table_widget({
            name: 'available',
            scrollable: true,
            height: '151px'
        });

        var columns = that.columns.values;
        that.available_table.set_columns(columns);

        that.available_table.init();

        that.selected_table = IPA.table_widget({
            name: 'selected',
            scrollable: true,
            height: '151px'
        });

        that.selected_table.set_columns(columns);

        that.selected_table.init();

        that.dialog_init();
    };

    that.create = function() {

        // do not call that.dialog_create();

        var search_panel = $('<div/>', {
            'class': 'adder-dialog-filter'
        }).appendTo(that.container);

        $('<input/>', {
            type: 'text',
            name: 'filter',
            style: 'width: 244px'
        }).appendTo(search_panel);

        search_panel.append(' ');

        $('<input/>', {
            type: 'button',
            name: 'find',
            value: 'Find'
        }).appendTo(search_panel);

        $('<input/>', {
            type: 'checkbox',
            name: 'hidememb',
            id: 'hidememb',
            checked: 'checked',
            style: 'margin-left: 5px; vertical-align: middle'
        }).appendTo(search_panel);

        var label = $('<label/>', {
            'for': 'hidememb',
            style: 'margin-left: 3px'
        });

        label.text(IPA.messages.dialogs.hide_already_enrolled);

        label.appendTo(search_panel);

        search_panel.append(IPA.create_network_spinner());

        var results_panel = $('<div/>', {
            'class': 'adder-dialog-results'
        }).appendTo(that.container);

        var available_panel = $('<div/>', {
            name: 'available',
            'class': 'adder-dialog-available'
        }).appendTo(results_panel);

        $('<div/>', {
            html: IPA.messages.dialogs.available,
            'class': 'ui-widget-header'
        }).appendTo(available_panel);

        that.available_table.create(available_panel);

        var buttons_panel = $('<div/>', {
            name: 'buttons',
            'class': 'adder-dialog-buttons'
        }).appendTo(results_panel);

        var p = $('<p/>').appendTo(buttons_panel);
        $('<input />', {
            type: 'button',
            name: 'remove',
            value: '<<'
        }).appendTo(p);

        p = $('<p/>').appendTo(buttons_panel);
        $('<input />', {
            type: 'button',
            name: 'add',
            value: '>>'
        }).appendTo(p);

        var selected_panel = $('<div/>', {
            name: 'selected',
            'class': 'adder-dialog-selected'
        }).appendTo(results_panel);

        $('<div/>', {
            html: IPA.messages.dialogs.prospective,
            'class': 'ui-widget-header'
        }).appendTo(selected_panel);

        that.selected_table.create(selected_panel);
    };

    that.setup = function() {

        // do not call that.dialog_setup();

        var available_panel = $('div[name=available]', that.container);
        that.available_table.setup(available_panel);

        var selected_panel = $('div[name=selected]', that.container);
        that.selected_table.setup(selected_panel);

        that.filter_field = $('input[name=filter]', that.container);

        var button = $('input[name=find]', that.container);
        that.find_button = IPA.button({
            name: 'find',
            'label': button.val(),
            'icon': 'ui-icon-search',
            'click': function() { that.search(); }
        });
        button.replaceWith(that.find_button);

        button = $('input[name=remove]', that.container);
        that.remove_button = IPA.button({
            name: 'remove',
            'label': button.val(),
            'click': function() {
                that.remove();
                return false;
            }
        });
        button.replaceWith(that.remove_button);

        button = $('input[name=add]', that.container);
        that.add_button = IPA.button({
            name: 'add',
            'label': button.val(),
            'click': function() {
                that.add();
                return false;
            }
        });
        button.replaceWith(that.add_button);

        that.search();
    };

    that.open = function(container) {

        that.buttons[IPA.messages.buttons.enroll] = that.execute;
        that.buttons[IPA.messages.buttons.cancel] = that.close;

        that.dialog_open(container);
    };

    that.add = function() {
        var rows = that.available_table.remove_selected_rows();
        that.selected_table.add_rows(rows);
    };

    that.remove = function() {
        var rows = that.selected_table.remove_selected_rows();
        that.available_table.add_rows(rows);
    };

    that.get_filter = function() {
        return that.filter_field.val();
    };

    that.get_hide_checkbox = function() {
        return that.hide_checkbox.checked;
    };

    that.clear_available_values = function() {
        that.available_table.empty();
    };

    that.clear_selected_values = function() {
        that.selected_table.empty();
    };

    that.add_available_value = function(record) {
        that.available_table.add_record(record);
    };

    that.get_selected_values = function() {
        return that.selected_table.save();
    };

    that.adder_dialog_init = that.init;
    that.adder_dialog_create = that.create;
    that.adder_dialog_setup = that.setup;

    return that;
};

/**
 * This dialog displays the values to be deleted.
 */
IPA.deleter_dialog =  function (spec) {

    spec = spec || {};

    var that = IPA.dialog(spec);

    that.title = spec.title || IPA.messages.buttons.remove;

    that.values = spec.values || [];

    that.add_value = function(value) {
        that.values.push(value);
    };

    that.set_values = function(values) {
        that.values = that.values.concat(values);
    };

    that.create = function() {

        $('<p/>', {
            'text': IPA.messages.search.delete_confirm
        }).appendTo(that.container);

        var div = $('<div/>', {
            style: 'overflow:auto; max-height: 100px'
        }).appendTo(that.container);

        var ul = $('<ul/>');
        ul.appendTo(div);

        for (var i=0; i<that.values.length; i++) {
            var value = that.values[i];
            if (value instanceof Object){
                var first = true;
                var str_value = "";
                for (var key in value){
                    if (value.hasOwnProperty(key)){
                        if (!first){
                            str_value += ',';
                        }
                        str_value += (key + ':' +value[key]);
                        first = false;
                    }
                }
                value = str_value;
            }

            $('<li/>',{
                'text': value
            }).appendTo(ul);
        }
    };

    that.open = function(container) {

        that.buttons[IPA.messages.buttons.remove] = that.execute;
        that.buttons[IPA.messages.buttons.cancel] = that.close;

        that.dialog_open(container);
    };

    return that;
};
