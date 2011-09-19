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

    that.entity = spec.entity;
    that.name = spec.name;
    that.id = spec.id;
    that.title = spec.title;
    that.width = spec.width || 400;
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
        return field;
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
            entity : that.entity
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

    /**
     * Create content layout
     */
    that.create = function() {

        var table = $('<table/>', {
            'class': 'section-table'
        }).appendTo(that.container);

        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            if (field.hidden) continue;

            var tr = $('<tr/>').appendTo(table);

            var td = $('<td/>', {
                'class': 'section-cell-label'
            }).appendTo(tr);

            $('<label/>', {
                name: field.name,
                title: field.label,
                'class': 'field-label',
                text: field.label+':'
            }).appendTo(td);

            td = $('<td/>', {
                'class': 'section-cell-field'
            }).appendTo(tr);

            var field_container = $('<div/>', {
                name: field.name,
                title: field.label,
                'class': 'field'
            }).appendTo(td);

            field.create(field_container);

            if (field.optional) {
                field_container.css('display', 'none');

                var link = $('<a/>', {
                    text: IPA.messages.widget.optional,
                    href: ''
                }).appendTo(td);

                link.click(function(field_container, link) {
                    return function() {
                        field_container.css('display', 'inline');
                        link.css('display', 'none');
                        return false;
                    };
                }(field_container, link));
            }

        }

        var sections = that.sections.values;
        for (var j=0; j<sections.length; j++) {
            var section = sections[j];

            var div = $('<div/>', {
                name: section.name,
                'class': 'dialog-section'
            }).appendTo(that.container);

            section.create(div);
        }

    };


    /**
     * Open dialog
     */
    that.open = function(container) {

        that.container = $('<div/>', { id : that.id });
        if (container) {
            container.append(that.container);
        }

        that.create();
        that.reset();

        that.container.dialog({
            title: that.title,
            modal: true,
            width: that.width,
            minWidth: that.width,
            height: that.height,
            minHeight: that.height,
            buttons: that.buttons,
            close: function(event, ui) {
                that.close();
            }
        });
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

    that.dialog_create = that.create;
    that.dialog_open = that.open;
    that.dialog_close = that.close;
    that.dialog_save = that.save;
    that.dialog_reset = that.reset;

    var fields = spec.fields || [];
    for (var i=0; i<fields.length; i++) {
        var field_spec = fields[i];
        var field;

        if (field_spec instanceof Object) {
            var factory = field_spec.factory || IPA.text_widget;
            field_spec.entity = that.entity;
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
            field = IPA.text_widget({
                name: field_spec,
                entity:that.entity,
                undo: false });
            that.add_field(field);
        }
    }

    return that;
};

/**
 * This dialog provides an interface for searching and selecting
 * values from the available results.
 */
IPA.adder_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.dialog(spec);
    that.external = spec.external;
    that.width = spec.width || 600;
    that.height = spec.height || 360;

    if (!that.entity) {
        var except = {
            expected: false,
            message:'Adder dialog created without entity.'
        };
        throw except;
    }

    var init = function() {
        that.available_table = IPA.table_widget({
            entity: that.entity,
            name: 'available',
            scrollable: true
        });

        that.selected_table = IPA.table_widget({
            entity: that.entity,
            name: 'selected',
            scrollable: true
        });

        if (spec.columns) {
            for (var i=0; i<spec.columns.length; i++) {
                that.create_column(spec.columns[i]);
            }
        }
    };

    that.get_column = function(name) {
        return that.available_table.get_column(name);
    };

    that.get_columns = function() {
        return that.available_table.get_columns();
    };

    that.add_column = function(column) {
        that.available_table.add_column(column);
        that.selected_table.add_column(column);
    };

    that.set_columns = function(columns) {
        that.clear_columns();
        for (var i=0; i<columns.length; i++) {
            that.add_column(columns[i]);
        }
    };

    that.clear_columns = function() {
        that.available_table.clear_columns();
        that.selected_table.clear_columns();
    };

    that.create_column = function(spec) {
        spec.entity = that.entity;
        var column = IPA.column(spec);
        that.add_column(column);
        return column;
    };

    that.create = function() {

        // do not call that.dialog_create();

        var container = $('<div/>', {
            'class': 'adder-dialog'
        }).appendTo(that.container);

        var top_panel = $('<div/>', {
            'class': 'adder-dialog-top'
        }).appendTo(container);

        $('<input/>', {
            type: 'text',
            name: 'filter'
        }).appendTo(top_panel);

        top_panel.append(' ');

        $('<input/>', {
            type: 'button',
            name: 'find',
            value: IPA.messages.buttons.find
        }).appendTo(top_panel);

        top_panel.append(IPA.create_network_spinner());

        var left_panel = $('<div/>', {
            'class': 'adder-dialog-left'
        }).appendTo(container);

        var available_panel = $('<div/>', {
            name: 'available',
            'class': 'adder-dialog-available'
        }).appendTo(left_panel);

        $('<div/>', {
            html: IPA.messages.dialogs.available,
            'class': 'adder-dialog-header ui-widget-header'
        }).appendTo(available_panel);

        var available_content = $('<div/>', {
            'class': 'adder-dialog-content'
        }).appendTo(available_panel);

        that.available_table.create(available_content);


        var right_panel = $('<div/>', {
            'class': 'adder-dialog-right'
        }).appendTo(container);

        var selected_panel = $('<div/>', {
            name: 'selected',
            'class': 'adder-dialog-selected'
        }).appendTo(right_panel);

        $('<div/>', {
            html: IPA.messages.dialogs.prospective,
            'class': 'adder-dialog-header ui-widget-header'
        }).appendTo(selected_panel);

        var selected_content = $('<div/>', {
            'class': 'adder-dialog-content'
        }).appendTo(selected_panel);

        that.selected_table.create(selected_content);


        var buttons_panel = $('<div/>', {
            name: 'buttons',
            'class': 'adder-dialog-buttons'
        }).appendTo(container);

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


        that.filter_field = $('input[name=filter]', that.container);

        var button = $('input[name=find]', that.container);
        that.find_button = IPA.button({
            name: 'find',
            'label': button.val(),
            'click': function() {
                that.search();
                return false;
            }
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

        if (that.external) {
            container.addClass('adder-dialog-with-external');

            var external_panel = $('<div/>', {
                name: 'external',
                'class': 'adder-dialog-external'
            }).appendTo(left_panel);

            $('<div/>', {
                html: IPA.messages.objects.sudorule.external,
                'class': 'adder-dialog-header ui-widget-header'
            }).appendTo(external_panel);

            var external_content = $('<div/>', {
                'class': 'adder-dialog-content'
            }).appendTo(external_panel);

            that.external_field = $('<input/>', {
                type: 'text',
                name: 'external'
            }).appendTo(external_content);

        }

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

    init();

    that.adder_dialog_create = that.create;

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
        that.values = values;
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

    that.deleter_dialog_create = that.create;

    return that;
};

IPA.message_dialog = function(spec) {

    var that = IPA.dialog(spec);

    var init = function() {
        spec = spec || {};
        that.message = spec.message || '';
        that.on_ok = spec.on_ok;
    };

    that.create = function() {
        $('<p/>', {
            'text': that.message
        }).appendTo(that.container);
    };

    that.add_button(IPA.messages.buttons.ok, function() {
        that.close();
        if(that.on_ok) {
            that.on_ok();
        }
    });

    init();

    return that;
};
