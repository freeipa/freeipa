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

IPA.dialog_button = function(spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.label = spec.label || spec.name;
    that.click = spec.click || click;

    function click() {
    }

    that.set_enabled = function(enabled) {
        if (enabled) {
            that.element.removeClass('ui-state-disabled');
        } else {
            that.element.addClass('ui-state-disabled');
        }
    };

    that.is_enabled = function() {
        return !that.element.hasClass('ui-state-disabled');
    };

    return that;
};

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
    that.width = spec.width || 500;
    that.height = spec.height;

    that.buttons = $.ordered_map();

    that.sections = $.ordered_map();

    var init = function() {

        var sections = spec.sections || [];

        for (var i=0; i<sections.length; i++) {
            var section_spec = sections[i];
            that.create_section(section_spec);
        }

        var fields = spec.fields || [];

        // add fields to the default section
        var section = that.get_section();
        section.add_fields(fields);
    };

    that.create_button = function(spec) {
        var factory = spec.factory || IPA.dialog_button;
        var button = factory(spec);
        that.add_button(button);
        return button;
    };

    that.add_button = function(button) {
        that.buttons.put(button.name, button);
    };

    that.get_button = function(name) {
        return that.buttons.get(name);
    };

    that.get_field = function(name) {
        for (var i=0; i<that.sections.length; i++) {
            var section = that.sections.values[i];
            var field = section.fields.get(name);
            if (field) return field;
        }
        return null;
    };

    that.get_fields = function() {
        var fields = [];
        for (var i=0; i<that.sections.length; i++) {
            var section = that.sections.values[i];
            $.merge(fields, section.fields.values);
        }
        return fields;
    };

    that.add_field = function(field) {
        var section = that.get_section();
        section.add_field(field);
        return field;
    };

    that.field = function(field) {
        that.add_field(field);
        return that;
    };

    that.is_valid = function() {
        for (var i=0; i<that.sections.length; i++) {
            var section = that.sections.values[i];
            if (!section.is_valid()) return false;
        }
        return true;
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

        var factory = spec.factory || IPA.details_table_section;
        spec.entity = that.entity;
        spec.undo = false;

        var section = factory(spec);
        that.add_section(section);

        return section;
    };

    that.get_section = function(name) {

        if (name) {
            return that.sections.get(name);

        } else {
            var length = that.sections.length;
            if (length) {
                // get the last section
                return that.sections.values[length-1];
            } else {
                // create a default section
                return that.create_section({ name: 'general' });
            }
        }
    };

    /**
     * Create content layout
     */
    that.create = function() {

        that.message_container = $('<div/>', {
            style: 'display: none',
            'class': 'dialog-message ui-state-highlight ui-corner-all'
        }).appendTo(that.container);

        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            var section = sections[i];

            var div = $('<div/>', {
                name: section.name,
                'class': 'dialog-section'
            }).appendTo(that.container);

            section.create(div);
        }

    };

    that.show_message = function(message) {
        that.message_container.text(message);
        that.message_container.css('display', '');
    };

    that.hide_message = function() {
        that.message_container.css('display', 'none');
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

        // create a map of button labels and handlers
        var dialog_buttons = {};
        for (var i=0; i<that.buttons.values.length; i++) {
            var button = that.buttons.values[i];
            dialog_buttons[button.label] = button.click;
        }

        that.container.dialog({
            title: that.title,
            modal: true,
            width: that.width,
            minWidth: that.width,
            height: that.height,
            minHeight: that.height,
            buttons: dialog_buttons,
            close: function(event, ui) {
                that.close();
            }
        });

        // find button elements
        var parent = that.container.parent();
        var buttons = $('.ui-dialog-buttonpane .ui-dialog-buttonset button', parent);

        buttons.each(function(index) {
            var button = that.buttons.values[index];
            button.element = $(this);
        });
    };

    that.option = function(name, value) {
        that.container.dialog('option', name, value);
    };

    that.save = function(record) {
        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            var section = sections[i];
            section.save(record);
        }
    };

    that.close = function() {
        that.container.dialog('destroy');
        that.container.remove();
    };

    that.reset = function() {
        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            sections[i].reset();
        }
    };

    init();

    that.dialog_create = that.create;
    that.dialog_open = that.open;
    that.dialog_close = that.close;
    that.dialog_save = that.save;
    that.dialog_reset = that.reset;

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

        that.find_button = IPA.button({
            name: 'find',
            label: IPA.messages.buttons.find,
            click: function() {
                that.search();
                return false;
            }
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
        IPA.button({
            name: 'add',
            label: '>>',
            click: function() {
                that.add();
                that.update_buttons();
                return false;
            }
        }).appendTo(p);

        p = $('<p/>').appendTo(buttons_panel);
        IPA.button({
            name: 'remove',
            label: '<<',
            click: function() {
                that.remove();
                that.update_buttons();
                return false;
            }
        }).appendTo(p);

        that.filter_field = $('input[name=filter]', that.container);

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

        var add_button = that.create_button({
            name: 'add',
            label: IPA.messages.buttons.enroll,
            click: function() {
                if (!add_button.is_enabled()) return;
                that.execute();
            }
        });

        that.create_button({
            name: 'cancel',
            label: IPA.messages.buttons.cancel,
            click: function() {
                that.close();
            }
        });

        that.dialog_open(container);

        that.update_buttons();
    };

    that.add = function() {
        var rows = that.available_table.remove_selected_rows();
        that.selected_table.add_rows(rows);
    };

    that.remove = function() {
        var rows = that.selected_table.remove_selected_rows();
        that.available_table.add_rows(rows);
    };

    that.update_buttons = function() {

        var values = that.selected_table.save();

        var button = that.get_button('add');
        button.set_enabled(values && values.length);
    };

    that.get_filter = function() {
        return that.filter_field.val();
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

    that.execute = function() {
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

        that.create_button({
            name: 'remove',
            label: IPA.messages.buttons.remove,
            click: function() {
                that.execute();
            }
        });

        that.create_button({
            name: 'cancel',
            label: IPA.messages.buttons.cancel,
            click: function() {
                that.close();
            }
        });

        that.dialog_open(container);
    };

    that.execute = function() {
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

    that.create_button({
        name: 'ok',
        label: IPA.messages.buttons.ok,
        click: function() {
            that.close();
            if(that.on_ok) {
                that.on_ok();
            }
        }
    });

    init();

    return that;
};
