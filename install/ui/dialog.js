/*jsl:import ipa.js */
/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
 *    Petr Vobornik <pvoborni@redhat.com>
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

/* REQUIRES: widget.js, details.js */

IPA.dialog_button = function(spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.label = spec.label || spec.name;
    that.click = spec.click || click;
    that.visible = spec.visible !== undefined ? spec.visible : true;

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

    that.entity = IPA.get_entity(spec.entity);
    that.name = spec.name || 'dialog';
    that.id = spec.id;
    that.title = spec.title;
    that.width = spec.width || 500;
    that.height = spec.height;
    that.close_on_escape = spec.close_on_escape !== undefined ?
                            spec.close_on_escape : true;

    that.widgets = IPA.widget_container();
    that.fields = IPA.field_container({ container: that });
    that.buttons = $.ordered_map();
    that.policies = IPA.facet_policies({
        container: that,
        policies: spec.policies
    });

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

    that.field = function(field) {
        that.fields.add_field(field);
        return that;
    };

    that.validate = function() {
        var valid = true;
        var fields = that.fields.get_fields();
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            valid = field.validate() && field.validate_required() && valid;
        }
        return valid;
    };

    that.get_id = function() {
        if (that.id) return that.id;
        if (that.name) return that.name;
        return null;
    };


    /**
     * Create content layout
     */
    that.create = function() {

        that.message_container = $('<div/>', {
            style: 'display: none',
            'class': 'dialog-message ui-state-highlight ui-corner-all'
        }).appendTo(that.container);

        var widgets = that.widgets.get_widgets();
        for (var i=0; i<widgets.length; i++) {
            var widget = widgets[i];

            var div = $('<div/>', {
                name: widget.name,
                'class': 'dialog-section'
            }).appendTo(that.container);

            widget.create(div);
        }

        that.policies.post_create();
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

        that.container = $('<div/>', {
            id : that.get_id(),
            'data-name': that.name
        });

        if (container) {
            container.append(that.container);
        }

        that.create();
        that.reset();

        that.container.dialog({
            title: that.title,
            modal: true,
            closeOnEscape: that.close_on_escape,
            width: that.width,
            minWidth: that.width,
            height: that.height,
            minHeight: that.height,
            close: function(event, ui) {
                that.close();
            }
        });

        that.set_buttons();
    };

    that.option = function(name, value) {
        that.container.dialog('option', name, value);
    };

    that.set_buttons = function() {

        // create a map of button labels and handlers
        var dialog_buttons = {};
        for (var i=0; i<that.buttons.values.length; i++) {
            var button = that.buttons.values[i];
            if (!button.visible) continue;
            dialog_buttons[button.label] = button.click;
        }

        //set buttons to dialog
        that.option('buttons', dialog_buttons);

        // find button elements
        var parent = that.container.parent();
        var buttons = $('.ui-dialog-buttonpane .ui-dialog-buttonset button', parent);

        buttons.each(function(index) {
            var button = that.buttons.values[index];
            button.element = $(this);
        });
    };

    that.display_buttons = function(names) {

        for (var i=0; i<that.buttons.values.length; i++) {
            var button = that.buttons.values[i];

            button.visible = names.indexOf(button.name) > -1;
        }
        that.set_buttons();
    };

    that.save = function(record) {
        var fields = that.fields.get_fields();
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            field.save(record);
        }
    };

    that.close = function() {
        that.container.dialog('destroy');
        that.container.remove();
    };

    that.reset = function() {
        var fields = that.fields.get_fields();
        for (var i=0; i<fields.length; i++) {
            fields[i].reset();
        }
    };

    that.create_builder = function() {

        var widget_builder = IPA.widget_builder({
            widget_options: {
                entity: that.entity,
                facet: that
            }
        });
        var field_builder = IPA.field_builder({
            field_options: {
                undo: false,
                entity: that.entity,
                facet: that
            }
        });
        var section_builder = IPA.section_builder({
            container: that,
            section_factory: IPA.details_table_section_nc,
            widget_builder: widget_builder,
            field_builder: field_builder
        });

        that.builder = IPA.details_builder({
            container: that,
            widget_builder: widget_builder,
            field_builder: field_builder,
            section_builder: section_builder
        });
    };

    that.init = function() {

        that.create_builder();
        that.builder.build(spec);
        that.fields.widgets_created();
        that.policies.init();
    };

    that.init();

    that.dialog_create = that.create;
    that.dialog_open = that.open;
    that.dialog_close = that.close;
    that.dialog_save = that.save;
    that.dialog_reset = that.reset;
    that.dialog_validate = that.validate;

    return that;
};

/**
 * This dialog provides an interface for searching and selecting
 * values from the available results.
 */
IPA.adder_dialog = function(spec) {

    spec = spec || {};

    spec.name = spec.name || 'adder_dialog';

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

        var div = $('<div/>').appendTo(buttons_panel);
        IPA.button({
            name: 'add',
            label: '>>',
            click: function() {
                that.add();
                that.update_buttons();
                return false;
            }
        }).appendTo(div);

        div = $('<div/>').appendTo(buttons_panel);
        IPA.button({
            name: 'remove',
            label: '<<',
            click: function() {
                that.remove();
                that.update_buttons();
                return false;
            }
        }).appendTo(div);

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
            label: IPA.messages.buttons.add,
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
    spec.name = spec.name || 'deleter_dialog';

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

    spec = spec || {};

    spec.name = spec.name || 'message_dialog';

    var that = IPA.dialog(spec);
    that.message = spec.message || '';
    that.on_ok = spec.on_ok;

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
            if (that.on_ok) {
                that.on_ok();
            }
        }
    });

    that.message_dialog_create = that.create;

    return that;
};

IPA.confirm_dialog = function(spec) {

    spec = spec || {};
    spec.message = spec.message || IPA.messages.actions.confirm;
    spec.title = spec.title || IPA.messages.dialogs.confirmation;

    var that = IPA.message_dialog(spec);
    that.on_cancel = spec.on_cancel;
    that.ok_label = spec.ok_label || IPA.messages.buttons.ok;
    that.cancel_label = spec.cancel_label || IPA.messages.buttons.cancel;
    that.confirmed = false;
    that.confirm_on_enter = spec.confirm_on_enter !== undefined ? spec.confirm_on_enter : true;

    that.close = function() {

        that.dialog_close();
        $(document).unbind('keyup', that.on_key_up);

        if (that.confirmed) {
            if (that.on_ok) {
                that.on_ok();
            }
        } else {
            if (that.on_cancel) {
                that.on_cancel();
            }
        }
    };

    that.open = function(container) {

        that.confirmed = false;
        that.dialog_open(container);
        $(document).bind('keyup', that.on_key_up);
    };

    that.on_key_up = function(event) {

        if (event.keyCode === $.ui.keyCode.ENTER) {
            event.preventDefault();
            that.confirmed = true;
            that.close();
        }
    };

    that.create_buttons = function() {

        that.buttons.empty();

        that.create_button({
            name: 'ok',
            label: that.ok_label,
            click: function() {
                that.confirmed = true;
                that.close();
            }
        });

        that.create_button({
            name: 'cancel',
            label: that.cancel_label,
            click: function() {
                that.confirmed = false;
                that.close();
            }
        });
    };

    that.create_buttons();

    that.confirm_dialog_close = that.close;
    that.confirm_dialog_open = that.open;

    return that;
};
