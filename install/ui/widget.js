/*jsl:import ipa.js */
/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *    Pavel Zuna <pzuna@redhat.com>
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

/* REQUIRES: ipa.js */

IPA.checkbox_column_width = 22;
IPA.required_indicator = '*';

IPA.widget = function(spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.id = spec.id;
    that.label = spec.label;
    that.tooltip = spec.tooltip;
    that.measurement_unit = spec.measurement_unit;
    that.entity = IPA.get_entity(spec.entity); //some old widgets still need it
    that.facet = spec.facet;

    that.create = function(container) {
        container.addClass('widget');
        that.container = container;
    };

    that.clear = function() {
    };

    that.set_visible = function(visible) {

        if (visible) {
            that.container.show();
        } else {
            that.container.hide();
        }
    };

    that.build_child = function(spec, factory) {

        if (typeof spec === 'function') {
            spec = {
                factory: spec
            };
        }

        $.extend(spec, {
            parent: that,
            entity: that.entity,
            facet: that.facet
        });

        var child = IPA.build(spec, factory);
        return child;
    };

    that.widget_create = that.create;

    return that;
};

IPA.input_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.width = spec.width;
    that.height = spec.height;

    that.undo = spec.undo === undefined ? true : spec.undo;
    that.writable = spec.writable === undefined ? true : spec.writable;
    that.read_only = spec.read_only;
    that.hidden = spec.hidden;

    //events
    //each widget can contain several events
    that.value_changed = IPA.observer();
    that.undo_clicked = IPA.observer();


    that.create_error_link = function(container) {
        container.append(' ');

        $('<span/>', {
            name: 'error_link',
            'class': 'ui-state-error ui-corner-all',
            style: 'display:none'
        }).appendTo(container);
    };

    that.create_required = function(container) {
        that.required_indicator = $('<span/>', {
            'class': 'required-indicator',
            text: IPA.required_indicator,
            style: 'display: none;'
        }).appendTo(container);
    };

    that.update = function() {
    };

    /**
     * This function saves the values entered in the UI.
     * It returns the values in an array, or null if
     * the field should not be saved.
     */
    that.save = function() {
        return [];
    };

    /**
     * This function creates an undo link in the container.
     * On_undo is a link click callback. It can be specified to custom
     * callback. If a callback isn't set, default callback is used. If
     * spefified to value other than a function, no callback is registered.
     */
    that.create_undo = function(container, on_undo) {
        container.append(' ');

        that.undo_span =
            $('<span/>', {
                name: 'undo',
                style: 'display: none;',
                'class': 'ui-state-highlight ui-corner-all undo',
                html: IPA.messages.widget.undo
            }).appendTo(container);

        if(on_undo === undefined) {
            on_undo = function() {
                that.undo_clicked.notify([], that);
            };
        }

        if(typeof on_undo === 'function') {
            that.undo_span.click(on_undo);
        }
    };

    that.get_undo = function() {
        return $(that.undo_span);
    };

    that.show_undo = function() {
        that.get_undo().css('display', 'inline');
    };

    that.hide_undo = function() {
        $(that.undo_span).css('display', 'none');
    };

    that.get_error_link = function() {
        return $('span[name="error_link"]', that.container);
    };

    that.show_error = function(message) {
        var error_link = that.get_error_link();
        error_link.html(message);
        error_link.css('display', 'block');
    };

    that.hide_error = function() {
        var error_link = that.get_error_link();
        error_link.css('display', 'none');
    };

    that.set_required = function(required) {

        that.required = required;

        if (that.required_indicator) {
            that.required_indicator.css('display', that.required ? 'inline' : 'none');
        }
    };

    that.on_value_changed = function() {
        var value = that.save();
        that.value_changed.notify([value], that);
    };

    that.focus_input = function() {};
    that.set_deleted = function() {};

    // methods that should be invoked by subclasses
    that.widget_hide_error = that.hide_error;
    that.widget_show_error = that.show_error;

    return that;
};

/*uses a browser specific technique to select a range.*/
IPA.select_range = function(input,start, end) {
    input.focus();
    if (input[0].setSelectionRange) {
        input[0].setSelectionRange(start, end);
    } else if (input[0].createTextRange) {
        var range = input[0].createTextRange();
        range.collapse(true);
        range.moveEnd('character', end);
        range.moveStart('character', start);
        range.select();
    }
};


IPA.text_widget = function(spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.size = spec.size || 30;
    that.input_type = spec.input_type || 'text';

    that.select_range = function(start, end){
        IPA.select_range(that.input, start, end);
    };

    that.create = function(container) {

        that.widget_create(container);

        container.addClass('text-widget');

        that.display_control = $('<label/>', {
            name: that.name,
            style: 'display: none;'
        }).appendTo(container);

        that.input = $('<input/>', {
            type: that.input_type,
            name: that.name,
            disabled: that.disabled,
            size: that.size,
            title: that.tooltip,
            keyup: function() {
                that.on_value_changed();
            }
        }).appendTo(container);

        that.input.bind('input', function() {
            that.on_value_changed();
        });

        if (that.undo) {
            that.create_undo(container);
        }

        that.create_error_link(container);
    };

    that.update = function(values) {
        var value = values && values.length ? values[0] : '';

        if (that.read_only || !that.writable) {
            that.display_control.text(value);
            that.display_control.css('display', 'inline');
            that.input.css('display', 'none');

        } else {
            that.input.val(value);
            that.display_control.css('display', 'none');
            that.input.css('display', 'inline');
        }
    };

    that.save = function() {
        if (that.read_only || !that.writable) {
            return null;

        } else {
            var value = that.input.val();
            return value === '' ? [] : [value];
        }
    };

    that.set_enabled = function(value) {

        that.input.prop('disabled', !value);
    };

    that.clear = function() {
        that.input.val('');
        that.display_control.text('');
    };

    that.focus_input = function() {
        that.input.focus();
    };

    that.set_deleted = function(deleted) {
        if(deleted) {
            that.input.addClass('strikethrough');
        } else {
            that.input.removeClass('strikethrough');
        }
    };

    // methods that should be invoked by subclasses
    that.text_load = that.load;

    return that;
};

IPA.password_widget = function(spec) {

    spec = spec || {};
    spec.input_type = 'password';

    var that = IPA.text_widget(spec);
    return that;
};

IPA.multivalued_widget = function(spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.widget_factory = spec.widget_factory || IPA.text_widget;
    that.size = spec.size || 30;
    that.undo_control;
    that.initialized = false;

    that.rows = [];

    that.on_child_value_changed = function(row) {
        if (that.test_dirty_row(row)) {
            row.widget.show_undo();
            row.remove_link.hide();
        } else {
            row.widget.hide_undo();
            row.remove_link.show();
        }

        that.value_changed.notify([], that);
    };

    that.on_child_undo_clicked = function(row) {
        if (row.is_new) {
            that.remove_row(row);
        } else {
            //reset
            row.widget.update(row.original_values);
            row.widget.set_deleted(false);
            row.deleted = false;
            row.remove_link.show();
        }

        row.widget.hide_undo();
        that.value_changed.notify([], that);
    };

    that.hide_undo = function() {

        $(that.undo_span).css('display', 'none');
        for(var i=0; i<that.rows.length; i++) {
            var row = that.rows[i];
            row.widget.hide_undo();
            row.remove_link.show();
        }
    };


    that.update_child = function(values, index) {
        that.rows[index].widget.update(values);
    };

    that.show_child_undo = function(index) {
        that.rows[index].widget.show_undo();
        that.show_undo();
    };

    that.hide_error = function() {

        that.widget_hide_error();

        for (var i=0; i<that.rows.length; i++) {
            that.rows[i].widget.hide_error();
        }
    };

    that.show_child_error = function(index, error) {

        that.rows[index].widget.show_error(error);
    };

    that.get_saved_value_row_index = function(index) {

        for (var i=0; i<that.rows.length;i++) {

            if(that.rows[i].deleted) index++;
            if(i === index) return i;
        }

        return -1; //error state
    };

    that.save = function() {

        var values = [];

        for (var i=0; i<that.rows.length;i++) {

            if(that.rows[i].deleted) continue;

            values.push(that.extract_child_value(that.rows[i].widget.save()));
        }

        return values;
    };

    that.extract_child_value = function(value) {

        if (value instanceof Array) {
            if (value.length > 0) {
                return value[0];
            }
            return '';
        }

        if (value) return value;

        return '';
    };

    that.focus_last = function() {
        var last_row = that.rows[that.rows.length-1];
        last_row.widget.focus_input();
    };

    that.add_row = function(values) {
        var row = {};
        that.rows.push(row);
        var row_index = that.rows.length - 1;
        row.is_new = that.initialized;

        row.container = $('<div/>', { name: 'value'});

        row.widget = that.widget_factory({
            name: that.name+'-'+row_index,
            undo: that.undo || row.is_new,
            read_only: that.read_only,
            writable: that.writable
        });

        row.widget.create(row.container);

        row.original_values = values;
        row.widget.update(values);

        row.widget.value_changed.attach(function() {
            that.on_child_value_changed(row);
        });
        row.widget.undo_clicked.attach(function() {
            that.on_child_undo_clicked(row);
        });

        row.remove_link = $('<a/>', {
            name: 'remove',
            href: 'jslink',
            title: IPA.messages.buttons.remove,
            html: IPA.messages.buttons.remove,
            click: function () {
                that.remove_row(row);
                that.value_changed.notify([], that);
                return false;
            }
        }).appendTo(row.container);

        if(row.is_new) {
            row.remove_link.hide();
            row.widget.show_undo();
            that.value_changed.notify([], that);
        }

        row.container.insertBefore(that.add_link);
    };

    that.create = function(container) {

        container.addClass('multivalued-widget');

        that.widget_create(container);

        that.create_error_link(container);

        that.add_link = $('<a/>', {
            name: 'add',
            href: 'jslink',
            title: IPA.messages.buttons.add,
            html: IPA.messages.buttons.add,
            click: function() {
                that.add_row('');
                that.focus_last();
                return false;
            }
        }).appendTo(container);


        container.append(' ');

        that.undo_span = $('<span/>', {
            name: 'undo_all',
            style: 'display: none;',
            'class': 'ui-state-highlight ui-corner-all undo',
            html: IPA.messages.widget.undo_all,
            click: function() {
                that.undo_clicked.notify([], that);
            }
        }).appendTo(container);
    };

    that.remove_row = function(row) {
        if (row.is_new) {
            row.container.remove();
            that.rows.splice(that.rows.indexOf(row), 1); //not supported by IE<9
        } else {
            row.deleted = true;
            row.widget.set_deleted(true);
            row.remove_link.hide();
            row.widget.show_undo();
        }
    };

    that.remove_rows = function() {
        for(var i=0; i < that.rows.length; i++) {
            that.rows[i].container.remove();
        }
        that.rows = [];
    };

    that.clear = function() {
        that.remove_rows();
    };

    that.test_dirty_row = function(row) {

        if (row.deleted || row.is_new) return true;

        var values = row.widget.save();

        if (row.original_values.length !== values.length) return true;

        for (var i=0; i<values.length; i++) {
            if (values[i] !== row.original_values[i]) {
                return true;
            }
        }

        return false;
    };

    that.test_dirty = function() {
        var dirty = false;

        for(var i=0; i < that.rows.length; i++) {
            dirty = dirty || that.test_dirty_row(that.rows[i]);
        }

        return dirty;
    };

    that.update = function(values, index) {

        var value;

        if (index === undefined) {

            that.initialized = false;
            that.remove_rows();

            for (var i=0; i<values.length; i++) {
                value = [values[i]];
                if(value[0]) {
                    that.add_row(value);
                }
            }

            that.initialized = true;

            if (that.read_only || !that.writable) {
                that.add_link.css('display', 'none');
            } else {
                that.add_link.css('display', 'inline');
            }

        } else {
            value = values[index];
            var row = that.rows[index];
            row.widget.update(values);
        }
    };

    return that;
};

IPA.checkbox_widget = function (spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    // default value
    that.checked = spec.checked || false;

    that.create = function(container) {

        that.widget_create(container);

        container.addClass('checkbox-widget');

        that.input = $('<input/>', {
            type: 'checkbox',
            name: that.name,
            checked: that.checked,
            title: that.tooltip,
            change: function() {
                that.value_changed.notify([that.save()], that);
            }
        }).appendTo(container);

        if (that.undo) {
            that.create_undo(container);
        }

        that.create_error_link(container);
    };

    that.save = function() {
        var value = that.input.is(':checked');
        return [value];
    };

    that.update = function(values) {
        var value;

        if (values && values.length) {
            value = values[0];
        }

        if (typeof value !== 'boolean') {
            // use default value
            value = that.checked;
        }

        that.input.prop('checked', value);
    };

    that.clear = function() {
        that.input.prop('checked', false);
    };

    that.checkbox_save = that.save;

    return that;
};

IPA.checkboxes_widget = function (spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.options = spec.options || [];
    that.direction = spec.direction || 'vertical';

    that.create = function(container) {

        that.widget_create(container);

        container.addClass('checkboxes-widget');

        var vertical = that.direction === 'vertical';

        for (var i=0; i<that.options.length; i++) {
            var option = that.options[i];
            $('<input/>', {
                type: 'checkbox',
                name: that.name,
                value: option.value,
                title: that.tooltip
            }).appendTo(container);

            $('<label/>', {
                text: option.label,
                title: that.tooltip
            }).appendTo(container);

            if (vertical) {
                $('<br/>').appendTo(container);
            }
        }

        if (that.undo) {
            that.create_undo(container);
        }

        var input = $('input[name="'+that.name+'"]', that.container);
        input.change(function() {
            that.value_changed.notify([that.save()], that);
        });

        that.create_error_link(container);
    };

    that.save = function() {
        var values = [];

        $('input[name="'+that.name+'"]:checked', that.container).each(function() {
            values.push($(this).val());
        });

        return values;
    };

    that.update = function(values) {
        var inputs = $('input[name="'+that.name+'"]', that.container);
        inputs.prop('checked', false);

        for (var j=0; values && j<values.length; j++) {
            var value = values[j];
            var input = $('input[name="'+that.name+'"][value="'+value+'"]', that.container);
            if (!input.length) continue;
            input.prop('checked', true);
        }
    };

    that.clear = function() {
        $('input[name="'+that.name+'"]').prop('checked', false);
    };

    that.add_option = function(option) {
        that.options.push(option);
    };

    // methods that should be invoked by subclasses
    that.checkboxes_update = that.update;

    return that;
};

IPA.radio_widget = function(spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.default_value = spec.default_value;
    that.options = spec.options;

    that.create = function(container) {

        that.widget_create(container);

        container.addClass('radio-widget');

        var name = IPA.html_util.get_next_id(that.name+'-');
        that.selector = 'input[name="'+name+'"]';

        for (var i=0; i<that.options.length; i++) {
            var option = that.options[i];

            var id = name+'-'+i;

            $('<input/>', {
                id: id,
                type: 'radio',
                name: name,
                value: option.value
            }).appendTo(container);

            $('<label/>', {
                text: option.label,
                'for': id
            }).appendTo(container);
        }

        if (that.undo) {
            that.create_undo(container);
        }

        var input = $(that.selector, that.container);
        input.change(function() {
            that.value_changed.notify([that.save()], that);
        });

        that.create_error_link(container);
    };

    that.save = function() {
        var input = $(that.selector+':checked', that.container);
        if (!input.length) return [];
        return [input.val()];
    };

    that.update = function(values) {

        $(that.selector, that.container).each(function() {
            var input = this;
            input.checked = false;
        });

        var value = values && values.length ? values[0] : '';
        var input = $(that.selector+'[value="'+value+'"]', that.container);
        if (input.length) {
            input.prop('checked', true);
        } else if (that.default_value) {
            input = $(that.selector+'[value="'+that.default_value+'"]', that.container);
            input.prop('checked', true);
        }

        that.value_changed.notify([that.save()], that);
    };

    that.clear = function() {
        $(that.selector, that.container).prop('checked', false);

        if (that.default_value) {
            var input = $(that.selector+'[value="'+that.default_value+'"]', that.container);
            input.prop('checked', true);
        }
    };

    // methods that should be invoked by subclasses
    that.radio_create = that.create;
    that.radio_save = that.save;

    return that;
};

IPA.select_widget = function(spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.options = spec.options || [];

    that.create = function(container) {

        that.widget_create(container);

        container.addClass('select-widget');

        that.select = $('<select/>', {
            name: that.name,
            change: function() {
                that.value_changed.notify([], that);
                return false;
            }
        }).appendTo(container);

        that.create_options();

        if (that.undo) {
            that.create_undo(container);
        }

        that.create_error_link(container);
    };

    that.create_options = function() {

        that.select.empty();

        for (var i=0; i<that.options.length; i++) {
            var option = that.options[i];

            $('<option/>', {
                text: option.label,
                value: option.value
            }).appendTo(that.select);
        }
    };

    that.save = function() {
        var value;

        if (that.select) {
            value = that.select.val() || '';
        } else if (that.options.length > 0) {
            value = that.options[0].value; //will be default value
        }

        return [value];
    };

    that.update = function(values) {
        var value = values[0];
        var option = $('option[value="'+value+'"]', that.select);
        if (!option.length) return;
        option.prop('selected', true);
    };

    that.empty = function() {
        $('option', that.select).remove();
    };

    that.clear = function() {
        $('option', that.select).prop('selected', false);
    };

    that.set_options_enabled = function(enabled, options) {

        if (!options) {
            $('option', that.select).prop('disabled', !enabled);
        } else {
            for (var i=0; i<options.length;i++) {
                var value = options[i];
                var option = $('option[value="'+value+'"]', that.select);
                option.prop('disabled', !enabled);
            }
        }
    };

    that.enable_options = function(options) {

        that.set_options_enabled(true, options);
    };

    that.disable_options = function(options) {

        that.set_options_enabled(false, options);
    };

    // methods that should be invoked by subclasses
    that.select_save = that.save;
    that.select_update = that.update;

    return that;
};

IPA.textarea_widget = function (spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.rows = spec.rows || 5;
    that.cols = spec.cols || 40;

    that.create = function(container) {

        that.widget_create(container);

        container.addClass('textarea-widget');

        that.input = $('<textarea/>', {
            name: that.name,
            rows: that.rows,
            cols: that.cols,
            disabled: that.disabled,
            title: that.tooltip,
            keyup: function() {
                that.on_value_changed();
            }
        }).appendTo(container);

        that.input.bind('input', function() {
            that.on_value_changed();
        });

        if (that.undo) {
            that.create_undo(container);
        }

        that.create_error_link(container);
    };

    that.save = function() {
        var value = that.input.val();
        return [value];
    };

    that.update = function(values) {
        var value = values && values.length ? values[0] : '';
        that.input.val(value);
    };

    that.clear = function() {
        that.input.val('');
    };

    return that;
};

IPA.formatter = function(spec) {

    spec = spec || {};

    var that = {};

    that.type = spec.type; // default is text

    // parse attribute value into a normalized value
    that.parse = function(value) {
        return value;
    };

    // format normalized value
    that.format = function(value) {
        return value;
    };

    return that;
};

IPA.boolean_formatter = function(spec) {

    spec = spec || {};

    var that = IPA.formatter(spec);

    that.true_value = spec.true_value || IPA.messages['true'];
    that.false_value = spec.false_value || IPA.messages['false'];
    that.show_false = spec.show_false;
    that.invert_value = spec.invert_value;

    // convert string boolean value into real boolean value, or keep the original value
    that.parse = function(value) {

        if (value === undefined || value === null) return '';

        if (value instanceof Array) {
            value = value[0];
        }

        if (typeof value === 'string') {
            value = value.toLowerCase();

            if (value === 'true') {
                value = true;
            } else if (value === 'false') {
                value = false;
            } // leave other values unchanged
        }

        if (typeof value === 'boolean') {
            if (that.invert_value) value = !value;
        }

        return value;
    };

    // convert boolean value into formatted string, or keep the original value
    that.format = function(value) {

        if (typeof value === 'boolean') {
            if (value) {
                value = that.true_value;

            } else {
                if (that.show_false) {
                    value = that.false_value;
                } else {
                    value = '';
                }
            }
        }

        return value;
    };

    that.boolean_formatter_parse = that.parse;
    that.boolean_formatter_format = that.format;

    return that;
};

IPA.boolean_status_formatter = function(spec) {

    spec = spec || {};

    var that = IPA.boolean_formatter(spec);

    that.true_value = spec.true_value || IPA.messages.status.enabled;
    that.false_value = spec.false_value || IPA.messages.status.disabled;
    that.show_false = true;
    that.type = 'html';

    that.format = function(value) {
        var status = value ? 'enabled' : 'disabled';
        var formatted_value = that.boolean_formatter_format(value);
        formatted_value = '<span class=\"icon '+status+'-icon\"/> '+formatted_value;
        return formatted_value;
    };

    return that;
};

/* Take an LDAP format date in UTC and format it */
IPA.utc_date_formatter = function(spec) {

    spec = spec || {};

    var that = IPA.formatter(spec);

    that.format = function(value) {

        if (!value) return '';
        var date =  IPA.parse_utc_date(value);
        if (!date) return value;
        return date.toString();
    };

    return that;
};

/*
  The entity name must be set in the spec either directly or via entity.name
*/
IPA.column = function (spec) {

    spec = spec || {};

    var that = {};

    that.entity = IPA.get_entity(spec.entity);
    that.name = spec.name;

    that.label = spec.label;
    that.width = spec.width;
    that.primary_key = spec.primary_key;
    that.link = spec.link;
    that.formatter = spec.formatter;

    if (!that.entity) {
        throw {
            expected: false,
            message: 'Column created without an entity.'
        };
    }

    that.setup = function(container, record, suppress_link) {

        container.empty();

        var value = record[that.name];
        var type;
        if (that.formatter) {
            value = that.formatter.parse(value);
            value = that.formatter.format(value);
            type = that.formatter.type;
        }
        value = value ? value.toString() : '';

        var c;
        if (that.link && !suppress_link) {
            c = $('<a/>', {
                href: '#'+value,
                click: function() {
                    return that.link_handler(value);
                }
            }).appendTo(container);

        } else {
            c = container;
        }

        if (type === 'html') {
            c.html(value);
        } else {
            c.text(value);
        }
    };

    that.link_handler = function(value) {
        return false;
    };


    /*column initialization*/
    if (that.entity && !that.label) {
        var metadata = IPA.get_entity_param(that.entity.name, that.name);
        if (metadata) {
            that.label = metadata.label;
        }
    }


    return that;
};

IPA.table_widget = function (spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.scrollable = spec.scrollable;
    that.selectable = spec.selectable === undefined ? true : spec.selectable;
    that.save_values = spec.save_values === undefined ? true : spec.save_values;
    that['class'] = spec['class'];

    that.pagination = spec.pagination;
    that.current_page = 1;
    that.total_pages = 1;
    that.page_length = spec.page_length || 20;

    that.multivalued = spec.multivalued === undefined ? true : spec.multivalued;

    that.columns = $.ordered_map();
    that.value_attr_name = spec.value_attribute || that.name;

    that.get_columns = function() {
        return that.columns.values;
    };

    that.get_column = function(name) {
        return that.columns.get(name);
    };

    that.add_column = function(column) {
        column.entity = that.entity;
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


    that.create = function(container) {

        that.widget_create(container);

        container.addClass('table-widget');

        that.table = $('<table/>', {
            'class': 'search-table'
        }).appendTo(container);

        if (that['class']) that.table.addClass(that['class']);

        if (that.scrollable) {
            that.table.addClass('scrollable');
        }

        that.thead = $('<thead/>').appendTo(that.table);

        var tr = $('<tr/>').appendTo(that.thead);

        var th;

        if (that.selectable) {
            th = $('<th/>', {
                'style': 'width: '+IPA.checkbox_column_width+'px;'
            }).appendTo(tr);

            if (that.multivalued) {
                var select_all_checkbox = $('<input/>', {
                    type: 'checkbox',
                    name: that.name,
                    title: IPA.messages.search.select_all
                }).appendTo(th);

                select_all_checkbox.change(function() {
                    if(select_all_checkbox.is(':checked')) {
                        that.select_all();
                    } else {
                        that.unselect_all();
                    }
                    return false;
                });
            }
        }
        var columns = that.columns.values;
        var column;

        var columns_without_width = 0;
        var per_column_space = 16; //cell padding(2x6px), border (2x1px), spacing (2px)
        var available_width = that.thead.width();
        available_width -= 2;  //first cell spacing

        //subtract checkbox column
        if(that.selectable) {
            available_width -= IPA.checkbox_column_width;
            available_width -= per_column_space;
        }

        //subtract width of columns with their width set
        for (i=0; i<columns.length; i++) {
            column = columns[i];
            if (column.width) {
                available_width -= parseInt(
                    column.width.substring(0, column.width.length-2),10);
                available_width -= per_column_space;
            } else {
                columns_without_width++;
            }
        }

        //width for columns without width set
        var new_column_width = (available_width -
                                per_column_space * columns_without_width) /
                                columns_without_width;


        //set the new width, now all columns should have width set
        for (i=0; i<columns.length; i++) {
            column = columns[i];
            if (!column.width) {
                column.width = new_column_width+"px";
            }
        }

        for (i=0; i<columns.length; i++) {
            column = columns[i];

            th = $('<th/>').appendTo(tr);

            th.css('width', column.width);
            th.css('max-width', column.width);

            var label = column.label;

            $('<div/>', {
                'style': 'float: left;',
                'html': label
            }).appendTo(th);

            if (i == columns.length-1) {
                that.buttons = $('<div/>', {
                    'name': 'buttons',
                    'style': 'float: right;'
                }).appendTo(th);
            }

        }

        that.tbody = $('<tbody/>').appendTo(that.table);

        // workaround for #2835
        if ($.browser.msie) {
            that.tbody.mousedown(function(event) {
                that.scroll_top = that.tbody.scrollTop();
                window.setTimeout(function() {
                    if (that.tbody.scrollTop() === 0) {
                        that.tbody.scrollTop(that.scroll_top);
                    }
                }, 0);
            });
        }

        if (that.height) {
            that.tbody.css('height', that.height);
        }

        that.row = $('<tr/>');

        var td;

        if (that.selectable) {
            td = $('<td/>', {
                'style': 'width: '+ (IPA.checkbox_column_width + 7) +'px;'
            }).appendTo(that.row);

            if (that.multivalued) {
                $('<input/>', {
                    type: 'checkbox',
                    name: that.name,
                    value: ''
                }).appendTo(td);
            } else {
                $('<input/>', {
                    type: 'radio',
                    name: that.name,
                    value: ''
                }).appendTo(td);
            }
        }

        var width;

        for (/* var */ i=0; i<columns.length; i++) {
            /* var */ column = columns[i];

            td = $('<td/>').appendTo(that.row);
            if (column.width) {
                width = parseInt(
                        column.width.substring(0, column.width.length-2),10);
                width += 7; //data cells lack right padding
                width += 'px';
                td.css('width', width);
                td.css('max-width', width);
            }

            $('<div/>', {
                'name': column.name
            }).appendTo(td);
        }

        that.tfoot = $('<tfoot/>').appendTo(that.table);

        tr = $('<tr/>').appendTo(that.tfoot);

        td = $('<td/>', {
            colspan: columns.length + (that.selectable ? 1 : 0)
        }).appendTo(tr);

        that.create_error_link(td);

        that.summary = $('<span/>', {
            'name': 'summary'
        }).appendTo(td);

        that.pagination_control = $('<span/>', {
            'class': 'pagination-control'
        }).appendTo(td);

        if (that.pagination) {

            $('<a/>', {
                text: IPA.messages.widget.prev,
                name: 'prev_page',
                click: function() {
                    that.prev_page();
                    return false;
                }
            }).appendTo(that.pagination_control);

            that.pagination_control.append(' ');

            $('<a/>', {
                text: IPA.messages.widget.next,
                name: 'next_page',
                click: function() {
                    that.next_page();
                    return false;
                }
            }).appendTo(that.pagination_control);

            that.pagination_control.append(' ');
            that.pagination_control.append(IPA.messages.widget.page);
            that.pagination_control.append(': ');

            that.current_page_input = $('<input/>', {
                type: 'text',
                name: 'current_page',
                keypress: function(e) {
                    if (e.which == 13) {
                        var page = parseInt(that.current_page_input.val(), 10) || 1;
                        that.set_page(page);
                    }
                }
            }).appendTo(that.pagination_control);

            that.pagination_control.append(' / ');

            that.total_pages_span = $('<span/>', {
                name: 'total_pages'
            }).appendTo(that.pagination_control);
        }
    };

    that.prev_page = function() {
        if (that.current_page > 1) {
            that.current_page--;
            that.refresh();
        }
    };

    that.next_page = function() {
        if (that.current_page < that.total_pages) {
            that.current_page++;
            that.refresh();
        }
    };

    that.set_page = function(page) {
        if (page < 1) {
            page = 1;
        } else if (page > that.total_pages) {
            page = that.total_pages;
        }
        that.current_page = page;
        that.current_page_input.val(page);
        that.refresh();
    };

    that.select_changed = function() {
    };

    that.select_all = function() {
        $('input[name="'+that.name+'"]', that.thead).prop('checked', true).
            attr('title', IPA.messages.search.unselect_all);
        $('input[name="'+that.name+'"]', that.tbody).prop('checked', true);
        that.select_changed();
    };

    that.unselect_all = function() {
        $('input[name="'+that.name+'"]', that.thead).prop('checked', false).
            attr('title', IPA.messages.search.select_all);
        $('input[name="'+that.name+'"]', that.tbody).prop('checked', false);
        that.select_changed();
    };

    that.set_values = function(values) {
        $('input[name="'+that.name+'"]', that.tbody).prop('checked', false);
        for (var i=0; values && i<values.length; i++) {
            var value = values[i];
            $('input[name="'+that.name+'"][value="'+value+'"]', that.tbody).prop('checked', true);
        }
        that.select_changed();
    };

    that.empty = function() {
        that.tbody.empty();
    };

    that.load = function(result) {

        that.empty();

        that.values = result[that.value_attr_name] || [];
        for (var i=0; i<that.values.length; i++) {
            var record = that.get_record(result, i);
            that.add_record(record);
        }
    };

    that.update = function(records) {

        that.empty();

        that.values = [];
        that.records = records;

        for (var i=0; i<records.length; i++) {
            var record = records[i];
            that.values.push(record[that.value_attr_name]);
            that.add_record(record);
        }
    };

    that.save = function() {
        if (that.save_values) {
            var values = [];

            $('input[name="'+that.name+'"]', that.tbody).each(function() {
                values.push($(this).val());
            });

            return values;

        } else {
            return null;
        }
    };

    that.get_selected_values = function() {
        var values = [];

        $('input[name="'+that.name+'"]:checked', that.tbody).each(function() {
            values.push($(this).val());
        });

        return values;
    };

    that.get_selected_rows = function() {
        return $('input[name="'+that.name+'"]:checked', that.tbody).closest('tr');
    };

    that.get_record = function(result, index) {

        var record = {};

        var columns = that.columns.values;
        for (var i=0; i<columns.length; i++){
            var name = columns[i].name;
            var values = result[name];
            if (!values) continue;

            if (values instanceof Array){
                record[name] = values[index];
            } else {
                record[name] = values;
            }
        }

        return record;
    };

    that.add_record = function(record) {

        var tr = that.row.clone();
        tr.appendTo(that.tbody);

        $('input[name="'+that.name+'"]', tr).click(function(){
            that.select_changed();
        });

        var select_set = false;
        var value;
        var columns = that.columns.values;

        for (var i=0; i<columns.length; i++){
            var column = columns[i];

            value = record[column.name];
            value = value ? value.toString() : '';

            if (column.primary_key) {
                $('input[name="'+that.name+'"]', tr).val(value);
                select_set = true;
            }

            var div = $('div[name="'+column.name+'"]', tr);

            that.setup_column(column, div, record);
        }

        if (!select_set) {
            value = record[that.value_attr_name];
            value = value ? value.toString() : '';
            $('input[name="'+that.name+'"]', tr).val(value);
        }

        return tr;
    };

    that.set_row_enabled = function(tr, enabled) {
        if (enabled) {
            tr.removeClass('disabled');
        } else {
            tr.addClass('disabled');
        }
    };

    that.setup_column = function(column, div, record) {
        column.setup(div, record);
    };

    that.add_rows = function(rows) {
        for (var i=0; i<rows.length; i++) {
            var tr = rows[i];
            $('input', tr).attr('name', that.name);
            that.tbody.append(tr);
        }
    };

    that.remove_selected_rows = function() {
        var rows = [];
        that.tbody.children().each(function() {
            var tr = $(this);
            if (!$('input[name="'+that.name+'"]', tr).get(0).checked) return;
            tr.detach();
            rows.push(tr);
        });
        return rows;
    };

    that.show_error = function(message) {
        var error_link = that.get_error_link();
        error_link.html(message);
        error_link.css('display', 'inline');
    };

    that.set_enabled = function(enabled) {
        $('input[name="'+that.name+'"]', that.table).prop('disabled', !enabled);
    };

    that.clear = function() {
        that.empty();
        that.summary.text('');
    };

    //column initialization
    if (spec.columns) {
        for (var i=0; i<spec.columns; i++) {
            that.create_column(spec.columns[i]);
        }
    }

    // methods that should be invoked by subclasses
    that.table_create = that.create;
    that.table_load = that.load;
    that.table_next_page = that.next_page;
    that.table_prev_page = that.prev_page;
    that.table_set_enabled = that.set_enabled;
    that.table_set_page = that.set_page;
    that.table_show_error = that.show_error;
    that.table_set_values = that.set_values;
    that.table_update = that.update;

    return that;
};


IPA.attribute_table_widget = function(spec) {


    spec = spec || {};
    spec.columns = spec.columns || [];

    var that = IPA.table_widget(spec);

    that.attribute_name = spec.attribute_name || that.name;
    that.adder_dialog_spec = spec.adder_dialog;
    that.css_class = spec.css_class;

    that.add_command = spec.add_command;
    that.remove_command = spec.remove_command;

    that.on_add = spec.on_add;
    that.on_add_error = spec.on_add_error;
    that.on_remove = spec.on_remove;
    that.on_remove_error = spec.on_remove_error;

    that.create_column = function(spec) {

        if (typeof spec === 'string') {
            spec = {
                name: spec
            };
        }

        spec.entity = that.entity;

        var factory = spec.factory || IPA.column;

        var column = factory(spec);
        that.add_column(column);
        return column;
    };

    that.create_columns = function() {
        that.clear_columns();
        if (spec.columns) {
            for (var i=0; i<spec.columns.length; i++) {
                that.create_column(spec.columns[i]);
            }
        }

        that.post_create_columns();
    };

    that.post_create_columns = function() {
    };

    that.create_buttons = function(container) {

        that.remove_button = IPA.action_button({
            name: 'remove',
            label: IPA.messages.buttons.remove,
            icon: 'remove-icon',
            'class': 'action-button-disabled',
            click: function() {
                if (!that.remove_button.hasClass('action-button-disabled')) {
                    that.remove_handler();
                }
                return false;
            }
        }).appendTo(container);

        that.add_button = IPA.action_button({
            name: 'add',
            label: IPA.messages.buttons.add,
            icon: 'add-icon',
            click: function() {
                if (!that.add_button.hasClass('action-button-disabled')) {
                    that.add_handler();
                }
                return false;
            }
        }).appendTo(container);
    };

    that.create = function(container) {

        that.create_columns();
        that.table_create(container);
        if (that.css_class)
            container.addClass(that.css_class);
        that.create_buttons(that.buttons);
    };

    that.set_enabled = function(enabled) {
        that.table_set_enabled(enabled);
        if (enabled) {
            if(that.add_button) {
                that.add_button.removeClass('action-button-disabled');
            }
        } else {
            $('.action-button', that.table).addClass('action-button-disabled');
            that.unselect_all();
        }
        that.enabled = enabled;
    };

    that.select_changed = function() {

        var values = that.get_selected_values();

        if (that.remove_button) {
            if (values.length === 0) {
                that.remove_button.addClass('action-button-disabled');
            } else {
                that.remove_button.removeClass('action-button-disabled');
            }
        }
    };

    that.add_handler = function() {
        var facet = that.entity.get_facet();

        if (facet.is_dirty()) {
            var dialog = IPA.dirty_dialog({
                entity:that.entity,
                facet: facet
            });

            dialog.callback = function() {
                that.show_add_dialog();
            };

            dialog.open(that.container);

        } else {
            that.show_add_dialog();
        }
    };

    that.remove_handler = function() {
        var facet = that.entity.get_facet();

        if (facet.is_dirty()) {
            var dialog = IPA.dirty_dialog({
                entity:that.entity,
                facet: facet
            });

            dialog.callback = function() {
                that.show_remove_dialog();
            };

            dialog.open(that.container);

        } else {
            that.show_remove_dialog();
        }
    };

    that.show_remove_dialog = function() {

        var dialog = that.create_remove_dialog();
        if (dialog) dialog.open(that.container);
    };

    that.create_remove_dialog = function() {
        var selected_values = that.get_selected_values();

        if (!selected_values.length) {
            var message = IPA.messages.dialogs.remove_empty;
            alert(message);
            return null;
        }

        var dialog = IPA.deleter_dialog({
            entity: that.entity,
            values: selected_values
        });

        dialog.execute = function() {
            var command = that.create_remove_command(
                selected_values,
                function(data, text_status, xhr) {
                    var handler = that.on_remove || that.on_command_success;
                    handler.call(this, data, text_status, xhr);
                    dialog.close();
                },
                function(xhr, text_status, error_thrown) {
                    var handler = that.on_remove_error || that.on_command_error;
                    handler.call(this, xhr, text_status, error_thrown);
                    dialog.close();
                }
            );
            command.execute();
        };

        return dialog;
    };

    that.on_command_success = function(data) {
        that.reload_facet(data);
    };

    that.on_command_error = function() {
        that.refresh_facet();
    };

    that.get_pkeys = function() {
        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        return [pkey];
    };

    that.get_additional_options = function() {
        return [];
    };

    that.create_remove_command = function(values, on_success, on_error) {

        var pkeys = that.get_pkeys();

        var command = IPA.command({
            entity: that.entity.name,
            method: that.remove_command || 'del',
            args: pkeys,
            on_success: on_success,
            on_error: on_error
        });

        command.set_option(that.attribute_name, values);

        var additional_options = that.get_additional_options();
        for (var i=0; i<additional_options.length; i++) {
            var option = additional_options[i];
            command.set_option(option.name, option.value);
        }

        return command;
    };

    that.create_add_dialog = function() {

        var dialog_spec = {
            entity: that.entity,
            method: that.add_command
        };

        if (that.adder_dialog_spec) {
            $.extend(dialog_spec, that.adder_dialog_spec);
        }

        var label = that.entity.metadata.label_singular;
        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        dialog_spec.title = dialog_spec.title || IPA.messages.dialogs.add_title;
        dialog_spec.title = dialog_spec.title.replace('${entity}', label);
        dialog_spec.title = dialog_spec.title.replace('${pkey}', pkey);


        var factory = dialog_spec.factory || IPA.entity_adder_dialog;
        var dialog = factory(dialog_spec);

        var cancel_button = dialog.buttons.get('cancel');
        dialog.buttons.empty();

        dialog.create_button({
            name: 'add',
            label: IPA.messages.buttons.add,
            click: function() {
                dialog.hide_message();
                dialog.add(
                    function(data, text_status, xhr) {
                        var handler = that.on_add || that.on_command_success;
                        handler.call(this, data, text_status, xhr);
                        dialog.close();
                    },
                    dialog.on_error);
            }
        });

        dialog.create_button({
            name: 'add_and_add_another',
            label: IPA.messages.buttons.add_and_add_another,
            click: function() {
                dialog.hide_message();
                dialog.add(
                    function(data, text_status, xhr) {
                        var label = that.entity.metadata.label_singular;
                        var message = IPA.messages.dialogs.add_confirmation;
                        message = message.replace('${entity}', label);
                        dialog.show_message(message);

                        var handler = that.on_add || that.on_command_success;
                        handler.call(this, data, text_status, xhr);

                        dialog.reset();
                    },
                    dialog.on_error);
            }
        });

        dialog.buttons.put('cancel', cancel_button);

        dialog.create_add_command = function(record) {
            return that.adder_dialog_create_command(dialog, record);
        };

        return dialog;
    };

    that.adder_dialog_create_command = function(dialog, record) {
        var command  = dialog.entity_adder_dialog_create_add_command(record);
        command.args = that.get_pkeys();

        var additional_options = that.get_additional_options();
        for (var i=0; i<additional_options.length; i++) {
            var option = additional_options[i];
            command.set_option(option.name, option.value);
        }

        return command;
    };

    that.show_add_dialog = function() {

        var dialog = that.create_add_dialog();
        dialog.open(that.container);
    };

    that.update = function(values) {
        that.table_update(values);
        that.unselect_all();
    };

    that.reload_facet = function(data) {

        //FIXME: bad approach - widget is directly manipulating with facet
        var facet = IPA.current_entity.get_facet();
        facet.load(data);
    };

    that.refresh_facet = function() {

        //FIXME: bad approach
        var facet = IPA.current_entity.get_facet();
        facet.refresh();
    };

    that.attribute_table_adder_dialog_create_command = that.adder_dialog_create_command;
    that.attribute_table_create_remove_command = that.create_remove_command;
    that.attribute_table_update = that.update;

    return that;
};

IPA.combobox_widget = function(spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.editable = spec.editable;
    that.searchable = spec.searchable;
    that.size = spec.size || 5;
    that.empty_option = spec.empty_option === undefined ? true : spec.empty_option;
    that.options = spec.options || [];
    that.input_field_changed = IPA.observer();
    that.z_index = spec.z_index ? spec.z_index + 9000000 : 9000000;

    that.create = function(container) {
        that.widget_create(container);

        container.addClass('combobox-widget');

        $(document).keyup(function(e) {
            if (e.which == 27) { // Escape
                that.close();
            }
        });

        that.input_container = $('<div/>', {
            'class': 'combobox-widget-input'
        }).appendTo(container);

        that.text = $('<label/>', {
            name: that.name,
            style: 'display: none;'
        }).appendTo(that.input_container);

        that.input = $('<input/>', {
            type: 'text',
            name: that.name,
            title: that.tooltip,
            readonly: !that.editable || that.read_only,
            keyup: function() {
                that.input_field_changed.notify([], that);
            },
            click: function() {
                if (that.editable) return false;
                if (that.is_open()) {
                    that.close();
                } else {
                    that.open();
                }
                return false;
            }
        }).appendTo(that.input_container);

        that.input.bind('input', function() {
            that.input_field_changed.notify([], that);
        });

        that.open_button = IPA.action_button({
            name: 'open',
            icon: 'combobox-icon',
            click: function() {
                if (that.is_open()) {
                    that.close();
                } else {
                    that.open();
                }
                return false;
            }
        }).appendTo(that.input_container);

        that.list_container = $('<div/>', {
            'class': 'combobox-widget-list',
            css: { 'z-index': that.z_index }
        }).appendTo(that.input_container);

        var div = $('<div/>', {
            style: 'position: relative; width: 100%;'
        }).appendTo(that.list_container);

        if (that.searchable) {
            that.filter = $('<input/>', {
                type: 'text',
                name: 'filter',
                keypress: function(e) {
                    if (e.which == 13) { // Enter
                        var filter = that.filter.val();
                        that.search(filter);
                    }
                }
            }).appendTo(div);

            that.search_button = IPA.action_button({
                name: 'search',
                icon: 'search-icon',
                click: function() {
                    var filter = that.filter.val();
                    that.search(filter);
                    return false;
                }
            }).appendTo(div);

            div.append('<br/>');
        }

        that.list = $('<select/>', {
            name: 'list',
            size: that.size,
            style: 'width: 100%',
            change: that.select_on_change
        }).appendTo(div);

        if (that.undo) {
            that.create_undo(container);
        }

        that.create_error_link(container);
    };

    that.select_on_change = function() {

        if (!that.is_open()) return;

        var value = that.list.val();
        that.input.val(value);
        IPA.select_range(that.input, 0, 0);

        that.close();
        that.value_changed.notify([[value]], that);
    };

    that.open = function() {
        if (!that.read_only)
            that.list_container.css('visibility', 'visible');
    };

    that.close = function() {
        that.list_container.css('visibility', 'hidden');
    };

    that.is_open = function() {
        return that.list_container.css('visibility') == 'visible';
    };

    that.search = function(filter, on_success, on_error) {

        that.recreate_options();
        if (on_success) on_success.call(this);
    };

    that.set_options = function(options) {
        that.options = options;
        that.recreate_options();
    };

    that.recreate_options = function() {

        that.remove_options();

        if (that.empty_option) {
            that.create_option();
        }

        for (var i=0; i<that.options.length; i++) {
            var option = that.options[i];

            var label, value;
            if (option instanceof Object) {
                label = option.label;
                value = option.value;
            } else {
                label = option;
                value = option;
            }

            that.create_option(label, value);
        }
    };

    that.update = function(values) {
        that.close();

        if (that.writable) {
            that.text.css('display', 'none');
            that.input.css('display', 'inline');
            that.open_button.css('display', 'inline');
        } else {
            that.text.css('display', 'inline');
            that.input.css('display', 'none');
            that.open_button.css('display', 'none');
        }

        if (that.searchable) {
            that.filter.empty();
        }

        // In a details page the following code will get the stored value.
        // In a dialog box the value will be null.
        var value = values.length ? values[0] : null;

        // In a details page the following code will show the stored
        // value immediately without waiting to populate the list.
        // In a dialog box it will show blank.
        that.set_value(value || '');

        // In a details page the following code will populate the list
        // and select the stored value.
        // In a dialog box it will populate the list and select the first
        // available option.
        that.search(
            null,
            function(data, text_status, xhr) {
                that.select(value);
            }
        );
    };

    that.set_value = function(value) {
        that.text.text(value);
        that.input.val(value);
    };

    that.select = function(value) {

        var option;

        if (value) {
            // select specified value
            option = $('option[value="'+value+'"]', that.list);
        } else {
            // select first available option
            option = $('option', that.list).first();
        }

        // if no option found, skip
        if (!option.length) return;

        option.prop('selected', true);

        that.set_value(option.val());
        that.value_changed.notify([], that);
    };

    that.save = function() {
        var value = that.input.val();
        return value === '' ? [] : [value];
    };

    that.create_option = function(label, value) {
        var option = $('<option/>', {
            text: label,
            value: value,
            click: that.select_on_change
        }).appendTo(that.list);
    };

    that.remove_options = function() {
        that.list.empty();
    };

    that.clear = function() {
        that.input.val('');
        that.remove_options();
    };

    return that;
};

IPA.entity_select_widget = function(spec) {

    spec = spec || {};
    spec.searchable = spec.searchable === undefined ? true : spec.searchable;

    var that = IPA.combobox_widget(spec);

    that.other_entity = IPA.get_entity(spec.other_entity);
    that.other_field = spec.other_field;

    that.options = spec.options || [];

    that.create_search_command = function(filter) {
        return IPA.command({
            entity: that.other_entity.name,
            method: 'find',
            args: [filter]
        });
    };

    that.search = function(filter, on_success, on_error) {

        that.on_search_success = on_success;

        var command = that.create_search_command(filter);
        command.on_success = that.search_success;
        command.on_error = on_error;

        command.execute();
    };

    that.search_success = function(data, text_status, xhr) {

        //get options
        var options = [];

        var entries = data.result.result;
        for (var i=0; i<data.result.count; i++) {
            var entry = entries[i];
            var values = entry[that.other_field];
            var value = values[0];

            options.push(value);
        }

        that.set_options(options);

        if (that.on_search_success) that.on_search_success.call(this, data, text_status, xhr);
    };

    return that;
};


IPA.link_widget = function(spec) {
    var that = IPA.input_widget(spec);

    that.is_link = spec.is_link || false;
    that.link_clicked = IPA.observer();

    that.create = function(container) {
        that.widget_create(container);
        that.link =
        $('<a/>', {
            href: 'jslink',
            title: '',
            html: '',
            click: function() {
                that.link_clicked.notify([], that);
                return false;
            }
        }).appendTo(container);

        that.nonlink = $('<label/>').
            appendTo(container);
    };

    that.update = function (values){

        if (values || values.length > 0) {
            that.nonlink.text(values[0]);
            that.link.text(values[0]);
            if(that.is_link) {
                that.link.css('display','inline');
                that.nonlink.css('display','none');
            } else {
                that.link.css('display','none');
                that.nonlink.css('display','inline');
            }
        } else {
            that.link.html('');
            that.nonlink.html('');
            that.link.css('display','none');
            that.nonlink.css('display','none');
        }
    };

    that.clear = function() {
        that.nonlink.text('');
        that.link.text('');
    };


    return that;
};

IPA.action_button = function(spec) {

    spec = spec || {};

    var button = $('<a/>', {
        id: spec.id,
        name: spec.name,
        href: spec.href || '#' + (spec.name || 'button'),
        title: spec.title || spec.label,
        'class': 'button action-button',
        style: spec.style,
        click: spec.click,
        blur: spec.blur
    });

    if (spec['class']) button.addClass(spec['class']);

    if (spec.icon) {
        $('<span/>', {
            'class': 'icon '+spec.icon
        }).appendTo(button);
    }

    if (spec.label) {
        $('<span/>', {
            'class': 'button-label',
            html: spec.label
        }).appendTo(button);
    }

    return button;
};

IPA.button = function(spec) {

    spec = spec || {};

    var button = $('<a/>', {
        id: spec.id,
        name: spec.name,
        href: spec.href || '#' + (spec.name || 'button')
    });

    var icons = { primary: spec.icon };
    var label = spec.label;

    button.button({
        icons: icons,
        label: label
    });

    button.click(spec.click);

    return button;
};

IPA.button_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.href = spec.href;
    that.style = spec.style;
    that.click = spec.click;
    that['class'] = spec['class'];
    that.disabled_class = 'button-disabled';

    that.on_click = function() {

        if (that.click) {
            that.click();
        }
        return false;
    };

    that.create = function(container) {
        that.button = IPA.button({
            id: that.id,
            name: that.name,
            href: that.href,
            title: that.tooltip,
            label: that.label,
            'class': that['class'],
            style: that.style,
            click: that.on_click
        }).appendTo(container);
    };

    that.get_enabled = function() {

        var enabled = true;

        if (that.button) {
            enabled = that.button.hasClass(that.disabled_class);
        }

        return enabled;
    };

    that.set_enabled = function(enabled) {

        enabled ? that.enable() : that.disable();
    };

    that.enable = function() {
        if (that.button) {
            that.button.removeClass(that.disabled_class);
        }
    };

    that.disable = function() {
        if (that.button) {
            that.button.addClass(that.disabled_class);
        }
    };

    return that;
};

IPA.html_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.html = spec.html;
    that.css_class = spec.css_class;

    that.create = function(container) {

        that.widget_create(container);

        if (that.css_class) {
            container.addClass(that.css_class);
        }

        if (that.html) {
            container.append(that.html);
        }
    };

    return that;
};

IPA.composite_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.widgets = IPA.widget_container();

    that.create = function(container) {

        that.widget_create(container);
        that.widgets.create(container);
    };

    that.clear = function() {

        var widgets = that.widgets.get_widgets();

        for (var i=0; i< widgets.length; i++) {
            widgets[i].clear();
        }
    };

    that.composite_widget_create = that.create;
    that.composite_widget_clear = that.clear;

    return that;
};

IPA.collapsible_section = function(spec) {

    spec = spec || {};

    var that = IPA.composite_widget(spec);

    that.create = function(container) {

        that.widget_create(container);

        that.header = $('<h2/>', {
            name: that.name,
            title: that.label
        }).appendTo(container);

        that.icon = $('<span/>', {
            name: 'icon',
            'class': 'icon section-expand '+IPA.expanded_icon
        }).appendTo(that.header);

        that.header.append(' ');

        that.header.append(that.label);

        that.content_container = $('<div/>', {
            name: that.name,
            'class': 'details-section'
        }).appendTo(container);

        that.header.click(function() {
            var visible = that.content_container.is(":visible");
            that.toggle(!visible);
        });

        that.composite_widget_create(that.content_container);
    };

    that.toggle = function(visible) {

        that.icon.toggleClass(IPA.expanded_icon, visible);
        that.icon.toggleClass(IPA.collapsed_icon, !visible);

        if (visible != that.content_container.is(":visible")) {
            that.content_container.slideToggle('slow');
        }
    };

    return that;
};

IPA.details_section = IPA.collapsible_section;

IPA.layout = function(spec) {
    return {};
};

// Creates list of widgets into table with two columns: label and widget
IPA.table_layout = function(spec) {

    spec = spec || {};

    var that = IPA.layout(spec);
    that.table_class = spec.table_class || 'section-table';
    that.label_cell_class = spec.label_cell_class || 'section-cell-label';
    that.field_cell_class = spec.field_cell_class || 'section-cell-field';
    that.label_class = spec.label_class || 'field-label';
    that.field_class = spec.field_class || 'field';

    that.create = function(widgets) {

        that.rows = $.ordered_map();

        var table = $('<table/>', {
            'class': that.table_class
        });

        for (var i=0; i<widgets.length; i++) {
            var widget = widgets[i];
            var tr = $('<tr/>');
            that.rows.put(widget.name, tr);

            if (widget.hidden) {
                tr.css('display', 'none');
            }

            tr.appendTo(table);

            var td = $('<td/>', {
                'class': that.label_cell_class,
                title: widget.label
            }).appendTo(tr);

            var label_text = widget.label + that.get_measurement_unit_text(widget) + ':';

            $('<label/>', {
                name: widget.name,
                'class': that.label_class,
                text: label_text
            }).appendTo(td);

            if(widget.create_required) {
                widget.create_required(td);
            }

            td = $('<td/>', {
                'class': that.field_cell_class,
                title: widget.label
            }).appendTo(tr);

            var widget_container = $('<div/>', {
                name: widget.name,
                'class': that.field_class
            }).appendTo(td);

            widget.create(widget_container);
        }
        return table;
    };


    that.get_measurement_unit_text = function(widget) {

        if (widget.measurement_unit) {
            var unit = IPA.messages.measurement_units[widget.measurement_unit];
            return ' (' + unit + ')';
        }
        return '';
    };

    return that;
};

IPA.details_table_section = function(spec) {

    spec = spec || {};

    var that = IPA.details_section(spec);
    that.layout = IPA.build_default(spec.layout, IPA.table_layout);
    that.action_panel = that.build_child(spec.action_panel);

    that.rows = $.ordered_map();

    that.composite_widget_create = function(container) {

        that.widget_create(container);

        if (that.action_panel) {
            that.action_panel.create(container);
        }
        var widgets = that.widgets.get_widgets();
        var table = that.layout.create(widgets);
        table.appendTo(container);
        that.rows = that.layout.rows;
    };


    that.add_row = function(name, row) {
        that.rows.put(name, row);
    };

    that.get_row = function(name) {
        return that.rows.get(name);
    };

    that.set_row_visible = function(name, visible) {
        var row = that.get_row(name);
        row.css('display', visible ? '' : 'none');
    };

    that.table_section_create = that.composite_widget_create;

    return that;
};

//non-collabsible section
IPA.details_table_section_nc = function(spec) {

    spec = spec || {};

    var that = IPA.details_table_section(spec);

    that.create = that.table_section_create;

    return that;
};

IPA.multiple_choice_section = function(spec) {

    spec = spec || {};

    var that = IPA.composite_widget(spec);
    that.choices = $.ordered_map().put_array(spec.choices, 'name');
    that.layout = IPA.build_default(spec.layout, IPA.table_layout);

    that.create = function(container) {

        var i, choice, choices;

        that.widget_create(container);
        that.container.addClass('multiple-choice-section');

        that.header_element = $('<div/>', {
            'class': 'multiple-choice-section-header',
            text: that.label
        }).appendTo(container);

        that.choice_container = $('<div/>', {
            'class': 'choices'
        }).appendTo(container);

        choices = that.choices.values;
        for (i=0; i<choices.length; i++) {
            choice = choices[i];
            that.create_choice(choice);
        }
    };

    that.create_choice = function(choice) {

        var widgets, i, widget, field, section, choice_el, header, radio,
            enabled, radio_id;

        widgets = [];

        if (choice.widgets) {
            for (i=0; i<choice.widgets.length; i++) {
                widget = that.widgets.get_widget(choice.widgets[i]);
                widgets.push(widget);
            }
        } else if (choice.fields) {
            for (i=0; i<choice.fields.length; i++) {
                field = that.facet.fields.get_field(choice.fields[i]);
                widgets.push(field.widget);
            }
        }

        choice_el = $('<div/>',{
            'class': 'choice',
            name: choice.name
        });

        header = $('<div/>',{
            'class': 'choice-header'
        }).appendTo(choice_el);

        enabled = choice.enabled !== undefined ? choice.enabled : false;

        radio_id = that.name + '_' + choice.name;

        $('<input/>',{
            type: 'radio',
            name: that.name,
            id: radio_id,
            value: choice.name,
            checked: enabled,
            change: function() {
                that.select_choice(this.value);
            }
        }).appendTo(header);

        $('<label/>',{
            text: choice.label,
            'for': radio_id
        }).appendTo(header);

        section = that.layout.create(widgets);
        section.appendTo(choice_el);
        choice_el.appendTo(that.choice_container);
    };

    that.select_choice = function(choice_name) {

        var i, choice, enabled;

        for (i=0; i<that.choices.values.length; i++) {
            choice = that.choices.values[i];
            enabled = choice.name === choice_name;
            that.set_enabled(choice, enabled);
        }
    };

    that.set_enabled = function (choice, enabled) {

        var i, field_name, field, fields, required;

        fields = that.facet.fields;

        for (i=0; i<choice.fields.length; i++) {
            field_name = choice.fields[i];
            field = fields.get_field(field_name);
            field.set_enabled(enabled);
            required = enabled && choice.required.indexOf(field_name) > -1;
            field.set_required(required);
            field.validate(); //hide validation errors
        }
    };

    that.init_enabled = function() {

        var i, choice;

        for (i=0; i<that.choices.values.length; i++) {
            choice = that.choices.values[i];
            if (choice.enabled) {
                that.select_choice(choice.name);
                break;
            }
        }
    };

    return that;
};

IPA.multiple_choice_section_policy = function(spec) {

    spec = spec || {};

    var that = IPA.facet_policy(spec);
    that.widget_name = spec.widget;

    that.init = function() {
        that.widget = that.container.widgets.get_widget(that.widget_name);
    };

    that.post_create = function() {
        that.widget.init_enabled();
    };

    return that;
};

IPA.enable_widget = function(spec) {

    spec = spec  || {};

    var that = IPA.radio_widget(spec);

    return that;
};


IPA.header_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.level = spec.level || 3;
    that.text = spec.text;
    that.description = spec.description;

    that.create = function(container) {
        container.append($('<h'+that.level+' />', {
            text: that.text,
            title: that.description
        }));
    };

    return that;
};

IPA.observer = function(spec) {

    var that = {};

    that.listeners = [];

    that.attach = function(callback) {
        that.listeners.push(callback);
    };

    that.detach = function(callback) {
        for(var i=0; i < that.listeners.length; i++) {
            if(callback === that.listeners[i]) {
                that.listeners.splice(i,1);
                break;
            }
        }
    };

    that.notify = function(args, context) {
        args = args || [];
        context = context || this;

        for(var i=0; i < that.listeners.length; i++) {
            that.listeners[i].apply(context, args);
        }
    };

    return that;
};

IPA.html_util = function() {

    var that = {};
    that.id_count = 0;

    that.get_next_id = function(prefix) {
        that.id_count++;
        return prefix ? prefix + that.id_count : that.id_count;
    };

    return that;
}();

IPA.widget_container = function(spec) {

    spec = spec || {};

    var that = {};

    that.new_container_for_child = spec.new_container_for_child !== undefined ?
    spec.new_container_for_child : true;

    that.widgets = $.ordered_map();
    that.widget_builder = spec.widget_builder || IPA.widget_builder();

    that.add_widget = function(widget) {
        that.widgets.put(widget.name, widget);
    };

    that.get_widget = function(path) {

        var path_len = path.length;
        var i = path.indexOf('.');
        var name, child_path, widget, child;

        if (i >= 0) {
            name = path.substring(0, i);
            child_path = path.substring(i + 1);

            child = that.widgets.get(name);
            widget = child.widgets.get_widget(child_path);
        } else {
            widget = that.widgets.get(path);
        }

        return widget;
    };

    that.get_widgets = function() {
        return that.widgets.values;
    };

    that.create = function(container) {

        var widgets = that.widgets.values;
        for (var i=0; i<widgets.length; i++) {
            var widget = widgets[i];

            var child_container = container;
            if(that.new_container_for_child) {
                child_container = $('<div/>', {
                    name: widget.name,
                    title: widget.label,
                    'class': widget['class']
                }).appendTo(container);
            }
            widget.create(child_container);

            if(i < widgets.length - 1) {
                that.create_widget_delimiter(container);
            }
        }
    };

    that.clear = function() {

        var widgets = that.widgets.values;
        for (var i=0; i<widgets.length; i++) {
            widgets[i].clear();
        }
    };

    that.create_widget_delimiter = function(container) {
    };

    that.widget_container_create = that.create;
    that.widget_container_clear = that.clear;

    return that;
};

IPA.widget_builder = function(spec) {

    spec = spec || {};

    var that = {};

    that.default_factory = spec.default_factory || IPA.text_widget;
    that.container = spec.container;
    that.widget_options = spec.widget_options || {};

    that.get_widget_factory = function(spec) {

        var factory;
        if (spec.factory) {
            factory = spec.factory;
        } else if(spec.type) {
            factory = IPA.widget_factories[spec.type];
        }

        if (!factory) {
            factory = that.default_factory;
        }

        return factory;
    };

    that.build_widget = function(spec, container) {

        container = container || that.container;

        if(!(spec instanceof Object)) {
            spec = { name: spec };
        }

        if(that.widget_options) {
            $.extend(spec, that.widget_options);
        }

        var factory = that.get_widget_factory(spec);

        var widget = factory(spec);

        if(container) {
            container.add_widget(widget);
        }

        if(spec.widgets) {
            that.build_widgets(spec.widgets, widget.widgets);
        }

        return widget;
    };

    that.build_widgets = function(specs, container) {

        container = container || that.container;

        for(var i=0; i<specs.length; i++) {
            that.build_widget(specs[i], container);
        }
    };

    return that;
};

IPA.sshkeys_widget = function(spec) {

    spec = spec || {};
    spec.widget_factory = IPA.sshkey_widget;

    var that = IPA.multivalued_widget(spec);

    that.test_dirty_row = function(row) {

        if(row.deleted || row.is_new) return true;

        var values = row.widget.save();

        var key = values[0];
        var original_key = row.original_values[0];

        if (original_key && original_key.key && original_key.key !== key) {
            return true;
        }

        return false;
    };

    return that;
};

IPA.sshkey_widget = function(spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.key = null;
    that.originally_set = false;

    that.create = function(container) {

        that.widget_create(container);

        container.addClass('text-widget');

        that.status_label = $('<span />', {
            'class': 'sshkey-status',
            text: ''
        }).appendTo(container);

        that.link = $('<a/>', {
            type: that.type,
            'class': 'sshkey-set',
            name: that.name,
            href: '#show-certificate',
            title: that.tooltip,
            text: IPA.messages.objects.sshkeystore.show_set_key,
            click: function() {
                that.open_edit_dialog();
                return false;
            }
        }).appendTo(container);

        if (that.undo) {
            that.create_undo(container);
        }

        that.create_error_link(container);
    };

    that.update = function(values) {

        var key = values && values.length ? values[0] : null;

        if (!key || key === '') {
            key = {};
        }

        that.key = $.extend({}, key);

        if (that.key.key && that.key.key !== '' &&
                that.key.fingerprint && that.key.fingerprint !== '') {
            that.originally_set = true;
            that.original_key = that.key.key;
        }
        that.update_link();
    };

    that.set_deleted = function(deleted) {
        if (deleted) {
            that.status_label.addClass('strikethrough');
        } else {
            that.status_label.removeClass('strikethrough');
        }
    };

    that.save = function() {
        var value = that.key.key;
        value = value ? [value] : [''];
        return value;
    };

    that.update_link = function() {
        var text = that.get_status();
        that.status_label.text(text);
    };

    that.get_status = function() {

        var text = '';
        var value = that.key.key;

        if (that.original_key) {

            if (value !== that.original_key) {
                if (value === '') {
                    text = IPA.messages.objects.sshkeystore.status_mod_ns;
                } else {
                    text = IPA.messages.objects.sshkeystore.status_mod_s;
                }
            } else {
                text = that.key.fingerprint;
            }

        } else {

            if (!value || value === '') {
                text = IPA.messages.objects.sshkeystore.status_new_ns;
            } else {
                text = IPA.messages.objects.sshkeystore.status_new_s;
            }
        }

        return text;
    };

    that.set_user_value = function(value) {

        var previous = that.key.key;
        that.key.key = value;
        that.update_link();

        if (value !== previous) {
            that.value_changed.notify([], that);
        }
    };

    that.open_edit_dialog = function() {

        var dialog = that.create_edit_dialog();
        dialog.open();
    };

    that.create_edit_dialog = function() {

        var dialog = IPA.dialog({
            name: 'sshkey-edit-dialog',
            title: IPA.messages.objects.sshkeystore.set_dialog_title,
            width: 500,
            height: 380
        });

        dialog.message = IPA.messages.objects.sshkeystore.set_dialog_help;

        dialog.create_button({
            name: 'update',
            label: IPA.messages.buttons.set,
            click: function() {
                var value = dialog.textarea.val();
                that.set_user_value(value);
                dialog.close();
            }
        });

        dialog.create_button({
            name: 'cancel',
            label: IPA.messages.buttons.cancel,
            click: function() {
                dialog.close();
            }
        });

        dialog.create = function() {

            dialog.container.append(dialog.message);

            dialog.textarea = $('<textarea/>', {
                'class': 'certificate',
                readonly: that.read_only
            }).appendTo(dialog.container);

            var key = that.key.key || '';
            dialog.textarea.val(key);
        };

        return dialog;
    };

    return that;
};

IPA.action_panel = function(spec) {

    spec = spec || {};
    spec.label = spec.label || IPA.messages.actions.title;

    var that = IPA.widget(spec);

    that.action_names = spec.actions;
    that.actions = $.ordered_map();
    that.facet = spec.facet;
    that.initialized = false;

    that.init = function() {

        for (var i=0; i<that.action_names.length; i++) {
            var name = that.action_names[i];
            var action = that.facet.actions.get(name);

            that.add_action(action, true);

            that.actions.put(name, action);
        }

        that.initialized = true;
    };

    that.add_action = function(action, batch) {
        that.actions.put(action.name, action);
        action.enabled_changed.attach(that.action_enabled_changed);
        action.visible_changed.attach(that.action_visible_changed);

        if (!batch) {
            that.create_items();
        }
    };

    that.create = function(container) {

        if (!that.initialized) that.init();

        that.element = $('<div/>', {
            'data-name': that.name,
            'class': 'action-panel'
        });

        that.header_element = $('<h3/>', {
            'class': 'action-title'
        }).appendTo(that.element);

        that.list_element = $('<ul/>', {
            'class': 'action-panel-list'
        }).appendTo(that.element);

        that.element.appendTo(container);

        that.create_items();
    };

    that.create_item = function(action) {

        var classes, state, li, a;

        if (!action.visible) return;

        classes = ['action'];
        state = action.enabled ? 'enabled' : 'disabled';
        classes.push(state);

        li = $('<li/>');
        a = $('<a/>', {
            'data-name': action.name,
            href: '#',
            text: action.label,
            'class': classes.join(' '),
            click: function() {
                that.action_clicked(action);
                return false;
            }
        }).appendTo(li);
        li.appendTo(that.list_element);
    };

    that.clear_items = function() {

        that.list_element.empty();
    };

    that.create_items = function() {

        if (!that.element) return;

        that.clear_items();

        var actions = that.actions.values;

        for (var i=0; i<actions.length; i++) {
            var action = actions[i];
            that.create_item(action);
        }

        that.header_element.text(that.label);
    };

    that.action_clicked = function(action) {

        if (!action.enabled || !action.visible) return;

        action.execute(that.facet);
    };

    that.action_enabled_changed = function() {

        that.create_items();
    };

    that.action_visible_changed = function() {

        that.create_items();
    };


    return that;
};

IPA.value_map_widget = function(spec) {

    spec = spec  || {};
    spec.read_only = true;

    var that = IPA.input_widget(spec);
    that.value_map = spec.value_map || {};
    that.default_label = spec.default_label || '';

    that.create = function(container) {
        that.widget_create(container);
        container.addClass('status-widget');

        that.display_control = $('<span/>', {
            name: that.name
        }).appendTo(container);
    };

    that.update = function(values) {

        var value, found, label;

        found = false;

        if ($.isArray(values)) {
            for (value in that.value_map) {

                if (!that.value_map.hasOwnProperty(value)) continue;

                if (values.indexOf(value) > -1) {
                    label = that.value_map[value];
                    found = true;
                }
            }
        }

        if (!found) {
            label = that.default_label;
        }

        that.display_control.text(label);
    };

    that.clear = function() {
        that.display_control.text('');
    };

    return that;
};

IPA.widget_factories['attribute_table'] = IPA.attribute_table_widget;
IPA.widget_factories['button'] = IPA.button_widget;
IPA.widget_factories['checkbox'] = IPA.checkbox_widget;
IPA.widget_factories['checkboxes'] = IPA.checkboxes_widget;
IPA.widget_factories['combobox'] = IPA.combobox_widget;
IPA.widget_factories['composite_widget'] = IPA.composite_widget;
IPA.widget_factories['details_table_section'] = IPA.details_table_section;
IPA.widget_factories['details_table_section_nc'] = IPA.details_table_section_nc;
IPA.widget_factories['multiple_choice_section'] = IPA.multiple_choice_section;
IPA.widget_factories['enable'] = IPA.enable_widget;
IPA.widget_factories['entity_select'] = IPA.entity_select_widget;
IPA.widget_factories['header'] = IPA.header_widget;
IPA.widget_factories['html'] = IPA.html_widget;
IPA.widget_factories['link'] = IPA.link_widget;
IPA.widget_factories['multivalued'] = IPA.multivalued_widget;
IPA.widget_factories['password'] = IPA.password_widget;
IPA.widget_factories['radio'] = IPA.radio_widget;
IPA.widget_factories['select'] = IPA.select_widget;
IPA.widget_factories['sshkeys'] = IPA.sshkeys_widget;
IPA.widget_factories['textarea'] = IPA.textarea_widget;
IPA.widget_factories['text'] = IPA.text_widget;
IPA.widget_factories['value_map'] = IPA.value_map_widget;