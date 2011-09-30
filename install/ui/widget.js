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

IPA.widget = function(spec) {

    spec = spec || {};

    var that = {};


    that.entity = spec.entity;
    that.id = spec.id;
    that.name = spec.name;
    that.label = spec.label;
    that.tooltip = spec.tooltip;

    that.disabled = spec.disabled;
    that.hidden = spec.hidden;
    that.optional = spec.optional || false;

    // read_only is set when widget is created
    that.read_only = spec.read_only;

    // writable is set during load
    that.writable = true;

    that.width = spec.width;
    that.height = spec.height;

    that.undo = typeof spec.undo == 'undefined' ? true : spec.undo;
    that.join = spec.join;

    that.param_info = spec.param_info;
    that.metadata = spec.metadata;

    that.values = [];
    that.dirty = false;
    that.valid = true;

    that.dirty_changed = IPA.observer();


    function set_param_info() {
        if (!that.param_info && that.entity) {
            that.param_info =
                IPA.get_entity_param(that.entity.name, that.name);
        }
        if (that.param_info) {
            if (that.label === undefined) {
                that.label = that.param_info.label;
            }
            if (that.tooltip === undefined) {
                that.tooltip = that.param_info.doc;
            }
        }
    }


    function meta_validate(meta, value){
        var message;

        if (meta.type == 'int') {
            if (!value.match(/^-?\d+$/)) {
                that.valid = false;
                that.show_error(IPA.messages.widget.validation.integer);
                return that.valid;
            }

            if (meta.minvalue !== undefined && value < meta.minvalue) {
                that.valid = false;
                message = IPA.messages.widget.validation.min_value;
                message = message.replace('${value}', meta.minvalue);
                that.show_error(message);
                return that.valid;
            }

            if (meta.maxvalue !== undefined && value > meta.maxvalue) {
                that.valid = false;
                message = IPA.messages.widget.validation.max_value;
                message = message.replace('${value}', meta.maxvalue);
                that.show_error(message);
                return that.valid;
            }
        }
        if (meta.pattern) {
            var regex = new RegExp(meta.pattern);
            if (!value.match(regex)) {
                that.valid = false;
                that.show_error(meta.pattern_errmsg);
                return that.valid;
            }
        }

        return that.valid;
    }

    that.create_error_link = function(container){
        container.append(' ');

        $('<span/>', {
            name: 'error_link',
            html: IPA.messages.widget.validation.error,
            'class': 'ui-state-error ui-corner-all',
            style: 'display:none'
        }).appendTo(container);
    };

    that.check_required = function(){
        var values = that.save();
        if (!values || !values.length || values[0] === '' ) {
            if (that.param_info &&
                that.param_info.required &&
                !that.optional &&
                !that.read_only &&
                that.writable) {
                that.valid = false;
                that.show_error(IPA.messages.widget.validation.required);
                return false;
            }
        }
        return true;
    };

    /*returns true and clears the error message if the field value  passes
      the validation pattern.  If the field value does not pass validation,
      displays the error message and returns false. */
    that.validate = function() {
        that.hide_error();
        that.valid = true;

        var values = that.save();
        if (!values) {
            return that.valid;
        }
        if (values.length === 0) {
            return that.valid;
        }
        var value = values[0];
        if (!value) {
            return that.valid;
        }

        if (that.metadata) {
            meta_validate(that.metadata, value);
        }

        if (that.valid && that.param_info) {
            meta_validate(that.param_info, value);
        }

        return that.valid;
    };


    /**
     * This function compares the original values and the
     * values entered in the UI. If the values have changed
     * it will return true.
     */
    that.test_dirty = function() {

        if (that.read_only) {
            return false;
        }

        var values = that.save();

        if (!values) { // ignore null values
            return false;
        }

        if (!that.values) {

            if (values instanceof Array) {

                if ((values.length === 0) ||
                    (values.length === 1) &&
                    (values[0] === '')) {
                    return false;
                }
            }

            return true;
        }

        if (values.length != that.values.length) {
            return true;
        }

        values.sort();
        that.values.sort();

        for (var i=0; i<values.length; i++) {
            if (values[i] != that.values[i]) {
                return true;
            }
        }

        return false;
    };

    that.create = function(container) {
        container.addClass('widget');
        that.container = container;
    };

    /**
     * This function stores the entire record and the values
     * of the field, then invoke reset() to update the UI.
     */
    that.load = function(record) {
        that.record = record;

        var value = record[that.name];
        if (value instanceof Array) {
            that.values = value;
        } else {
            that.values = value ? [value] : [];
        }

        that.writable = true;

        if (that.param_info) {
            if (that.param_info.primary_key) {
                that.writable = false;
            }

            if (that.param_info.flags && 'no_update' in that.param_info.flags) {
                that.writable = false;
            }
        }

        if (that.record.attributelevelrights) {
            var rights = that.record.attributelevelrights[that.name];
            if (!rights || rights.indexOf('w') < 0) {
                that.writable = false;
            }
        }

        that.reset();
    };

    that.reset = function() {
        that.update();
        that.validate();
        that.set_dirty(false);
    };

    that.update = function() {
    };

    /**
     * This function saves the values entered in the UI.
     * It returns the values in an array, or null if
     * the field should not be saved.
     */
    that.save = function() {
        return that.values;
    };

    /**
     * This function compares the original values and the
     * values entered in the UI. If the values have changed
     * it will return true.
     */
    that.is_dirty = function() {
        return that.dirty;
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
                that.reset();
            };
        }

        if(typeof on_undo === 'function') {
            that.undo_span.click(on_undo);
        }
    };

    that.set_dirty = function(dirty) {
        var old = that.dirty;
        that.dirty = dirty;
        if (that.undo) {
            if (dirty) {
                that.show_undo();
            } else {
                that.hide_undo();
            }
        }

        if(old !== dirty) {
            that.dirty_changed.notify([], that);
        }
    };

    that.get_undo = function() {
        return $(that.undo_span);
    };

    that.show_undo = function() {
        $(that.undo_span).css('display', 'inline');
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

    that.set_enabled = function() {
    };

    that.refresh = function() {
    };


    /*widget initialization*/
    set_param_info();

    // methods that should be invoked by subclasses
    that.widget_create = that.create;
    that.widget_hide_error = that.hide_error;
    that.widget_load = that.load;
    that.widget_reset = that.reset;
    that.widget_save = that.save;
    that.widget_set_dirty = that.set_dirty;
    that.widget_show_error = that.show_error;
    that.widget_test_dirty = that.test_dirty;

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

    var that = IPA.widget(spec);

    that.size = spec.size || 30;
    that.type = spec.type || 'text';

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
            type: that.type,
            name: that.name,
            disabled: that.disabled,
            size: that.size,
            title: that.tooltip,
            keyup: function() {
                that.set_dirty(that.test_dirty());
                that.validate();
            }
        }).appendTo(container);

        if (that.undo) {
            that.create_undo(container);
        }

        that.create_error_link(container);
    };

    that.update = function() {
        var value = that.values && that.values.length ? that.values[0] : '';

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

    // methods that should be invoked by subclasses
    that.text_load = that.load;

    return that;
};

IPA.multivalued_text_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.size = spec.size || 30;

    that.get_undo = function(index) {
        if (index === undefined) {
            return $('span[name="undo_all"]', that.container);

        } else {
            var row = that.get_row(index);
            return $('span[name="undo"]', row);
        }
    };

    that.test_dirty = function(index) {
        if (index === undefined) {
            return that.widget_test_dirty();
        }

        var row = that.get_row(index);
        var input = $('input[name="'+that.name+'"]', row);

        if (input.is('.strikethrough')) {
            return true;
        }

        var value = input.val();
        if (value !== that.values[index]) {
            return true;
        }

        return false;
    };

    that.set_dirty = function(dirty, index) {
        var old = that.dirty;
        that.dirty = dirty;

        if (that.undo) {
            if (dirty) {
                that.show_undo(index);
            } else {
                that.hide_undo(index);
            }

            if (index !== undefined) {
                // update undo all
                that.set_dirty(that.test_dirty());
            }
        }

        if(old !== dirty) {
            that.dirty_changed.notify([], that);
        }
    };

    that.show_undo = function(index) {
        var undo = that.get_undo(index);
        undo.css('display', 'inline');
    };

    that.hide_undo = function(index) {
        var undo = that.get_undo(index);
        undo.css('display', 'none');
    };

    that.create = function(container) {

        that.widget_create(container);

        container.addClass('multivalued-text-widget');

        //create template row

        that.template = $('<div/>', {
            name: 'value'
        });

        $('<input/>', {
            type: 'text',
            name: that.name,
            disabled: that.disabled,
            size: that.size,
            title: that.tooltip
        }).appendTo(that.template);

        that.template.append(' ');

        $('<a/>', {
            name: 'remove',
            href: 'jslink',
            title: IPA.messages.buttons.remove,
            html: IPA.messages.buttons.remove
        }).appendTo(that.template);

        if (that.undo) {
            that.create_undo(that.template, false /* no callback */);
        }

        that.create_error_link(container);

        $('<a/>', {
            name: 'add',
            href: 'jslink',
            title: IPA.messages.buttons.add,
            html: IPA.messages.buttons.add,
            click: function() {
                that.add_row('');
                var input = $('input[name="'+that.name+'"]:last', that.container);
                input.focus();
                return false;
            }
        }).appendTo(container);

        //create other

        container.append(' ');

        $('<span/>', {
            name: 'undo_all',
            style: 'display: none;',
            'class': 'ui-state-highlight ui-corner-all undo',
            html: IPA.messages.widget.undo_all,
            click: function() {
                that.reset();
            }
        }).appendTo(container);
    };

    that.save = function() {
        var values = [];
        if (that.read_only || !that.writable) {
            $('label[name="'+that.name+'"]', that.container).each(function() {
                var input = $(this);
                var value = input.html();
                values.push(value);
            });

        } else {
            $('input[name="'+that.name+'"]', that.container).each(function() {
                var input = $(this);
                if (input.is('.strikethrough')) return;

                var value = input.val();
                values.push(value);
            });
        }
        return values;
    };

    that.add_row = function(value) {

        var add_link = $('a[name=add]', that.container);

        var row = that.template.clone();
        row.insertBefore(add_link);

        var input = $('input[name="'+that.name+'"]', row);
        var remove_link = $('a[name=remove]', row);
        var undo_link = $('span[name=undo]', row);

        if (that.read_only || !that.writable) {
            var label = $('<label/>', {
                name: that.name,
                text: value
            });
            input.replaceWith(label);

            remove_link.css('display', 'none');

        } else {
            input.val(value);

            var index = that.row_index(row);
            if (index >= that.values.length) {
                // show undo/remove link for new value
                that.set_dirty(true, index);
                if (that.undo) {
                    remove_link.css('display', 'none');
                } else {
                    remove_link.css('display', 'inline');
                }
            }

            input.keyup(function() {
                var index = that.row_index(row);
                // uncross removed value
                input.removeClass('strikethrough');
                that.set_dirty(that.test_dirty(index), index);
                if (that.undo) {
                    if (index < that.values.length) {
                        remove_link.css('display', 'inline');
                    }
                }
                that.validate();
            });

            remove_link.click(function() {
                var index = that.row_index(row);
                if (index < that.values.length) {
                    // restore old value then cross it out
                    that.update(index);
                    input.addClass('strikethrough');
                    that.set_dirty(true, index);
                    remove_link.css('display', 'none');
                } else {
                    // remove new value
                    that.remove_row(index);
                    that.set_dirty(that.test_dirty());
                }
                return false;
            });

            undo_link.click(function() {
                var index = that.row_index(row);
                if (index < that.values.length) {
                    // restore old value
                    input.removeClass('strikethrough');
                    remove_link.css('display', 'inline');
                    that.reset(index);
                } else {
                    // remove new value
                    that.remove_row(index);
                    that.set_dirty(that.test_dirty());
                }
            });
        }
    };

    that.remove_row = function(index) {
        that.get_row(index).remove();
    };

    that.remove_rows = function() {
        that.get_rows().remove();
    };

    that.get_row = function(index) {
        return $('div[name=value]:eq('+index+')', that.container);
    };

    that.get_rows = function() {
        return $('div[name=value]', that.container);
    };

    that.row_index = function(row) {
        return that.get_rows().index(row);
    };

    that.reset = function(index) {
        that.update(index);
        that.set_dirty(false, index);
    };

    that.update = function(index) {

        var value;

        if (index === undefined) {
            that.remove_rows();

            for (var i=0; i<that.values.length; i++) {
                value = that.values[i];
                that.add_row(value);
            }

            var add_link = $('a[name=add]', that.container);

            if (that.read_only || !that.writable) {
                add_link.css('display', 'none');
            } else {
                add_link.css('display', 'inline');
            }

        } else {
            value = that.values[index];
            var row = that.get_row(index);
            var input = $('input[name="'+that.name+'"]', row);
            input.val(value);
        }
    };

    return that;
};

IPA.checkbox_widget = function (spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

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
                that.set_dirty(that.test_dirty());
            }
        }).appendTo(container);

        if (that.undo) {
            that.create_undo(container);
        }

        that.create_error_link(container);
    };

    that.load = function(record) {
        that.widget_load(record);
        that.values = record[that.name] || [false];
        that.reset();
    };

    that.save = function() {
        var value = that.input.is(':checked');
        return [value];
    };

    that.update = function() {
        var value;

        if (that.values && that.values.length) {
            // use loaded value
            value = that.values[0];
        } else {
            // use default value
            value = that.checked;
        }

        // convert string into boolean
        if (value === 'TRUE') {
            value = true;
        } else if (value === 'FALSE') {
            value = false;
        }

        that.input.attr('checked', value);
    };

    that.checkbox_save = that.save;
    that.checkbox_load = that.load;

    return that;
};

IPA.checkboxes_widget = function (spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.direction = spec.direction || 'vertical';
    that.options = spec.options || [];

    that.add_option = function(option) {
        that.options.push(option);
    };

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
            that.set_dirty(that.test_dirty());
        });

        that.create_error_link(container);
    };


    that.load = function(record) {
        that.values = record[that.name] || [];
        that.reset();
    };

    that.save = function() {
        var values = [];

        $('input[name="'+that.name+'"]:checked', that.container).each(function() {
            values.push($(this).val());
        });

        return values;
    };

    that.update = function() {
        var inputs = $('input[name="'+that.name+'"]', that.container);
        inputs.attr('checked', false);

        for (var j=0; that.values && j<that.values.length; j++) {
            var value = that.values[j];
            var input = $('input[name="'+that.name+'"][value="'+value+'"]', that.container);
            if (!input.length) continue;
            input.attr('checked', true);
        }
    };

    // methods that should be invoked by subclasses
    that.checkboxes_update = that.update;

    return that;
};

IPA.radio_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.options = spec.options;

    that.create = function(container) {

        that.widget_create(container);

        container.addClass('radio-widget');

        for (var i=0; i<that.options.length; i++) {
            var option = that.options[i];

            $('<input/>', {
                'type': 'radio',
                'name': that.name,
                'value': option.value
            }).appendTo(container);

            container.append(option.label);
        }

        if (that.undo) {
            that.create_undo(container);
        }

        var input = $('input[name="'+that.name+'"]', that.container);
        input.change(function() {
            that.set_dirty(that.test_dirty());
        });

        that.create_error_link(container);
    };

    that.load = function(record) {
        that.widget_load(record);
        if (!that.values.length) {
            that.values = [''];
        }
        that.reset();
    };

    that.save = function() {
        var input = $('input[name="'+that.name+'"]:checked', that.container);
        if (!input.length) return [];
        return [input.val()];
    };

    that.update = function() {

        $('input[name="'+that.name+'"]', that.container).each(function() {
            var input = this;
            input.checked = false;
        });

        var value = that.values && that.values.length ? that.values[0] : '';
        var input = $('input[name="'+that.name+'"][value="'+value+'"]', that.container);
        if (input.length) {
            input.attr('checked', true);
        }
    };

    // methods that should be invoked by subclasses
    that.radio_create = that.create;
    that.radio_save = that.save;

    return that;
};

IPA.select_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.options = spec.options || [];

    that.create = function(container) {

        that.widget_create(container);

        container.addClass('select-widget');

        var select = $('<select/>', {
            name: that.name
        }).appendTo(container);

        for (var i=0; i<that.options.length; i++) {
            var option = that.options[i];

            $('<option/>', {
                text: option.label,
                value: option.value
            }).appendTo(select);
        }

        if (that.undo) {
            that.create_undo(container);
        }

        that.select = $('select[name="'+that.name+'"]', that.container);
        that.select.change(function() {
            that.set_dirty(that.test_dirty());
        });

        that.create_error_link(container);
    };

    that.load = function(record) {
        var value = record[that.name];
        if (value instanceof Array) {
            that.values = value;
        } else {
            that.values = value ? [value] : [''];
        }
        that.reset();
    };

    that.save = function() {
        var value = that.select.val() || '';
        return [value];
    };

    that.update = function() {
        var value = that.values[0];
        var option = $('option[value="'+value+'"]', that.select);
        if (!option.length) return;
        option.attr('selected', 'selected');
    };

    that.empty = function() {
        $('option', that.select).remove();
    };

    // methods that should be invoked by subclasses
    that.select_load = that.load;
    that.select_save = that.save;
    that.select_update = that.update;

    return that;
};

IPA.textarea_widget = function (spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

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
                that.set_dirty(that.test_dirty());
                that.validate();
            }
        }).appendTo(container);

        if (that.undo) {
            that.create_undo(container);
        }

        that.create_error_link(container);
    };

    that.load = function(record) {
        var value = record[that.name];
        if (value instanceof Array) {
            that.values = value;
        } else {
            that.values = value ? [value] : [''];
        }
        that.reset();
    };

    that.save = function() {
        var value = that.input.val();
        return [value];
    };

    that.update = function() {
        var value = that.values && that.values.length ? that.values[0] : '';
        that.input.val(value);
    };

    return that;
};

/*
  The entity name must be set in the spec either directly or via entity.name
*/
IPA.column = function (spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.label = spec.label;
    that.width = spec.width;
    that.entity_name = spec.entity ? spec.entity.name : spec.entity_name;
    that.primary_key = spec.primary_key;
    that.link = spec.link;
    that.format = spec.format;

    if (!that.entity_name){
        var except = {
            expected: false,
            message:'Column created without an entity_name.'
        };
        throw except;
    }

    that.setup = function(container, record) {

        container.empty();

        var value = record[that.name];
        if (that.format && value) {
            value = that.format(value);
        }
        value = value ? value.toString() : '';

        if (that.link) {
            $('<a/>', {
                href: '#'+value,
                text: value,
                click: function() {
                    return that.link_handler(value);
                }
            }).appendTo(container);

        } else {
            container.text(value);
        }
    };

    that.link_handler = function(value) {
        return false;
    };


    /*column initialization*/
    if (that.entity_name && !that.label) {
        var param_info = IPA.get_entity_param(that.entity_name, that.name);
        if (param_info) {
            that.label = param_info.label;
        }
    }


    return that;
};

IPA.table_widget = function (spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.scrollable = spec.scrollable;
    that.selectable = spec.selectable === undefined ? true : spec.selectable;
    that.save_values = spec.save_values === undefined ? true : spec.save_values;
    that['class'] = spec['class'];

    that.current_page = 1;
    that.total_pages = 1;
    that.page_length = spec.page_length;

    that.columns = $.ordered_map();

    that.get_columns = function() {
        return that.columns.values;
    };

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
                'style': 'width: 22px;'
            }).appendTo(tr);

            var select_all_checkbox = $('<input/>', {
                type: 'checkbox',
                name: 'select',
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

        var columns = that.columns.values;
        for (var i=0; i<columns.length; i++) {
            var column = columns[i];

            th = $('<th/>').appendTo(tr);

            if (that.scrollable) {
                var width;
                if (column.width) {
                    width = parseInt(
                        column.width.substring(0, column.width.length-2),10);
                    width += 16;
                } else {
                    /* don't use the checkbox column as part of the overall
                       calculation for column widths.  It is so small
                       that it throws off the average. */
                    width = (that.table.width() -
                             (that.selectable ?
                              IPA.checkbox_column_width : 0)) /
                        columns.length;
                }
                width += 'px';
                th.css('width', width);
                column.width = width;
            } else {
                if (column.width) {
                    th.css('width', column.width);
                }
            }

            var label = column.label;

            $('<span/>', {
                'style': 'float: left;',
                'html': label
            }).appendTo(th);

            if (i == columns.length-1) {
                that.buttons = $('<span/>', {
                    'name': 'buttons',
                    'style': 'float: right;'
                }).appendTo(th);
            }
            if (that.scrollable && !column.width){
                column.width = th.width() +'px';
            }
        }

        that.tbody = $('<tbody/>').appendTo(that.table);

        if (that.height) {
            that.tbody.css('height', that.height);
        }

        that.row = $('<tr/>');

        var td;

        if (that.selectable) {
            td = $('<td/>', {
                'style': 'width: '+ IPA.checkbox_column_width +'px;'
            }).appendTo(that.row);

            $('<input/>', {
                'type': 'checkbox',
                'name': 'select',
                'value': 'user'
            }).appendTo(td);
        }

        for (/* var */ i=0; i<columns.length; i++) {
            /* var */ column = columns[i];

            td = $('<td/>').appendTo(that.row);
            if (column.width) {
                td.css('width', column.width);
            }

            $('<span/>', {
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

        that.pagination = $('<span/>', {
            'name': 'pagination'
        }).appendTo(td);

        if (that.page_length) {

            $('<a/>', {
                text: IPA.messages.widget.prev,
                name: 'prev_page',
                click: function() {
                    that.prev_page();
                    return false;
                }
            }).appendTo(that.pagination);

            that.pagination.append(' ');

            $('<a/>', {
                text: IPA.messages.widget.next,
                name: 'next_page',
                click: function() {
                    that.next_page();
                    return false;
                }
            }).appendTo(that.pagination);

            that.pagination.append(' ');
            that.pagination.append(IPA.messages.widget.page);
            that.pagination.append(': ');

            that.current_page_input = $('<input/>', {
                type: 'text',
                name: 'current_page',
                keypress: function(e) {
                    if (e.which == 13) {
                        var page = parseInt(that.current_page_input.val(), 10) || 1;
                        that.set_page(page);
                    }
                }
            }).appendTo(that.pagination);

            that.pagination.append(' / ');

            that.total_pages_span = $('<span/>', {
                name: 'total_pages'
            }).appendTo(that.pagination);
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
        $('input[name=select]', that.thead).attr('checked', true).
            attr('title', IPA.messages.search.unselect_all);
        $('input[name=select]', that.tbody).attr('checked', true);
        that.select_changed();
    };

    that.unselect_all = function() {
        $('input[name=select]', that.thead).attr('checked', false).
            attr('title', IPA.messages.search.select_all);
        $('input[name=select]', that.tbody).attr('checked', false);

        that.select_changed();
    };

    that.empty = function() {
        that.tbody.empty();
    };

    that.load = function(result) {

        that.empty();

        that.values = result[that.name];
        if (that.values) {
            for (var i=0; i<that.values.length; i++) {
                var record = that.get_record(result, i);
                that.add_record(record);
            }
        }
        that.unselect_all();
    };

    that.save = function() {
        if (that.save_values) {
            var values = [];

            $('input[name="select"]', that.tbody).each(function() {
                values.push($(this).val());
            });

            return values;

        } else {
            return null;
        }
    };

    that.get_selected_values = function() {
        var values = [];

        $('input[name="select"]:checked', that.tbody).each(function() {
            values.push($(this).val());
        });

        return values;
    };

    that.get_selected_rows = function() {
        return $('input[name="select"]:checked', that.tbody).closest('tr');
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
            }else{
                record[name] = values;
            }
        }

        return record;
    };

    that.add_record = function(record) {

        var tr = that.row.clone();
        tr.appendTo(that.tbody);

        $('input[name="select"]', tr).click(function(){
            that.select_changed();
        });


        var columns = that.columns.values;
        for (var i=0; i<columns.length; i++){
            var column = columns[i];

            var value = record[column.name];
            value = value ? value.toString() : '';

            if (column.primary_key) {
                $('input[name="select"]', tr).val(value);
            }

            var span = $('span[name="'+column.name+'"]', tr);

            column.setup(span, record);
        }
    };

    that.add_rows = function(rows) {
        for (var i=0; i<rows.length; i++) {
            that.tbody.append(rows[i]);
        }
    };

    that.remove_selected_rows = function() {
        var rows = [];
        that.tbody.children().each(function() {
            var tr = $(this);
            if (!$('input[name="select"]', tr).get(0).checked) return;
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
        if (enabled) {
            $('input[name="select"]', that.table).attr('disabled', false);
        } else {
            $('input[name="select"]', that.table).attr('disabled', true);
        }
    };

    if (spec.columns) {
        for (var i=0; i<spec.columns; i++) {
            that.create_column(spec.columns[i]);
        }
    }

    // methods that should be invoked by subclasses
    that.table_create = that.create;
    that.table_next_page = that.next_page;
    that.table_prev_page = that.prev_page;
    that.table_set_enabled = that.set_enabled;
    that.table_set_page = that.set_page;
    that.table_show_error = that.show_error;

    return that;
};

IPA.combobox_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.editable = spec.editable;
    that.searchable = spec.searchable;
    that.list_size = spec.list_size || 5;
    that.empty_option = spec.empty_option === undefined ? true : spec.empty_option;

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
            readonly: !that.editable,
            keyup: function() {
                that.validate();
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
            'class': 'combobox-widget-list'
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
            size: that.list_size,
            style: 'width: 100%',
            change: function() {
                var value = $('option:selected', that.list).val();
                that.input.val(value);
                IPA.select_range(that.input, 0, 0);

                that.close();
                that.validate();
                that.set_dirty(that.test_dirty());
            }
        }).appendTo(div);

        if (that.undo) {
            that.create_undo(container);
        }

        that.create_error_link(container);
    };

    that.open = function() {
        that.list_container.css('visibility', 'visible');
    };

    that.close = function() {
        that.list_container.css('visibility', 'hidden');
    };

    that.is_open = function() {
        return that.list_container.css('visibility') == 'visible';
    };

    that.search = function(filter) {
    };

    that.update = function() {
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
        var value = that.values.length ? that.values[0] : null;

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

        option.attr('selected', 'selected');

        that.set_value(option.val());
        that.set_dirty(that.test_dirty());
    };

    that.save = function() {
        var value = that.input.val();
        return value === '' ? [] : [value];
    };

    that.create_option = function(text, value) {
        return $('<option/>', {
            text: text,
            value: value
        }).appendTo(that.list);
    };

    that.remove_options = function() {
        that.list.empty();
    };

    return that;
};

IPA.entity_select_widget = function(spec) {

    spec = spec || {};
    spec.searchable = spec.searchable === undefined ? true : spec.searchable;

    var that = IPA.combobox_widget(spec);

    that.other_entity = spec.other_entity;
    that.other_field = spec.other_field;

    that.create_search_command = function(filter) {
        return IPA.command({
            entity: that.other_entity,
            method: 'find',
            args: [filter]
        });
    };

    that.search = function(filter, on_success, on_error) {

        var command = that.create_search_command(filter);

        command.on_success = function(data, text_status, xhr) {

            that.remove_options();

            if (that.empty_option) {
                that.create_option();
            }

            var entries = data.result.result;
            for (var i=0; i<data.result.count; i++) {
                var entry = entries[i];
                var values = entry[that.other_field];
                var value = values[0];

                that.create_option(value, value);
            }

            if (on_success) on_success.call(this, data, text_status, xhr);
        };

        command.on_error = on_error;

        command.execute();
    };

    return that;
};

IPA.entity_link_widget = function(spec) {
    var that = IPA.widget(spec);
    var other_entity = spec.other_entity;

    function other_pkeys (){
        return that.entity.get_primary_key();
    }
    that.other_pkeys = spec.other_pkeys || other_pkeys;

    that.create = function(container) {
        that.widget_create(container);
        that.link =
        $('<a/>', {
            href: 'jslink',
            title: '',
            html: '',
            click: function() {
                IPA.nav.show_entity_page(
                    IPA.get_entity(other_entity),
                    'default',
                    that.other_pkeys());
                return false;
            }
        }).appendTo(container);

        that.nonlink = $('<label/>').
            appendTo(container);
    };

    that.load = function (record){
        that.widget_load(record);
        if (that.values || that.values.length > 0){
            that.nonlink.text(that.values[0]);
            that.link.text(that.values[0]);
            that.link.css('display','none');
            that.nonlink.css('display','inline');
        }else{
            that.link.html('');
            that.nonlink.html('');
            that.link.css('display','none');
            that.nonlink.css('display','none');
        }

        function find_success(result) {
            if (result.result){
                that.link.css('display','inline');
                that.nonlink.css('display','none');
            }
        }
        function find_error(err){
        }
        IPA.command({
            entity: other_entity,
            method: 'show',
            args:that.other_pkeys(),
            options:{},
            retry:false,
            on_success:find_success,
            on_error:find_error
        }).execute();
    };


    return that;
};

IPA.action_button = function(spec) {
    var button = IPA.button(spec);
    button.removeClass("ui-state-default").addClass("action-button");
    return button;
};

IPA.button = function(spec) {

    spec = spec || {};

    var button = $('<a/>', {
        id: spec.id,
        name: spec.name,
        href: spec.href || '#' + (spec.name || 'button'),
        title: spec.title || spec.label,
        'class': 'ui-state-default ui-corner-all input_link',
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
