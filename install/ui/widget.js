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

    that.id = spec.id;
    that.name = spec.name;
    that.label = spec.label;
    that.tooltip = spec.tooltip;

    that.disabled = spec.disabled;
    that.hidden = spec.hidden;
    that.conditional = spec.conditional;
    that.optional = spec.optional || false;

    // read_only is set during initialization
    that.read_only = spec.read_only;

    // writable is set during load
    that.writable = true;

    that._entity_name = spec.entity_name;

    that.width = spec.width;
    that.height = spec.height;

    that.undo = typeof spec.undo == 'undefined' ? true : spec.undo;
    that.join = spec.join;

    that.param_info = spec.param_info;
    that.metadata = spec.metadata;

    that.values = [];
    that.dirty = false;
    that.valid = true;

    that.__defineGetter__("entity_name", function(){
        return that._entity_name;
    });

    that.__defineSetter__("entity_name", function(entity_name){
        that._entity_name = entity_name;
    });


    function meta_validate(meta, value){
        var message;

        if (meta.type == 'int') {
            if (!value.match(/^-?\d+$/)) {
                that.valid = false;
                that.show_error(IPA.messages.widget.validation.integer);
                return;
            }

            if (meta.minvalue && value < meta.minvalue) {
                that.valid = false;
                message = IPA.messages.widget.validation.min_value;
                message = message.replace('${value}', meta.minvalue);
                that.show_error(message);
                return;
            }

            if (meta.maxvalue && value > meta.maxvalue) {
                that.valid = false;
                message = IPA.messages.widget.validation.max_value;
                message = message.replace('${value}', meta.maxvalue);
                that.show_error(message);
                return;
            }
        }
        if (meta.pattern) {
            var regex = new RegExp(meta.pattern);
            if (!value.match(regex)) {
                that.valid = false;
                that.show_error(meta.pattern_errmsg);
                return;
            }
        }

    }

    /*returns true and clears the error message if the field value  passes
      the validation pattern.  If the field value does not pass validation,
      displays the error message and returns false. */
    that.validate = function() {

        that.hide_error();

        that.valid = true;

        var values = that.save();
        if (!values || !values.length) {
            if (that.param_info &&
                that.param_info.required &&
                !that.optional) {
                that.valid = false;
                that.show_error(IPA.messages.widget.validation.required);
            }
            return;
        }

        var value = values[0];
        if (!value) {
            return;
        }

        if (that.metadata) {
            meta_validate(that.metadata,value);
        }
        if (that.param_info) {
            meta_validate(that.param_info,value);
        }
    };

    that.init = function() {
        if (that.entity_name) {
            that.entity = IPA.get_entity(that.entity_name);
            that.param_info = IPA.get_entity_param(that.entity_name, that.name);

            if (that.param_info) {

                if (that.label === undefined) {
                    that.label = that.param_info.label;
                }

                if (that.tooltip === undefined) {
                    that.tooltip = that.param_info.doc;
                }
            }
        }
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
        that.container = container;
    };

    that.setup = function(container) {
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

    that.create_undo = function(container) {
        that.undo_span =
            $('<span/>', {
                name: 'undo',
                style: 'display: none;',
                'class': 'ui-state-highlight ui-corner-all undo',
                html: 'undo'
            }).appendTo(container);
    };

    that.set_dirty = function(dirty) {
        that.dirty = dirty;
        if (that.undo) {
            if (dirty) {
                that.show_undo();
            } else {
                that.hide_undo();
            }
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

    // methods that should be invoked by subclasses
    that.widget_init = that.init;
    that.widget_create = that.create;
    that.widget_setup = that.setup;
    that.widget_load = that.load;
    that.widget_reset = that.reset;
    that.widget_save = that.save;
    that.widget_set_dirty = that.set_dirty;
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

        $('<label/>', {
            name: that.name,
            style: 'display: none;'
        }).appendTo(container);

        $('<input/>', {
            type: that.type,
            name: that.name,
            disabled: that.disabled,
            size: that.size,
            title: that.tooltip
        }).appendTo(container);

        if (that.undo) {
            container.append(' ');
            that.create_undo(container);
        }

        container.append(' ');

        $('<span/>', {
            name: 'error_link',
            html: IPA.messages.widget.validation.error,
            'class': 'ui-state-error ui-corner-all',
            style: 'display:none'
        }).appendTo(container);
    };

    that.setup = function(container) {

        that.widget_setup(container);

        var input = $('input[name="'+that.name+'"]', that.container);
        input.keyup(function() {
            that.set_dirty(that.test_dirty());
            that.validate();
        });

        var undo = that.get_undo();
        undo.click(function() {
            that.reset();
        });
        that.input = input;
    };

    that.update = function() {
        var value = that.values && that.values.length ? that.values[0] : '';

        var label = $('label[name="'+that.name+'"]', that.container);
        var input = $('input[name="'+that.name+'"]', that.container);

        if (that.read_only || !that.writable) {
            label.html(value);
            label.css('display', 'inline');
            input.css('display', 'none');

        } else {
            $('input[name="'+that.name+'"]', that.container).val(value);
            label.css('display', 'none');
            input.css('display', 'inline');
        }
    };

    that.save = function() {
        if (that.read_only || !that.writable) {
            return null;

        } else {
            var input = $('input[name="'+that.name+'"]', that.container);
            var value = input.val();
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

        var div = $('<div/>', {
            name: 'value'
        }).appendTo(container);

        $('<input/>', {
            type: 'text',
            name: that.name,
            disabled: that.disabled,
            size: that.size,
            title: that.tooltip
        }).appendTo(div);

        div.append(' ');

        $('<a/>', {
            name: 'remove',
            href: 'jslink',
            title: IPA.messages.buttons.remove,
            html: IPA.messages.buttons.remove
        }).appendTo(div);

        if (that.undo) {
            div.append(' ');
            that.create_undo(div);
        }

        div.append(' ');

        $('<span/>', {
            name: 'error_link',
            html: IPA.messages.widget.validation.error,
            'class': 'ui-state-error ui-corner-all',
            style: 'display:none'
        }).appendTo(div);

        $('<a/>', {
            name: 'add',
            href: 'jslink',
            title: IPA.messages.buttons.add,
            html: IPA.messages.buttons.add
        }).appendTo(container);

        container.append(' ');

        $('<span/>', {
            name: 'undo_all',
            style: 'display: none;',
            'class': 'ui-state-highlight ui-corner-all undo',
            html: 'undo all'
        }).appendTo(container);
    };

    that.setup = function(container) {

        that.widget_setup(container);

        that.template = $('div[name=value]', that.container);
        that.template.detach();

        var undo = that.get_undo();
        undo.click(function() {
            that.reset();
        });

        var add_link = $('a[name=add]', that.container);
        add_link.click(function() {
            that.add_row('');
            var input = $('input[name="'+that.name+'"]:last', that.container);
            input.focus();
            return false;
        });
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
                'name': that.name,
                'html': value
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

    that.checked = spec.checked || '';

    that.create = function(container) {

        $('<input/>', {
            type: 'checkbox',
            name: that.name,
            checked : that.checked,
            title: that.tooltip
        }).appendTo(container);

        if (that.undo) {
            that.create_undo(container);
        }
    };

    that.setup = function(container) {

        that.widget_setup(container);

        var input = $('input[name="'+that.name+'"]', that.container);
        input.change(function() {
            that.set_dirty(that.test_dirty());
        });

        var undo = that.get_undo();
        undo.click(function() {
            that.reset();
        });
    };

    that.load = function(record) {
        that.values = record[that.name] || [false];
        that.reset();
    };

    that.save = function() {
        var value = $('input[name="'+that.name+'"]', that.container).is(':checked');
        return [value];
    };

    that.update = function() {
        var value = that.values && that.values.length ? that.values[0] : false;
        if (value ==="FALSE"){
            value = false;
        }
        if (value ==="TRUE"){
            value = true;
        }

        $('input[name="'+that.name+'"]', that.container).get(0).checked = value;
    };

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
    };

    that.setup = function(container) {

        that.widget_setup(container);

        var input = $('input[name="'+that.name+'"]', that.container);
        input.change(function() {
            that.set_dirty(that.test_dirty());
        });

        var undo = that.get_undo();
        undo.click(function() {
            that.reset();
        });
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

        for (var i=0; i<inputs.length; i++) {
            inputs.get(i).checked = false;
        }

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
    };

    that.setup = function(container) {

        that.widget_setup(container);

        var input = $('input[name="'+that.name+'"]', that.container);
        input.change(function() {
            that.set_dirty(that.test_dirty());
        });

        var undo = that.get_undo();
        undo.click(function() {
            that.reset();
        });
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
    that.radio_save = that.save;

    return that;
};

IPA.select_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.options = spec.options || [];

    that.create = function(container) {

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
            container.append(' ');
            that.create_undo(container);
        }
    };

    that.setup = function(container) {
        that.widget_setup(container);

        that.select = $('select[name="'+that.name+'"]', that.container);
        that.select.change(function() {
            that.set_dirty(that.test_dirty());
        });

        var undo = that.get_undo();
        undo.click(function() {
            that.reset();
        });
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

        $('<textarea/>', {
            name: that.name,
            rows: that.rows,
            cols: that.cols,
            disabled: that.disabled,
            title: that.tooltip
        }).appendTo(container);

        if (that.undo) {
            container.append(' ');
            that.create_undo(container);
        }

        $("<span/>",{
            name:'error_link',
            html: IPA.messages.widget.validation.error,
            "class":"ui-state-error ui-corner-all",
            style:"display:none"
        }).appendTo(container);
    };

    that.setup = function(container) {

        that.widget_setup(container);

        var input = $('textarea[name="'+that.name+'"]', that.container);
        input.keyup(function() {
            that.set_dirty(that.test_dirty());
            that.validate();

        });

        var undo = that.get_undo();
        undo.click(function() {
            that.reset();
        });
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
        var value = $('textarea[name="'+that.name+'"]', that.container).val();
        return [value];
    };

    that.update = function() {
        var value = that.values && that.values.length ? that.values[0] : '';
        $('textarea[name="'+that.name+'"]', that.container).val(value);
    };

    return that;
};


IPA.column = function (spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.label = spec.label;
    that.width = spec.width;

    that.entity_name = spec.entity_name;
    that.primary_key = spec.primary_key;
    that.link = spec.link;

    that.format = spec.format;

    that.init = function() {
        if (that.entity_name && !that.label) {
            var param_info = IPA.get_entity_param(that.entity_name, that.name);
            if (param_info) {
                that.label = param_info.label;
            } else {
                alert('Cannot find label for ' + that.entity_name + ' ' +
                      that.name);
            }
        }
    };

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
                html: value,
                click: function() {
                    return that.link_handler(value);
                }
            }).appendTo(container);

        } else {
            container.append(value);
        }

    };

    that.link_handler = function(value) {
        return false;
    };

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

    that.init = function() {
        that.widget_init();

        var columns = that.columns.values;
        for (var i=0; i<columns.length; i++) {
            var column = columns[i];
            column.init();
        }
    };

    that.create = function(container) {

        that.widget_create(container);

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
                var checked = select_all_checkbox.is(':checked');
                select_all_checkbox.attr('title', checked ? IPA.messages.search.unselect_all : IPA.messages.search.select_all);
                var checkboxes = $('input[name=select]', that.tbody).get();
                for (var i=0; i<checkboxes.length; i++) {
                    checkboxes[i].checked = checked;
                }
                that.select_changed();
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
                    width = (that.table.width() - (that.selectable ? IPA.checkbox_column_width : 0)) /
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
                $('<span/>', {
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

    that.setup = function(container) {

        that.widget_setup(container);
    };

    that.empty = function() {
        that.tbody.empty();
    };

    that.load = function(result) {

        that.empty();

        that.values = result[that.name];
        if (!that.values) return;

        for (var i=0; i<that.values.length; i++) {
            var record = that.get_record(result, i);
            that.add_record(record);
        }
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
    that.table_init = that.init;
    that.table_create = that.create;
    that.table_setup = that.setup;
    that.table_set_enabled = that.set_enabled;
    that.table_prev_page = that.prev_page;
    that.table_next_page = that.next_page;
    that.table_set_page = that.set_page;

    return that;
};

IPA.entity_select_widget = function(spec) {

    var that = IPA.widget(spec);
    var entity = spec.entity || 'group';
    var field_name = spec.field_name || 'cn';
    var editable = spec.editable || false;

    function populate_select(value) {
        function find_success(result) {
            $('option', that.entity_select).remove();

            // add default empty value
            $('<option/>', {
                text: '',
                value: ''
            }).
            appendTo(that.entity_select);

            var entities = result.result.result;
            for (var i =0; i < result.result.count; i +=1){
                var entity = entities[i];
                var field_array = entity[field_name];
                var field_value = field_array[0];
                var option =
                    $('<option/>',{
                        text:field_value,
                        value:field_value
                    }).
                    appendTo(that.entity_select);
                if (value === field_value){
                    option.attr('selected','selected');
                }
            }
            that.set_dirty(that.test_dirty());
        }
        function find_error(err){
        }
        IPA.command({
            entity: entity,
            method: 'find',
            args:[that.entity_filter.val()],
            options:{},
            on_success:find_success,
            on_error:find_error
        }).execute();
    }

    that.create = function(container) {

        if (editable){
            that.edit_box = $('<input />',{
                type: 'text',
                title: that.tooltip
            });

            $('<div style:"display=block;" />').
                append(that.edit_box).
                appendTo(container);
        }

        that.entity_select = $('<select/>', {
            id: that.name + '-entity-select',
            change: function(){
                if (editable){
                    that.edit_box.val(
                        $('option:selected', that.entity_select).val());
                    IPA.select_range(that.edit_box,0,0);
                }
                that.set_dirty(that.test_dirty());
            }
        }).appendTo(container);

        that.entity_filter = $('<input/>', {
            size:10,
            type: 'text',
            id: 'entity_filter',
            style: 'display: none;',
            keyup: function(){
                populate_select(current_value());
            }
        }).appendTo(container);

        $('<a/>', {
            href: '',
            text: 'add ' +entity + ' filter: ',
            click: function() {
                that.entity_filter.css('display','inline');
                $(this).css('display','none');
                return false;
            }
        }).appendTo(container);

        if (that.undo) {
            that.create_undo(container);
        }
        var undo = that.get_undo();
        undo.click(function() {
            that.reset();
        });

        populate_select();
    };

    that.reset = function() {
        that.entity_filter.val(that.values[0]);
        that.set_dirty(false);
        populate_select(that.values[0]);
        if (editable){
            that.edit_box.val(that.values[0]);
        }
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

    function current_value(){
        var value;
        if (editable){
            value = that.edit_box.val();
        }else{
            value = $('option:selected', that.entity_select).val();
        }
        return value;
    }

    that.save = function() {
        var value = current_value();
        return [value];
    };

    return that;
};

IPA.entity_link_widget = function(spec) {
    var that = IPA.widget(spec);
    var no_link_value = spec.no_link_value || null;
    var should_link = true;
    var other_pkey = null;
    var other_entity = spec.entity;

    that.super_create = that.create;
    that.create = function(container) {
        that.super_create(container);
        that.link =
        $('<a/>', {
            href: 'jslink',
            title: '',
            html: '',
            click: function() {
                if (should_link){
                     IPA.nav.show_page(other_entity, 'default', other_pkey);
                }
                return false;
            }
        }).appendTo(container);

        that.label = $('<label/>').
            appendTo(container);
    };
    that.should_link = function(){
        return (other_pkey !== no_link_value);
    };

    that.reset = function(record) {
        other_pkey = null;
        if (that.values || that.values.length > 0){
            other_pkey = that.values[0];
            var should_link =  that.should_link();
            if (should_link){
                that.link.html(other_pkey);
                that.link.css('display','inline');
                that.label.css('display','none');
            }else{
                that.label.html(other_pkey);
                that.link.css('display','none');
                that.label.css('display','inline');
            }
        }else{
            should_link = false;
            that.link.html('');
            that.label.html('');
            that.link.css('display','none');
            that.label.css('display','none');
        }
    };

    return that;
};