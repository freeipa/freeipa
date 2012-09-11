/*jsl:import ipa.js */
/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *    Pavel Zuna <pzuna@redhat.com>
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2011 Red Hat
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

/* REQUIRES: ipa.js, widget.js */

IPA.field = function(spec) {
    spec = spec || {};

    var that = {};

    that.entity = IPA.get_entity(spec.entity);
    that.container = null;
    that.name = spec.name;
    that.param = spec.param || spec.name;
    that.label = spec.label;
    that.tooltip = spec.tooltip;
    that.measurement_unit = spec.measurement_unit;
    that.formatter = spec.formatter;

    that.widget = null;
    that.widget_name = spec.widget;

    // override the required flag in metadata
    that.required = spec.required;

    // read_only is set when widget is created
    that.read_only = spec.read_only;

    // writable is set during load
    that.writable = true;

    that.enabled = spec.enabled === undefined ? true : spec.enabled;
    that.flags = spec.flags || [];

    that.undo = spec.undo === undefined ? true : spec.undo;

    that.metadata = spec.metadata;
    that.validators = spec.validators || [];

    that.priority = spec.priority;

    that.values = [];
    that.dirty = false;
    that.valid = true;

    that.dirty_changed = IPA.observer();

    var init = function() {
        if (!that.metadata && that.entity) {
            that.metadata = IPA.get_entity_param(that.entity.name, that.param);
        }
        if (that.metadata) {
            if (that.label === undefined) {
                that.label = that.metadata.label;
            }
            if (that.tooltip === undefined) {
                that.tooltip = that.metadata.doc;
            }
        }

        that.validators.push(IPA.metadata_validator());
    };

    that.is_required = function() {
        if (that.read_only) return false;
        if (!that.writable) return false;

        if (that.required !== undefined) return that.required;
        return that.metadata && that.metadata.required;
    };

    that.set_required = function(required) {
        that.required = required;

        that.update_required();
    };

    that.update_required = function() {
        if(that.widget && that.widget.set_required) {
            that.widget.set_required(that.is_required());
        }
    };

    that.validate_required = function() {
        var values = that.save();
        if (IPA.is_empty(values) && that.is_required() && that.enabled) {
            that.valid = false;
            var message = IPA.get_message('widget.validation.required',
                "Required field");
            that.show_error(message);
            return false;
        }
        return true;
    };

    /**
     *   Returns true and clears the error message if the field value passes
     *   the validation pattern. If the field value does not pass validation,
     *   displays the error message and returns false.
     */
    that.validate = function() {
        that.hide_error();
        that.valid = true;

        if (!that.enabled) return that.valid;

        var values = that.save();

        if (IPA.is_empty(values)) {
            return that.valid;
        }

        var value = values[0];

        for (var i=0; i<that.validators.length; i++) {
            var validation_result = that.validators[i].validate(value, that);
            that.valid = validation_result.valid;
            if (!that.valid) {
                that.show_error(validation_result.message);
                break;
            }
        }

        return that.valid;
    };

    /**
     * This function stores the entire record and the values
     * of the field, then invoke reset() to update the UI.
     */
    that.load = function(record) {
        that.record = record;

        that.values = that.get_value(record, that.param);

        that.load_writable(record);

        that.reset();
    };

    that.get_value = function(record, name) {

        var value = record[name];

        if (!(value instanceof Array)) {
            value = value !== undefined ? [value] : [];
        }

        if (!value.length) {
            value = [''];
        }

        return value;
    };

    that.load_writable = function(record) {

        that.writable = true;

        if (that.metadata) {
            if (that.metadata.primary_key) {
                that.writable = false;
            }

            if (that.metadata.flags && 'no_update' in that.metadata.flags) {
                that.writable = false;
            }
        }

        if (record.attributelevelrights) {
            var rights = record.attributelevelrights[that.param];
            if (!rights || rights.indexOf('w') < 0) {
                that.writable = false;
            }
        }
    };

    that.reset = function() {
        that.set_widget_flags();
        that.update_required();
        that.update();
        that.validate();
        that.set_dirty(false);
    };

    that.update = function() {

        if (!that.widget || !that.widget.update) return;

        var formatted_values;

        // The formatter is currently only used on read-only fields only
        // because it cannot parse formatted values back to internal values.
        if (that.formatter && that.read_only) {
            formatted_values = [];
            for (var i=0; that.values && i<that.values.length; i++) {
                var value = that.values[i];
                var formatted_value = that.formatter.format(value);
                formatted_values.push(formatted_value);
            }
        } else {
            formatted_values = that.values;
        }

        that.widget.update(formatted_values);
    };

    that.get_update_info = function() {

        var update_info = IPA.update_info_builder.new_update_info();
        if (that.is_dirty()) {
            var values = that.save();
            var field_info = IPA.update_info_builder.new_field_info(that, values);
            update_info.fields.push(field_info);
        }
        return update_info;
    };

    /**
     * This function saves the values entered in the UI.
     * It returns the values in an array, or null if
     * the field should not be saved.
     */
    that.save = function(record) {

        var values = that.values;

        if(!that.enabled) return [''];

        if(that.widget) {
            values = that.widget.save();
        }

        if(record) {
            record[that.param] = values;
        }

        return values;
    };

    /**
     * This function compares the original values and the
     * values entered in the UI. If the values have changed
     * it will return true.
     */
    that.test_dirty = function() {

        if (that.read_only) return false;

        var values = that.save();

        //check for empty value: null, [''], '', []
        var orig_empty = IPA.is_empty(that.values);
        var new_empty= IPA.is_empty(values);
        if (orig_empty && new_empty) return false;
        if (orig_empty != new_empty) return true;

        //strict equality - checks object's ref equality, numbers, strings
        if (values === that.values) return false;

        //compare values in array
        if (values.length !== that.values.length) return true;

        return !that.dirty_are_equal(that.values, values);
    };

    that.dirty_are_equal = function(orig_vals, new_vals) {

        orig_vals.sort();
        new_vals.sort();

        for (var i=0; i<orig_vals.length; i++) {
            if (orig_vals[i] !== new_vals[i]) {
                return false;
            }
        }

        return true;
    };

    /**
     * This function compares the original values and the
     * values entered in the UI. If the values have changed
     * it will return true.
     */
    that.is_dirty = function() {
        return that.dirty;
    };

    that.set_dirty = function(dirty) {
        var old = that.dirty;
        that.dirty = dirty;
        if (that.undo) {
            that.show_undo(dirty);
        }

        if (old !== dirty) {
            that.dirty_changed.notify([], that);
        }
    };


    that.show_error = function(message) {
        if (that.widget && that.widget.show_error) that.widget.show_error(message);
    };

    that.hide_error = function() {
        if (that.widget && that.widget.hide_error) that.widget.hide_error();
    };

    that.show_undo = function(value) {
        if (that.widget && that.widget.show_undo) {
            if(value) { that.widget.show_undo(); }
            else { that.widget.hide_undo(); }
        }
    };

    that.set_enabled = function(value) {
        that.enabled = value;
        if (that.widget && that.widget.set_enabled) {
            that.widget.set_enabled(value);
        }
    };

    that.refresh = function() {
    };

    that.set_widget_flags = function() {

        if (that.widget) {
            if (that.label) that.widget.label = that.label;
            if (that.tooltip) that.widget.tooltip = that.tooltip;
            if (that.measurement_unit) that.widget.measurement_unit = that.measurement_unit;
            that.widget.undo = that.undo;
            that.widget.writable = that.writable;
            that.widget.read_only = that.read_only;
        }
    };

    that.widgets_created = function() {

        that.widget = that.container.widgets.get_widget(that.widget_name);

        if(that.widget) {
            that.set_widget_flags();

            that.widget.value_changed.attach(that.widget_value_changed);
            that.widget.undo_clicked.attach(that.widget_undo_clicked);
        }
    };

    that.widget_value_changed = function() {
        that.set_dirty(that.test_dirty());
        that.validate();
    };

    that.widget_undo_clicked = function() {
        that.reset();
    };

    init();

    // methods that should be invoked by subclasses
    that.field_dirty_are_equal = that.dirty_are_equal;
    that.field_load = that.load;
    that.field_reset = that.reset;
    that.field_save = that.save;
    that.field_set_dirty = that.set_dirty;
    that.field_show_error = that.show_error;
    that.field_test_dirty = that.test_dirty;
    that.field_widgets_created = that.widgets_created;

    return that;
};

IPA.validator = function(spec) {

    spec = spec || {};

    var that = {};

    that.message = spec.message || IPA.get_message('widget.validation.error');

    that.false_result = function(message) {
        return {
            valid: false,
            message: message || that.message
        };
    };

    that.true_result = function() {
        return {
            valid: true
        };
    };

    that.validate = function() {
        return that.true_result();
    };

    return that;
};

IPA.metadata_validator = function(spec) {

    var that = IPA.validator(spec);

    that.validate = function(value, context) {

        var message;
        var metadata = context.metadata;
        var number = false;

        if (!metadata || IPA.is_empty(value)) return that.true_result();

        if (metadata.type === 'int') {
            number = true;
            if (!value.match(/^-?\d+$/)) {
                return that.false_result(IPA.messages.widget.validation.integer);
            }
        } else if (metadata.type === 'Decimal') {
            number = true;
            if (!value.match(/^-?\d+(\.\d+)?$/)) {
                return that.false_result(IPA.messages.widget.validation.decimal);
            }
        }

        if (number) {

            if (IPA.defined(metadata.minvalue, true) && Number(value) < Number(metadata.minvalue)) {
                message = IPA.messages.widget.validation.min_value;
                message = message.replace('${value}', metadata.minvalue);
                return that.false_result(message);
            }

            if (IPA.defined(metadata.maxvalue, true) && Number(value) > Number(metadata.maxvalue)) {
                message = IPA.messages.widget.validation.max_value;
                message = message.replace('${value}', metadata.maxvalue);
                return that.false_result(message);
            }
        }

        if (metadata.pattern) {
            var regex = new RegExp(metadata.pattern);
            if (!value.match(regex)) {
                return that.false_result(metadata.pattern_errmsg);
            }
        }

        return that.true_result();
    };

    return that;
};

IPA.unsupported_validator = function(spec) {

    var that = IPA.validator(spec);

    that.unsupported = spec.unsupported || [];
    that.message = spec.message || IPA.messages.widget.validation.unsupported;

    that.validate = function(value, context) {

        if (IPA.is_empty(value)) return that.true_result();

        if (that.unsupported.indexOf(value) > -1) return that.false_result();

        return that.true_result();
    };

    return that;
};

IPA.same_password_validator = function(spec) {

    spec = spec || {};

    var that = IPA.validator(spec);
    that.other_field = spec.other_field;

    that.message = spec.message || IPA.messages.password.password_must_match;

    that.validate = function(value, context) {

        var other_field = context.container.fields.get_field(that.other_field);
        var other_value = other_field.save();
        var this_value = context.save();

        if (IPA.array_diff(this_value, other_value)) return that.false_result();

        return that.true_result();
    };

    return that;
};

IPA.checkbox_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    that.checked = spec.checked || false;
    that.boolean_formatter = IPA.boolean_formatter();

    that.load = function(record) {

        that.record = record;

        that.values = that.get_value(record, that.param);

        var value = that.boolean_formatter.parse(that.values);
        if (value === '') value = that.widget.checked; //default value

        that.values = [value];

        that.load_writable(record);

        that.reset();
    };

    that.widgets_created = function() {

        that.field_widgets_created();
        that.widget.checked = that.checked;
    };

    // a checkbox will always have a value, so it's never required
    that.is_required = function() {
        return false;
    };

    that.checkbox_load = that.load;

    return that;
};

IPA.checkboxes_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    return that;
};

IPA.radio_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    // a radio will always have a value, so it's never required
    that.is_required = function() {
        return false;
    };

    that.widgets_created = function() {

        that.field_widgets_created();
    };

    return that;
};

IPA.multivalued_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    that.load = function(record) {

        that.field_load(record);
    };

    that.test_dirty = function() {
        var dirty = that.field_test_dirty();
        dirty = dirty || that.widget.test_dirty(); //also checks order
        return dirty;
    };

    that.validate = function() {

        var values = that.save();

        return that.validate_core(values);
    };

    that.validate_core = function(values) {

        that.hide_error();
        that.valid = true;

        if (IPA.is_empty(values)) {
            return that.valid;
        }

        for (var i=0; i<values.length; i++) {

            for (var j=0; j<that.validators.length; j++) {

                var validation_result = that.validators[j].validate(values[i], that);
                if (!validation_result.valid) {
                    that.valid = false;
                    var row_index = that.widget.get_saved_value_row_index(i);
                    that.widget.show_child_error(row_index, validation_result.message);
                    break;
                }
            }
        }

        return that.valid;
    };

    return that;
};

IPA.sshkeys_field = function(spec) {

    spec = spec || {};

    var that = IPA.multivalued_field(spec);

    that.sshfp_attr = 'sshpubkeyfp' || spec.sshfp_attr;

    that.load = function(record) {

        var keys = that.get_value(record, that.param);
        var fingerprints = that.get_value(record, that.sshfp_attr);

        var values = [];

        if (keys.length === fingerprints.length) {
            for (var i=0; i<keys.length; i++) {

                if (keys[i] === '') continue;

                var value = {
                    key: keys[i],
                    fingerprint: fingerprints[i]
                };
                values.push(value);
            }
        }

        that.values = values;

        that.load_writable(record);

        that.reset();
    };

    that.dirty_are_equal = function(orig_vals, new_vals) {

        var i;
        var orig_keys = [];

        for (i=0; i<orig_vals.length; i++) {
            orig_keys.push(orig_vals[i].key);
        }

        return that.field_dirty_are_equal(orig_keys, new_vals);
    };

    return that;
};

IPA.select_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    that.widgets_created = function() {

        that.field_widgets_created();
    };

    return that;
};


IPA.combobox_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    that.widgets_created = function() {

        that.field_widgets_created();
        that.widget.input_field_changed.attach(that.on_input_field_changed);
    };

    that.on_input_field_changed = function() {
        that.validate();
    };

    return  that;
};

IPA.link_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    that.other_entity = IPA.get_entity(spec.other_entity);

    function other_pkeys () {
        return that.entity.get_primary_key();
    }
    that.other_pkeys = spec.other_pkeys || other_pkeys;

    that.on_link_clicked = function() {

        IPA.nav.show_entity_page(
            that.other_entity,
            'default',
            that.other_pkeys());
    };

    that.load = function(record) {

        that.field_load(record);
        that.check_entity_link();
    };

    that.check_entity_link = function() {

        //In some cases other entity may not be present.
        //For example when DNS is not configured.
        if (!that.other_entity) {
            that.widget.is_link = false;
            that.widget.update(that.values);
            return;
        }

        IPA.command({
            entity: that.other_entity.name,
            method: 'show',
            args: that.other_pkeys(),
            options: {},
            retry: false,
            on_success: function(data) {
                that.widget.is_link = data.result && data.result.result;
                that.widget.update(that.values);
            },
            on_error: function() {
                that.widget.is_link = false;
                that.widget.update(that.values);
            }
        }).execute();
    };

    that.widgets_created = function() {
        that.field_widgets_created();
        that.widget.link_clicked.attach(that.on_link_clicked);
    };


    return that;
};

IPA.enable_field = function(spec) {

    spec = spec  || {};

    var that = IPA.radio_field(spec);

    that.enable_method = spec.enable_method || 'enable';
    that.disable_method = spec.enable_method || 'disable';
    that.enable_option = spec.enable_option || 'TRUE';

    that.get_update_info = function() {

        var info = IPA.update_info_builder.new_update_info();
        if(that.test_dirty()) {
            var values = that.save();
            var method = that.disable_method;

            if(values[0] === that.enable_option) {
                method = that.enable_method;
            }

            var command = IPA.command({
                entity: that.entity.name,
                method: method,
                args: that.entity.get_primary_key(),
                options: {all: true, rights: true}
            });


            info.append_command(command, that.priority);
        }

        return info;
    };

    return that;
};

// TODO: Add support for nested fields
IPA.field_container = function(spec) {

    spec = spec || {};

    var that = {};

    that.container = spec.container; //usually facet or dialog

    that.fields = $.ordered_map();

    that.get_field = function(name) {
        return that.fields.get(name);
    };

    that.get_fields = function(name) {
        return that.fields.values;
    };

    that.add_field = function(field) {
        field.container = that.container;
        that.fields.put(field.name, field);
    };

    that.widgets_created = function() {
        var fields = that.fields.values;

        for (var i=0; i<fields.length; i++) {
            fields[i].widgets_created();
        }
    };

    that.container_add_field = that.add_field;

    return that;
};

IPA.field_builder = function(spec) {

    spec = spec || {};

    var that = {};

    that.default_factory = spec.default_factory || IPA.field;
    that.container = spec.container;
    that.field_options = spec.field_options || {};

    that.get_field_factory = function(spec) {

        var factory;
        if (spec.factory) {
            factory = spec.factory;
        } else if(spec.type) {
            factory = IPA.field_factories[spec.type];
        }

        if (!factory) {
            factory = that.default_factory;
        }

        return factory;
    };

    that.build_field = function(spec, container) {

        container = container || that.container;

        if(!(spec instanceof Object)) {
            spec = { name: spec };
        }

        if(that.field_options) {
            $.extend(spec, that.field_options);
        }

        var factory = that.get_field_factory(spec);

        var field = factory(spec);

        if(container) {
            container.add_field(field);
        }

        return field;
    };

    that.build_fields = function(specs, container) {

        container = container || that.container;

        for(var i=0; i<specs.length; i++) {
            that.build_field(specs[i], container);
        }
    };

    return that;
};

IPA.field_factories['checkbox'] = IPA.checkbox_field;
IPA.field_factories['checkboxes'] = IPA.checkboxes_field;
IPA.field_factories['combobox'] = IPA.combobox_field;
IPA.field_factories['enable'] = IPA.enable_field;
IPA.field_factories['entity_select'] = IPA.combobox_field;
IPA.field_factories['field'] = IPA.field;
IPA.field_factories['link'] = IPA.link_field;
IPA.field_factories['multivalued'] = IPA.multivalued_field;
IPA.field_factories['password'] = IPA.field;
IPA.field_factories['radio'] = IPA.radio_field;
IPA.field_factories['select'] = IPA.select_field;
IPA.field_factories['sshkeys'] = IPA.sshkeys_field;
IPA.field_factories['textarea'] = IPA.field;
IPA.field_factories['text'] = IPA.field;
IPA.field_factories['value_map'] = IPA.field;