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

    that.entity = spec.entity;
    that.container = null;
    that.name = spec.name;
    that.label = spec.label;
    that.tooltip = spec.tooltip;

    that.widget = null;
    that.widget_name = spec.widget;

    // override the required flag in metadata
    that.required = spec.required;

    // read_only is set when widget is created
    that.read_only = spec.read_only;

    // writable is set during load
    that.writable = true;

    that.enabled = spec.enabled === undefined ? true : spec.enabled;

    that.undo = spec.undo === undefined ? true : spec.undo;
    that.join = spec.join;

    that.metadata = spec.metadata;

    that.priority = spec.priority;

    that.values = [];
    that.dirty = false;
    that.valid = true;

    that.dirty_changed = IPA.observer();

    var init = function() {
        if (!that.metadata && that.entity) {
            that.metadata = IPA.get_entity_param(that.entity.name, that.name);
        }
        if (that.metadata) {
            if (that.label === undefined) {
                that.label = that.metadata.label;
            }
            if (that.tooltip === undefined) {
                that.tooltip = that.metadata.doc;
            }
        }
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
        if (!values || !values.length || values[0] === '') {
            if (that.is_required()) {
                that.valid = false;
                that.show_error(IPA.messages.widget.validation.required);
                return false;
            }
        }
        return true;
    };

    /*returns true and clears the error message if the field value  passes
     *   the validation pattern.  If the field value does not pass validation,
     *   displays the error message and returns false. */
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

        if (!that.metadata) {
            return that.valid;
        }

        var message;

        if (that.metadata.type == 'int') {
            if (!value.match(/^-?\d+$/)) {
                that.valid = false;
                that.show_error(IPA.messages.widget.validation.integer);
                return that.valid;
            }

            if (that.metadata.minvalue !== undefined && value < that.metadata.minvalue) {
                that.valid = false;
                message = IPA.messages.widget.validation.min_value;
                message = message.replace('${value}', that.metadata.minvalue);
                that.show_error(message);
                return that.valid;
            }

            if (that.metadata.maxvalue !== undefined && value > that.metadata.maxvalue) {
                that.valid = false;
                message = IPA.messages.widget.validation.max_value;
                message = message.replace('${value}', that.metadata.maxvalue);
                that.show_error(message);
                return that.valid;
            }
        }

        if (that.metadata.pattern) {
            var regex = new RegExp(that.metadata.pattern);
            if (!value.match(regex)) {
                that.valid = false;
                that.show_error(that.metadata.pattern_errmsg);
                return that.valid;
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

        var value = record[that.name];
        if (value instanceof Array) {
            that.values = value;
        } else {
            that.values = value !== undefined ? [value] : [];
        }

        if (!that.values.length) {
            that.values = [''];
        }

        that.load_writable(record);

        that.reset();
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
            var rights = record.attributelevelrights[that.name];
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
        if(that.widget && that.widget.update) that.widget.update(that.values);
    };

    that.get_update_info = function() {

        var update_info = IPA.update_info_builder.new_update_info();
        if(that.is_dirty()) {
            update_info.fields.push(IPA.update_info_builder.new_field_info(
                that,
                that.save()));
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
            record[that.name] = values;
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
        var orig_empty = that.is_empty(that.values);
        var new_empty= that.is_empty(values);
        if (orig_empty && new_empty) return false;
        if (orig_empty != new_empty) return true;

        //strict equality - checks object's ref equality, numbers, strings
        if (values === that.values) return false;

        //compare values in array
        if (values.length !== that.values.length) return true;

        values.sort();
        that.values.sort();

        for (var i=0; i<values.length; i++) {
            if (values[i] != that.values[i]) {
                return true;
            }
        }

        return false;
    };

    that.is_empty = function(value) {

        var empty = false;

        if (!value) empty = true;

        if (value instanceof Array) {
            empty = empty || value.length === 0 ||
                    (value.length === 1) && (value[0] === '');
        }

        if (value === '') empty = true;

        return empty;
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
            if(that.label) that.widget.label = that.label;
            if(that.title) that.widget.title = that.title;
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
    that.field_load = that.load;
    that.field_reset = that.reset;
    that.field_save = that.save;
    that.field_set_dirty = that.set_dirty;
    that.field_show_error = that.show_error;
    that.field_test_dirty = that.test_dirty;
    that.field_widgets_created = that.widgets_created;

    return that;
};

IPA.checkbox_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    that.checked = spec.checked || false;

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

    that.checkbox_load = that.load;
/*
    // a checkbox will always have a value, so it's never required
    that.is_required = function() {
        return false;
    };
*/
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

    that.widgets_created = function() {

        that.field_widgets_created();
    };

    that.load = function(record) {

        that.field_load(record);
    };

    that.test_dirty = function() {
        var dirty = that.field_test_dirty();
        dirty = dirty || that.widget.test_dirty(); //also checks order
        return dirty;
    };

    that.widget_value_changed = function() {
        that.set_dirty(that.test_dirty());
        //that.validate(); disabling validation for now
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

    var other_entity = spec.other_entity;

    function other_pkeys () {
        return that.entity.get_primary_key();
    }
    that.other_pkeys = spec.other_pkeys || other_pkeys;

    that.on_link_clicked = function() {

        IPA.nav.show_entity_page(
            IPA.get_entity(other_entity),
            'default',
            that.other_pkeys());
    };

    that.load = function(record) {

        that.field_load(record);
        that.check_entity_link();
    };

    that.check_entity_link = function() {

        IPA.command({
            entity: other_entity,
            method: 'show',
            args: that.other_pkeys(),
            options: {},
            retry: false,
            on_success: function (result) {
                that.widget.is_link = result.result !== undefined;
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

IPA.field_factories['field'] = IPA.field;
IPA.field_factories['text'] = IPA.field;
IPA.field_factories['password'] = IPA.field;
IPA.field_factories['checkbox'] = IPA.checkbox_field;
IPA.field_factories['checkboxes'] = IPA.checkboxes_field;
IPA.field_factories['radio'] = IPA.radio_field;
IPA.field_factories['multivalued'] = IPA.multivalued_field;
IPA.field_factories['select'] = IPA.select_field;
IPA.field_factories['textarea'] = IPA.field;
IPA.field_factories['entity_select'] = IPA.combobox_field;
IPA.field_factories['combobox'] = IPA.combobox_field;
IPA.field_factories['link'] = IPA.link_field;
IPA.field_factories['enable'] = IPA.enable_field;
