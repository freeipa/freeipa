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


define([
    'dojo/_base/array',
    'dojo/_base/lang',
    './metadata',
    './builder',
    './ipa',
    './jquery',
    './navigation',
    './phases',
    './reg',
    './text'],
       function(array, lang, metadata_provider, builder, IPA, $, navigation, phases, reg, text) {

/**
 * Field module
 * @class field
 * @singleton
 */
var exp = {};

/**
 * Field
 * @class IPA.field
 */
IPA.field = function(spec) {
    spec = spec || {};

    var that = IPA.object();

    /**
     * Entity
     * @property {entity.entity}
     */
    that.entity = IPA.get_entity(spec.entity);

    /**
     * Facet
     * @property {facet.facet}
     */
    that.facet = spec.facet;

    /**
     * Container
     * @property {facet.facet|IPA.dialog}
     */
    that.container = null;

    /**
     * Name
     * @property {string}
     */
    that.name = spec.name;

    /**
     * Entity param name
     *
     * - defaults to `name`
     * - can be change if multiple fields touches the same param
     * @property {string}
     */
    that.param = spec.param || spec.name;

    /**
     * Entity param which provides access control rights
     *
     * - defaults to `param`
     * - some params might be virtual and thus actual rights might be
     *   defined by other param.
     * @property {string}
     */
    that.acl_param = spec.acl_param || that.param;

    /**
     * Label
     * @property {string}
     */
    that.label = text.get(spec.label);

    /**
     * Tooltip
     * @property {string}
     */
    that.tooltip = text.get(spec.tooltip);

    /**
     * Measurement unit
     * @property {string}
     */
    that.measurement_unit = spec.measurement_unit;

    /**
     * Formatter
     *
     * - transforms field value to widget value
     * - only for read-only fields
     * @property {IPA.formatter}
     */
    that.formatter = builder.build('formatter', spec.formatter);

    /**
     * Widget
     * @property {IPA.input_widget}
     */
    that.widget = null;

    /**
     * Widget name within `container`
     * @property {string}
     */
    that.widget_name = spec.widget;

    /**
     * Override the required flag in metadata
     * @property {boolean}
     */
    that.required = spec.required;

    /**
     * read_only is set when widget is created
     * @readonly
     * @property {boolean}
     */
    that.read_only = spec.read_only;

    /**
     * Writable is set during load
     * @readonly
     * @property {boolean}
     */
    that.writable = true;

    /**
     * Enabled
     * @readonly
     * @property {boolean}
     */
    that.enabled = spec.enabled === undefined ? true : spec.enabled;

    /**
     * Flags
     * @property {Array.<string>}
     */
    that.flags = spec.flags || [];

    /**
     * Undo is displayable
     *
     * - when false, undo button is not displayed even when the field is dirty
     * @property {boolean}
     */
    that.undo = spec.undo === undefined ? true : spec.undo;

    /**
     * Metadata
     * @property {Object}
     */
    that.metadata = spec.metadata;

    /**
     * Validators
     * @property {Array.<IPA.validator>}
     */
    that.validators = builder.build('validator', spec.validators) || [];

    /**
     * Field priority
     * @property {number}
     */
    that.priority = spec.priority;

    /**
     * Loaded values
     * @property {Array.<Object>}
     */
    that.values = [];

    /**
     * Field is dirty (value is modified)
     * @readonly
     * @property {boolean}
     */
    that.dirty = false;

    /**
     * Current value is valid - passes validators
     * @property {boolean}
     */
    that.valid = true;

    /**
     * Dirty has changed
     * @event
     * @property {IPA.observer}
     */
    that.dirty_changed = IPA.observer();

    var init = function() {
        if (typeof that.metadata === 'string') {
            that.metadata = metadata_provider.get(that.metadata);
        }
        if (!that.metadata && that.entity) {
            that.metadata = IPA.get_entity_param(that.entity.name, that.param);
        }
        if (that.metadata) {
            if (!that.label) {
                that.label = that.metadata.label || '';
            }
            if (!that.tooltip) {
                that.tooltip = that.metadata.doc || '';
            }
        }

        that.validators.push(IPA.metadata_validator());
    };

    /**
     * Evaluate if field has to have some value
     * @return {boolean}
     */
    that.is_required = function() {
        if (that.read_only) return false;
        if (!that.writable) return false;

        if (that.required !== undefined) return that.required;
        return that.metadata && that.metadata.required;
    };

    /**
     * Required setter
     * @param {boolean} required
     */
    that.set_required = function(required) {
        that.required = required;

        that.update_required();
    };

    /**
     * Update required state in widget to match field's
     * @protected
     */
    that.update_required = function() {
        if(that.widget && that.widget.set_required) {
            that.widget.set_required(that.is_required());
        }
    };

    /**
     * Check if value is set when it has to be. Show error if not.
     * @return {boolean}
     */
    that.validate_required = function() {
        var values = that.save();
        if (IPA.is_empty(values) && that.is_required() && that.enabled) {
            that.valid = false;
            var message = text.get('@i18n:widget.validation.required',
                "Required field");
            that.show_error(message);
            return false;
        }
        return true;
    };

    /**
     * Returns true and clears the error message if the field value passes
     * the validation pattern. If the field value does not pass validation,
     * displays the error message and returns false.
     * @return {boolean}
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
     * of the field, then invoke `reset()` to update the UI.
     */
    that.load = function(record) {
        that.record = record;

        that.values = that.get_value(record, that.param);

        that.load_writable(record);

        that.reset();
    };

    /**
     * Get value of attribute with given name from record (during `load`)
     *
     * @protected
     * @param {Object} record
     * @param {string} name
     * @return {Array} array of values
     */
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

    /**
     * Evaluate if field is writable according to ACL in record and field
     * configuration. Updates `writable` property.
     *
     * Not writable:
     *
     * - primary keys
     * - with 'no_update' metadata flag
     *
     * Writable:
     *
     * - attribute level rights for acl param contains 'w'
     * - with 'w_if_no_aci' flag and no attribute level rights and user has
     *   rights to modify objectclass
     *
     * @protected
     * @param {Object} record
     */
    that.load_writable = function(record) {

        that.writable = true;

        if (that.metadata) {
            if (that.metadata.primary_key) {
                that.writable = false;
            }

            if (that.metadata.flags && array.indexOf(that.metadata.flags, 'no_update') > -1) {
                that.writable = false;
            }
        }

        if (record.attributelevelrights) {
            var rights = record.attributelevelrights[that.acl_param];
            var oc_rights= record.attributelevelrights['objectclass'];
            var write_oc = oc_rights && oc_rights.indexOf('w') > -1;

            // Some objects in LDAP may not have set proper object class and
            // therefore server doesn't send proper attribute rights. Flag
            // 'w_if_no_aci' should be used when we want to ensure that UI
            // shows edit interface in such cases. Usable only when user can
            // modify object classes.
            // For all others, lack of rights means no write.
            if ((!rights && !(that.flags.indexOf('w_if_no_aci') > -1 && write_oc)) ||
                 (rights && rights.indexOf('w') < 0)) {
                that.writable = false;
            }
        }
    };

    /**
     * Reset field and widget to loaded values
     */
    that.reset = function() {
        that.set_widget_flags();
        that.update_required();
        that.update();
        that.validate();
        that.set_dirty(false);
    };

    /**
     * Update widget with loaded values.
     */
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

    /**
     * Create and return update info.
     *
     * Update info is a record which contains information about modifications
     * since load.
     * @return {Object} update info
     */
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
     * @return {Array} values
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
     * @protected
     * @return {boolean} dirty
     */
    that.test_dirty = function() {

        if (that.read_only || !that.writable) return false;

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

    /**
     * Compares values in two arrays
     * @protected
     * @param {Array} orig_vals
     * @param {Array} new_vals
     * @return {boolean} values are equal
     */
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
     * Getter for `dirty`
     * @return {boolean}
     */
    that.is_dirty = function() {
        return that.dirty;
    };

    /**
     * Setter for `dirty`
     * @param {boolean} dirty
     */
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


    /**
     * Display validation error
     * @protected
     * @param {string} message
     */
    that.show_error = function(message) {
        if (that.widget && that.widget.show_error) that.widget.show_error(message);
    };

    /**
     * Hide validation error
     * @protected
     */
    that.hide_error = function() {
        if (that.widget && that.widget.hide_error) that.widget.hide_error();
    };

    /**
     * Show/hide undo button
     * @protected
     * @param {boolean} value true:show, false:hide
     */
    that.show_undo = function(value) {
        if (that.widget && that.widget.show_undo) {
            if(value) { that.widget.show_undo(); }
            else { that.widget.hide_undo(); }
        }
    };

    /**
     * `enabled` setter
     * @param {boolean} value
     */
    that.set_enabled = function(value) {
        that.enabled = value;
        if (that.widget && that.widget.set_enabled) {
            that.widget.set_enabled(value);
        }
    };

    /**
     * Subject to removal
     * @deprecated
     */
    that.refresh = function() {
    };

    /**
     * Reflect `label`, `tooltip`, `measurement_unit`, `undo`, `writable`,
     * `read_only` into widget.
     */
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

    /**
     * Bind field to a widget defined by `widget_name`
     */
    that.widgets_created = function() {

        that.widget = that.container.widgets.get_widget(that.widget_name);

        if(that.widget) {
            that.set_widget_flags();

            that.widget.value_changed.attach(that.widget_value_changed);
            that.widget.undo_clicked.attach(that.widget_undo_clicked);
        }
    };

    /**
     * Handler for widget's `value_changed` event
     */
    that.widget_value_changed = function() {
        that.set_dirty(that.test_dirty());
        that.validate();
    };

    /**
     * Handler for widget's `undo_clicked` event
     */
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

/**
 * Validator
 *
 * - base class, always returns positive result
 *
 * @class IPA.validator
 */
IPA.validator = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    /**
     * Error message
     * @property {string}
     */
    that.message = text.get(spec.message || '@i18n:widget.validation.error');

    /**
     * Create negative validation result
     * @return {Object} result
     */
    that.false_result = function(message) {
        return {
            valid: false,
            message: message || that.message
        };
    };

    /**
     * Create positive validation result
     * @return {Object} result
     */
    that.true_result = function() {
        return {
            valid: true
        };
    };

    /**
     * Perform validation logic
     * @param {Mixed} value
     * @param {Object} context expected context is field which value is validated
     * @return {Object} validation result
     */
    that.validate = function() {
        return that.true_result();
    };

    return that;
};

/**
 * Metadata validator
 *
 * Validates value according to supplied metadata
 *
 * @class IPA.metadata_validator
 * @extends IPA.validator
 */
IPA.metadata_validator = function(spec) {

    var that = IPA.validator(spec);

    /**
     * @inheritDoc
     */
    that.validate = function(value, context) {

        var message;
        var metadata = context.metadata;
        var number = false;

        if (!metadata || IPA.is_empty(value)) return that.true_result();

        if (metadata.type === 'int') {
            number = true;
            if (!value.match(/^-?\d+$/)) {
                return that.false_result(text.get('@i18n:widget.validation.integer'));
            }
        } else if (metadata.type === 'Decimal') {
            number = true;
            if (!value.match(/^-?\d+(\.\d+)?$/)) {
                return that.false_result(text.get('@i18n:widget.validation.decimal'));
            }
        }

        if (number) {

            if (IPA.defined(metadata.minvalue, true) && Number(value) < Number(metadata.minvalue)) {
                message = text.get('@i18n:widget.validation.min_value');
                message = message.replace('${value}', metadata.minvalue);
                return that.false_result(message);
            }

            if (IPA.defined(metadata.maxvalue, true) && Number(value) > Number(metadata.maxvalue)) {
                message = text.get('@i18n:widget.validation.max_value');
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

/**
 * Checks if value is supported
 *
 * @class IPA.unsupported_validator
 * @extends IPA.validator
 */
IPA.unsupported_validator = function(spec) {

    spec.message = spec.message ||'@i18n:widgets.validation.unsupported';

    var that = IPA.validator(spec);

    /**
     * Unsupported values
     * @property {Array.<string>}
     */
    that.unsupported = spec.unsupported || [];

    /**
     * @inheritDoc
     */
    that.validate = function(value, context) {

        if (IPA.is_empty(value)) return that.true_result();

        if (that.unsupported.indexOf(value) > -1) return that.false_result();

        return that.true_result();
    };

    return that;
};

/**
 * Check if value is the same as in other field.
 *
 * - designed for password confirmation
 *
 * @class IPA.same_password_validator
 * @extends IPA.validator
 */
IPA.same_password_validator = function(spec) {

    spec = spec || {};

    var that = IPA.validator(spec);

    /**
     * Other field name
     * @property {string}
     */
    that.other_field = spec.other_field;

    that.message = text.get(spec.message || '@i18n:password.password_must_match',
                            "Passwords must match");

    /**
     * @inheritDoc
     */
    that.validate = function(value, context) {

        var other_field = context.container.fields.get_field(that.other_field);
        var other_value = other_field.save();
        var this_value = context.save();

        if (IPA.array_diff(this_value, other_value)) return that.false_result();

        return that.true_result();
    };

    return that;
};

/**
 * Used along with checkbox widget
 *
 * @class IPA.checkbox_field
 * @extends IPA.field
 */
IPA.checkbox_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    /**
     * Check value by default
     * @property {boolean}
     */
    that.checked = spec.checked || false;

    /**
     * Boolean formatter for parsing loaded values.
     * @property {IPA.boolean_formatter}
     */
    that.boolean_formatter = IPA.boolean_formatter();

    /**
     * @inheritDoc
     */
    that.load = function(record) {

        that.record = record;

        that.values = that.get_value(record, that.param);

        var value = that.boolean_formatter.parse(that.values);
        if (value === '') value = that.widget.checked; //default value

        that.values = [value];

        that.load_writable(record);

        that.reset();
    };

    /**
     * @inheritDoc
     */
    that.widgets_created = function() {

        that.field_widgets_created();
        that.widget.checked = that.checked;
    };

    /**
     * A checkbox will always have a value, so it's never required.
     *
     * @return {boolean} false
     */
    that.is_required = function() {
        return false;
    };

    that.checkbox_load = that.load;

    return that;
};

/**
 * Used along with checkboxes widget
 *
 * @class IPA.checkboxes_field
 * @extends IPA.field
 */
IPA.checkboxes_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    return that;
};

/**
 * Used along with radio widget
 *
 * @class IPA.radio_field
 * @extends IPA.field
 */
IPA.radio_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    /**
     * A radio will always have a value, so it's never required
     *  @return {boolean} false
     */
    that.is_required = function() {
        return false;
    };

    /**
     * @inheritDoc
     */
    that.widgets_created = function() {

        that.field_widgets_created();
    };

    return that;
};

/**
 * Used along with multivalued widget
 *
 * @class IPA.multivalued_field
 * @extends IPA.field
 */
IPA.multivalued_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    /**
     * @inheritDoc
     */
    that.load = function(record) {

        that.field_load(record);
    };

    /**
     * @inheritDoc
     */
    that.test_dirty = function() {
        var dirty = that.field_test_dirty();
        dirty = dirty || that.widget.test_dirty(); //also checks order
        return dirty;
    };

    /**
     * @inheritDoc
     */
    that.validate = function() {

        var values = that.save();

        return that.validate_core(values);
    };

    /**
     * Validate each value separately.
     * @protected
     * @param {Array} values
     * @return {boolean} valid
     */
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

/**
 * Used along with ssh key widget
 *
 * @class IPA.sshkeys_field
 * @extends IPA.multivalued_field
 */
IPA.sshkeys_field = function(spec) {

    spec = spec || {};

    var that = IPA.multivalued_field(spec);

    /**
     * By default has 'w_if_no_aci' flag.
     *
     * - fixes upgrade issue. When attr rights are missing due to lack of
     *   object class.
     */
    that.flags = spec.flags || ['w_if_no_aci'];

    /**
     * Name of fingerprint param
     * @property {string}
     */
    that.sshfp_attr = spec.sshfp_attr || 'sshpubkeyfp';

    /**
     * @inheritDoc
     */
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

    /**
     * @inheritDoc
     */
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

/**
 * Used along with select widget
 *
 * @class IPA.select_field
 * @extends IPA.field
 */
IPA.select_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    /**
     * @inheritDoc
     */
    that.widgets_created = function() {

        that.field_widgets_created();
    };

    return that;
};

/**
 * Used along with link widget
 *
 * @class IPA.link_field
 * @extends IPA.field
 */
IPA.link_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    /**
     * Entity a link points to
     * @property {entity.entity}
     */
    that.other_entity = IPA.get_entity(spec.other_entity);

    function other_pkeys () {
        return that.facet.get_pkeys();
    }

    /**
     * Function which should return primary keys of link target in case of
     * link points to an entity.
     * @property {Function}
     */
    that.other_pkeys = spec.other_pkeys || other_pkeys;

    /**
     * Handler for widget `link_click` event
     */
    that.on_link_clicked = function() {

        navigation.show_entity(
            that.other_entity.name,
            'default',
            that.other_pkeys());
    };

    /**
     * @inheritDoc
     */
    that.load = function(record) {

        that.field_load(record);
        that.check_entity_link();
    };

    /**
     * Check if entity exists
     *
     * - only if link points to an entity
     * - update widget's `is_link` accordingly
     */
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

    /**
     * @inheritDoc
     */
    that.widgets_created = function() {
        that.field_widgets_created();
        that.widget.link_clicked.attach(that.on_link_clicked);
    };


    return that;
};

/**
 * Field for enabling/disabling entity
 *
 * - expects radio widget
 * - requires facet to use 'update_info' update method
 *
 * @class IPA.enable_field
 * @extends IPA.field
 */
IPA.enable_field = function(spec) {

    spec = spec  || {};

    var that = IPA.radio_field(spec);

    /**
     * Name of entity's enable method
     * @property {string}
     */
    that.enable_method = spec.enable_method || 'enable';

    /**
     * Name of entity's disable method
     * @property {string}
     */
    that.disable_method = spec.enable_method || 'disable';

    /**
     * Value of radio's enable option
     * @property {string}
     */
    that.enable_option = spec.enable_option || 'TRUE';

    /**
     * @inheritDoc
     */
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
                args: that.facet.get_pkeys(),
                options: {all: true, rights: true}
            });


            info.append_command(command, that.priority);
        }

        return info;
    };

    return that;
};

/**
 * Collection of fields
 * @class IPA.field_container
 */
IPA.field_container = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    /**
     * Parent container
     *
     * - usually facet or dialog
     */
    that.container = spec.container;

    /**
     * Collection of fields
     * @property {ordered_map}
     * @protected
     */
    that.fields = $.ordered_map();

    /**
     * Get field with given name
     * @param {string} name
     * @return {IPA.field}
     */
    that.get_field = function(name) {
        return that.fields.get(name);
    };

    /**
     * Get all fields
     * @return {Array.<IPA.field>}
     */
    that.get_fields = function() {
        return that.fields.values;
    };

    /**
     * Add field
     * @param {IPA.field} field
     */
    that.add_field = function(field) {
        field.container = that.container;
        that.fields.put(field.name, field);
    };

    /**
     * Call each field's `widgets_created` method.
     */
    that.widgets_created = function() {
        var fields = that.fields.values;

        for (var i=0; i<fields.length; i++) {
            fields[i].widgets_created();
        }
    };

    that.container_add_field = that.add_field;

    return that;
};

/**
 * Old field builder
 * @class IPA.field_builder
 */
IPA.field_builder = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    /**
     * Field context property: container
     * @property {facet.facet|IPA.dialog}
     */
    that.container = spec.container;

    /**
     * Map of additional field context properties
     * @property {Object}
     */
    that.field_options = spec.field_options || {};

    /**
     * Build one field
     * @param {Object} spec
     * @param {facet.facet|IPA.dialog} container
     */
    that.build_field = function(spec, container) {

        var context = lang.mixin({}, that.field_options);
        context.container = container || that.container;
        var field = builder.build('field', spec, context);
        return field;
    };

    /**
     * Build multiple fields
     * @param {Array.<Object>} spec
     * @param {facet.facet|IPA.dialog} container
     */
    that.build_fields = function(specs, container) {

        return that.build_field(specs, container);
    };

    return that;
};

/**
 * Field pre_op build operation
 * @member field
 * @return spec
 */
exp.pre_op = function(spec, context) {

    if (context.facet) spec.facet = context.facet;
    if (context.entity) spec.entity = context.entity;
    if (context.undo !== undefined) spec.undo = context.undo;
    return spec;
};

/**
 * Field post_op build operation
 * @member field
 * @return obj
 */
exp.post_op = function(obj, spec, context) {

    if (context.container) context.container.add_field(obj);
    return obj;
};

/**
 * Field builder with registry
 * @member field
 */
exp.builder = builder.get('field');
exp.builder.factory = IPA.field;
exp.builder.string_mode = 'property';
exp.builder.string_property = 'name';
reg.set('field', exp.builder.registry);
exp.builder.pre_ops.push(exp.pre_op);
exp.builder.post_ops.push(exp.post_op);

/**
 * Validator builder with registry
 * @member field
 */
exp.validator_builder = builder.get('validator');
reg.set('validator', exp.validator_builder.registry);

/**
 * Register fields and validators to global registry
 * @member field
 */
exp.register = function() {
    var f = reg.field;
    var v = reg.validator;

    f.register('checkbox', IPA.checkbox_field);
    f.register('checkboxes', IPA.checkboxes_field);
    f.register('combobox', IPA.field);
    f.register('enable', IPA.enable_field);
    f.register('entity_select', IPA.field);
    f.register('field', IPA.field);
    f.register('link', IPA.link_field);
    f.register('multivalued', IPA.multivalued_field);
    f.register('password', IPA.field);
    f.register('radio', IPA.radio_field);
    f.register('select', IPA.select_field);
    f.register('sshkeys', IPA.sshkeys_field);
    f.register('textarea', IPA.field);
    f.register('text', IPA.field);
    f.register('value_map', IPA.field);

    v.register('metadata', IPA.metadata_validator);
    v.register('unsupported', IPA.unsupported_validator);
    v.register('same_password', IPA.same_password_validator);
};
phases.on('registration', exp.register);

return exp;
});