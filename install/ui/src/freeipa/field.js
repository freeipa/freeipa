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
    'dojo/_base/declare',
    'dojo/_base/lang',
    'dojo/Evented',
    './metadata',
    './builder',
    './datetime',
    './ipa',
    './jquery',
    './navigation',
    './phases',
    './reg',
    './rpc',
    './text',
    './util',
    './FieldBinder'],
       function(array, declare, lang, Evented, metadata_provider, builder, datetime,
                IPA, $, navigation, phases, reg, rpc, text, util, FieldBinder) {

/**
 * Field module
 *
 * Contains basic fields, adapters and validators.
 *
 * @class
 * @singleton
 */
var field = {};

/**
 * Field
 * @class
 * @alternateClassName IPA.field
 */
field.field = IPA.field = function(spec) {
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
    that.container = spec.container;

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
     * Some fields needs to skip checking whether they are writable or not
     * in metadata. It is possible by setting this option to true.
     * Field example: association_table_field
     *
     * @property {string}
     */
    that.check_writable_from_metadata = spec.check_writable_from_metadata !== undefined ?
                spec.check_writable_from_metadata : true;

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
     * Rights which determines what operation can do with this field or
     * attribute.
     *
     * E.g., 'rscwo' - read, search, compare, write(mod-add), obliterate(mod-del)
     *
     * @property {string}
     */
    that.acl_rights = spec.acl_rights || 'r';

    /**
     * Label
     * @property {string}
     */
    that.label = text.get(spec.label);

    /**
     * Title
     * @property {string}
     */
    that.title = text.get(spec.title);

    /**
     * Measurement unit
     * @property {string}
     */
    that.measurement_unit = spec.measurement_unit;

    /**
     * Data parser
     *
     * - transforms datasource value to field value
     * @property {IPA.formatter}
     */
    that.data_parser = builder.build('formatter', spec.data_parser);

    /**
     * Data formatter
     *
     * - formats field value to datasource value
     *
     * @property {IPA.formatter}
     */
    that.data_formatter = builder.build('formatter', spec.data_formatter);

    /**
     * UI parser
     *
     * - formats widget value to field value
     *
     * @property {IPA.formatter}
     */
    that.ui_parser = builder.build('formatter', spec.ui_parser);

    /**
     * UI formatter
     *
     * - formats field value to widget value
     * - in spec one can use also `formatter` instead of `ui_formatter`
     *
     * @property {IPA.formatter}
     */
    that.ui_formatter = builder.build('formatter', spec.ui_formatter || spec.formatter);


    /**
     * Adapter whích selected values from record on load.
     *
     * @property {field.Adapter}
     */
    that.adapter = builder.build('adapter', spec.adapter || 'adapter', { context: that });

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
     * Turns off loading value from command output on details pages.
     * Used in certmap_match.
     * @property {boolean}
     */
    that.autoload_value = spec.autoload_value === undefined ? true :
                                spec.autoload_value;

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
     * Override of metadata.minvalue
     * @property {number}
     */
    that.minvalue = spec.minvalue;

    /**
     * Override of metadata.maxvalue
     * @property {number}
     */
    that.maxvalue = spec.maxvalue;

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
     * Loaded value
     *
     * - currently value is supposed to be an Array. This might change in a
     *   future.
     *
     * @property {Array.<Object>}
     */
    that.value = [];

    /**
     * Default value
     * @property {Mixed}
     */
    that.default_value = spec.default_value || null;

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

    /**
     * Last validation result
     * @property {Object}
     */
    that.validation_result = null;

    /**
     * Controls if field should perform validation when it's not supposed to
     * be edited by user (`is_editable()`).
     * @property {boolean}
     */
    that.validate_noneditable = spec.validate_noneditable !== undefined ?
        spec.validate_noneditable : false;

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
            if (!that.title) {
                that.title = that.metadata.doc || '';
            }
        }

        that.set_value([], true); // default value
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
     *
     * Note that final required state also depends on `read_only` and
     * `writable` states.
     *
     * @param {boolean} required
     */
    that.set_required = function(required) {
        var old = that.is_required();
        that.required = required;
        var current = that.is_required();

        if (current !== old) {
            that.emit('require-change', { source: that, required: current });
        }
    };

    /**
     * Check if value is set when it has to be. Report if not.
     * @return {boolean} value passes the require check
     */
    that.validate_required = function() {
        var values = that.get_value();
        var result = { valid: true, message: null };
        if ((that.validate_noneditable || that.is_editable()) &&
             util.is_empty(values) && that.is_required()) {
            result.valid = false;
            result.message = text.get('@i18n:widget.validation.required',
                "Required field");
            that.set_valid(result);
        }
        return result.valid;
    };

    /**
     * Validates the field.
     * Sets the result by `set_valid` call.
     * @return {boolean} field is valid
     */
    that.validate = function() {

        var result = { valid: true, message: null, errors: [], results: []};
        var values = that.get_value();

        if ((that.validate_noneditable || that.is_editable()) && !util.is_empty(values)) {

            // validate all values
            for (var i=0, il=values.length; i<il; i++) {
                for (var j=0, jl=that.validators.length; j<jl; j++) {
                    var res = that.validators[j].validate(values[i], that);
                    result.results[i] = res;
                    if (!res.valid) {
                        result.valid = false;
                        result.errors[i] = res;
                        // set error message only for first error
                        if (!result.message) result.message = res.message;
                        break; // report only one error per value
                    }
                }
            }
        }

        that.set_valid(result);
        return result.valid;
    };

    /**
     * Set valid state and validation error message
     * @param {Object|null} result Validation result
     * @fires valid-change
     */
    that.set_valid = function(result) {

        var old_result = that.validation_result;
        that.valid = result.valid;
        that.validation_result = result;

        if (!util.equals(old_result, result)) {
            that.emit('valid-change', {
                source: that,
                valid: result.valid,
                result: result
            });
        }
    };

    /**
     * This function calls adapter to get value from record and date_parser to
     * process it. The it sets is as `value`.
     */
    that.load = function(data) {

        var value = that.adapter.load(data);
        var parsed = util.parse(that.data_parser, value, "Parse error:"+that.name);
        value = parsed.value;
        if (!parsed.ok) {
            window.console.warn(parsed.message);
        }

        // this part is quite application specific and should be moved to
        // different component
        var record = that.adapter.get_record(data);
        that.load_writable(record);

        that.set_value(value, true);
    };

    /**
    * Evaluate if field is writable according to ACL in record and field
    * configuration. Updates `writable` property.
    *
    * Not writable:
    *
    * - primary keys
    * - with 'no_update' metadata flag
    */
    that.load_writable_from_metadata = function(writable) {
        if (that.metadata) {
            if (that.metadata.primary_key) {
                writable = false;
            }

            // In case that field has set always_writable attribute, then
            // 'no_update' flag is ignored in WebUI. It is done because of
            // commands like user-{add,remove}-certmap. They operate with user's
            // attribute, which cannot be changed using user-mod, but only
            // using command user-{add,remove}-certmap. Therefore it has set
            // 'no_update' flag, but we need to show 'Add', 'Remove' buttons in
            // WebUI.
            if (that.metadata.flags &&
                array.indexOf(that.metadata.flags, 'no_update') > -1 &&
                !that.always_writable) {
                writable = false;
            }
        }

        return writable;
    };


    /**
     * Evaluate if field is writable according to ACL in record and field
     * configuration. Updates `writable` property.
     *
     * Not writable (checked in method that.load_writable_from_metadata()):
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

        var writable = true;
        var old = that.acl_rights;

        function has_write(record, param) {
            var rights = record.attributelevelrights[param];
            var has = !!rights && rights.indexOf('w') > -1;
            return has;
        }

        if (that.check_writable_from_metadata) {
            writable = that.load_writable_from_metadata(writable);
        }

        if (record && record.attributelevelrights) {
            var rights = record.attributelevelrights[that.acl_param];
            var write_attr = has_write(record, that.acl_param);
            var all_rights = record.attributelevelrights['*'];
            var write_all = has_write(record, '*');

            // don't assume any value if the rights are not defined, keep the original
            if (rights !== undefined || all_rights !== undefined) {
                that.acl_rights = rights || all_rights || '';
            }

            // Some objects in LDAP may not have proper object class set and
            // therefore server doesn't send proper attribute rights. Flag
            // 'w_if_no_aci' should be used when we want to ensure that UI
            // shows edit interface in such cases. Usable only when user can
            // modify object classes.
            var write_oc = has_write(record, 'objectclass');
            var may_add_oc = !rights && write_oc && that.flags.indexOf('w_if_no_aci') > -1;

            // If no rights, change writable to False:
            writable = writable && (write_attr || write_all || may_add_oc);
        }

        that.set_writable(writable);
        if (old !== that.acl_rights) {
            that.emit('acl-rights-change', { source: that, rights: that.acl_rights, old: old });
        }
    };

    /**
     * Set writable
     * @fires writable-change
     * @param {boolean} writable
     */
    that.set_writable = function(writable) {

        var old = !!that.writable;
        that.writable = writable;
        if (old !== writable) {
            that.emit('writable-change', { source: that, writable: writable });
        }

        that.set_required(that.required); // force update of required
    };

    /**
     * Set read only
     * @fires readonly-change
     * @param {boolean} writable
     */
    that.set_read_only = function(read_only) {

        var old = !!that.read_only;
        that.read_only = read_only;
        if (old !== read_only) {
            that.emit('readonly-change', { source: that, readonly: read_only });
        }
        that.set_required(that.required); // force update of required
    };

    /**
     * Get if field is intended to be edited
     *
     * It's a combination of `enabled`, 'writable` and `read_only` state.
     *
     * @returns {Boolean}
     */
    that.is_editable = function() {

        return that.enabled && that.writable && !that.read_only;
    };

    /**
     * Reset field and widget to loaded values
     */
    that.reset = function() {
        that.emit('reset', { source: that });
        that.set_value(that.get_pristine_value(), true);
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
        if (that.dirty) {
            var values = that.save();
            var field_info = IPA.update_info_builder.new_field_info(that, values);
            update_info.fields.push(field_info);
        }
        return update_info;
    };

    /**
     * Prepare value for persistor.
     *
     * Sets `record[param]` option if `record` is supplied.
     *
     * Returns `['']` when disabled. Otherwise value formatted by
     * `data_formatter` and `adapter`.
     *
     * @param {Object} [record]
     * @return {Array} values
     */
    that.save = function(record) {

        if (!that.enabled) return ['']; // not pretty, maybe leave it for caller

        var value = that.get_value();
        var formatted = util.format(that.data_formatter, value);
        if (formatted.ok) {
            value = formatted.value;
        } else {
            window.console.warn('Output data format error:\n'+
                                JSON.stringify(formatted));
        }

        var diff = that.adapter.save(value, record);
        value = diff[that.param]; // a hack which should be removed. This
                                  // function should not return any value. But
                                  // current consumers expect it.
        return value;
    };

    /**
     * Get field's value
     *
     * Returns pure value; doesn't use any formatter.
     *
     * @returns {Mixed} field's value
     */
    that.get_value = function() {
       return that.value;
    };

    /**
     * Set value
     *
     * Always raises value-change when setting pristine value
     *
     * @param {Mixed} value
     * @param {boolean} pristine - value is pristine
     * @fires value-change
     * @fires dirty-change
     */
    that.set_value = function(value, pristine) {

        that.set_previous_value(that.value);
        that.value = value;

        if (util.dirty(that.value, that.previous_value, that.get_dirty_check_options()) ||
            pristine) {
            that.emit('value-change', {
                source: that,
                value: that.value,
                previous: that.previous_value
            });
        }

        var dirty = false;
        if (pristine) {
            that.set_pristine_value(value);
        } else {
            dirty = that.test_dirty();
        }
        that.set_dirty(dirty);
        that.validate();
    };

    that.get_previous_value = function() {
        return that.previous_value;
    };

    that.set_previous_value = function(value) {
        that.previous_value = value;
    };

    that.get_pristine_value = function() {
        return that.pristine_value;
    };

    that.set_pristine_value = function(value) {
        that.pristine_value = value;
    };

    /**
     * Gets widget values
     * @returns {Array}
     */
    that.get_widget_values = function() {

        var values = [''];

        if (that.widget) {
            values = that.widget.save();
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

        // remove? this check should part of container which cares, the
        // field should not care
        if (that.read_only || !that.writable) return false;

        var pristine = that.get_pristine_value();
        var value = that.get_value();

        return util.dirty(value, pristine, that.get_dirty_check_options());
    };

    /**
     * Returns options for dirty check
     * @returns {Object}
     */
    that.get_dirty_check_options = function() {

        return {
            unordered: !that.ordered
        };
    };

    /**
     * Setter for `dirty`
     * @param {boolean} dirty
     */
    that.set_dirty = function(dirty) {
        var old = that.dirty;
        that.dirty = dirty;

        if (old !== dirty) {
            that.dirty_changed.notify([], that);
            that.emit('dirty-change', { source: that, dirty: dirty });
        }
    };

    /**
     * `enabled` setter
     * @param {boolean} value
     */
    that.set_enabled = function(value) {
        var old = !!that.enabled;
        that.enabled = value;
        if (old !== that.enabled) {
            that.emit('enable-change', { source: that, enabled: that.enabled });
        }
    };

    /**
     * Bind field to a widget defined by `widget_name`
     */
    that.widgets_created = function() {

        that.widget = that.container.widgets.get_widget(that.widget_name);
        if (that.widget) {
            that._binder = new FieldBinder(that, that.widget);
            that._binder.bind();
            that._binder.copy_properties();
        }
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
 * Adapter's task is to select wanted data from RPC response
 *
 * This default adapter expects that context will be a field and data
 * will be FreeIPA JsonRPC response.
 *
 * @class
 */
field.Adapter = declare(null, {

    /**
     * Adapter's context; e.g., field
     *
     * @property {Object}
     */
    context: null,

    /**
     * Index of result in batch results array
     * @type {Number}
     */
    result_index: 0,

    /**
     * When result of API call is an array of object this object index
     * allows to specify exact object in array according to its position.
     * Default value is null which means do not use object_index.
     *
     * @type {Number|null}
     */
    object_index: null,

    /**
     * Name of the record which we want to extract from the result.
     * Used in dnslocations.
     * @type {String}
     */
    result_name: 'result',

    /**
     * Extract record from RPC call response
     *
     * Tries to detect if supplied data is RPC call response if so, it
     * extracts the record. Otherwise it returns supplied data as the record.
     *
     * @param  {Object} data Response data or record
     * @return {Object} record
     */
    get_record: function(data) {

        // detection if it's result or raw RPC command response
        // each RPC response should define properties as follows
        if (data.id === undefined || data.result === undefined || data.error === undefined) {
            return data;
        }

        var dr = data.result;
        var record = null;
        if (dr) {
            if (IPA.defined(dr[this.result_name])) record = dr[this.result_name];
            else if (dr.results) {
                var result = dr.results[this.result_index];
                if (result) record = result[this.result_name];
                var res_type = typeof record;
                var obj_in_type = typeof this.object_index;
                if (record && res_type === 'object' && obj_in_type === 'number')
                    record = record[this.object_index];
            }
        }
        return record;
    },

    /**
     * Get single value from record
     * @param {Object} record Record
     * @param {string} name Attribute name
     * @returns {Array} attribute value
     * @protected
     */
    get_value: function(record, name) {
        var value = record[name];
        return util.normalize_value(value);
    },

    /**
     * By default just select attribute with name defined by `context.param`
     * from a record. Uses default value if value is not in record and context
     * defines it.
     * @param {Object} data Object which contains the record or the record
     * @param {string} [attribute] attribute name - overrides `context.param`
     * @param {Mixed} [def_val] default value - overrides `context.default_value`
     * @returns {Array} attribute value
     */
    load: function(data, attribute, def_val) {
        var record = this.get_record(data);
        var value = null;
        var attr = attribute || this.context.param;
        var def = def_val || this.context.default_value;
        if (record) {
            value = this.get_value(record, attr);
        }
        if (util.is_empty(value) && !util.is_empty(def)) {
            value = util.normalize_value(def);
        }
        value = rpc.extract_objects(value);
        return value;
    },

    /**
     * Save value into record
     *
     * Default behavior is to save it as property which name is defined by
     * contex's param.
     * @param {Object} value Value to save
     * @param {Object} record Record to save the value into
     * @returns {Object} what was saved
     */
    save: function(value, record) {

        var diff = {};
        diff[this.context.param] = value;
        if (record) {
            lang.mixin(record, diff);
        }
        return diff;
    },

    constructor: function(spec) {
        declare.safeMixin(this, spec);
        this.context = spec.context || {};
    }
});

/**
 * Validator
 *
 * - base class, always returns positive result
 *
 * Result format
 *
 * - validation result is an object with mandatory `valid` property which
 *   has to be set to a boolean value. True if value is valid, false otherwise.
 * - if `valid === false` result should also contain `message` property with
 *   human readable error text
 * - it may contain also other properties; e.g., `errors` which contains an
 *   array with other validation result objects in case of complex validation.
 *
 * @class
 * @alternateClassName IPA.validator
 */
field.validator = IPA.validator = function(spec) {

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
 * Javascript integer validator
 *
 * It allows to insert only integer numbers which can be safely represented by
 * Javascript.
 *
 * @class
 * @alternateClassName IPA.integer_validator
 * @extends IPA.validator
 */
 field.integer_validator = IPA.integer_validator = function(spec) {

     var that = IPA.validator(spec);

     /**
      * @inheritDoc
      */
     that.validate = function(value) {

         if (!value.match(/^-?\d+$/)) {
             return that.false_result(text.get('@i18n:widget.validation.integer'));
         }

         if (!Number.isSafeInteger(parseInt(value, 10))) {
             return that.false_result(text.get('@i18n:widget.validation.unsupported'));
         }

         return that.true_result();
     };

     that.integer_validate = that.validate;

     return that;
 };


/**
 * Javascript positive integer validator
 *
 * It allows to insert only positive integer.
 *
 * @class
 * @alternateClassName IPA.positive_integer_validator
 * @extends IPA.validator
 */
 field.positive_integer_validator = IPA.positive_integer_validator = function(spec) {

    var that = IPA.integer_validator(spec);

    /**
    * @inheritDoc
    */

    that.validate = function(value) {

        var integer_check = that.integer_validate(value);

        if (!integer_check.valid) {
            return integer_check;
        }

        var num = parseInt(value, 10);

        if (num <= 0) {
            return that.false_result(
                text.get('@i18n:widget.validation.positive_number'));
        }

        return that.true_result();
    };

    return that;
 };


/**
 * Metadata validator
 *
 * Validates value according to supplied metadata
 *
 * @class
 * @alternateClassName IPA.metadata_validator
 * @extends IPA.validator
 */
field.metadata_validator = IPA.metadata_validator = function(spec) {

    var that = IPA.validator(spec);

    that.get_property = function(name, obj, metadata) {
        var prop = null;
        if (IPA.defined(obj[name], true)) {
            prop = obj[name];
        } else if (IPA.defined(metadata[name], true)) {
            prop = metadata[name];
        }
        return prop;
    };

    /**
     * @inheritDoc
     */
    that.validate = function(value, context) {

        var message;
        var metadata = context.metadata;
        var number = false;

        if (!metadata || util.is_empty(value)) return that.true_result();

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

            var numVal = Number(value);
            var minvalue = that.get_property('minvalue', context, metadata);
            var maxvalue = that.get_property('maxvalue', context, metadata);

            if (IPA.defined(minvalue) &&  numVal < Number(minvalue)) {
                message = text.get('@i18n:widget.validation.min_value');
                message = message.replace('${value}', metadata.minvalue);
                return that.false_result(message);
            }

            if (IPA.defined(maxvalue) && numVal > Number(maxvalue)) {
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
 * @class
 * @alternateClassName IPA.unsupported_validator
 * @extends IPA.validator
 */
field.unsupported_validator = IPA.unsupported_validator = function(spec) {

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

        if (util.is_empty(value)) return that.true_result();

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
 * @class
 * @alternateClassName IPA.same_password_validator
 * @extends IPA.validator
 */
field.same_password_validator = IPA.same_password_validator = function(spec) {

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

        var other_field = context.container.get_field(that.other_field);
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
 * @class
 * @alternateClassName IPA.datetime_field
 * @extends IPA.field
 */
field.datetime_field = IPA.datetime_field = function(spec) {

    spec = spec || {};
    spec.data_formatter = spec.data_formatter || {
        $type: 'datetime',
        template: datetime.templates.generalized
    };
    spec.data_parser = spec.formatter || 'datetime';
    spec.ui_parser = spec.ui_parser || 'datetime';

    var that = IPA.field(spec);
    return that;
};

/**
 * Used along with checkbox widget
 *
 * @class
 * @alternateClassName IPA.checkbox_field
 * @extends IPA.field
 */
field.checkbox_field = IPA.checkbox_field = function(spec) {

    spec = spec || {};
    spec.data_parser = 'boolean';

    var that = IPA.field(spec);

    /**
     * A checkbox will always have a value, so it's never required.
     *
     * @return {boolean} false
     */
    that.is_required = function() {
        return false;
    };

    return that;
};

/**
 * Used along with radio widget
 *
 * @class
 * @alternateClassName IPA.radio_field
 * @extends IPA.field
 */
field.radio_field = IPA.radio_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    /**
     * A radio will always have a value, so it's never required
     *  @return {boolean} false
     */
    that.is_required = function() {
        return false;
    };

    return that;
};

/**
 * Used along with ssh key widget
 *
 * - by default has  `w_if_no_aci` to workaround missing object class
 *
 * @class
 * @alternateClassName IPA.sshkeys_field
 * @extends IPA.field
 */
field.sshkeys_field = IPA.sshkeys_field = function(spec) {

    spec = spec || {};
    spec.adapter = spec.adapter || field.SshKeysAdapter;
    spec.flags = spec.flags || ['w_if_no_aci'];

    var that = IPA.field(spec);
    return that;
};


/**
 * Field for certificates widget.
 * - has the ObjectAdapter as default
 * - by default has  `w_if_no_aci` to workaround missing object class
 *
 * @class
 * @alternateClassName IPA.certs_field
 * @extends IPA.field
 */
field.certs_field = IPA.certs_field = function(spec) {
    spec = spec || {};
    spec.adapter = spec.adapter || field.ObjectAdapter;
    spec.flags = spec.flags || ['w_if_no_aci'];

    var that = IPA.field(spec);

    /**
     * The index of record from batch command where ACLs are returned.
     * Necessary for correct display 'add' and 'delete' buttons in certificate
     * widget.
     *
     * @param {Number} acl_result_index
     */
    that.acl_result_index = spec.acl_result_index;

    that.load = function(data) {
        var value = that.adapter.load(data);
        var parsed = util.parse(that.data_parser, value, "Parse error:"+that.name);
        value = parsed.value;
        if (!parsed.ok) {
            window.console.warn(parsed.message);
        }

        // specific part for certificates - it is necessary to read rights from
        // result of user-show command not from cert-find result.
        // Therefore we need to get record with different index. The correct
        // index is set in acl_result_index variable, old index is stored
        // and then put back.
        var old_index = that.adapter.result_index;
        if (that.acl_result_index !== undefined) {
            that.adapter.result_index = that.acl_result_index;
        }

        var record = that.adapter.get_record(data);
        that.adapter.result_index = old_index;

        that.load_writable(record);

        that.set_value(value, true);
    };

    return that;
};


/**
 * Used along with custom_command_multivalued widget
 *
 * - by default has `w_if_no_aci` to workaround missing object class
 * - by default has always_writable=true to workaround aci rights
 *
 * @class
 * @alternateClassName IPA.custom_command_multivalued_field
 * @extends IPA.field
 */
field.certmap_command_multivalued_field = function(spec) {

    spec = spec || {};
    spec.flags = spec.flags || ['w_if_no_aci'];

    var that = IPA.field(spec);

    /**
     * Set field always writable in case that it is set to true
     * @param Boolean always_writable
     */
    that.always_writable = spec.always_writable === undefined ? true :
            spec.always_writable;

    return that;
};


IPA.custom_command_multivalued_field = field.custom_command_multivalued_field;

/**
 * SSH Keys Adapter
 * @class
 * @extends field.Adapter
 */
field.SshKeysAdapter = declare([field.Adapter], {

    /**
     * Transforms record into array of key, fingerprint pairs
     *
     * """
     *  // input:
     *  {
     *      'ipasshpubkey': [ 'foo', 'foo1'],
     *      'sshpubkeyfp': ['fooFP', 'fooFP2']
     *  }
     *
     *  // output:
     *  [
     *      { key: 'foo', fingerprint: 'fooFP'},
     *      { key: 'foo1', fingerprint: 'fooFP2'},
     *  ]
     * """
     */
    load: function(data) {

        var record = this.get_record(data);
        var keys = this.get_value(record, this.context.param);
        var fingerprints = this.get_value(record, 'sshpubkeyfp');
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
        return values;
    },

    /**
     * Transforms array of pairs into array of keys and save it into record.
     * @param {Array} values Source values
     * @param {Object} record Target record.
     * @returns {Array} saved value
     */
    save: function(values, record) {

        var ret = [];
        for (var i=0; i<values.length; i++) {
            ret.push(values[i].key);
        }
        return this.inherited(arguments, [ret, record]);
    }
});


/**
 * ObjectAdapter is basic adapter which converts object to more usable format.
 * All properties which have only one value are tranformed this way:
 *  property1: {"__base64__": "value1"} => property1: "value1",
 *  property2: {"value2"} => property2: "value2",
 * Works for __base64__ as well as for __datetime__ and __dns_name__
 *
 * In case that the property has more values, then they are returned as array.
 *
 * @class
 * @extends field.Adapter
 */
field.ObjectAdapter = declare([field.Adapter], {

    normalize_object: function(obj) {
        for (var property in obj) {
            if (obj.hasOwnProperty(property)) {
                obj[property] = rpc.extract_objects([obj[property]]);
                if (obj[property].length == 1) {
                    obj[property] = obj[property][0];
                }
            }
        }
    },

    load: function(data) {

        var record = this.get_record(data);

        for (var i=0; i<record.length; i++) {
            this.normalize_object(record[i]);
        }

        return record;
    }
});


/**
 * Custom adapter for fields which handles situations when there is no value
 * for attribute (name) of the field and we want to use alternative attribute
 * from response. We can set the alternative attribute name to the 'alt_attr'
 * attribute of the adapter.
 * This adapter is used i.e. in table in search facet for services. Handles
 * situations where older services don't have canonical name.
 *
 * @class
 * @extends field.Adapter
 */
field.AlternateAttrFieldAdapter = declare([field.Adapter], {
    /**
     * In case that the value is not get using field name then use alternative
     * name.
     * @param {Object} data Object which contains the record or the record
     * @param {string} [attribute] attribute name - overrides `context.param`
     * @param {Mixed} [def_val] default value - overrides `context.default_value`
     * @returns {Array} attribute value
     */
    load: function(data, attribute, def_val) {
        var record = this.get_record(data);
        var value = null;
        var attr = attribute || this.context.param;
        var def = def_val || this.context.default_value;
        if (record) {
            value = this.get_value(record, attr);
            if (util.is_empty(value) && this.context.adapter.alt_attr) {
                value = this.get_value(record, this.context.adapter.alt_attr);
            }
        }
        if (util.is_empty(value) && !util.is_empty(def)) {
            value = util.normalize_value(def);
        }
        value = rpc.extract_objects(value);
        return value;
    }
});


/**
 * Custom adapter specifically implemented for certmap_match where it
 * transform items in format {domain: "xxx", uid: [arrayof_uids]} to
 * {[{domain: "xxx", uid: "uid1"}, {domain: "xxx", uid: 'uid2'}, ...]}.
 * This is necessary for possibility to correctly display table.
 *
 * @class
 * @extends field.Adapter
 */
field.CertMatchTransformAdapter = declare([field.Adapter], {

    /**
    * @param {Array} record
    */
    transform_one_record: function(record) {
        var domain = record.domain;
        var uids = record.uid;
        var results = [];

        for (var i=0, l=uids.length; i<l; i++) {
            results.push({
                domain: domain,
                uid: uids[i]
            });
        }

        return results;
    },

    /**
     * Transform record to array of arrays with objects in the following format:
     * {domain: 'xxx', uid: 'uid1'}
     *
     * @param {Array|Object} record
     */
    transform_record: function(record) {
        if (lang.isArray(record)) {
            for (var i=0, l=record.length; i<l; i++) {
                record[i] = this.transform_one_record(record[i]);
            }
        } else {
            record = this.transform_one_record(record);
        }
    },

    /**
     * Merge array of arrays of object into array of objects.
     *
     * @param {Array} records
     */
    merge_object_into_array: function(records) {
        if (!lang.isArray(records)) return records;

        var merged = [];
        for (var i=0, l=records.length; i<l; i++) {
            merged = merged.concat(records[i]);
        }

        return merged;
    },

    /**
     *
     * @param {Object} data Object which contains the record or the record
     * @returns {Array} attribute values
     */
    load: function(data) {
        var record = this.get_record(data);

        this.transform_record(record);

        var values = this.merge_object_into_array(record);

        return values;
    }
});


/**
 * Field for enabling/disabling entity
 *
 * - expects radio widget
 * - requires facet to use 'update_info' update method
 *
 * @class
 * @alternateClassName IPA.enable_field
 * @extends IPA.field
 */
field.enable_field = IPA.enable_field = function(spec) {

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

            var command = rpc.command({
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
 * @class
 * @alternateClassName IPA.field_container
 */
field.field_container = IPA.field_container = function(spec) {

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
 * @class
 * @alternateClassName IPA.field_builder
 */
field.field_builder = IPA.field_builder = function(spec) {

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
field.pre_op = function(spec, context) {

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
field.post_op = function(obj, spec, context) {

    if (context.container) context.container.add_field(obj);
    return obj;
};

/**
 * Field builder with registry
 * @member field
 */
field.builder = builder.get('field');
field.builder.factory = field.field;
field.builder.string_mode = 'property';
field.builder.string_property = 'name';
reg.set('field', field.builder.registry);
field.builder.pre_ops.push(field.pre_op);
field.builder.post_ops.push(field.post_op);

/**
 * Validator builder with registry
 * @member field
 */
field.validator_builder = builder.get('validator');
reg.set('validator', field.validator_builder.registry);

/**
 * Adapter builder with registry
 * @member field
 */
field.adapter_builder = builder.get('adapter');
field.adapter_builder.ctor = field.Adapter;
field.adapter_builder.post_ops.push(function(obj, spec, context) {
        if (context.context) {
            obj.context = context.context;
        }
        return obj;
    }
);
reg.set('adapter', field.adapter_builder.registry);

/**
 * Register fields and validators to global registry
 * @member field
 */
field.register = function() {
    var f = reg.field;
    var v = reg.validator;
    var l = reg.adapter;

    f.register('certs', field.certs_field);
    f.register('checkbox', field.checkbox_field);
    f.register('checkboxes', field.field);
    f.register('combobox', field.field);
    f.register('certmap_multivalued', field.certmap_command_multivalued_field);
    f.register('datetime', field.datetime_field);
    f.register('enable', field.enable_field);
    f.register('entity_select', field.field);
    f.register('field', field.field);
    f.register('link', field.field);
    f.register('multivalued', field.field);
    f.register('password', field.field);
    f.register('radio', field.radio_field);
    f.register('select', field.field);
    f.register('sshkeys', field.sshkeys_field);
    f.register('textarea', field.field);
    f.register('text', field.field);
    f.register('value_map', field.field);

    v.register('metadata', field.metadata_validator);
    v.register('unsupported', field.unsupported_validator);
    v.register('same_password', field.same_password_validator);
    v.register('integer', field.integer_validator);
    v.register('positive_integer', field.positive_integer_validator);

    l.register('adapter', field.Adapter);
    l.register('object_adapter', field.ObjectAdapter);
    l.register('alternate_attr_field_adapter', field.AlternateAttrFieldAdapter);
    l.register('certmatch_transform', field.CertMatchTransformAdapter);
};
phases.on('registration', field.register);

return field;
});
