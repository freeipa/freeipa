/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2013 Red Hat
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

define(['dojo/_base/declare',
        'dojo/on',
        './builder',
        './field',
        './ordered-map'
       ],
       function(declare, on, builder, field_mod, ordered_map) {

    /**
     * Form mixin
     *
     * Manages fields and related logic.
     *
     * Expects that this mixin will be mixed in a class which will implement
     * `Stateful`.
     *
     * @class FormMixin
     */
    var FormMixin = declare([], {

        /**
         * Some field is dirty
         * @property {boolean}
         */
        dirty: null,

        /**
         * Fields
         * @property {ordered_map}
         */
        fields: null,

        /**
         * Builds fields on add if not already built
         *
         * @property {field.field_builder}
         */
        field_builder: null,

        /**
         * Raised when `dirty` state changes
         * @event dirty-change
         */

        /**
         * Raised after fields reset
         * @event reset
         */

        /**
         * Get field by name
         * @param {string} name
         */
        get_field: function(name) {
            return this.fields.get(name);
        },

        /**
         * Get all fields
         * @return {Array.<IPA.field>}
         */
        get_fields: function() {
            return this.fields.values;
        },

        /**
         * Add field
         * @param {IPA.field|Object|String} field
         *                           Field or field spec
         */
        add_field: function(field) {
            field.container = this;
            var built = this.field_builder.build_field(field);
            this.register_field_listeners(built);
            this.fields.put(field.name, built);
            return built;
        },

        /**
         * Add multiple fields
         * @param {Array} fields
         */
        add_fields: function(fields) {

            if (!fields) return [];

            var built = [];
            for (var i=0; i<fields.length; i++) {
                var f = this.add_field(fields[i]);
                built.push(f);
            }
            return built;
        },

        /**
         * Registers listeners for field events
         * @param {IPA.field} field
         * @protected
         */
        register_field_listeners: function(field) {

            on(field, 'dirty-change', this.on_field_dirty_change.bind(this));
        },

        /**
         * Field's dirty-change handler
         * @param {Object} event
         * @protected
         * @fires dirty-change
         */
        on_field_dirty_change: function(event) {

            var old = this.dirty;

            if (event.dirty) {
                this.dirty = true;
            } else {
                this.dirty = this.is_dirty();
            }

            if (old !== this.dirty) {
                this.emit('dirty-change', { source: this, dirty: this.dirty });
            }
        },

        /**
         * Perform check if any field is dirty
         *
         * @return {boolean}
         *                  - true: some field is dirty
         *                  - false: all field's aren't dirty
         */
        is_dirty: function() {
            var fields = this.get_fields();
            for (var i=0; i<fields.length; i++) {
                if (fields[i].enabled && fields[i].dirty) {
                    return true;
                }
            }
            return false;
        },

        /**
         * Reset all fields
         * @fires reset
         */
        reset: function() {

            var fields = this.get_fields();
            for (var i=0; i<fields.length; i++) {
                var field = fields[i];
                field.reset();
            }

            this.emit('reset', { source: this });
        },

        /**
         * Validate all fields
         * @return {boolean} true when all fields are valid
         */
        validate: function() {
            var valid = true;
            var fields = this.get_fields();
            for (var i=0; i<fields.length; i++) {
                var field = fields[i];
                valid = field.validate() && field.validate_required() && valid;
            }
            return valid;
        },

        /** Constructor */
        constructor: function(spec) {

            this.fields = ordered_map();
            var builder_spec = spec.field_builder || field_mod.field_builder;
            this.field_builder = builder.build(null, builder_spec);
            this.dirty = false;
        }
    });

    return FormMixin;
});
