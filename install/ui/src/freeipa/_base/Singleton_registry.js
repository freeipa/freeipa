/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2012 Red Hat
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
        'dojo/_base/array',
        'dojo/_base/lang',
        './construct',
        './Builder',
        './Construct_registry'
        ], function(declare, array, lang, construct, Builder, Construct_registry) {

    /**
     * Registry for storing singleton instances of various items based
     * on their type.
     *
     * @class _base.Singleton_registry
     */
    var Singleton_registry = declare(null, {

        /**
         * Internal map for instances
         * @protected
         * @property {Object}
         */
        _map: {},

        /**
         * Builder used for building new instances. Builder has to have a
         * Constructor registry set.
         * @property {_base.Builder}
         */
        builder: null,

        /**
         * Gets an instance of given type. Creates a new one if it doesn't
         * exist.
         *
         * When an object is passed in, the function returns it.
         *
         * @param {string|Object} type Type's name. Or the object itself.
         * @return {Object|null}
         */
        get: function(type) {

            if (typeof type === 'object') return type;

            var obj = this._map[type];

            if (!obj) {
                if (!this.builder) return null;
                try {
                    obj = this._map[type] = this.builder.build(type);
                } catch (e) {
                    if (e.code === 'no-ctor-fac') obj = null;
                    else {
                        window.console.error('Error while building: ' + type);
                        throw e;
                    }
                }
            }

            return obj;
        },

        /**
         * Set object of given type - overwrites existing
         *
         * @param {string} type
         * @param {Mixed} object
         */
        set: function (type, obj) {
            this._map[type] = obj;
        },

        /**
         * Removes object of given type from registry
         *
         * @param {string} type
         */
        remove: function(type) {

            var undefined;
            this._map[type] = undefined;
        },

        /**
         * Registers construction specification
         *
         * @param {string|Object} type type or construction spec
         * @param {Function} func ctor or factory function
         * @param {Object} [default_spec] default spec object for given type
         *
         * @return {Object}
         */
        register: function(type, func, default_spec) {
            this._check_builder();
            this.builder.registry.register(type, func, default_spec);
        },

        /**
         * Makes a copy of construct specification of original type. Extends
         * it with values in supplied construct specification.
         *
         * @param {string} org_type Original type
         * @param {string} new_type New type
         * @param {Object} construct_spec Construction specification
         */
        copy: function(org_type, new_type, construct_spec) {
            this._check_builder();
            this.builder.registry.copy(org_type, new_type, construct_spec);
        },

        /**
         * Create new construction specification based on an existing one and
         * a specification object. Save it as a new type.
         * @param  {string|Function} type New type or a callback to get
         *                                the type: `callback(spec)`
         * @param  {Object} spec Construction specification
         */
        register_from_spec: function(type, spec) {
            this._check_builder();
            var cs = this.builder.merge_spec(spec, true);
            if (typeof type === 'function') {
                cs.type = type(cs.spec);
            } else {
                cs.type = type;
            }
            this.builder.registry.register(cs);
        },

        _check_builder: function() {
            if (!lang.exists('builder.registry', this)) {
                throw {
                    error: 'Object Initialized Exception: builder not initalized',
                    context: this
                };
            }
        },

        constructor: function(spec) {

            spec = spec || {};
            this._map = {};
            this.builder = spec.builder || new Builder({
                registry: new Construct_registry()
            });
        }
    });

    return Singleton_registry;
});