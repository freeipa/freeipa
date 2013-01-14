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
        './construct'
        ], function(declare, array, lang, construct) {

    var Construct_registry = declare(null, {
        /**
         * Registry for storing construction specification.
         * @class
         * @name Construct_registry
         */

        /**
         * Internal map for construction specifications.
         * @protected
         */
        _map: {},

        /**
         * Registers construction specification
         *
         * @param type {String|Object} type or construction spec
         * @param func {Function} constructor or factory function
         * @param [default_spec] {Object} default spec object for given type
         *
         * @returns Object
         *
         * Examples:
         *
         * May be defined by single construction spec object:
         *   var construction_spec = {
         *       type: string,
         *       factory: function,
         *       constructor: function,
         *       spec: object
         *   };
         *   register(construction_spec);
         *
         * or by defining them separately as params:
         *   register(type, factory|constructor, spec);
         */
        register: function(type, func, default_spec) {

            var spec, f, c;

            if (typeof type === 'object') {
                spec = type;
            } else {
                construct.is_constructor(func) ? c = func : f = func;
                spec = {
                    type: type,
                    factory: f,
                    constructor: c,
                    spec: default_spec
                };
            }

            if (typeof spec.type !== 'string' || spec.type !== '') {
                throw 'Argument exception: Invalid type';
            }
            if (typeof spec.factory !== 'function' &&
                    typeof spec.constructor !== 'function') {
                throw 'Argument exception: No factory or constructor defined';
            }

            this._map[spec.type] = spec;
            return spec;
        },

        /**
         * Gets construction specification for given type.
         *
         * @param type {String} Type name
         * @returns Object|null
         */
        get: function(type) {
            return this._map[type] || null;
        }
    });

    return Construct_registry;
});