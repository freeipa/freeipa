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

    var Builder = declare(null, {
        /**
         * Builds objects based on specication.
         *
         * @class
         * @name Builder
         */

        /**
         * Construct registry
         * @property ./Construct_registry
         */
        registry: null,

        /**
         * Build object based on spec.
         *
         * @param spec {String|Function|Object} Build spec
         *
         * String: type name, queries registry
         * Function: factory or constructor
         * Object: spec object
         *
         * Build control properies of spec object:
         *      constructor: Function
         *      factory: Function
         *      mixim_spec: Boolean
         *      type: String
         *
         * All other properties will be passed to object construction method.
         */
        build: function(spec) {

            var cs = this._get_construction_spec(spec);
            var obj = this._build(cs);
            return obj;
        },

        _get_construction_spec: function(spec) {

            var cs = {};

            if (typeof spec === 'function') {
                // spec constructor or factory

                if (construct.is_constructor(spec)) {
                    cs.constructor = spec;
                } else {
                    cs.factory = spec;
                }
            } else if (typeof spec === 'string') {
                // spec is type name
                cs = this._query_registry(spec);
            } else if (typeof spec === 'object') {
                var c = spec.constructor,
                    f = spec.factory,
                    m = spec.mixim_spec,
                    t = spec.type;

                var s = lang.clone(spec);
                delete s.constructor;
                delete s.factory;
                delete s.mixim_spec;
                delete s.type;

                if (c) {
                    cs.constructor = c;
                    cs.spec = s;
                }
                else if (f) {
                    cs.factory = f;
                    cs.spec = s;
                }
                else if (t) {
                    cs = this._query_registry(t);
                    if (cs.spec && m) {
                        lang.mixin(cs.spec, s);
                    } else {
                        cs.spec = s;
                    }
                }
            }

            return cs;
        },

        _query_registry: function(type) {

            if (this.registry) {
                return this.registry.get(type);
            } else {
                throw {
                    error: 'Build error: construct registry required',
                    spec: type
                };
            }
        },

        _build: function(construction_spec) {

            var cs = construction_spec,
                obj = null;

            if (cs.factory && typeof cs.factory === 'function') {
                obj = cs.factory(cs.spec);
            } else if (cs.constructor && typeof cs.constructor === 'function') {
                obj = new cs.constructor(cs.spec);
            } else {
                throw {
                    error: 'Build error: missing or invalid constructor or factory',
                    spec: cs
                };
            }

            return obj;
        },

        /**
         * Constructor
         *
         * set spec.registry to use Construct_registry instance
         */
        constructor: function(spec) {

            spec = spec || {};
            if (spec.registry) this.registry = spec.registry;
        }
    });

    return Builder;
});