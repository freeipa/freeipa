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
         * @param {String|Function|Object} Build spec
         *
         * String: type name, queries registry
         * Function: factory or constructor
         * Object: spec object
         *
         * Build control properies of spec object:
         *      $constructor: Function
         *      $factory: Function
         *      $mixim_spec: Boolean
         *      $type: String
         *      $pre_ops: []
         *      $post_ops: []
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
                var c = spec.$constructor,
                    f = spec.$factory,
                    m = spec.$mixim_spec,
                    t = spec.$type,
                    pre = spec.$pre_ops,
                    post = spec.$post_ops;

                var s = lang.clone(spec);
                delete s.$constructor;
                delete s.$factory;
                delete s.$mixim_spec;
                delete s.$type;
                delete s.$pre_ops;
                delete s.$post_ops;

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

                cs.pre_ops = cs.pre_ops || [];
                cs.post_ops = cs.post_ops || [];
                if (pre) cs.pre_ops.push.call(cs.pre_ops, pre);
                if (pre) cs.post_ops.push.call(cs.post_ops, post);
            }

            return cs;
        },

        /**
         * Queries registry and returns copy of construction specification
         */
        _query_registry: function(type) {

            if (this.registry) {
                var cs = this.registry.get(type);
                if (!cs) throw construct.no_cs_for_type_error(type);
                cs = construct.copy_cs(cs);
                return cs;
            } else {
                throw {
                    error: 'Build error: construct registry required',
                    builder: this
                };
            }
        },

        _build: function(construction_spec) {

            var cs = construction_spec,
                obj = null,
                i;

            if (cs.pre_ops) {
                for (i=0; i<cs.pre_ops.length; i++) {
                    var preop = cs.pre_ops[i];
                    var preop_t = typeof preop;
                    if (preop_t === 'function') {
                        cs.spec = preop(cs.spec || {});
                    } else if (preop_t === 'object') {
                        lang.mixin(cs.spec, preop);
                    }
                }
            }

            cs.spec = cs.spec || {};

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

            if (cs.post_ops && obj) {
                for (i=0; i<cs.post_ops.length; i++) {
                    var postop = cs.post_ops[i];
                    var postop_t = typeof postop;
                    if (postop_t === 'function') {
                        obj = postop(obj);
                    } else if (postop_t === 'object') {
                        lang.mixin(obj, postop);
                    }
                }
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