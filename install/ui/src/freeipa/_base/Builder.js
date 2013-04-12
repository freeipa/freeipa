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
        './Spec_mod'
        ], function(declare, array, lang, construct, Spec_mod) {

    var undefined;

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
         * Specification modifier
         */
        spec_mod: null,

        factory: null,

        ctor: null,

        post_ops: [],

        pre_ops: [],

        /**
         * Build object based on spec.
         *
         * @param {String|Function|Object|Array} Build spec
         * @param {Object} build context
         * @param {Object} overrides
         *
         * String: type name, queries registry
         * Function: factory or ctor
         * Object: spec object
         * Array: array of spec objects
         *
         * Build control properies of spec object:
         *      $ctor: Function
         *      $factory: Function
         *      $mixim_spec: Boolean
         *      $type: String
         *      $pre_ops: []
         *      $post_ops: []
         *
         * All other properties will be passed to object construction method.
         *
         * Builder default factory and ctor is overridden by those specified
         * in overrides when overrides are set.
         */
        build: function(spec, context, overrides) {

            var f,c;

            if (spec === undefined || spec === null) return null;
            if (!construct.is_spec(spec)) return spec;

            context = context || {};

            if (overrides) {
                f = this.factory;
                c = this.ctor;
                if (typeof overrides === 'function') {
                    if (construct.is_ctor(overrides)) {
                        overrides = { $ctor: overrides };
                    } else {
                        overrides = { $factory: overrides };
                    }
                }
                this.factory = overrides.$factory;
                this.ctor = overrides.$ctor;
            }

            var objects;
            if (lang.isArray(spec)) {
                objects = [];
                for (var i=0; i<spec.length; i++) {
                    var obj = this._build(spec[i], context);
                    objects.push(obj);
                }
            } else {
                objects = this._build(spec, context);
            }

            if (overrides) {
                this.factory = f;
                this.ctor = c;
            }

            return objects;
        },

        _build: function(spec, context) {
            var cs = this._get_construction_spec(spec);
            var obj = this._build_core(cs, context);
            return obj;
        },

        _get_construction_spec: function(spec) {

            var cs = {};

            if (typeof spec === 'function') {
                // spec ctor or factory

                if (construct.is_ctor(spec)) {
                    cs.ctor = spec;
                } else {
                    cs.factory = spec;
                }
            } else if (typeof spec === 'string') {
                // spec is type name
                cs = this._query_registry(spec);
            } else if (typeof spec === 'object') {
                var c = spec.$ctor,
                    f = spec.$factory,
                    m = spec.$mixim_spec,
                    t = spec.$type,
                    pre = spec.$pre_ops,
                    post = spec.$post_ops;

                var s = lang.mixin({},spec);
                delete s.$ctor;
                delete s.$factory;
                delete s.$mixim_spec;
                delete s.$type;
                delete s.$pre_ops;
                delete s.$post_ops;

                if (t) {
                    cs = this._query_registry(t);
                    if (cs.spec && m) {
                        lang.mixin(cs.spec, s);
                    } else {
                        cs.spec = s;
                    }
                } else {
                    cs.spec = s;
                }

                if (c) cs.ctor = c;
                if (f) cs.factory = f;

                cs.pre_ops = cs.pre_ops || [];
                cs.post_ops = cs.post_ops || [];
                if (pre) cs.pre_ops.push.call(cs.pre_ops, pre);
                if (pre) cs.post_ops.push.call(cs.post_ops, post);
                cs.spec = cs.spec || {};

                if (!cs.factory && !cs.ctor) {
                    if (this.ctor) cs.ctor = this.ctor;
                    else if (this.factory) cs.factory = this.factory;
                }
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
                cs = construct.clone(cs);
                return cs;
            } else {
                throw {
                    error: 'Build error: construct registry required',
                    builder: this
                };
            }
        },

        _build_core: function(construction_spec, context) {

            var cs = construction_spec,
                obj = null;

            // deep clone to prevent modification of original spec by preops
            cs.spec = construct.clone(cs.spec);

            cs.spec = this._run_preops(this.pre_ops, cs.spec, context);
            if (cs.pre_ops) {
                cs.spec = this._run_preops(cs.pre_ops, cs.spec, context);
            }
            cs.spec = cs.spec || {};

            // do we want following?, remove?
            this.spec_mod.mod(cs.spec, cs.spec);
            this.spec_mod.del_rules(cs.spec);

            if (cs.factory && typeof cs.factory === 'function') {
                obj = cs.factory(cs.spec);
            } else if (cs.ctor && typeof cs.ctor === 'function') {
                obj = new cs.ctor(cs.spec);
            } else {
                throw {
                    error: 'Build error: missing or invalid ctor or factory',
                    spec: cs
                };
            }

            obj = this._run_post_ops(this.post_ops, obj, cs.spec, context);
            if (cs.post_ops) {
                obj = this._run_post_ops(cs.post_ops, obj, cs.spec, context);
            }

            return obj;
        },

        _run_preops: function(pre_ops, spec, context) {
            for (var i=0; i<pre_ops.length; i++) {
                var preop = pre_ops[i];
                var preop_t = typeof preop;
                if (preop_t === 'function') {
                    spec = preop(spec, context);
                } else if (preop_t === 'object') {
                    var temp = lang.clone(preop);
                    this.spec_mod.mod(spec, temp);
                    this.spec_mod.del_rules(temp);
                    lang.mixin(spec, preop);
                }
            }
            return spec;
        },

        _run_post_ops: function(post_ops, obj, spec, context) {
            for (var i=0; i<post_ops.length; i++) {
                var postop = post_ops[i];
                var postop_t = typeof postop;
                if (postop_t === 'function') {
                    obj = postop(obj, spec, context);
                } else if (postop_t === 'object') {
                    lang.mixin(obj, postop);
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
            if (spec.factory) this.factory = spec.factory;
            if (spec.ctor) this.ctor = spec.ctor;
            if (spec.registry) this.registry = spec.registry;
            if (spec.spec_mod) this.spec_mod = spec.spec_mod;
            else this.spec_mod = new Spec_mod();
            if (spec.pre_ops) this.pre_ops.push.call(this.pre_ops, spec.pre_ops);
            if (spec.post_ops) this.post_ops.push.call(this.post_ops, spec.post_ops);
        }
    });

    return Builder;
});