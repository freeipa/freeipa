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
        './Construct_registry',
        './Spec_mod'
        ], function(declare, array, lang, construct, Construct_registry, Spec_mod) {

    var undefined;

    /**
     * Builder
     *
     * Builds objects based on their specification.
     * @class _base.Builder
     */
    var Builder = declare(null, {
        /**
         * Construct registry
         * @property {_base.Construct_registry}
         */
        registry: null,

        /**
         * Specification modifier
         * @property {_base.Spec_mod}
         */
        spec_mod: null,

        /**
         * Default factory
         * @property {Function|null}
         */
        factory: null,

        /**
         * Default constructor
         * @property {Function|null}
         */
        ctor: null,

        /**
         * Array of spec modifiers.
         *
         * Are applied before build on spec object.
         *
         * Spec modifier can be:
         *
         * - a function which is called before build
         *      - takes params: spec, context
         *      - returns spec
         * - an object which is mixed in into spec
         * - an object with properties for Spec_mod
         *
         * @property {Array|null}
         */
        pre_ops: null,

        /**
         * Array of object modifiers.
         *
         * Object modifier is a function which is after build.
         *
         * - takes params: built object, spec, context
         * - returns object
         * @property {Array|null}
         */
        post_ops: null,

        /**
         * Controls what builder do when spec is a string. Possible values:
         *
         * - 'type'
         * - 'property'
         *
         * ##Type
         * Spec is type. Queries registry for obtaining construction spec.
         *
         * ##Property
         * Spec is a property of spec, name of property is set in
         * `string_property`. This mode should be combined with default
         * factory or ctor otherwise the build will fail.
         *
         * @property {string}
         */
        string_mode: 'type',

        /**
         * Property name for `string_mode` == `property`
         * @property {string}
         */
        string_property: '',

        /**
         * Build object based on spec.
         *
         * @param {string|Function|Object|Array} spec Build spec
         *
         * - **String**: type name, queries registry
         * - **Function**: factory or ctor
         * - **Object**: spec object
         * - **Array**: array of spec objects
         *
         * Build control properties of spec object:
         *
         * - $ctor: Function
         * - $factory: Function
         * - $mixim_spec: boolean
         * - $type: string
         * - $pre_ops: []
         * - $post_ops: []
         *
         * All other properties will be passed to object construction method.
         * @param {Object} context build context
         * @param {Object} overrides
         * Builder default factory and ctor is overridden by those specified
         * in overrides when overrides are set.
         */
        build: function(spec, context, overrides) {

            var f,c, pre, post;

            if (spec === undefined || spec === null) return null;
            if (!construct.is_spec(spec)) return spec;

            context = context || {};

            // save
            if (overrides) {
                f = this.factory;
                c = this.ctor;
                pre = this.pre_ops;
                post = this.post_ops;
                if (typeof overrides === 'function') {
                    if (construct.is_ctor(overrides)) {
                        overrides = { $ctor: overrides };
                    } else {
                        overrides = { $factory: overrides };
                    }
                }
                this.factory = overrides.$factory;
                this.ctor = overrides.$ctor;
                if (overrides.$pre_ops) this.pre_ops = overrides.$pre_ops;
                if (overrides.$post_ops) this.post_ops = overrides.$post_ops;
            }

            // build
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

            // restore
            if (overrides) {
                this.factory = f;
                this.ctor = c;
                this.pre_ops = pre;
                this.post_ops = post;
            }

            return objects;
        },

        /**
         * Create new construction spec from an existing one based on object
         * specification object and save the new construction spec
         *
         * @param  {Object}             spec        Specification object
         * @return {Object}                         Construction specification
         */
        merge_spec: function(spec, force_mixin) {
            var cs = {};

            if (typeof spec === 'function') {
                // spec ctor or factory

                if (construct.is_ctor(spec)) {
                    cs.ctor = spec;
                } else {
                    cs.factory = spec;
                }
            } else if (typeof spec === 'string') {
                // spec is type name or spec property
                cs = this._get_cs_string(spec);
            } else if (typeof spec === 'object') {
                var c = spec.$ctor,
                    f = spec.$factory,
                    m = spec.$mixim_spec || force_mixin,
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
                if (pre) cs.pre_ops.push.apply(cs.pre_ops, pre);
                if (post) cs.post_ops.push.apply(cs.post_ops, post);
            }
            return cs;
        },

        /**
         * Build single object
         * @protected
         */
        _build: function(spec, context) {
            var cs = this._get_construction_spec(spec);
            var obj = this._build_core(cs, context);
            return obj;
        },

        /**
         * Normalizes construction specification
         * @protected
         */
        _get_construction_spec: function(spec) {

            var cs = this.merge_spec(spec);
            cs.spec = cs.spec || {};
            if (!cs.factory && !cs.ctor) {
                if (this.ctor) cs.ctor = this.ctor;
                else if (this.factory) cs.factory = this.factory;
            }

            return cs;
        },

        /**
         * Queries registry and returns copy of construction specification
         * @protected
         */
        _query_registry: function(type) {

            if (this.registry) {
                var cs = this.registry.get(type);
                if (!cs) cs = {};
                cs = construct.clone(cs);
                return cs;
            } else {
                throw {
                    error: 'Build error: construct registry required',
                    builder: this
                };
            }
        },

        /**
         * Get cs from string according to string mode
         * @protected
         */
        _get_cs_string: function(spec) {

            var cs;
            if (this.string_mode === 'type') {
                cs = this._query_registry(spec);
            } else {
                var sp = {};
                sp[this.string_property] = spec;
                cs = { spec: sp };
            }
            return cs;
        },

        /**
         * Core build method
         * @protected
         */
        _build_core: function(construction_spec, context) {

            var cs = construction_spec,
                obj = null;

            if (!(cs.factory && typeof cs.factory === 'function') &&
                !(cs.ctor && typeof cs.ctor === 'function')) {
                throw {
                    error: 'Build error: missing or invalid ctor or factory',
                    code: 'no-ctor-fac',
                    spec: cs
                };
            }

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

            try {
                if (cs.factory) {
                    obj = cs.factory(cs.spec);
                } else {
                    obj = new cs.ctor(cs.spec);
                }

                obj = this._run_post_ops(this.post_ops, obj, cs.spec, context);
                if (cs.post_ops) {
                    obj = this._run_post_ops(cs.post_ops, obj, cs.spec, context);
                }
            } catch (e) {
                if (e.expected) {
                    // expected exceptions thrown by builder just mean that
                    // object is not to be built
                    obj = null;
                } else {
                    window.console.error(e.stack);
                    throw e;
                }
            }

            return obj;
        },

        /**
         * Apply pre_ops
         * @protected
         */
        _run_preops: function(pre_ops, spec, context) {
            for (var i=0; i<pre_ops.length; i++) {
                var preop = pre_ops[i];
                var preop_t = typeof preop;
                if (preop_t === 'function') {
                    spec = preop(spec, context);
                } else if (preop_t === 'object') {
                    var temp = construct.clone(preop);
                    this.spec_mod.mod(spec, temp);
                    this.spec_mod.del_rules(temp);
                    lang.mixin(spec, temp);
                }
            }
            return spec;
        },

        /**
         * Apply post_ops
         * @protected
         */
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
            this.pre_ops = [];
            this.post_ops = [];
            if (spec.factory) this.factory = spec.factory;
            if (spec.ctor) this.ctor = spec.ctor;
            if (spec.registry) this.registry = spec.registry;
            else this.registry = new Construct_registry();
            if (spec.spec_mod) this.spec_mod = spec.spec_mod;
            else this.spec_mod = new Spec_mod();
            if (spec.pre_ops) this.pre_ops.push.call(this.pre_ops, spec.pre_ops);
            if (spec.post_ops) this.post_ops.push.call(this.post_ops, spec.post_ops);
        }
    });

    return Builder;
});