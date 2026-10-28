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

    /**
     * Registry for storing construction specification.
     * @class _base.Construct_registry
     */
    var Construct_registry = declare(null, {


        /**
         * Internal map for construction specifications.
         * @protected
         */
        _map: null,

        /**
         * Registers construction specification
         *
         *      // May be defined by single construction spec object:
         *      var construction_spec = {
         *          type: String,
         *          factory: Function,
         *          ctor: Function,
         *          spec: Object,
         *          pre_ops: [],
         *          post_ops: []
         *      };
         *      register(construction_spec);
         *
         *      // or by defining them separately as params:
         *      register(type, factory|ctor, spec);
         *
         * @param {string|Object} type type or construction spec
         * @param {Function} func ctor or factory function
         * @param {Object} [default_spec] default spec object for given type
         *
         * @returns {Object}
         */
        register: function(type, func, default_spec) {

            var cs, f, c;

            if (typeof type === 'object') {
                cs = type;
            } else {
                construct.is_ctor(func) ? c = func : f = func;
                cs = {
                    type: type,
                    factory: f,
                    ctor: c,
                    spec: default_spec
                };
            }

            if (!cs.pre_ops) cs.pre_ops = [];
            if (!cs.post_ops) cs.post_ops = [];

            this._check_spec(cs);

            this._map[cs.type] = cs;
            return cs;
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

            var def_cs = construct_spec;
            var old_cs = this._check_get(org_type);
            var cs = construct.clone(old_cs);

            cs.type = new_type;
            if (def_cs.pre_ops) cs.pre_ops.push.apply(cs.pre_ops, def_cs.pre_ops);
            if (def_cs.post_ops) cs.post_ops.push.apply(cs.post_ops, def_cs.post_ops);
            if (def_cs.factory) cs.factory = def_cs.factory;
            if (def_cs.ctor) cs.ctor = def_cs.ctor;
            if (def_cs.spec) {
                cs.spec = cs.spec || {};
                lang.mixin(cs.spec, def_cs.spec);
            }

            this._check_spec(cs);

            this._map[cs.type] = cs;
            return cs;
        },

        /**
         * Registers pre operation.
         *
         * Purpose of pre operation is to modify spec object before build
         * operation.
         *
         * When op is Function it gets called with spec as a param and should
         * return modified spec.
         *
         * When op is Object, the object gets mixed in into spec.
         *
         * @param {string} type
         * @param {Function|Object} op
         * @param {boolean} move op to first position
         */
        register_pre_op: function(type, op, first) {

            var cs = this._check_get(type);
            if (first) cs.pre_ops.unshift(op);
            else cs.pre_ops.push(op);
        },

        /**
         * Registers post operation.
         *
         * Purpose of post operation is to modify built object.
         *
         * When op is Function it gets called with built object as a param
         * and should return modified obj.
         *
         * When op is Object, the object gets mixed in into built object. Use
         * with caution.
         *
         * @param {string} type
         * @param {Function|Object} op
         * @param {boolean} first move op to first position
         */
        register_post_op: function(type, op, first) {

            var cs = this._check_get(type);
            if (first) cs.post_ops.unshift(op);
            else cs.post_ops.push(op);
        },

        /**
         * Gets construction specification for given type.
         *
         * @param {string} string Type name
         * @returns {Object|null}
         */
        get: function(type) {
            return this._map[type] || null;
        },

        _check_get: function(type) {
            var cs = this.get(type);
            if (!cs) throw construct.no_cs_for_type_error(type);
            return cs;
        },

        _check_spec: function(spec) {
            if (typeof spec.type !== 'string' || spec.type === '') {
                throw 'Argument exception: Invalid type';
            }
            if (!lang.isArrayLike(spec.pre_ops)) {
                throw 'Argument exception: Invalid pre_ops type.';
            }
            if (!lang.isArrayLike(spec.post_ops)) {
                throw 'Argument exception: Invalid post_ops type.';
            }
        },

        constructor: function(spec) {
            this._map = {};
        }
    });

    return Construct_registry;
});