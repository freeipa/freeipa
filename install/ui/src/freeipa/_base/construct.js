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
        'dojo/_base/lang'
        ], function(declare, array, lang) {

    /**
     * Helper module
     * @class _base.construct
     * @singleton
     */
    var construct = {

        /**
         * Checks if supplied object is a constructor function.
         * It can recognize only classes declared by `dojo/_base/declare`.
         * @param {Object} obj
         */
        is_ctor: function(obj) {

            return typeof obj === 'function' && typeof obj.extend === 'function';
        },

        /**
         * Finds out if object is a spec object.
         *
         * Object is not a spec object when it has an `isInstanceOf` function.
         *
         * @param {Object} obj
         */
        is_spec: function(obj) {
            var ret = false;
            if (typeof obj === 'object') {
                ret = typeof obj.isInstanceOf === 'function';
            }
            return !ret;
        },

        /**
         * Deep clone
         *
         * - does not clone framework objects
         * - fails on cyclic non-framework objects
         *
         * based on `dojo/_base/lang.clone`
         *
         * @param {Mixed} src object to clone
         */
        clone: function(src) {

            if(!src || typeof src != "object" || lang.isFunction(src)) {
                // null, undefined, any non-object, or function
                return src; // anything
            }
            if(src.nodeType && "cloneNode" in src) {
                // DOM Node
                return src.cloneNode(true); // Node
            }
            if (!construct.is_spec(src)) {
                // framework object
                return src;
            }
            if (src instanceof Date) {
                // Date
                return new Date(src.getTime()); // Date
            }
            if (src instanceof RegExp) {
                // RegExp
                return new RegExp(src);   // RegExp
            }
            var r, i, l;
            if (lang.isArray(src)){
                // array
                r = [];
                for (i = 0, l = src.length; i < l; ++i) {
                    if (i in src){
                        r.push(construct.clone(src[i]));
                    }
                }
            } else {
                // generic objects
                r = src.constructor ? new src.constructor() : {};
            }
            return lang._mixin(r, src, construct.clone);
        },

        /**
         * Run object's init function after instantiation if it has one
         * @param {Object} obj
         * @param {Object} spec
         */
        init_post_op: function(obj, spec) {
            if (obj && typeof obj.init === 'function') {
                obj.init(spec);
            }
            return obj;
        },

        no_cs_for_type_error: function(type) {
            return {
                error: 'No construction specification for given type',
                type: type
            };
        }
    };
    return construct;
});