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
        'dojo/_base/array',
        'dojo/_base/lang',
       './_base/Builder',
        './_base/Singleton_registry'
        ], function(declare, array, lang, Builder, Singleton_registry) {

    var builder_registry = new Singleton_registry();
    builder_registry.builder.ctor = Builder;

    /**
     * Global builder interface.
     *
     * Contains a map of builders for a specific object type.
     *
     * @class builder
     * @singleton
     */
    var exp = {
        /**
         * Registry of builders
         * @property {_base.Singleton_registry}
         */
        builders: builder_registry,

        /**
         * Get builder for object type
         *
         * @param {string} object type
         */
        get: function(obj_type) {
            return this.builders.get(obj_type);
        },

        /**
         * Set builder for object type.
         *
         * @param {string} object type
         * @param {_base.Builder} builder
         */
        set: function(obj_type, builder) {
            this.builders.set(obj_type, builder);
        },

        /**
         * Build object by builder for given object type.
         *
         * @param {string} object type. Uses generic builder if empty string.
         * @param {string|Object|Function} spec
         * @param {Object|null} context
         * @param {Object|null} build overrides
         */
        build: function(obj_type, spec, context, overrides) {

            obj_type = obj_type || 'generic';
            var builder = this.builders.get(obj_type);
            return builder.build(spec, context, overrides);
        }
    };

    return exp;
});