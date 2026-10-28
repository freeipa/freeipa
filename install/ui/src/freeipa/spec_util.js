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
        'dojo/_base/lang'
        ], function(declare, array, lang, construct) {

    var undefined;

    /**
     * Utility for working with specification objects
     * @class spec_util
     * @singleton
     */
    var exp = {

        /**
         * Set default value of spec's attribute when not already
         *
         * @param {Object} spec
         * @param {string} attribute name
         * @param {*} default value
         * @param {Object} object
         */
        def: function(spec, attr_name, def) {

            if (spec[attr_name] === undefined) {
                spec[attr_name] = def;
            }
        },

        /**
         * Set spec[spec_attr_name] to obj[attr_name].
         *
         * Use def value if spec doesn't contain the value.
         *
         * Do nothing if no value is defined.
         */
        set: function(obj, spec, attr_name, def, spec_attr_name) {

            spec_attr_name = spec_attr_name || attr_name;

            if (spec[spec_attr_name] !== undefined) {
                obj[attr_name] = spec[spec_attr_name];
            } else if (def !== undefined) {
                obj[attr_name] = def;
            }
        },


        /**
         * Set entity name as entity to spec if context contains entity
         */
        context_entity: function(spec, context) {

            if (context.entity && !spec.entity) {
                if (typeof context.entity === 'string') {
                    spec.entity = context.entity;
                } else {
                    spec.entity = context.entity.name;
                }
            }
        }
    };

    return exp;
});