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

/**
 * Registry-like object which serves as a registry of registries.
 *
 * Registry object should implement `register` and `get; method as Singleton or
 * Construct registry do. It's expected that there will be different types of
 * registries for various object types.
 *
 * Existing registries can be accessed directly by properties.
 *
 * Use set method for setting new registry.
 * Use get/registry method for getting/registering object in a registry.
 *
 * Registries should be named by their object type in singular form:
 *
 *   * entity
 *   * widget
 *   * action
 *   * formatter
 *   * facet
 *   * dialog
 *
 * @class reg
 * @singleton
 */
define(['dojo/_base/declare',
        'dojo/_base/array',
        'dojo/_base/lang',
        './_base/Singleton_registry'
        ], function(declare, array, lang, Singleton_registry) {

    var reg = new Singleton_registry();
    reg.builder.ctor = Singleton_registry;

    var exp = reg._map;

    /**
     * Get registry
     * @param {string} object_type
     * @param {string} type
     * @return {_base.Construct_registry/_base.Singleton_registry}
     */
    exp.get = function(object_type, type) {

        var registry = reg.get(object_type);
        return registry.get(type);
    };

    /**
     * Create and register new registry
     * @param {string} object_type
     * @param {string} type
     * @param {Function} func
     * @param {Object} default_spec
     */
    exp.register =  function(object_type, type, func, default_spec) {
        var registry = reg.get(object_type);
        registry.register(type, func, default_spec);
    };

    /**
     * Set new registry
     * @param {string} object_type
     * @param {_base.Construct_registry|_base.Singleton_registry} registry
     */
    exp.set = function(object_type, registry) {
        reg.set(object_type, registry);
    };


    return exp;
});