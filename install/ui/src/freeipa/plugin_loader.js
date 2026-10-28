/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2013 Red Hat
 * see file 'COPYING'./for use and warranty information
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

define([
    'dojo/_base/array',
    'dojo/_base/lang',
    'dojo/Deferred',
    'dojo/promise/all'
],function(array, lang, Deferred, all) {

    /**
     * Plugin loader
     * @class
     * @singleton
     */
    var plugin_loader = {

        /**
         * Register plugins
         * @param {Array.<string>} plugins
         */
        register_plugins: function(plugins) {

            var packages = [];

            array.forEach(plugins, function(name) {
                packages.push({
                    name: name,
                    location: 'plugins/'+name
                });
            });

            require({ packages: packages});
        },

        /**
         * Load plugin
         * @param {string} name
         * @return {Promise}
         */
        load_plugin: function(name) {
            var plugin_loaded = new Deferred();

            var mid = name+'/'+name;

            require([mid], function(plugin) {
                plugin_loaded.resolve(plugin);
            });

            return plugin_loaded.promise;
        },

        /**
         * Load plugins
         *
         * - loads plugin list from `freeipa/plugins` module.
         * @return {Promise}
         */
        load_plugins: function() {

            var plugins_loaded = new Deferred();

            require(['freeipa/plugins'], function(plugins) {
                var loading = [];

                this.register_plugins(plugins);

                array.forEach(plugins, function(plugin) {
                    loading.push(this.load_plugin(plugin));
                }.bind(this));

                all(loading).then(function(results) {
                    plugins_loaded.resolve(results);
                });
            }.bind(this));

           return plugins_loaded.promise;
        }
    };

    return plugin_loader;
});
