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
 * Menu proxy.
 *
 * Exports public interface for dealing with menu items.
 */
define([
        'dojo/_base/lang',
        './app', // creates circular dependency
        './ipa',
        'exports' // for handling circular dependency
       ],
       function(lang, app, IPA, exports) {


    var get_menu = function() {
            return app.app.menu;
        },

        /**
         * Adds menu item.
         * Takes a spec of menu item.
         * Normalizes item's name, parent, adds children if specified
         *
         * @param {menu_item} items
         * @param {String|menu_item} parent
         * @param {Object} options
         */
        add_item = function(item, parent, options) {
            var menu = get_menu();
            return menu.add_item(item, parent, options);
        },

        /**
         * Removes menu item
         *
         * @param {String|menu_item} name or menu item to remove
         *
         */
        remove_item = function(item) {

            var menu = get_menu();
            return menu.items.remove(item);
        },

        /**
         * Query internal data store by using default search options or supplied
         * search options.
         *
         * @param Object Query filter
         * @param ?Object Search options, overrides default
         * @return QueryResult
         */
        query = function(query, search_options) {

            var menu = get_menu();

            if (search_options) {
                return menu.items.query(query, search_options);
            } else {
                return menu.query(query);
            }
        },

        /**
         * Get current instance of menu
         */
        get = function() {
            return get_menu();
        };

    // Module export
    exports = {
        add_item: add_item,
        remove_item: remove_item,
        query: query,
        get: get
    };

    return exports;
});