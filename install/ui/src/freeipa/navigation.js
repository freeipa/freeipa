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


define([
        'dojo/_base/lang',
        './app_container',
        './ipa'
       ],
       function(lang, app_container, IPA) {


    var get_router = function() {
        return app_container.app.router;
    };

    var navigation = {
        /**
         * Navigation tells application to show certain facet.
         *
         * It's proxy for navigation/Router instance in current running
         * application.
         *
         * Modules just use the interface, they don't have to care about the logic in
         * the background.
         * @class navigation
         */

        /**
         * Sets property of params depending on arg type following way:
         *   for String sets params.facet
         *   for Facet sets params.facet  (based on show function)
         *   for Object sets params.args
         *   for Array sets params.pkeys
         *  @ignore
         *  @param Object params
         *  @param {Object|facet.facet|string|Function} arg
         */
        set_params: function(params, arg) {
            if (lang.isArray(arg)) {
                params.pkeys = arg;
            } else if (typeof arg === 'object') {

                if (typeof arg.show === 'function') params.facet = arg;
                else params.args = arg;
            } else if (typeof arg === 'string') {
                params.facet = arg;
            }
        },

        /**
         * Show facet.
         *
         * Takes 3 arguments:
         *    * facet(String or Facet)
         *    * pkeys (Array)
         *    * args (Object)
         *
         * Argument order is not defined. They are recognized based on their
         * type.
         *
         * When facet is defined as a string it has to be registered in
         * facet register. //FIXME: not yet implemented
         *
         * When it's an object (Facet) and has an entity set it will be
         * dealt as entity facet.
         * @method show
         * @param {Object|facet.facet|string|Function} arg1
         * @param {Object|facet.facet|string|Function} arg2
         * @param {Object|facet.facet|string|Function} arg3
         */
        show: function(arg1, arg2, arg3) {

            var nav = get_router();
            var params = {};

            this.set_params(params, arg1);
            this.set_params(params, arg2);
            this.set_params(params, arg3);

            var facet = params.facet;

            if (typeof facet === 'string') {
                // FIXME: doesn't work at the moment
                throw 'Not yet supported';
                //facet = IPA.get_facet(facet);
            }

            if (!facet) throw 'Argument exception: missing facet';

            if (facet && facet.entity) {
                return nav.navigate_to_entity_facet(
                    facet.entity.name,
                    facet.name,
                    params.pkeys,
                    params.args);
            } else {
                return nav.navigate_to_facet(facet.name, params.args);
            }
        },

        /**
         * Show entity facet
         *
         * arg1,arg2,arg3 are:
         *      facet name as String
         *      pkeys as Array
         *      args as Object
         * @method show_entity
         * @param String Enity name
         * @param {Object|facet.facet|string|Function} arg1
         * @param {Object|facet.facet|string|Function} arg2
         * @param {Object|facet.facet|string|Function} arg3
         */
        show_entity: function(entity_name, arg1, arg2, arg3) {
            var nav = get_router();
            var params = {};

            this.set_params(params, arg1);
            this.set_params(params, arg2);
            this.set_params(params, arg3);
            return nav.navigate_to_entity_facet(entity_name, params.facet,
                                                params.pkeys, params.args);
        },

        /**
         * Show default facet
         * @method show_default
         */
        show_default: function() {
            // TODO: make configurable
            return this.show_entity('user', 'search');
        }
    };
    return navigation;
});
