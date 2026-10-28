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
        'dojo/Evented',
        'dojo/router'
       ],
       function(declare, Evented, router) {

    /**
     * Router
     *
    * This component keeps menu and routes in sync. It signalizes
    * other components to display facet by sending 'show-facet' event.
    * Other components can use navigate_to_* methods to change currently
    * displayed facet. This change can be canceled in 'facet-change'
    * event handler.
    * @class navigation.Router
    */
    var navigation = declare([Evented], {

        /**
         * Holds references to register route handlers.
         * Can be used for unregistering routes.
         * @property {Array.<Function>}
         */
        route_handlers: [],

        /**
         *  Prefix of all routes for this navigation. Useful for multiple
         *  navigation objects in one application.
         *  @property {string}
         */
        route_prefix: '',

        /**
         * Used during facet changing. Set it to true in 'facet-change'
         * event handler to stop the change.
         * @property {boolean}
         */
        canceled: false,

        /**
         * Flag to indicate that next hash change should not invoke showing a
         * facet.
         * Main purpose: updating hash.
         * @property {boolean}
         */
        ignore_next: false,

        /**
         * Register a route-handler pair to a dojo.router
         * Handler will be run in context of this object
         *
         * @param {string|Array.<string>} route or routes to register
         * @param {Function} handler to be associated with the route(s)
         */
        register_route: function(route, handler) {

            if (route instanceof Array) {
                for (var i=0, l=route.length; i<l; i++) {
                    this.register_route(route[i], handler);
                }
            } else {
                var r = this.route_prefix + route;
                this.route_handlers.push(router.register(r, handler.bind(this)));
            }
        },

        /**
         * Navigate to given hash
         *
         * @fires facet-change
         * @fires facet-change-canceled
         */
        navigate_to_hash: function(hash, facet) {

            this.canceled = false;
            this.emit('facet-change', { facet: facet, hash: hash });
            if (this.canceled) {
                this.emit('facet-change-canceled', { facet: facet, hash : hash });
                return false;
            }
            this.update_hash(hash, false);
            return true;
        },

        /**
         * Changes hash to supplied
         *
         * @param {string} Hash to set
         * @param {boolean} Whether to suppress following hash change handler
         */
        update_hash: function(hash, ignore_change) {
            if (window.location.hash === "#" + hash) return;
            this.ignore_next = !!ignore_change;
            router.go(hash);
        },

        /**
         * Returns and resets `ignore_next` property.
         */
        check_clear_ignore: function() {
            var ignore = this.ignore_next;
            this.ignore_next = false;
            return ignore;
        },

        /**
         * Tells other component to show given facet.
         */
        show_facet: function(facet) {

            this.emit('facet-show', {
                facet: facet
            });
        },

        /**
         * Raise 'error'
         * @protected
         * @fires error
         */
        _error: function(msg, type, context) {

            this.emit('error', {
                message: msg,
                type: type,
                context: context
            });
        },

        /**
         * Starts routing
         */
        startup: function() {
            router.startup();
        },

        constructor: function(spec) {
            spec = spec || {};
        }

    });

    return navigation;
});
