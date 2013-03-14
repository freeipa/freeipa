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
        'dojo/router',
        'dojo/_base/lang',
        'dojo/_base/array',
        'dojo/io-query',
        'dojo/topic',
        '../entities',
        '../facets',
        '../ipa' //TODO: remove dependancy
       ],
       function(declare, router, lang, array, ioquery, topic, entities, facets, IPA) {

    /**
    * Class navigation
    * This component keeps menu and routes in sync. It signalizes
    * other components to display facet by sending 'show-facet' event.
    * Other components can use navigate_to_* methods to change currently
    * displayed facet. This change can be canceled in 'facet-change'
    * event handler.
    */
    var navigation = declare(null, {

        /**
         * Holds references to register route handlers.
         * Can be used for unregistering routes.
         * @type Array
         */
        route_handlers: [],

        /**
         *  Prefix of all routes for this navigation. Useful for multiple
         *  navigation objects in one application.
         *  @type String
         */
        route_prefix: '',

        /**
         * Variations of entity routes
         */
        entity_routes: [
            '/e/:entity/:facet/:pkeys/*args',
            '/e/:entity/:facet//*args',
            '/e/:entity/:facet/:pkeys',
            '/e/:entity/:facet',
            '/e/:entity'
        ],

        /**
         * Variations of simple page routes
         */
        page_routes: [
            '/p/:page/*args',
            '/p/:page'
        ],

        /**
         * Used during facet changing. Set it to true in 'facet-change'
         * event handler to stop the change.
         * @type Boolean
         */
        canceled: false,

        /**
         * Flag to indicate that next hash change should not invoke showing a
         * facet.
         * Main purpose: updating hash.
         * @type Boolen
         */
        ignore_next: false,


        /**
         * Register a route-handler pair to a dojo.router
         * Handler will be run in context of this object
         *
         * @param {string|array} route or routes to register
         * @param {function} handler to be associated with the route(s)
         */
        register_route: function(route, handler) {
            // TODO: add multiple routes for one handler
            route = this.route_prefix + route;
            this.route_handlers.push(router.register(route, lang.hitch(this, handler)));
        },

        /**
         * Initializates router
         *  - registers handlers
         */
        init_router: function() {

            // entity pages
            array.forEach(this.entity_routes, function(route) {
                this.register_route(route, this.entity_route_handler);
            }, this);

            // special pages
            this.register_route(this.page_routes, this.page_route_handler);
        },

        /**
         * Handler for entity routes
         * Shouldn't be invoked directly.
         */
        entity_route_handler: function(event) {

            if (this.check_clear_ignore()) return;

            var entity_name = event.params.entity;
            var facet_name = event.params.facet;
            var pkeys = this._decode_pkeys(event.params.pkeys || '');
            var args = ioquery.queryToObject(event.params.args || '');
            args.pkeys = pkeys;

            // set new facet state
            //var entity = entities.get(entity_name);
            var entity = IPA.get_entity(entity_name); // TODO: replace with prev line
            var facet = entity.get_facet(facet_name);
            facet.set_state(args);

            this.show_facet(facet);
        },

        /**
         * General facet route handler
         * Shouldn't be invoked directly.
         */
        page_route_handler: function(event) {

            if (this.check_clear_ignore()) return;

            var facet_name = event.params.page;
            var args = ioquery.queryToObject(event.params.args || '');

//             // Find menu item
//             var items = this.menu.items.query({ page: facet_name });
//
//             // Select menu item
//             if (items.total > 0) {
//                 this.menu.select(items[items.total-1]);
//             }

            // set new facet state
            var facet = facets.get(facet_name);
            facet.set_state(args);

            this.show_facet(facet);
        },

        /**
         * Used for switching to entitie's facets. Current target facet
         * state is used as params (pkeys, args) when none of pkeys and args
         * are used (useful for switching to previous page with keeping the context).
         */
        navigate_to_entity_facet: function(entity_name, facet_name, pkeys, args) {

            //var entity = entities.get(entity_name);
            var entity = IPA.get_entity(entity_name); // TODO: replace with prev line
            var facet = entity.get_facet(facet_name);

            if (!facet) return false; // TODO: maybe replace with exception

            // Use current state if none supplied
            if (!pkeys && !args) {
                args = facet.get_state();
            }
            args = args || {};

            // Facets may be nested and require more pkeys than supplied.
            args.pkeys = facet.get_pkeys(pkeys);

            var hash = this._create_entity_facet_hash(facet, args);
            return this.navigate_to_hash(hash, facet);
        },

        /**
         * Navigate to other facet.
         */
        navigate_to_facet: function(facet_name, args) {

            // TODO: uncoment when `facets` are implemented
//             var facet = facets.get(facet_name);
//             if (!args) args = facet.get_args();
//             var hash = this._create_facet_hash(facet, { args: args });
//             return this.navigate_to_hash(hash, facet);
        },

        /**
         * Low level function.
         *
         * Public usage should be limited reinitializing canceled navigations.
         */
        navigate_to_hash: function(hash, facet) {

            this.canceled = false;
            topic.publish('facet-change', { facet: facet, hash: hash });
            if (this.canceled) {
                topic.publish('facet-change-canceled', { facet: facet, hash : hash });
                return false;
            }
            this.update_hash(hash, false);
            return true;
        },

        /**
         * Changes hash to supplied
         *
         * @param {String} Hash to set
         * @param {Boolean} Whether to suppress following hash change handler
         */
        update_hash: function(hash, ignore_change) {
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
         * Creates from facet state appropriate hash.
         */
        _create_entity_facet_hash: function(facet, state) {
            state = lang.clone(state);
            var entity_name = facet.entity.name;
            var pkeys = this._encode_pkeys(state.pkeys || []);
            delete state.pkeys;
            var args = ioquery.objectToQuery(state || {});

            var path = [this.route_prefix, 'e', entity_name, facet.name];
            if (!IPA.is_empty(args)) path.push(pkeys, args);
            else if (!IPA.is_empty(pkeys)) path.push(pkeys);

            var hash = path.join('/');
            return hash;
        },

        /**
         * Creates hash of general facet.
         */
        _create_facet_hash: function(facet, state) {
            var args = ioquery.objectToQuery(state.args || {});
            var path = [this.route_prefix, 'p', facet.name];

            if (!IPA.is_empty(args)) path.push(args);
            var hash = path.join('/');
            return hash;
        },

        /**
         * Creates hash from supplied facet and state.
         *
         * @param {facet} facet
         * @param {Object} state
         */
        create_hash: function(facet, state) {
            if (facet.entity) return this._create_entity_facet_hash(facet, state);
            else return this._create_facet_hash(facet, state);
        },


        /**
         * Tells other component to show given facet.
         */
        show_facet: function(facet) {

            topic.publish('facet-show', {
                facet: facet
            });
        },

        /**
         * URI Encodes array items and delimits them by '&'
         * Example: ['foo ', 'bar'] => 'foo%20&bar'
         */
        _encode_pkeys: function(pkeys) {

            var ret = [];
            array.forEach(pkeys, function(pkey) {
                ret.push(encodeURIComponent(pkey));
            });
            return ret.join('&');
        },

        /**
         * Splits strings by '&' and return an array of URI decoded parts.
         * Example: 'foo%20&bar' => ['foo ', 'bar']
         */
        _decode_pkeys: function(str) {

            if (!str) return [];

            var keys = str.split('&');
            for (var i=0; i<keys.length; i++) {
                keys[i] = decodeURIComponent(keys[i]);
            }
            return keys;
        },

        /**
         * Starts routing
         */
        startup: function() {
            router.startup();
        },

        constructor: function(spec) {
            spec = spec || {};
            this.init_router();
        }

    });

    return navigation;
});
