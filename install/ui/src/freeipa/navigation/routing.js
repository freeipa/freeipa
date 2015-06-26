/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2014 Red Hat
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
        'dojo/_base/declare',
        'dojo/_base/lang',
        'dojo/_base/array',
        'dojo/io-query',
        '../reg',
        '../util'
       ],
       function(declare, lang, array, ioquery, reg, util) {

/**
 * Routing mechanism
 * @class navigation.routing
 * @singleton
 */
var routing = {

    /**
     * Router instance
     * @property {navigation.Router}
     */
    router: null,

    /**
     * Map of router handlers
     * @property {Object}
     */
    route_handlers: {},

    /**
     * Map of hash creators
     * @property {Object}
     */
    hash_creators: {},

    /**
     * Facet name to hash creator map
     *
     * - Key: facet name
     * - Value: hash creator
     *
     * @type {Object}
     */
    hc_facet_map: {},

    /**
     * Hash creator priority queue
     *
     * First item == highest priority
     *
     * @type {Array}
     */
    hc_queue: [],

    /**
     * Map of navigators
     * @type {Object}
     */
    navigators: {},

    /**
     * Add hash creator at the beginning of hash creator queue
     * @param {navigation.routing.HashCreator} hash_creator
     * @param {Number} [position]
     */
    add_hash_creator: function(hash_creator, position) {

        if (position !== undefined) {
            this.hc_queue.splice(position, 0, hash_creator);
        } else {
            this.hc_queue.unshift(hash_creator);
        }
    },

    /**
     * Add hash creator to hash creator map
     * @param  {string} facet_name
     * @param  {navigation.routing.HashCreator} hash_creator
     */
    assign_hash_creator: function (facet_name, hash_creator) {
        this.hc_facet_map[facet_name] = hash_creator;
    },

    /**
     * Get hash creator for given facet
     *
     * Lookup priority:
     *
     * - facet -> hash creator map
     * - hash creator queue
     *
     * @param  {facets.Facet} facet [description]
     * @return {navigation.routing.HashCreator}
     */
    get_hash_creator: function(facet) {

        var name = facet.name;
        var hc = this.hc_facet_map[name];
        if (!hc) {
            for (var i=0, l=this.hc_queue.length; i<l; i++) {
                if (this.hc_queue[i].handles(facet)) {
                    hc = this.hc_queue[i];
                    break;
                }
            }
        }
        return hc || null;
    },

    /**
     * Create hash for given facet
     *
     * @param  {facets.Facet} facet
     * @param  {Object|null} options
     * @return {string} hash
     */
    create_hash: function(facet, options) {
        var hc = this.get_hash_creator(facet);
        if (!hc) return '';
        return hc.create_hash(this.router, facet, options);
    },

    /**
     * Navigate by a Navigator
     *
     * Expects path as argument. Path is an array where
     * first element is name of the Navigator, rest are
     * navigators params.
     *
     * @param  {Array} path
     * @return {boolean}
     */
    navigate: function(path) {

        path = path.slice(0);
        var nav_name = path.shift();
        var nav = this.get_navigator(nav_name);
        return nav.navigate.apply(nav, path);
    },

    /**
     * Navigate to specific facet with give options
     * @param  {facets.Facet} facet
     * @param  {Object} options Options for hash creator
     * @return {boolean}
     */
    navigate_to_facet: function(facet, options) {
        var hash = this.create_hash(facet, options);
        return this.router.navigate_to_hash(hash, facet);
    },

    update_hash: function(facet, options) {

        var hash = this.create_hash(facet, options);
        this.router.update_hash(hash, true);
    },

    /**
     * Add route handler to router
     * @param {string|string[]} route  Route or routes.
     * @param {navigation.routing.RouteHandler} handler Handler
     */
    add_route: function(route, handler) {
        this.route_handlers[handler.name] = handler;
        this.router.register_route(route, handler.get_handler());
    },

    /**
     * Add navigator
     * @param {navigation.routing.Navigator} navigator
     */
    add_navigator: function(navigator) {
        this.navigators[navigator.name] = navigator;
    },

    /**
     * Get navigator by name
     * @param  {string} name Navigator's name
     * @return {navigation.routing.Navigator}
     */
    get_navigator: function(name) {
        return this.navigators[name];
    },

    /**
     * Path for default facet
     * @type {Array}
     */
    default_path: ['entity', 'user', 'search'],

    /**
     * Variations of entity routes
     * @property {string[]}
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
     * @property {string[]}
     */
    page_routes: [
        '/p/:page/*args',
        '/p/:page'
    ]
};

/**
 * General route handler
 *
 * @class navigation.routing.RouteHandler
 */
routing.RouteHandler = declare([], {

    handler: null,

    name: 'generic',

    /**
     * Handle router event
     * @param  {Object} event
     * @param  {navigation.Router} router
     */
    handle: function (event, router) {
        if (router.check_clear_ignore()) return;

        var facet_name = event.params.page;
        var args;
        try {
            args = ioquery.queryToObject(event.params.args || '');
        } catch (e) {
            router._error('URI error', 'route', event.params);
            return;
        }

        // set new facet state
        var facet = reg.facet.get(facet_name);
        if (!facet) {
            router._error('Unknown facet', 'route', event.params);
            return;
        }
        facet.reset_state(args);
        router.show_facet(facet);
    },

    /**
     * Create handler callback for router
     * @return {Function} callback
     */
    get_handler: function() {

        if (!this.handler) {
            var self = this;
            this.handler = function(event) {
                self.handle(event, this);
            };
        }
        return this.handler;
    }
});

/**
 * Entity route handler
 *
 * @class navigation.routing.EntityRouteHandler
 * @extends {navigation.routing.RouteHandler}
 */
routing.EntityRouteHandler = declare([routing.RouteHandler], {

    name: 'entity',

    /**
     * @inheritDoc
     */
    handle: function (event, router) {
         if (router.check_clear_ignore()) return;

        var entity_name = event.params.entity;
        var facet_name = event.params.facet;
        var pkeys, args;
        try {
            pkeys = this._decode_pkeys(event.params.pkeys || '');
            args = ioquery.queryToObject(event.params.args || '');
        } catch (e) {
            router._error('URI error', 'route', event.params);
            return;
        }
        args.pkeys = pkeys;

        // set new facet state
        var entity = reg.entity.get(entity_name);
        if (!entity) {
            router._error('Unknown entity', 'route', event.params);
            return;
        }
        var facet = entity.get_facet(facet_name);
        if (!facet) {
            router._error('Unknown facet', 'route', event.params);
            return;
        }
        facet.reset_state(args);
        router.show_facet(facet);
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
    }
});

/**
 * Hash creator creates a hash string from given facet and options
 *
 * This is default hash creator for generic facets.
 *
 * @class navigation.routing.HashCreator
 */
routing.HashCreator = declare([], {

    prefix: 'p',

    name: 'generic',

    create_hash: function(router, facet, options) {

        var path = [router.route_prefix, this.prefix, facet.name];
        var args = ioquery.objectToQuery(options || {});
        if (!util.is_empty(args)) path.push(args);
        var hash = path.join('/');
        return hash;
    },

    handles: function(facet) {
        return true;
    }
});

/**
 * Hash creator for entity facets
 * @class navigation.routing.EntityHashCreator
 * @extends navigation.routing.HashCreator
 */
routing.EntityHashCreator = declare([routing.HashCreator], {

    prefix: 'e',

    name: 'entity',

    create_hash: function(router, facet, options) {

        options = lang.clone(options);
        var entity_name = facet.entity.name;
        var pkeys = this._encode_pkeys(options.pkeys || []);
        delete options.pkeys;
        var args = ioquery.objectToQuery(options || {});

        var path = [router.route_prefix, this.prefix, entity_name, facet.name];
        if (!util.is_empty(args)) path.push(pkeys, args);
        else if (!util.is_empty(pkeys)) path.push(pkeys);

        var hash = path.join('/');
        return hash;
    },

    handles: function(facet) {
        return !!facet.entity;
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
    }
});

/**
 * Navigate to other facet.
 *
 * @class navigation.routing.Navigator
 */
routing.Navigator = declare([], {

    name: 'generic',

    navigate: function(facet_name, args) {

        var facet = reg.facet.get(facet_name);
        if (!facet) {
            routing.router._error('Unknown facet', 'navigation', { facet: facet_name});
            return false;
        }
        if (!args) args = facet.get_state();

        return routing.navigate_to_facet(facet, args);
    }
});

/**
 * Used for switching to entities' facets. Current target facet
 * state is used as params (pkeys, args) when none of pkeys and args
 * are used (useful for switching to previous page with keeping the context).
 *
 * @class navigation.routing.EntityNavigator
 * @extends navigation.routing.Navigator
 */
routing.EntityNavigator = declare([routing.Navigator], {

    name: 'entity',

    navigate: function(entity_name, facet_name, pkeys, args) {

        var entity = reg.entity.get(entity_name);
        if (!entity) {
            routing.router._error('Unknown entity', 'navigation', { entity: entity_name});
            return false;
        }

        var facet = entity.get_facet(facet_name);
        if (!facet) {
            routing.router._error('Unknown facet', 'navigation', { facet: facet_name});
            return false;
        }

        // Use current state if none supplied
        if (!pkeys && !args) {
            args = facet.get_state();
        }
        args = args || {};

        // Facets may be nested and require more pkeys than supplied.
        args.pkeys = facet.get_pkeys(pkeys);

        return routing.navigate_to_facet(facet, args);
    }
});

/**
 * Init routing
 *
 * Sets default routes, handlers, hash creators and navigators
 *
 * @param  {navigation.Router} router
 */
routing.init = function(router) {

    if (router) this.router = router;
    var generic_hc = new routing.HashCreator();
    var entity_hc = new routing.EntityHashCreator();
    var generic_rh = new routing.RouteHandler();
    var entity_rh = new routing.EntityRouteHandler();
    var generic_n = new routing.Navigator();
    var entity_n = new routing.EntityNavigator();
    this.add_hash_creator(generic_hc);
    this.add_hash_creator(entity_hc);
    this.add_route(this.page_routes, generic_rh);
    this.add_route(this.entity_routes, entity_rh);
    this.add_navigator(generic_n);
    this.add_navigator(entity_n);
};

return routing;

});