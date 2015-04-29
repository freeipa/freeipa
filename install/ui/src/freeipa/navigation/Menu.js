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
       'dojo/store/Memory',
       'dojo/_base/array',
       'dojo/_base/lang',
       'dojo/store/Observable',
       'dojo/Evented',
       '../reg',
       '../text'
       ], function(declare, Memory_store, array, lang, Observable, Evented, reg, text) {


return declare([Evented],
    /**
     * Menu store
     *
     * Maintains menu hierarchy and selection state.
     *
     * @class navigation.Menu
     *
     */
    {
    /**
     * Menu name
     * @property {String}
     */
    name: null,

    /**
     * Dojo Store of menu items
     * @property {Store}
     */
    items: null,

    /**
    * Delimiter used in name creation
    * To avoid having multiple menu items with the same name.
    * @property {String}
    */
    path_delimiter: '/',

    /**
     * Selected menu items
     * @property {Array}
     */
    selected: [],

    /**
     * Default search options: sort by position
     * @property {Object}
     */
    search_options: { sort: [{attribute:'position'}]},

    /**
     * Takes a spec of menu item.
     * Normalizes item's name, parent, adds children if specified
     *
     * @param {Object} item - spec
     * @param {string/Object} parent - name or menu item
     * @param {Object} options
     */
    add_item: function(item, parent, options) {

        item = lang.clone(item); //don't modify original spec

        // each item must have a name and a label
        // FIXME: consider to move entity and facet stuff outside of this object
        if (!item.name) {
            if (item.facet && item.entity) {
                item.name = item.entity + '_' + item.facet;
            } else {
                item.name = item.facet || item.entity;
            }
        }
        if (!item.name) {
            window.console.error('Missing menu item property: \'name\'', item);
            return false;
        }
        if (item.label) item.label = text.get(item.label);
        if (item.title) item.title = text.get(item.title);

        if (item.entity) {
            var entity = reg.entity.get(item.entity);
            if (!entity) {
                return false; //quit
            }
            if (!item.label) item.label = entity.label;
            if (!item.title) item.title = entity.title;
        } else if (item.facet) {
            var facet = reg.facet.get(item.facet);
            if (!facet) {
                return false; //quit
            }
            if (!item.label) item.label = facet.label;
            if (!item.title) item.title = facet.title;
        }

        item.hidden = !!item.hidden;
        item.selected = false;

        // check parent
        if (typeof parent === 'string') {
            parent = this.items.get(parent);
            if (!parent) throw 'Menu item\'s parent doesn\t exist';
        } else if (typeof parent === 'object') {
            if (!this.items.getIdentity(parent)) {
                throw 'Supplied parent isn\'t menu item';
            }
        }

        var parent_name = parent ? parent.name : null;
        var siblings = this.items.query({ parent: parent_name });
        if (!item.position) item.position = siblings.total;
        // TODO: add reordering of siblings when position set

        item.parent = parent_name;
        if (parent) {
            // names have to be unique
            item.name = parent.name + this.path_delimiter + item.name;
        }

        // children will be added separately
        var children = item.children;
        delete item.children;

        // finally add the item
        try {
            this.items.add(item);
        } catch(e) {
            window.console.error("Unable to add menu item", item);
            throw e;
        }

        // add children
        if (children) {
            array.forEach(children, function(child) {
                this.add_item(child, item);
            }, this);
        }
        return true;
    },

    /**
     * Add multiple items
     * @param {Array} items - spec of items
     */
    add_items: function(/* Array */ items) {
        array.forEach(items, function(item) {
            this.add_item(item);
        }, this);
    },

    /**
     * Query internal data store by using default search options.
     *
     * @param {Object} Query filter
     * @return {QueryResult}
     */
    query: function(query) {
        return this.items.query(query, this.search_options);
    },

    /**
     * Marks item and all its parents as selected.
     * @private
     */
    _select: function(item) {

        item.selected = true;
        this.selected.push(item);
        this.items.put(item);

        if (item.parent) {
            var parent = this.items.get(item.parent);
            parent.selected_child = item.name;
            this._select(parent);
        }
    },

    /**
     * Selects a menu item and all it's ancestors.
     * @param {string/navigation.MenuItem} item menu item to select
     */
    select: function(item) {

        if (typeof item == 'string') {
            item = this.items.get(item);
        }

        // FIXME: consider to raise an exception
        if (!item || !this.items.getIdentity(item)) return false;

        // deselect previous
        var old_selection = lang.clone(this.selected);
        array.forEach(this.selected, function(mi) {
            mi.selected = false;
            this.items.put(mi);
        }, this);
        this.selected = [];

        // select new
        this._select(item);

        var select_state = {
            item: item,
            new_selection: this.selected,
            old_selection: old_selection
        };

        this.emit('selected', select_state);
        return select_state;
    },

    /**
     * @param {Object} spec - Specification object
     * @param {Array} spec.items - Menu items
     * @param {string} spec.name - Name
     */
    constructor: function(spec) {
        spec = spec || {};
        this.items = new Observable( new Memory_store({
            idProperty: 'name'
        }));

        spec = lang.clone(spec);
        this.add_items(spec.items || []);
        delete spec.items;
        declare.safeMixin(this, spec);
    }
}); //declare freeipa.menu
}); //define
