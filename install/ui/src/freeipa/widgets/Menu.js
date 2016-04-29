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
        'dojo/_base/array',
        'dojo/dom',
        'dojo/dom-construct',
        'dojo/dom-prop',
        'dojo/dom-class',
        'dojo/dom-style',
        'dojo/dom-attr',
        'dojo/query',
        'dojo/Evented',
        'dojo/on',
        '../jquery',
        '../ipa'], function(declare, array, dom, construct, prop, dom_class,
                            dom_style, attr, query, Evented, on, $, IPA) {

    return declare([Evented], {
        /**
         * Creates UI for freeipa.navigation.menu. Provides an event when
         * a menu items is selected.
         *
         * @class widgets.Menu
         */

        /**
         * @event item-select(menu_item)
         */


        /**
         * Object store of menu items
         * @protected
         * @property {navigation.Menu}
         */
        menu: null,

        /**
         * dom_node of this widget. FIXME: move to superclass (none yet)
         * @property {HTMLElement}
         */
        dom_node: null,

        /**
         * Turns off update on data change
         * @property {boolean}
         */
        ignore_changes: false,

        /**
         * Css class for nodes containing a submenu of certain level_class
         * @property {string}
         */
        level_class: 'menu-level',

        /**
         * Renders widget's elements
         */
        render: function() {
            if (this.dom_node) {
                construct.empty(this.dom_node);
            }

            this.dom_node = this._render_children(null, null, this.dom_node, null, 1);

            return this.dom_node;
        },

        /**
         * Render submenu container of given level
         *
         * @protected
         * @param {Number} level submenu level
         */
        _render_level_container: function(level, parent) {

            var lvl_class = this._get_lvl_class(level);
            var type_cls = 'nav';
            if (level === 1) {
                type_cls = 'nav navbar-nav navbar-primary persistent-secondary';
            } else if (level === 2) {
                type_cls = 'nav navbar-nav navbar-persistent';
            } else {
                type_cls = 'dropdown-menu';
            }

            var cont = construct.create('ul', {
                'class': type_cls + ' ' + lvl_class
            });

            return cont;
        },

        /**
         * Render item and submenu to container
         */
        _render_item: function(menu_item, container, level) {

            var self = this;
            var click_handler = function(event) {
                if (event.defaultPrevented) return;
                self.item_clicked(menu_item, event);
                event.preventDefault();
            };

            var item_node = construct.create('li', {
                'data-name': menu_item.name,
                click: click_handler
            });
            var a_node = construct.create('a', {}, item_node);

            var children = this._get_children(menu_item);
            if (level > 1 && children.total > 0) {
                dom_class.add(item_node, 'dropdown-submenu');
                dom_class.add(a_node, 'dropdown-toggle');
                prop.set(item_node, 'onclick', undefined);
                attr.set(a_node, 'data-toggle', 'dropdown');
                attr.set(a_node, 'data-target', '#');
                $(a_node).dropdown();
            }

            this._update_item(menu_item, item_node);

             // create submenu
            this._render_children(menu_item, children, null, item_node, level + 1);

            construct.place(item_node, container);
        },

        /**
         * Render children of menu_item or top level items if menu_item is
         * null.
         *
         * @protected
         * @param {navigation.MenuItem|null} menu_item
         * @param {Object|null} children query result
         * @param {HTMLElement|null} item_container  container for children
         * @param {HTMLElement|null} container container for item_container
         * @param {number} level
         */
        _render_children: function(menu_item, children, item_container, container, level) {

            if (children === null) {
                children = this._get_children(menu_item);
            }

            if (!item_container) {
                item_container = this._render_level_container(level, container);
            }

            if (children.total > 0) {
                array.forEach(children, function(menu_item) {
                    this._render_item(menu_item, item_container, level);
                }, this);
            }

            if (container) {
                construct.place(item_container, container);
                // use jQuery resize to make use of window.resize throttling
                $(window).bind('resize', function() {
                    this._adjust_size(container, item_container, level);
                }.bind(this));
            }
            return item_container;
        },

        _get_children: function(menu_item) {
            var name = menu_item ? menu_item.name : null;
            var children = this.menu.items.query({ parent: name, hidden: false },
                                 { sort: [{attribute:'position'}]});
            return children;
        },

        _get_lvl_class: function(level) {
            return this.level_class + '-' + level;
        },

        /**
         * Updates content of li_node associated with menu_item base on
         * menu_item's state.
         *
         * @protected
         * @param {navigation.MenuItem|string} menu_item
         * @param {HTMLElement} [li_node]
         */
        _update_item: function(menu_item, li_node) {

            if (typeof menu_item === 'string') {
                menu_item = this.menu.items.get(menu_item);
            }

            if (!li_node) {
                li_node = query('li[data-name=\''+menu_item.name+'\']')[0];

                // Quit for non-existing nodes.
                // FIXME: maybe change to exception
                if (!li_node) return;
            }

            dom_class.toggle(li_node, 'disabled', !!menu_item.disabled);
            dom_class.toggle(li_node, 'active', menu_item.selected);
            dom_style.set(li_node, {
                display: menu_item.hidden ? 'none': 'default'
            });

            var a_node = query('a', li_node)[0];

            prop.set(a_node, 'href', '#' + menu_item.name);
            prop.set(a_node, 'textContent', menu_item.label);
            prop.set(a_node, 'title', menu_item.title || menu_item.label);
        },

        /**
         * Displays only supplied menu items.
         * @param {navigation.MenuItem[]} menu_items Items to show
         */
        select: function(menu_items) {

            // hide all except top level
            var exception = this._get_lvl_class(1);
            query('div.submenu', this.dom_node).forEach(function(submenu_node) {

                if (dom_class.contains(submenu_node, exception)) return;

                dom_style.set(submenu_node, {
                    display: 'none'
                });
            }, this);

            // show and update selected
            array.forEach(menu_items, function(item) {
                this._update_item(item);
            }, this);

            // to force adjusting of item sizes
            $(window).trigger('resize');
        },

        /**
         * Handles changes in this.menu object.
         *
         * @protected
         * @param {navigation.MenuItem} object
         * @param {number} removedFrom
         * @param {number} insertedInto
         */
        _items_changed: function(object, removedFrom, insertedInto) {

            if (this.ignore_changes) return;

            if (removedFrom === -1 && insertedInto === -1) {
                this._update_item(object);
            } else {
                // on add or removal, replace whole menu
                this.render();
                this.select(this.menu.selected);
            }
        },

        /**
         * Sets this.menu and starts to watch its changes
         * @param {navigation.Menu} menu
         */
        set_menu: function(menu) {
            this.menu = menu;
            //get all items
            var q = menu.items.query();
            q.observe(this._items_changed.bind(this), true);
            on(this.menu, 'selected', function(event) {
                this.select(event.new_selection);
            }.bind(this));
        },

        /**
         * Internal handler for clicking on menu item.
         * Raises item-select event.
         * @protected
         * @param {navigation.MenuItem} menu_items
         */
        _item_clicked: function(menu_item) {
            this.emit('item-select', menu_item);
        },

        /**
         * Handles click on menu item.
         *
         * Intended for overriding.
         *
         * @param {navigation.MenuItem} menu_item
         * @param {Event} event
         */
        item_clicked: function(menu_item/*, event*/) {
            this._item_clicked(menu_item);
        },

        /**
         * Adjust parent size according to child size
         * @param  {HTMLElement} parent parent menu item container
         * @param  {HTMLElement} child child menu item container
         * @param  {number} level level of the child menu item
         */
        _adjust_size: function(parent, child, level) {

            if (level !== 2) return;

            var child_height = dom_style.get(child, 'height');
            var absolute = dom_style.get(child, 'position') === 'absolute';
            if (child_height && absolute) {
                dom_style.set(parent, 'marginBottom', child_height+'px');
            }
        }
    });
});
