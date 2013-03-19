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
        'dojo/_base/lang',
        'dojo/dom',
        'dojo/dom-construct',
        'dojo/dom-prop',
        'dojo/dom-class',
        'dojo/dom-style',
        'dojo/dom-attr',
        'dojo/query',
        'dojo/Evented',
        'dojo/on',
        '../ipa'], function(declare, array, lang, dom, construct, prop, dom_class,
                            dom_style, attr, query, Evented, on, IPA) {

    return declare([Evented], {
        /**
         * @name freeipa.widget.menu
         * @class
         *
         * Creates UI for freeipa.navigation.menu. Provides an event when
         * a menu items is selected.
         *
         * event: item-select(menu_item)
         */


        /**
         * Object store of menu items
         * @protected
         * @type freeipa.navigation.menu
         */
        menu: null,

        /**
         * domNode of this widget. FIXME: move to superclass (none yet)
         * @type Node
         */
        domNode: null,

        /**
         * Turns off update on data change
         * @type Boolen
         */
        ignore_changes: false,

        /**
         * Css class for nodes containing a submenu of certain level_class
         * @type String
         */
        level_class: 'menu-level',

        /**
         * Renders widget's elements
         */
        render: function() {
            if (this.domNode) {
                construct.empty(this.domNode);
            } else {
                this.domNode = construct.create('div', {
                    'class': 'navigation'
                });
            }
            if (this.menu) {
                this._render_children(null, this.domNode, 1);
            }
            return this.domNode;
        },

        /**
         * Render children of menu_item
         * Top level items are rendered if menu_items is null
         *
         * @protected
         * @param {menu_item|null} menu_item
         * @param {Node} node
         * @param {Number} level
         */
        _render_children: function (menu_item, node, level) {

            var self = this;
            var name = menu_item ? menu_item.name : null;
            var children = this.menu.items.query({ parent: name },
                                 { sort: [{attribute:'position'}]});

            var lvl_class = this._get_lvl_class(level);

            if (children.total > 0) {
                var menu_node = construct.create('div', {
                    'class': 'submenu ' + lvl_class
                    //style: { display: 'none' }
                });

                if (menu_item) {
                    attr.set(menu_node, 'data-item', menu_item.name);
                }

                var ul_node = construct.create('ul', null, menu_node);

                array.forEach(children, function(menu_item) {

                    var click_handler = function(event) {
                        self.item_clicked(menu_item, event);
                        event.preventDefault();
                    };

                    var li_node = construct.create('li', {
                        'data-name': menu_item.name,
                        click: click_handler
                    }, ul_node);

                    var a_node = construct.create('a', {}, li_node);

                    this._update_item(menu_item, li_node);

                    // create submenu
                    this._render_children(menu_item, menu_node, level + 1);
                }, this);

                construct.place(menu_node, node);
            }
        },

        _get_lvl_class: function(level) {
            return this.level_class + '-' + level;
        },

        /**
         * Updates content of li_node associated with menu_item base on
         * menu_item's state.
         *
         * @protected
         * @param {menu_item|string} menu_item
         * @param {Node} [li_node]
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

            dom_class.toggle(li_node, 'disabled', !menu_item.disabled);
            dom_class.toggle(li_node, 'selected', menu_item.selected);
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
         * @param {menu_item[]} menu_items Items to show
         */
        select: function(menu_items) {

            // hide all except top level
            var exception = this._get_lvl_class(1);
            query('div.submenu', this.domNode).forEach(function(submenu_node) {

                if (dom_class.contains(submenu_node, exception)) return;

                dom_style.set(submenu_node, {
                    display: 'none'
                });
            }, this);

            // show and update selected
            array.forEach(menu_items, function(item) {
                this._update_item(item);

                // show submenu
                var item_div = query('div[data-item=\''+item.name+'\']', this.domNode)[0];
                if (item_div) {
                    dom_style.set(item_div, {
                        display: 'block'
                    });
                }
            }, this);
        },

        /**
         * Handles changes in this.menu object.
         *
         * @protected
         * @param {menu_item} object
         * @param {Number} removedFrom
         * @param {Number} insertedInto
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
         * @param {freeipa.navigation.menu} menu
         */
        set_menu: function(menu) {
            this.menu = menu;
            //get all items
            var q = menu.items.query();
            q.observe(lang.hitch(this, this._items_changed), true);
            on(this.menu, 'selected', lang.hitch(this, function(event) {
                this.select(event.new_selection);
            }));
        },

        /**
         * Internal handler for clicking on menu item.
         * Raises item-select event.
         */
        _item_clicked: function(menu_item) {
            this.emit('item-select', menu_item);
        },

        /**
         * Handles click on menu item.
         *
         * Intended for overriding.
         *
         * @param {menu_item} menu_item
         * @param {Event} event
         */
        item_clicked: function(menu_item/*, event*/) {
            this._item_clicked(menu_item);
        }
    });
});