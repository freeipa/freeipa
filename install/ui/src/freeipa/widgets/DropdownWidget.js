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
        'dojo/Stateful',
        'dojo/on',
        '../jquery',
        '../ipa'], function(declare, array, lang, dom, construct, prop, dom_class,
                            dom_style, attr, query, Evented, Stateful, on, $, IPA) {

    return declare([Stateful, Evented], {
        /**
         * Represents and creates a dropdown widget. It can contain multiple
         * levels.
         *
         * @class widgets.DropdownWidget
         */

        /**
         * Raised when menu item is clicked
         * @event item-click
         */

        /**
         * Dropdown name
         * @property {string}
         */
        name: '',

        /**
         * Element type
         * @property {string}
         */
        el_type: 'div',

        /**
         * Element class
         * @property {string}
         */
        'class': 'dropdown',

        /**
         * Submenu class
         */
        submenu_class: 'dropdown-submenu',

        /**
         * Toggle button text
         * @property {string}
         */
        toggle_text: '',

        /**
         * Icon displayed after toggle text
         * @property {String}
         */
        toggle_icon: null,

        /**
         * Toggle classes
         *
         * e.g.: `btn btn-default`
         *
         * @property {String}
         */
        toggle_class: '',

        /**
         * Toggle button content. Replaces toggle button text if set. Can be
         * use for more complex toggle buttons.
         * @property {HTMLElement|HTMLElement[]}
         */
        toggle_content: null,

        /**
         * Array of dropdown items to display. Item can have `items` field
         * with an array of child items.
         * @property {Array}
         */
        items: [],

        /**
         * dom_node of this widget
         * @property {HTMLElement}
         */
        dom_node: null,

        /**
         * Container for items
         * @protected
         * @property {HTMLElement}
         */
        ul_node: null,

        /**
         * Menu is right aligned
         * @type {Boolean}
         */
        right_aligned: false,

        render: function() {
            if (this.dom_node) {
                construct.empty(this.dom_node);

            } else {
                this.dom_node = construct.create(this.el_type, {
                    name: this.name || '',
                    'class': this['class']
                });
            }

            this._render_toggle(this.dom_node);
            this._render_list(this.dom_node);
            this._render_items(this.items);

            return this.dom_node;
        },

        get_items: function() {
            return this.items;
        },

        set_items: function(items) {
            this.items = items;
            if (this.ul_node) this.render();
        },

        disable_item: function(item_name) {
            var item = this._find_item(item_name);
            if (item && this.ul_node) {
                item.disabled = true;
                $("li[data-name=" + item.name +"]", this.ul_node ).replaceWith(
                    this._render_item(item));
            }
        },

        enable_item: function(item_name) {
            var item = this._find_item(item_name);
            if (item && this.ul_node) {
                item.disabled = false;
                $("li[data-name=" + item.name +"]", this.ul_node ).replaceWith(
                    this._render_item(item));
            }
        },

        _find_item: function(item_name) {
            for (var i=0, l=this.items.length; i<l; i++) {
                if (this.items[i].name && this.items[i].name == item_name) {
                    return this.items[i];
                }
            }
            return null;
        },

        _render_toggle: function(container) {

            this.toggle_node = construct.create('a', {
                'class': 'dropdown-toggle',
                'data-toggle': 'dropdown',
                href: '#'
            });
            if (this.toggle_class) dom_class.add(this.toggle_node, this.toggle_class);

            this._update_toggle();
            if (container) {
                construct.place(this.toggle_node, container);
            }
            return this.toggle_node;
        },

        _update_toggle: function() {
            if (!this.toggle_node) return;
            if (this.toggle_content) {
                if (lang.isArray(this.toggle_content)) {
                    array.forEach(this.toggle_content, function(item) {
                        construct.place(item, this.toggle_node);
                    }, this);
                } else {
                    construct.place(this.toggle_content, this.toggle_node);
                }
            } else {
                prop.set(this.toggle_node, 'textContent', this.toggle_text);
                if (this.toggle_icon) {
                    var icon = construct.create('i', {
                        'class': this.toggle_icon
                    }, this.toggle_node);
                }
            }
        },

        _toggle_textSetter: function(value) {
            this.toggle_text = value;
            this._update_toggle();
        },

        _toggle_contentSetter: function(value) {
            this.toggle_content = value;
            this._update_toggle();
        },

        _itemsSetter: function(value) {
            this._clear_items();
            this.items = value;
            this._render_items(this.items);
        },

        _clear_items: function() {
            this.items = [];
            if (this.ul_node) {
                construct.empty(this.ul_node);
            }
        },

        _render_list: function(container, nested) {

            var ul = construct.create('ul', {
                'class': 'dropdown-menu'
            });
            if (this.right_aligned) {
                dom_class.add(ul, 'dropdown-menu-right');
            }
            if (container) {
                construct.place(ul, container);
            }
            if (!nested) this.ul_node = ul;
            return ul;
        },

        _render_items: function(items, container) {

            if (!container) container = this.ul_node;
            array.forEach(items, function(item) {
                this._render_item(item, container);
            }, this);
        },

        _render_item: function(item, container) {

            var li = construct.create('li', {
                'data-name': item.name || '',
                role: 'presentation'
            });

            var a = construct.create('a', {
                'href': '#' + item.name || ''
            });
            if (item['class'] !== 'divider') {
                construct.place(a, li);
            }

            if (item.icon) {
                construct.create('i', {
                    'class': 'fa ' + item.icon
                }, a);
            }

            var text = document.createTextNode(' '+item.label || '');
            construct.place(text, a);

            if (item['class']) {
                dom_class.add(li, item['class']);
            }

            if (item.disabled) {
                dom_class.add(li, 'disabled');
                attr.set(a, 'tabIndex', -1);
            }

            if (item.items && item.items.length > 0) {
                dom_class.add(li, 'dropdown-submenu');
                var ul = this._render_list(li, true);
                this._render_items(item.items, ul);
            } else {
                on(a, 'click', function(event) {
                    this.on_item_click(event, item);
                    event.preventDefault();
                }.bind(this));
            }

            if (container) {
                construct.place(li, container);
            }
            return li;
        },

        on_item_click: function(event, item) {

            if (item.click) item.click();
            this.emit('item-click', item);
        },

        constructor: function(spec) {
            declare.safeMixin(this, spec);
        }
    });
});
