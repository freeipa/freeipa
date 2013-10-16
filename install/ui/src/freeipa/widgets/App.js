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
        'dojo/_base/lang',
        'dojo/_base/array',
        'dojo/dom',
        'dojo/dom-construct',
        'dojo/dom-prop',
        'dojo/dom-class',
        'dojo/dom-style',
        'dojo/query',
        'dojo/on',
        'dojo/Evented',
        'dojo/Stateful',
        './Menu',
        './DropdownWidget',
        'dojo/NodeList-dom'
       ],
       function(declare, lang, array, dom, construct, prop, dom_class,
                dom_style, query, on, Stateful, Evented, Menu, DropdownWidget) {

    /**
     * Main application widget
     *
     * This class serves as top level widget. It creates basic UI: controls
     * rendering of header, footer and placeholder for facets.
     *
     * @class widgets.App
     */
    var app = declare([Stateful, Evented], {

        //widgets
        menu_widget: null,

        //nodes:

        domNode: null,

        container_node: null,

        header_node: null,

        password_expires_node: null,

        logged_user_node: null,

        menu_node: null,

        content_node: null,

        app_id: 'container',

        logged: false,

        _loggedSetter: function(value) {
            this.logged = value;
            //TODO show/hide menu
        },

        fullname: '',

        _fullnameSetter: function(value) {
            this.fullname = value;
            if (this.logged_user_node) {
                prop.set(this.logged_user_node, 'textContent', value);
            }
        },

        render: function() {

            this.domNode = construct.create('div', {
                id: this.app_id,
                'class': 'app-container'
            });

            if (this.container_node) {
                construct.place(this.domNode, this.container_node);
            }

            this._render_header();

            this.content_node = construct.create('div', {
                'class': 'content'
            }, this.domNode);
        },

        _render_header: function() {
            this.header_node = construct.create('div', {
                'class': 'header rcue'
            });

            this._render_nav_util();
            construct.place(this.nav_util_node, this.header_node);

            this.menu_node = this.menu_widget.render();
            construct.place(this.menu_node, this.header_node);

            construct.place(this.header_node, this.domNode);
        },

        _render_nav_util: function() {
            this.nav_util_node = construct.create('div', {
                'class': 'navbar utility'
            });

            this.nav_util_inner_node = construct.create('div', {
                'class': 'navbar-inner'
            }, this.nav_util_node);

            this._render_brand();
            construct.place(this.brand_node, this.nav_util_inner_node);

            this.nav_util_tool_node = construct.create('ul', {
                'class': 'nav pull-right'
            }, this.nav_util_inner_node);

            this.password_expires_node = construct.create('li', {
                'class': 'header-passwordexpires'
            }, this.nav_util_tool_node);

            var network_activity = construct.create('li', {
                'class': 'header-network-activity-indicator network-activity-indicator'
            }, this.nav_util_tool_node);

            construct.create('img', {
                'src': 'images/spinner-header.gif'
            }, network_activity);

            var user_toggle = this._render_user_toggle_nodes();
            this.user_menu.set('toggle_content', user_toggle);
            construct.place(this.user_menu.render(), this.nav_util_tool_node);

            return this.nav_util_node;
        },

        _render_brand: function() {
            this.brand_node = construct.create('a', {
                'class': 'brand',
                href: '#'
            });

            construct.create('img', {
                src: 'images/header-logo.png',
                alt: 'FreeIPA' // TODO: replace with configuration value
            }, this.brand_node);

            return this.brand_node;
        },

        _render_user_toggle_nodes: function() {

            var nodes = [];

            nodes.push(construct.create('span', {
                'class': 'icon-user icon-white'
            }));

            this.logged_user_node = construct.create('span', {
                'class': 'loggedinas'
            });
            nodes.push(this.logged_user_node);

            nodes.push(construct.create('b', {
                'class': 'caret'
            }));

            return nodes;
        },

        on_user_menu_click: function(item) {

            if (item.name === 'profile') {
                this.emit('profile-click');
            } else if (item.name === 'logout') {
                this.emit('logout-click');
            } else if (item.name == 'password_reset') {
                this.emit('password-reset-click');
            }
        },

        constructor: function(spec) {
            spec = spec || {};
            this.menu_widget = new Menu();
            this.user_menu = new DropdownWidget({
                el_type:  'li',
                name: 'profile-menu',
                items: [
                    {
                        name: 'profile',
                        label: 'Profile'
                    },
                    {
                        name: 'password_reset',
                        label: 'Change password'
                    },
                    {
                        'class': 'divider'
                    },
                    {
                        name: 'logout',
                        label: 'Logout'
                    }
                ]
            });
            on(this.user_menu, 'item-click', lang.hitch(this, this.on_user_menu_click));
        }

    });

    return app;
});