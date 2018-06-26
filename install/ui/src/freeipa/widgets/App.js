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
        'dojo/query',
        'dojo/on',
        './Menu',
        './DropdownWidget',
        './FacetContainer',
        '../text',
        '../widget',
        'dojo/NodeList-dom'
       ],
       function(declare, array, dom, construct, prop, dom_class,
                dom_style, query, on, Menu, DropdownWidget,
                FacetContainer, text, widgets) {

    /**
     * Main application widget
     *
     * This class serves as top level widget. It creates basic UI: controls
     * rendering of header, footer and placeholder for facets.
     *
     * @class widgets.App
     */
    var app = declare([FacetContainer], {

        //widgets
        menu_widget: null,

        //nodes:
        dom_node: null,

        container_node: null,

        header_node: null,

        password_expires_node: null,

        logged_user_node: null,

        menu_node: null,

        indicator_node: null,

        id: 'container',

        logged: false,

        use_activity_indicator: true,

        _loggedSetter: function(value) {
            this.logged = value;
            //TODO show/hide menu
        },

        fullname: '',

        _fullnameSetter: function(value) {
            this.fullname = value;
            if (this.logged_user_node) {
                prop.set(this.logged_user_node, 'textContent', ' '+ value);
            }
        },

        render: function() {

            this.dom_node = construct.create('div', {
                id: this.id,
                'class': 'app-container'
            });

            if (this.container_node) {
                construct.place(this.dom_node, this.container_node);
            }

            this._render_navigation();

            this.content_node = construct.create('div', {
                'class': 'content'
            }, this.dom_node);

            if (this.use_activity_indicator) {
                this.indicator_node = construct.create('div', {}, this.dom_node);
                this.activity_indicator.create(this.indicator_node);
            }
        },

        _render_navigation: function() {

            this.nav_node = construct.create('nav', {
                'class': 'navbar navbar-default navbar-pf',
                role: 'navigation'
            });

            this._render_nav_header();
            construct.place(this.header_node, this.nav_node);

            this._render_nav_util();
            construct.place(this.nav_util_node, this.nav_node);

            this.menu_node = this.menu_widget.render();
            construct.place(this.menu_node, this.nav_util_node);

            construct.place(this.nav_node, this.dom_node);
        },

        _render_nav_header: function() {

            this.header_node = construct.create('div', {
                'class': 'navbar-header'
            }, this.nav_node);

            var button = construct.create('button', {
                'class': 'navbar-toggle',
                'data-toggle': 'collapse',
                'data-target': '.navbar-collapse-21'
            });

            construct.create('span', {
                'class': 'sr-only',
                innerHTML: 'Toggle navigation'
            }, button);

            construct.create('span', { 'class': 'icon-bar' }, button);
            construct.create('span', { 'class': 'icon-bar' }, button);
            construct.create('span', { 'class': 'icon-bar' }, button);

            construct.place(button, this.header_node);

            this._render_brand();
            construct.place(this.brand_node, this.header_node);
            return this.header_node;
        },

        _render_nav_util: function() {

            this.nav_util_node = construct.create('div', {
                'class': 'collapse navbar-collapse navbar-collapse-21'
            }, this.nav_node);



            this.nav_util_tool_node = construct.create('ul', {
                'class': 'nav navbar-nav navbar-utility'
            }, this.nav_util_node);

            this.password_expires_node = construct.create('li', {
                'class': 'header-passwordexpires'
            }, this.nav_util_tool_node);

            var user_toggle = this._render_user_toggle_nodes();
            this.user_menu.set('toggle_content', user_toggle);
            construct.place(this.user_menu.render(), this.nav_util_tool_node);

            return this.nav_util_node;
        },

        _render_brand: function() {
            this.brand_node = construct.create('a', {
                'class': 'navbar-brand',
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
                'class': 'fa fa-user'
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

        collapse_menu: function() {
            if (this.nav_util_node) {
                var $nav = $(this.nav_util_node);
                if ($nav.hasClass('in')) {
                    $nav.collapse('hide');
                }
            }
        },

        disable_user_menu_item: function(name) {
            this.user_menu.disable_item(name);
        },

        on_menu_item_click: function(item) {
            this.collapse_menu();
        },

        on_user_menu_click: function(item) {

            if (item.name === 'profile') {
                this.emit('profile-click');
            } else if (item.name === 'logout') {
                this.emit('logout-click');
            } else if (item.name == 'password_reset') {
                this.emit('password-reset-click');
            } else if (item.name == 'configuration') {
                this.emit('configuration-click');
            } else if (item.name == 'about') {
                this.emit('about-click');
            }
            this.collapse_menu();
        },

        constructor: function(spec) {
            spec = spec || {};
            this.menu_widget = new Menu();
            this.activity_indicator = widgets.activity_widget({
                mode: 'icon',
                text: text.get('@i18n:status.working', 'Working')
            });
            this.user_menu = new DropdownWidget({
                el_type:  'li',
                name: 'profile-menu',
                items: [
                    {
                        name: 'profile',
                        label: text.get('@i18n:profile-menu.profile',
			    'Profile'),
                        icon: 'fa-user'
                    },
                    {
                        name: 'password_reset',
                        label: text.get('@i18n:profile-menu.password_reset',
			    'Change password'),
                        icon: 'fa-key'
                    },
                    {
                        'class': 'divider'
                    },
                    {
                        name: 'configuration',
                        label: text.get('@i18n:profile-menu.configuration',
			    'Customization'),
                        icon: 'fa-gear'
                    },
                    {
                        name: 'about',
                        label: text.get('@i18n:profile-menu.about', 'About'),
                        icon: 'fa-question'
                    },
                    {
                        'class': 'divider'
                    },
                    {
                        name: 'logout',
                        label: text.get('@i18n:profile-menu.logout',
			    'Log out'),
                        icon: 'fa-sign-out'
                    }
                ]
            });
            on(this.user_menu, 'item-click', this.on_user_menu_click.bind(this));
            on(this.menu_widget, 'item-select', this.on_menu_item_click.bind(this));
        }

    });

    return app;
});
