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
        'dojo/NodeList-dom'
       ],
       function(declare, lang, array, dom, construct, prop, dom_class,
                dom_style, query, on, Stateful, Evented, Menu) {

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

        logged_nodes: null,

        logged_user_node: null,

        logged_user_link_node: null,

        logout_link_node: null,

        menu_node: null,

        content_node: null,

        app_id: 'container',

        logged: false,

        _loggedSetter: function(value) {
            this.logged = value;
            if (this.logged_nodes) {
                this.logged_nodes.style('visibility', value ? 'visible' : 'hidden');
            }
        },

        fullname: '',

        _fullnameSetter: function(value) {
            this.fullname = value;
            if (this.logged_user_node) {
                prop.set(this.logged_user_node, 'textContent', value);
            }
        },

        render: function() {
            // TODO: this method may be split into several components


            this.domNode = construct.create('div', {
                id: this.app_id,
                'class': 'app-container'
            });

            if (this.container_node) {
                construct.place(this.domNode, this.container_node);
            }

            this._render_header();

            this.menu_node = this.menu_widget.render();
            construct.place(this.menu_node, this.domNode);

            this.content_node = construct.create('div', {
                'class': 'content'
            }, this.domNode);
        },

        _render_header: function() {
            this.header_node = construct.create('div', {
                'class': 'header'
            }, this.domNode);

            // logo
            construct.place(''+
                '<span class="header-logo">'+
                     '<a href="#"><img src="images/ipa-logo.png" />'+
                                 '<img src="images/ipa-banner.png" /></a>'+
                '</span>', this.header_node);

            // right part
            construct.place(''+
            '<span class="header-right">'+
                '<span class="header-passwordexpires"></span>'+
                '<span class="loggedinas header-loggedinas" style="visibility:hidden;">'+
                    '<a href="#"><span class="login_header">Logged in as</span>: <span class="login"></span></a>'+
                '</span>'+
                '<span class="header-loggedinas" style="visibility:hidden;">'+
                    ' | <a href="#logout" class="logout">Logout</a>'+
                '</span>'+
                '<span class="header-network-activity-indicator network-activity-indicator">'+
                    '<img src="images/spinner-header.gif" />'+
                '</span>'+
            '</span>', this.header_node);


            this.password_expires_node = query('.header-passwordexpires', this.header_node)[0];
            this.logged_nodes = query('.header-loggedinas', this.header_node);
            this.logged_header_node = query('.login_header')[0];
            this.logged_user_node = query('.loggedinas .login', this.header_node)[0];
            this.logged_user_link_node = query('.loggedinas a', this.header_node)[0];
            this.logout_link_node = query('.logout')[0];

            on(this.logout_link_node, 'click', lang.hitch(this,this.on_logout));
            on(this.logged_user_link_node, 'click', lang.hitch(this,this.on_profile));

            construct.place(this.header_node, this.domNode);
        },

        on_profile: function(event) {
            event.preventDefault();
            this.emit('profile-click');
        },

        on_logout: function(event) {
            event.preventDefault();
            this.emit('logout-click');
        },

        constructor: function(spec) {
            spec = spec || {};
            this.menu_widget = new Menu();
        }

    });

    return app;
});